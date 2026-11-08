//! End-to-end verification tests with a test-only RSA key standing in for
//! GitHub's OIDC signer. The key is a fixture and trusted by nothing real.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hartland::attest::{ActionResult, Digest, Envelope, Statement, audience_for};
use hartland::jwt::{Jwk, Jwks};
use hartland::keyring::{Builder, Keyring};
use serde_json::json;

const KEY: &[u8] = include_bytes!("fixtures/test-only-rsa.pk8");
const KID: &str = "test-kid";
const WORKFLOW: &str = "nhawkes/hartland/.github/workflows/build.yml";
const COMMIT: &str = "8cf622e2e7dfaad7a1d7a08e12037a801c8fa8dc";

fn keypair() -> ring::signature::RsaKeyPair {
    ring::signature::RsaKeyPair::from_pkcs8(KEY).unwrap_or_else(|e| panic!("fixture key: {e}"))
}

fn jwks() -> Jwks {
    let kp = keypair();
    let c: ring::rsa::PublicKeyComponents<Vec<u8>> = kp.public().into();
    let (n, e) = (B64.encode(c.n), B64.encode(c.e));
    Jwks { keys: vec![Jwk { kty: "RSA".into(), kid: KID.into(), n, e, alg: Some("RS256".into()), use_: Some("sig".into()) }] }
}

fn keyring() -> Keyring {
    Keyring { builders: vec![Builder { workflow: WORKFLOW.into(), commits: vec![COMMIT.into()] }] }
}

fn sign(header: serde_json::Value, claims: serde_json::Value) -> String {
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{h}.{p}");
    let kp = keypair();
    let mut sig = vec![0; kp.public().modulus_len()];
    kp.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut sig)
        .unwrap();
    format!("{input}.{}", B64.encode(sig))
}

fn claims(aud: &str) -> serde_json::Value {
    json!({
        "iss": "https://token.actions.githubusercontent.com",
        "aud": aud,
        "repository": "someone/hartland-packages",
        "job_workflow_ref": format!("{WORKFLOW}@{COMMIT}"),
        "job_workflow_sha": COMMIT,
        "runner_environment": "github-hosted",
        "run_id": "123",
        "iat": 1, "exp": 301,
    })
}

fn digest(c: char) -> Digest {
    Digest { hash: std::iter::repeat_n(c, 64).collect(), size: 10 }
}

fn payload() -> Vec<u8> {
    let s = Statement::new(vec![
        ActionResult { action: digest('b'), result: digest('c') },
        ActionResult { action: digest('a'), result: digest('d') },
    ]);
    hartland::statement_bytes(&s)
}

fn envelope_with(mutate: impl FnOnce(&mut serde_json::Value)) -> Envelope {
    let p = payload();
    let mut c = claims(&audience_for(&p));
    mutate(&mut c);
    Envelope::new(&p, sign(json!({"alg": "RS256", "kid": KID, "typ": "JWT"}), c))
}

fn err(env: &Envelope) -> String {
    hartland::verify_envelope(env, &jwks(), &keyring()).expect_err("must be rejected")
}

#[test]
fn accepts_valid_envelope() {
    let (statement, signer) = hartland::verify_envelope(&envelope_with(|_| {}), &jwks(), &keyring()).unwrap();
    assert_eq!(signer.workflow, WORKFLOW);
    assert_eq!(signer.commit, COMMIT);
    assert_eq!(signer.repository, "someone/hartland-packages");
    // Sorted by action digest, subjects in step with results.
    assert_eq!(statement.predicate.results[0].action, digest('a'));
    assert_eq!(statement.subject[0].digest["sha256"], digest('a').hash);
}

#[test]
fn accepts_builder_called_by_branch_name_at_trusted_commit() {
    let env = envelope_with(|c| c["job_workflow_ref"] = json!(format!("{WORKFLOW}@refs/heads/main")));
    assert!(hartland::verify_envelope(&env, &jwks(), &keyring()).is_ok());
}

#[test]
fn rejects_tampered_payload() {
    let mut env = envelope_with(|_| {});
    let mut other = payload();
    other.push(b' ');
    env.payload = base64::engine::general_purpose::STANDARD.encode(other);
    assert!(err(&env).contains("audience does not match"));
}

#[test]
fn rejects_wrong_audience() {
    let env = envelope_with(|c| c["aud"] = json!("hartland-attest:sha256:00"));
    assert!(err(&env).contains("audience does not match"));
}

#[test]
fn rejects_self_hosted_runner() {
    let env = envelope_with(|c| c["runner_environment"] = json!("self-hosted"));
    assert!(err(&env).contains("GitHub-hosted"));
}

#[test]
fn rejects_untrusted_commit() {
    let env = envelope_with(|c| c["job_workflow_sha"] = json!("0000000000000000000000000000000000000000"));
    assert!(err(&env).contains("not in the keyring"));
}

#[test]
fn rejects_untrusted_workflow() {
    let env = envelope_with(|c| c["job_workflow_ref"] = json!(format!("someone/evil/.github/workflows/build.yml@{COMMIT}")));
    assert!(err(&env).contains("not in the keyring"));
}

#[test]
fn rejects_other_issuer() {
    let env = envelope_with(|c| c["iss"] = json!("https://example.invalid"));
    assert!(err(&env).contains("not issued by GitHub"));
}

#[test]
fn rejects_bad_signature() {
    let mut env = envelope_with(|_| {});
    let t = &mut env.signatures[0].token;
    let last = t.pop().unwrap();
    t.push(if last == 'A' { 'B' } else { 'A' });
    assert!(err(&env).contains("signature") || err(&env).contains("base64"));
}

#[test]
fn rejects_alg_none_and_unknown_kid() {
    let p = payload();
    let none = Envelope::new(&p, sign(json!({"alg": "none", "kid": KID}), claims(&audience_for(&p))));
    assert!(err(&none).contains("unsupported alg"));
    let unknown = Envelope::new(&p, sign(json!({"alg": "RS256", "kid": "other"}), claims(&audience_for(&p))));
    assert!(err(&unknown).contains("unknown signing key"));
}

#[test]
fn rejects_mismatched_subjects() {
    let mut s = Statement::new(vec![ActionResult { action: digest('a'), result: digest('b') }]);
    s.subject[0].digest.insert("sha256".into(), digest('e').hash);
    let p = hartland::statement_bytes(&s);
    let env = Envelope::new(&p, sign(json!({"alg": "RS256", "kid": KID}), claims(&audience_for(&p))));
    assert!(err(&env).contains("subject does not match"));
}

#[test]
fn jwks_merge_keeps_old_keys_and_refuses_changed_material() {
    let mut archive = jwks();
    let mut newer = Jwks { keys: vec![Jwk { kid: "k2".into(), ..archive.keys[0].clone() }] };
    assert_eq!(archive.merge(&newer).unwrap(), 1);
    assert_eq!(archive.keys.len(), 2);
    assert_eq!(archive.merge(&newer).unwrap(), 0);
    newer.keys[0].n = "AQAB".into();
    assert!(archive.merge(&newer).is_err());
}

// ---- package attestations ----

fn package_envelope(repo_claim: &str, sha_claim: Option<&str>, predicate_repo: &str, predicate_commit: &str) -> Envelope {
    use hartland::package::{Package, PackageStatement};
    let st = PackageStatement::new(
        Package { target: "packages//examples/hello:hello".into(), repository: predicate_repo.into(), commit: predicate_commit.into() },
        [("hello".to_string(), digest('f').hash)].into(),
    );
    let p = hartland::package::statement_bytes(&st);
    let mut c = claims(&audience_for(&p));
    c["repository"] = json!(repo_claim);
    match sha_claim {
        Some(s) => c["sha"] = json!(s),
        None => {
            c.as_object_mut().unwrap().remove("sha");
        }
    }
    Envelope::new(&p, sign(json!({"alg": "RS256", "kid": KID}), c))
}

#[test]
fn package_accepts_matching_source() {
    let env = package_envelope("someone/pkgs", Some("abc123"), "someone/pkgs", "abc123");
    let (st, signer) = hartland::package::verify(&env, &jwks(), &keyring()).unwrap();
    assert_eq!(st.digest_of("hello"), Some(digest('f').hash.as_str()));
    assert_eq!(signer.source_commit.as_deref(), Some("abc123"));
}

#[test]
fn package_rejects_claimed_repository_mismatch() {
    let env = package_envelope("someone/pkgs", Some("abc123"), "victim/pkgs", "abc123");
    assert!(hartland::package::verify(&env, &jwks(), &keyring()).unwrap_err().contains("ran for someone/pkgs"));
}

#[test]
fn package_rejects_claimed_commit_mismatch() {
    let env = package_envelope("someone/pkgs", Some("abc123"), "someone/pkgs", "def456");
    assert!(hartland::package::verify(&env, &jwks(), &keyring()).unwrap_err().contains("commit def456"));
}

#[test]
fn package_rejects_token_without_commit() {
    let env = package_envelope("someone/pkgs", None, "someone/pkgs", "abc123");
    assert!(hartland::package::verify(&env, &jwks(), &keyring()).is_err());
}

#[test]
fn package_rejects_action_batch_as_package() {
    // A signed action-results batch must not pass as a package attestation.
    assert!(hartland::package::verify(&envelope_with(|_| {}), &jwks(), &keyring()).unwrap_err().contains("bad package statement")
        || hartland::package::verify(&envelope_with(|_| {}), &jwks(), &keyring()).unwrap_err().contains("not a hartland package"));
}

// ---- first tier (Actions-cache directory) ----

fn signed_batch(results: &[(String, hartland::reapi::re::ActionResult)]) -> (String, Vec<u8>) {
    use prost::Message as _;
    let pairs = results
        .iter()
        .map(|(a, r)| {
            let b = r.encode_to_vec();
            ActionResult { action: Digest { hash: a.clone(), size: 1 }, result: Digest { hash: hartland::attest::sha256_hex(&b), size: b.len() as u64 } }
        })
        .collect();
    let p = hartland::statement_bytes(&Statement::new(pairs));
    let env = serde_json::to_vec(&Envelope::new(&p, sign(json!({"alg": "RS256", "kid": KID}), claims(&audience_for(&p))))).unwrap();
    (hartland::attest::sha256_hex(&env), env)
}

fn result_with(out: &[u8]) -> hartland::reapi::re::ActionResult {
    use hartland::reapi::re;
    re::ActionResult {
        output_files: vec![re::OutputFile {
            path: "o".into(),
            digest: Some(re::Digest { hash: hartland::attest::sha256_hex(out), size_bytes: out.len() as i64 }),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[tokio::test]
async fn l1_round_trip_and_tamper_resistance() {
    use hartland::l1::{L1, bundle_bytes};
    let dir = std::env::temp_dir().join(format!("hartland-l1-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let l1 = L1::open(dir.clone()).await.unwrap();

    let (a1, a2) = (digest('a').hash, digest('b').hash);
    let (o1, o2) = (b"out one".to_vec(), b"out two".to_vec());
    let (r1, r2) = (result_with(&o1), result_with(&o2));
    let (h1, h2) = (hartland::attest::sha256_hex(&o1), hartland::attest::sha256_hex(&o2));
    let (env_hash, env) = signed_batch(&[(a1.clone(), r1.clone()), (a2.clone(), r2.clone())]);

    // A forged third entry (not in the signed statement) and a tampered
    // second entry must be dropped; the genuine first entry survives.
    let forged = result_with(b"evil");
    let bundle = bundle_bytes(&[
        (a1.clone(), r1.clone(), vec![h1.clone()]),
        (a2.clone(), result_with(b"tampered"), vec![h2.clone()]),
        (digest('c').hash, forged, vec![]),
    ])
    .unwrap();
    l1.put_blob(&h1, &o1).await.unwrap();
    l1.put_blob(&h2, &o2).await.unwrap();
    l1.write_batch(&env_hash, &env, &bundle).await.unwrap();

    let batches = l1.load(&jwks(), &keyring()).await;
    assert_eq!(batches.len(), 1);
    let actions: Vec<&String> = batches[0].results.iter().map(|(a, _, _)| a).collect();
    assert_eq!(actions, vec![&a1], "only the genuine signed entry is accepted");

    // An untrusted builder's batch is ignored entirely.
    let other = Keyring { builders: vec![Builder { workflow: WORKFLOW.into(), commits: vec!["0".repeat(40)] }] };
    assert!(l1.load(&jwks(), &other).await.is_empty());

    // A tampered blob reads as absent.
    assert_eq!(l1.get_blob(&h1).await.as_deref(), Some(&o1[..]));
    let p = dir.join("blobs").join(&h1[..2]).join(&h1);
    std::fs::write(&p, b"changed").unwrap();
    assert!(l1.get_blob(&h1).await.is_none());

    // Pruning keeps referenced blobs and drops unreferenced ones.
    let stray = b"stray".to_vec();
    let hs = hartland::attest::sha256_hex(&stray);
    l1.put_blob(&hs, &stray).await.unwrap();
    l1.prune(10, &jwks(), &keyring()).await.unwrap();
    assert!(!l1.has_blob(&hs).await, "unreferenced blob pruned");
    assert!(l1.has_blob(&h1).await, "referenced blob kept");
    let _ = std::fs::remove_dir_all(&dir);
}
