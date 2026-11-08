//! End-to-end verification tests with a test-only RSA key standing in for
//! GitHub's OIDC signer. The key is a fixture and trusted by nothing real.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hartland::attest::{Audience, Batch, Envelope, Pair, SignatureError, VerifyError};
use hartland::bundle::{CachedResult, VerifiedBatch, bundle_bytes};
use hartland::cas::Blob;
use hartland::digest::{ActionId, BatchId, Digest, GitSha, Sha256};
use hartland::jwt::{Jwks, JwtError};
use hartland::keyring::{Keyring, TrustError};
use hartland::l1::L1;
use hartland::package::{Package, PackageStatement};
use hartland::reapi::re;
use prost::Message as _;
use serde_json::{Value, json};
use std::collections::HashSet;

const KEY: &[u8] = include_bytes!("fixtures/test-only-rsa.pk8");
const KID: &str = "test-kid";
const WORKFLOW: &str = "nhawkes/hartland/.github/workflows/build.yml";
const COMMIT: &str = "8cf622e2e7dfaad7a1d7a08e12037a801c8fa8dc";
const SOURCE: &str = "abc1230000000000000000000000000000000000";

fn keypair() -> ring::signature::RsaKeyPair {
    ring::signature::RsaKeyPair::from_pkcs8(KEY).unwrap_or_else(|e| panic!("fixture key: {e}"))
}

fn jwk(kid: &str) -> Value {
    let c: ring::rsa::PublicKeyComponents<Vec<u8>> = keypair().public().into();
    json!({"kty": "RSA", "kid": kid, "n": B64.encode(c.n), "e": B64.encode(c.e), "alg": "RS256", "use": "sig"})
}

fn jwks() -> Jwks {
    serde_json::from_value(json!({"keys": [jwk(KID)]})).unwrap()
}

fn keyring() -> Keyring {
    Keyring::trusting(WORKFLOW.parse().unwrap(), [COMMIT.parse().unwrap()])
}

fn sign(header: Value, claims: Value) -> String {
    let h = B64.encode(serde_json::to_vec(&header).unwrap());
    let p = B64.encode(serde_json::to_vec(&claims).unwrap());
    let input = format!("{h}.{p}");
    let kp = keypair();
    let mut sig = vec![0; kp.public().modulus_len()];
    kp.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .unwrap();
    format!("{input}.{}", B64.encode(sig))
}

fn claims(payload: &[u8]) -> Value {
    json!({
        "iss": "https://token.actions.githubusercontent.com",
        "aud": Audience::of(payload).to_string(),
        "repository": "someone/hartland-packages",
        "job_workflow_ref": format!("{WORKFLOW}@{COMMIT}"),
        "job_workflow_sha": COMMIT,
        "runner_environment": "github-hosted",
        "sha": SOURCE,
        "run_id": "123",
        "iat": 1, "exp": 301,
    })
}

fn header() -> Value {
    json!({"alg": "RS256", "kid": KID, "typ": "JWT"})
}

fn digest(n: u8) -> Digest {
    Digest {
        hash: Sha256::of(&[n]),
        size: 10,
    }
}

fn payload() -> Vec<u8> {
    Batch::new([
        Pair {
            action: digest(2),
            result: digest(3),
        },
        Pair {
            action: digest(1),
            result: digest(4),
        },
    ])
    .to_bytes()
}

fn envelope_with(mutate: impl FnOnce(&mut Value)) -> Envelope {
    let p = payload();
    let mut c = claims(&p);
    mutate(&mut c);
    Envelope::new(p, sign(header(), c))
}

fn verify(env: &Envelope) -> Result<hartland::attest::Signed<Batch>, VerifyError> {
    env.verify(&jwks(), &keyring())
}

/// The single signature's failure.
fn sig_err(env: &Envelope) -> SignatureError {
    match verify(env) {
        Err(VerifyError::NoValidSignature(mut v)) if v.len() == 1 => v.remove(0),
        other => panic!("expected one signature error, got {:?}", other.map(|_| ())),
    }
}

/// Re-reads an envelope after editing its wire form.
fn tampered(env: &Envelope, edit: impl FnOnce(&mut Value)) -> Envelope {
    let mut v: Value = serde_json::from_slice(&env.to_bytes()).unwrap();
    edit(&mut v);
    Envelope::parse(&serde_json::to_vec(&v).unwrap()).unwrap()
}

#[test]
fn accepts_valid_envelope() {
    let signed = verify(&envelope_with(|_| {})).unwrap();
    assert_eq!(signed.signer.workflow.to_string(), WORKFLOW);
    assert_eq!(signed.signer.commit.to_string(), COMMIT);
    assert_eq!(
        signed.signer.repository.to_string(),
        "someone/hartland-packages"
    );
    assert_eq!(
        signed.statement.results[&ActionId(digest(1).hash)].result,
        digest(4)
    );
}

#[test]
fn statement_wire_form_is_sorted_with_subjects_in_step() {
    let v: Value = serde_json::from_slice(&payload()).unwrap();
    let mut actions = [digest(1).hash.to_string(), digest(2).hash.to_string()];
    actions.sort();
    assert_eq!(
        v["predicate"]["results"][0]["action"]["hash"],
        json!(actions[0])
    );
    assert_eq!(v["subject"][0]["digest"]["sha256"], json!(actions[0]));
    assert_eq!(v["_type"], json!("https://in-toto.io/Statement/v1"));
}

#[test]
fn accepts_builder_called_by_branch_name_at_trusted_commit() {
    assert!(
        verify(&envelope_with(
            |c| c["job_workflow_ref"] = json!(format!("{WORKFLOW}@refs/heads/main"))
        ))
        .is_ok()
    );
}

#[test]
fn rejects_tampered_payload() {
    let env = tampered(&envelope_with(|_| {}), |v| {
        let mut other = payload();
        other.push(b' ');
        v["payload"] = json!(base64::engine::general_purpose::STANDARD.encode(other));
    });
    assert!(matches!(
        sig_err(&env),
        SignatureError::Trust(TrustError::Audience)
    ));
}

#[test]
fn rejects_wrong_audience() {
    let env = envelope_with(|c| c["aud"] = json!("hartland-attest:sha256:00"));
    assert!(matches!(
        sig_err(&env),
        SignatureError::Trust(TrustError::Audience)
    ));
}

#[test]
fn rejects_self_hosted_runner() {
    let env = envelope_with(|c| c["runner_environment"] = json!("self-hosted"));
    assert!(matches!(
        sig_err(&env),
        SignatureError::Trust(TrustError::SelfHosted)
    ));
}

#[test]
fn rejects_untrusted_commit() {
    let env = envelope_with(|c| c["job_workflow_sha"] = json!("0".repeat(40)));
    assert!(matches!(
        sig_err(&env),
        SignatureError::Trust(TrustError::Untrusted(..))
    ));
}

#[test]
fn rejects_untrusted_workflow() {
    let env = envelope_with(|c| {
        c["job_workflow_ref"] = json!(format!("someone/evil/.github/workflows/build.yml@{COMMIT}"))
    });
    assert!(matches!(
        sig_err(&env),
        SignatureError::Trust(TrustError::Untrusted(..))
    ));
}

#[test]
fn rejects_other_issuer_and_malformed_claims() {
    let env = envelope_with(|c| c["iss"] = json!("https://example.invalid"));
    assert!(matches!(
        sig_err(&env),
        SignatureError::Jwt(JwtError::Claims(_))
    ));
    let env = envelope_with(|c| c["job_workflow_sha"] = json!("2533ca1"));
    assert!(matches!(
        sig_err(&env),
        SignatureError::Jwt(JwtError::Claims(_))
    ));
}

#[test]
fn rejects_bad_signature() {
    let env = tampered(&envelope_with(|_| {}), |v| {
        let t = v["signatures"][0]["token"].as_str().unwrap().to_string();
        let flipped = if t.ends_with('A') { 'B' } else { 'A' };
        v["signatures"][0]["token"] = json!(format!("{}{flipped}", &t[..t.len() - 1]));
    });
    assert!(matches!(
        sig_err(&env),
        SignatureError::Jwt(JwtError::Signature | JwtError::Encoding)
    ));
}

#[test]
fn rejects_alg_none_and_unknown_kid() {
    let p = payload();
    let none = Envelope::new(
        p.clone(),
        sign(json!({"alg": "none", "kid": KID}), claims(&p)),
    );
    assert!(matches!(
        sig_err(&none),
        SignatureError::Jwt(JwtError::Header(_))
    ));
    let unknown = Envelope::new(
        p.clone(),
        sign(json!({"alg": "RS256", "kid": "other"}), claims(&p)),
    );
    assert!(matches!(
        sig_err(&unknown),
        SignatureError::Jwt(JwtError::UnknownKey(_))
    ));
}

#[test]
fn rejects_unknown_signature_kind_and_unsigned() {
    let env = tampered(&envelope_with(|_| {}), |v| {
        v["signatures"][0]["kind"] = json!("pgp")
    });
    assert!(matches!(sig_err(&env), SignatureError::UnsupportedKind));
    let env = tampered(&envelope_with(|_| {}), |v| v["signatures"] = json!([]));
    assert!(matches!(verify(&env), Err(VerifyError::Unsigned)));
}

#[test]
fn rejects_mismatched_subjects() {
    let mut v: Value = serde_json::from_slice(
        &Batch::new([Pair {
            action: digest(1),
            result: digest(2),
        }])
        .to_bytes(),
    )
    .unwrap();
    v["subject"][0]["digest"]["sha256"] = json!(digest(5).hash.to_string());
    let p = serde_json::to_vec(&v).unwrap();
    let env = Envelope::new(p.clone(), sign(header(), claims(&p)));
    assert!(matches!(verify(&env), Err(VerifyError::Statement(_))));
}

#[test]
fn jwks_round_trips_and_merge_keeps_old_keys_and_refuses_changed_material() {
    let mut archive = jwks();
    let text = serde_json::to_value(&archive).unwrap();
    assert_eq!(
        text,
        json!({"keys": [jwk(KID)]}),
        "archive format unchanged"
    );
    let newer: Jwks = serde_json::from_value(json!({"keys": [jwk("k2")]})).unwrap();
    assert_eq!(archive.merge(newer.clone()).unwrap(), 1);
    assert_eq!(archive.len(), 2);
    assert_eq!(archive.merge(newer).unwrap(), 0);
    let mut changed = jwk("k2");
    changed["n"] = json!("AQAB");
    assert!(
        archive
            .merge(serde_json::from_value(json!({"keys": [changed]})).unwrap())
            .is_err()
    );
}

// ---- package attestations ----

fn package_envelope(
    repo_claim: &str,
    sha_claim: Option<&str>,
    predicate_repo: &str,
    predicate_commit: &str,
) -> Envelope {
    let st = PackageStatement::new(
        Package {
            target: "packages//examples/hello:hello".into(),
            repository: predicate_repo.parse().unwrap(),
            commit: predicate_commit.parse().unwrap(),
        },
        [("hello".to_string(), digest(6).hash)].into(),
    )
    .unwrap();
    let p = st.to_bytes();
    let mut c = claims(&p);
    c["repository"] = json!(repo_claim);
    match sha_claim {
        Some(s) => c["sha"] = json!(s),
        None => drop(c.as_object_mut().unwrap().remove("sha")),
    }
    Envelope::new(p, sign(header(), c))
}

fn verify_package(
    env: &Envelope,
) -> Result<hartland::attest::Signed<PackageStatement>, VerifyError> {
    hartland::package::verify(env, &jwks(), &keyring())
}

#[test]
fn package_accepts_matching_source() {
    let signed = verify_package(&package_envelope(
        "someone/pkgs",
        Some(SOURCE),
        "someone/pkgs",
        SOURCE,
    ))
    .unwrap();
    assert_eq!(signed.statement.outputs.get("hello"), Some(&digest(6).hash));
    assert_eq!(
        signed.signer.source_commit,
        Some(SOURCE.parse::<GitSha>().unwrap())
    );
}

#[test]
fn package_rejects_claimed_repository_mismatch() {
    let env = package_envelope("someone/pkgs", Some(SOURCE), "victim/pkgs", SOURCE);
    assert!(matches!(
        verify_package(&env),
        Err(VerifyError::WrongRepository { .. })
    ));
}

#[test]
fn package_rejects_claimed_commit_mismatch() {
    let env = package_envelope(
        "someone/pkgs",
        Some(SOURCE),
        "someone/pkgs",
        &"d".repeat(40),
    );
    assert!(matches!(
        verify_package(&env),
        Err(VerifyError::WrongCommit { .. })
    ));
}

#[test]
fn package_rejects_token_without_commit() {
    let env = package_envelope("someone/pkgs", None, "someone/pkgs", SOURCE);
    assert!(matches!(
        verify_package(&env),
        Err(VerifyError::WrongCommit { actual: None, .. })
    ));
}

#[test]
fn package_rejects_action_batch_as_package() {
    // A signed action-results batch must not pass as a package attestation.
    assert!(matches!(
        verify_package(&envelope_with(|_| {})),
        Err(VerifyError::Statement(_))
    ));
}

// ---- first tier (Actions-cache directory) ----

fn signed_batch(results: &[(ActionId, &re::ActionResult)]) -> bytes::Bytes {
    let pairs = results.iter().map(|(a, r)| Pair {
        action: Digest { hash: a.0, size: 1 },
        result: Digest::of(&r.encode_to_vec()),
    });
    let p = Batch::new(pairs).to_bytes();
    Envelope::new(p.clone(), sign(header(), claims(&p)))
        .to_bytes()
        .into()
}

fn result_with(out: &[u8]) -> re::ActionResult {
    re::ActionResult {
        output_files: vec![re::OutputFile {
            path: "o".into(),
            digest: Some(Digest::of(out).into()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn cached(action: ActionId, result: re::ActionResult, blobs: &[Sha256]) -> CachedResult {
    CachedResult {
        action,
        result,
        blobs: blobs.iter().copied().collect(),
    }
}

#[tokio::test]
async fn first_tier_round_trip_and_tamper_resistance() {
    let dir = tempfile::tempdir().unwrap();
    let l1 = L1::open(dir.path().to_path_buf()).await.unwrap();

    let (a1, a2) = (ActionId(digest(1).hash), ActionId(digest(2).hash));
    let (o1, o2) = (Blob::new(&b"out one"[..]), Blob::new(&b"out two"[..]));
    let (r1, r2) = (result_with(o1.data()), result_with(o2.data()));
    let envelope = signed_batch(&[(a1, &r1), (a2, &r2)]);
    let id = BatchId(Sha256::of(&envelope));

    // A forged third entry (not in the signed statement) and a tampered
    // second entry must be dropped; the genuine first entry survives.
    let bundle = bundle_bytes(&[
        cached(a1, r1.clone(), &[o1.hash()]),
        cached(a2, result_with(b"tampered"), &[o2.hash()]),
        cached(ActionId(digest(3).hash), result_with(b"evil"), &[]),
    ]);
    l1.put_blob(&o1).await.unwrap();
    l1.put_blob(&o2).await.unwrap();
    l1.write_batch(&id, envelope.clone(), bundle.clone())
        .await
        .unwrap();

    let batches = l1.load(&jwks(), &keyring()).await;
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].id, id);
    let actions: Vec<ActionId> = batches[0].results.iter().map(|r| r.action).collect();
    assert_eq!(actions, [a1], "only the genuine signed entry is accepted");

    // The same check applies to a batch fetched from anywhere.
    assert_eq!(
        VerifiedBatch::accept(envelope.clone(), &bundle, &jwks(), &keyring())
            .unwrap()
            .results
            .len(),
        1
    );

    // An untrusted builder's batch is ignored entirely.
    let other = Keyring::trusting(WORKFLOW.parse().unwrap(), ["0".repeat(40).parse().unwrap()]);
    assert!(l1.load(&jwks(), &other).await.is_empty());

    // A batch filed under the wrong name is ignored.
    let wrong = BatchId(Sha256::of(b"elsewhere"));
    l1.write_batch(&wrong, envelope, bundle).await.unwrap();
    assert_eq!(l1.load(&jwks(), &keyring()).await.len(), 1);

    // A tampered blob reads as absent.
    assert_eq!(
        l1.blobs().get(&o1.hash()).await.map(|b| b.into_data()),
        Some(o1.data().clone())
    );
    let p = dir
        .path()
        .join("blobs")
        .join(o1.hash().shard())
        .join(o1.hash().to_string());
    std::fs::write(&p, b"changed").unwrap();
    assert!(l1.blobs().get(&o1.hash()).await.is_none());

    // Pruning keeps referenced blobs and drops unreferenced ones.
    let stray = Blob::new(&b"stray"[..]);
    l1.put_blob(&stray).await.unwrap();
    l1.put_blob(&o1).await.unwrap();
    l1.prune(10, &HashSet::new(), &jwks(), &keyring())
        .await
        .unwrap();
    assert!(
        !l1.blobs().contains(&stray.hash()).await,
        "unreferenced blob pruned"
    );
    assert!(
        l1.blobs().contains(&o1.hash()).await,
        "referenced blob kept"
    );
}

#[test]
fn keyring_file_format() {
    // As written by ci/attested-build.sh and keys/builders.json.
    let text = json!({"builders": [{"workflow": WORKFLOW, "commits": [COMMIT]}]});
    let k: Keyring = serde_json::from_value(text.clone()).unwrap();
    assert_eq!(k, keyring());
    assert_eq!(serde_json::to_value(&k).unwrap(), text);
    assert!(
        serde_json::from_value::<Keyring>(
            json!({"builders": [{"workflow": "not-a-workflow", "commits": []}]})
        )
        .is_err()
    );
}
