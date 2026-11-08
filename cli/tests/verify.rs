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
