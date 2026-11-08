//! Hartland: attested builds anchored in GitHub-hosted runners.

pub mod attest;
pub mod execute;
pub mod ghcr_store;
pub mod github;
pub mod http;
pub mod jwt;
pub mod keyring;
pub mod oci;
pub mod package;
pub mod proxy;
pub mod reapi;
pub mod sandbox;

use attest::{Envelope, SIGNATURE_KIND, Statement};
use keyring::{Keyring, Signer};

/// Verifies an envelope's signature: some signature must be a GitHub Actions
/// token, valid against the key archive, bound to these exact payload bytes,
/// and from a builder the keyring trusts. Returns the payload and signer.
pub fn verify_signed(env: &Envelope, jwks: &jwt::Jwks, keyring: &Keyring) -> Result<(Vec<u8>, Signer), String> {
    let payload = env.payload_bytes()?;
    let audience = attest::audience_for(&payload);
    let mut errors = Vec::new();
    let mut signer = None;
    for sig in &env.signatures {
        if sig.kind != SIGNATURE_KIND {
            errors.push(format!("unsupported signature kind {}", sig.kind));
            continue;
        }
        match jwt::verify(&sig.token, jwks).and_then(|c| keyring.accept(&c, &audience)) {
            Ok(s) => {
                signer = Some(s);
                break;
            }
            Err(e) => errors.push(e),
        }
    }
    let signer = signer.ok_or_else(|| {
        if errors.is_empty() { "envelope has no signatures".to_string() } else { errors.join("; ") }
    })?;
    Ok((payload, signer))
}

/// Verifies a signed batch of action results.
pub fn verify_envelope(env: &Envelope, jwks: &jwt::Jwks, keyring: &Keyring) -> Result<(Statement, Signer), String> {
    let (payload, signer) = verify_signed(env, jwks, keyring)?;
    let statement: Statement = serde_json::from_slice(&payload).map_err(|e| format!("bad statement: {e}"))?;
    statement.check()?;
    Ok((statement, signer))
}

/// Serialises a statement to the exact bytes that get signed.
pub fn statement_bytes(s: &Statement) -> Vec<u8> {
    serde_json::to_vec(s).expect("statement serialises")
}
