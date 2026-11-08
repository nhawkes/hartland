//! Minimal RS256 JWT verification against an archive of JSON Web Keys.
//!
//! Only what GitHub Actions OIDC tokens need: alg RS256, key chosen by `kid`.
//! Expiry is deliberately not checked: tokens live 300 s, but serve here as
//! durable signatures over their claims.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub e: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Adds keys not already present (by kid). Keys are never removed, so old
    /// signatures stay verifiable after GitHub rotates keys. Returns the
    /// number added; fails if a known kid arrives with different material.
    pub fn merge(&mut self, other: &Jwks) -> Result<usize, String> {
        let mut added = 0;
        for k in &other.keys {
            match self.keys.iter().find(|x| x.kid == k.kid) {
                Some(x) if x.n == k.n && x.e == k.e => {}
                Some(_) => return Err(format!("key {} changed material; refusing", k.kid)),
                None => {
                    self.keys.push(k.clone());
                    added += 1;
                }
            }
        }
        self.keys.sort_by(|a, b| a.kid.cmp(&b.kid));
        Ok(added)
    }
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

/// Verifies the signature and returns the decoded claims.
pub fn verify(token: &str, jwks: &Jwks) -> Result<serde_json::Value, String> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err("token is not a three-part JWT".to_string()),
    };
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|e| format!("bad header: {e}"))?;
    if header.alg != "RS256" {
        return Err(format!("unsupported alg {}", header.alg));
    }
    let kid = header.kid.ok_or("token has no kid")?;
    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| format!("unknown signing key {kid}; run `hartland jwks update`?"))?;
    if key.kty != "RSA" {
        return Err(format!("key {kid} is not RSA"));
    }
    let public = ring::signature::RsaPublicKeyComponents { n: decode(&key.n)?, e: decode(&key.e)? };
    let signed = &token[..h.len() + 1 + p.len()];
    public
        .verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &decode(s)?)
        .map_err(|_| "signature does not verify".to_string())?;
    serde_json::from_slice(&decode(p)?).map_err(|e| format!("bad claims: {e}"))
}

fn decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("bad base64url: {e}"))
}
