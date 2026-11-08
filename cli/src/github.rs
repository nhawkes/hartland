//! The two GitHub endpoints we use: minting an OIDC token inside a job, and
//! fetching the public signing keys.

use crate::jwt::Jwks;

pub const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

/// Requests an OIDC token with the given audience. Only works inside a GitHub
/// Actions job with `id-token: write`. The request credentials are read from
/// the environment; callers must keep them away from build actions.
pub fn request_token(audience: &str) -> Result<String, String> {
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .map_err(|_| "ACTIONS_ID_TOKEN_REQUEST_URL not set (not in Actions, or no id-token: write?)")?;
    let bearer = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| "ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")?;
    let sep = if url.contains('?') { '&' } else { '?' };
    let full = format!("{url}{sep}audience={}", percent_encode(audience));
    let body = ureq::get(&full)
        .header("Authorization", &format!("bearer {bearer}"))
        .call()
        .map_err(|e| format!("token request failed: {e}"))?
        .into_body()
        .read_to_string()
        .map_err(|e| format!("token response unreadable: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("token response not JSON: {e}"))?;
    v.get("value").and_then(|t| t.as_str()).map(str::to_string).ok_or("token response has no value".to_string())
}

pub fn fetch_jwks() -> Result<Jwks, String> {
    let body = ureq::get(JWKS_URL)
        .call()
        .map_err(|e| format!("JWKS fetch failed: {e}"))?
        .into_body()
        .read_to_string()
        .map_err(|e| format!("JWKS unreadable: {e}"))?;
    serde_json::from_str(&body).map_err(|e| format!("JWKS not valid: {e}"))
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
