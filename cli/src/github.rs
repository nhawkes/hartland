//! The two GitHub endpoints we use: minting an OIDC token inside a job, and
//! fetching the public signing keys.

use crate::jwt::Jwks;

pub const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

/// Requests an OIDC token with the given audience. Only works inside a GitHub
/// Actions job with `id-token: write`. The request credentials are read from
/// the environment; callers must keep them away from build actions.
pub async fn request_token(audience: &str) -> Result<String, String> {
    let url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .map_err(|_| "ACTIONS_ID_TOKEN_REQUEST_URL not set (not in Actions, or no id-token: write?)")?;
    let bearer = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| "ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")?;
    let resp = crate::http::client()
        .get(&url)
        .query(&[("audience", audience)])
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("token request refused: {e}"))?;
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("token response not JSON: {e}"))?;
    v.get("value").and_then(|t| t.as_str()).map(str::to_string).ok_or_else(|| "token response has no value".to_string())
}

pub async fn fetch_jwks() -> Result<Jwks, String> {
    crate::http::client()
        .get(JWKS_URL)
        .send()
        .await
        .map_err(|e| format!("JWKS fetch failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("JWKS fetch refused: {e}"))?
        .json()
        .await
        .map_err(|e| format!("JWKS not valid: {e}"))
}
