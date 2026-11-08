//! The two GitHub endpoints we use: minting an OIDC token inside a job, and
//! fetching the public signing keys.

use crate::jwt::Jwks;

pub const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("{0} not set (not in GitHub Actions, or no `id-token: write`?)")]
    NotInActions(&'static str),
    #[error("token request failed: {0}")]
    Request(#[from] reqwest::Error),
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    value: String,
}

/// Requests an OIDC token for `audience` (an attestation's `Audience`, or
/// any other binding such as a peer's endpoint key). Only works inside a GitHub Actions
/// job with `id-token: write`. The request credentials are read from the
/// environment; callers must keep them away from build actions.
pub async fn request_token(audience: &impl std::fmt::Display) -> Result<String, TokenError> {
    let var = |k: &'static str| std::env::var(k).map_err(|_| TokenError::NotInActions(k));
    let url = var("ACTIONS_ID_TOKEN_REQUEST_URL")?;
    let bearer = var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")?;
    let r: TokenResponse = crate::http::client()
        .get(&url)
        .query(&[("audience", audience.to_string())])
        .bearer_auth(bearer)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(r.value)
}

pub async fn fetch_jwks() -> Result<Jwks, reqwest::Error> {
    crate::http::client()
        .get(JWKS_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}
