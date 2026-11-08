//! Minimal RS256 JWT verification against an archive of JSON Web Keys.
//!
//! Only what GitHub Actions OIDC tokens need: alg RS256, key chosen by `kid`.
//! Expiry is deliberately not checked: tokens live 300 s, but serve here as
//! durable signatures over their claims.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use monostate::MustBe;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::serde_as;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token is not a three-part JWT")]
    Shape,
    #[error("bad base64url in token")]
    Encoding,
    #[error("bad token header (want alg RS256 with a kid): {0}")]
    Header(serde_json::Error),
    #[error("unknown signing key {0}; run `hartland jwks update`?")]
    UnknownKey(String),
    #[error("signature does not verify")]
    Signature,
    #[error("token claims are not of the expected shape: {0}")]
    Claims(serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("key {0} changed material; refusing")]
pub struct ChangedKey(String);

/// An RSA public key. Material is decoded on parse.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    kty: MustBe!("RSA"),
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    n: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    e: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
}

/// The archive, by key id. Keys are never removed, so old signatures stay
/// verifiable after GitHub rotates keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawJwks", into = "RawJwks")]
pub struct Jwks {
    keys: BTreeMap<String, Jwk>,
}

#[derive(Serialize, Deserialize)]
struct RawJwks {
    keys: Vec<RawJwk>,
}

#[derive(Serialize, Deserialize)]
struct RawJwk {
    kid: String,
    #[serde(flatten)]
    key: Jwk,
}

impl From<RawJwks> for Jwks {
    fn from(r: RawJwks) -> Jwks {
        Jwks {
            keys: r.keys.into_iter().map(|k| (k.kid, k.key)).collect(),
        }
    }
}

impl From<Jwks> for RawJwks {
    fn from(j: Jwks) -> RawJwks {
        RawJwks {
            keys: j
                .keys
                .into_iter()
                .map(|(kid, key)| RawJwk { kid, key })
                .collect(),
        }
    }
}

impl Jwks {
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Adds keys not already present. Returns the number added; refuses a
    /// known kid arriving with different material.
    pub fn merge(&mut self, other: Jwks) -> Result<usize, ChangedKey> {
        let mut added = 0;
        for (kid, key) in other.keys {
            match self.keys.get(&kid) {
                Some(have) if have.n == key.n && have.e == key.e => {}
                Some(_) => return Err(ChangedKey(kid)),
                None => {
                    self.keys.insert(kid, key);
                    added += 1;
                }
            }
        }
        Ok(added)
    }
}

#[derive(Deserialize)]
struct Header {
    #[allow(dead_code)]
    alg: MustBe!("RS256"),
    kid: String,
}

/// Verifies the signature and parses the claims as `C`.
pub fn verify<C: DeserializeOwned>(token: &str, jwks: &Jwks) -> Result<C, JwtError> {
    let [h, p, s] = token
        .split('.')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| JwtError::Shape)?;
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|_| JwtError::Encoding);
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(JwtError::Header)?;
    let key = jwks
        .keys
        .get(&header.kid)
        .ok_or_else(|| JwtError::UnknownKey(header.kid.clone()))?;
    let public = ring::signature::RsaPublicKeyComponents {
        n: &key.n,
        e: &key.e,
    };
    let signed = &token[..h.len() + 1 + p.len()];
    public
        .verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            signed.as_bytes(),
            &decode(s)?,
        )
        .map_err(|_| JwtError::Signature)?;
    serde_json::from_slice(&decode(p)?).map_err(JwtError::Claims)
}
