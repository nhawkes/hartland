//! Keys certified by GitHub: a chain from one OIDC token to many signatures.
//!
//! A job generates an Ed25519 key and requests one OIDC token whose audience
//! is `hartland-key:<public key>`. The token is GitHub's certificate that
//! the trusted builder, on a hosted runner, running for repository R in run
//! N (event E), holds that key. Everything else the job signs (result
//! batches, membership of a build) it signs with the key, attaching the
//! certificate. The same key is the job's iroh endpoint key, so it also
//! authenticates the job's connections.
//!
//! Signing and verification use ring; nothing here is unsafe.

use crate::digest::ParseError;
use crate::jwt::{self, Jwks, JwtError};
use crate::keyring::{Claims, Keyring, Signer, TrustError};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde_with::{DeserializeFromStr, SerializeDisplay, serde_as};
use std::fmt;
use std::str::FromStr;

/// An Ed25519 public key.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> PublicKey {
        PublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Checks `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &SignatureBytes) -> Result<(), CertError> {
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(message, &signature.0)
            .map_err(|_| CertError::BadSignature)
    }
}

impl FromStr for PublicKey {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<PublicKey, ParseError> {
        let bad = || ParseError::Hex {
            len: 32,
            input: s.chars().take(80).collect(),
        };
        if s.len() != 64 || s.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| bad())?;
        Ok(PublicKey(out))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

/// An Ed25519 signature.
#[serde_as]
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SignatureBytes(#[serde_as(as = "serde_with::base64::Base64")] [u8; 64]);

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureBytes({})", hex::encode(&self.0[..8]))
    }
}

impl SignatureBytes {
    pub fn from_bytes(bytes: [u8; 64]) -> SignatureBytes {
        SignatureBytes(bytes)
    }
}

/// The audience by which GitHub certifies that a job holds a key.
pub struct KeyAudience<'a>(pub &'a PublicKey);

impl fmt::Display for KeyAudience<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hartland-key:{}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("signature does not verify against the certified key")]
    BadSignature,
    #[error(transparent)]
    Jwt(#[from] JwtError),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error("not a valid Ed25519 seed")]
    BadSeed,
    #[error("no randomness available")]
    Random,
    #[error("this key has no certificate yet")]
    Uncertified,
}

/// A key and GitHub's certificate for it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Certificate {
    pub key: PublicKey,
    /// The OIDC token whose audience names `key`.
    pub token: String,
}

impl Certificate {
    /// The token must verify, name this key, and come from a builder the
    /// keyring trusts on a hosted runner.
    pub fn verify(&self, jwks: &Jwks, keyring: &Keyring) -> Result<Signer, CertError> {
        let claims: Claims = jwt::verify(&self.token, jwks)?;
        Ok(keyring.accept(&claims, &KeyAudience(&self.key))?)
    }
}

/// This job's key, with its certificate once one has been requested.
pub struct Identity {
    seed: [u8; 32],
    pair: Ed25519KeyPair,
    certificate: Option<Certificate>,
}

impl Identity {
    pub fn generate() -> Result<Identity, CertError> {
        let mut seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
            .map_err(|_| CertError::Random)?;
        Identity::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Identity, CertError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| CertError::BadSeed)?;
        Ok(Identity {
            seed,
            pair,
            certificate: None,
        })
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(
            self.pair
                .public_key()
                .as_ref()
                .try_into()
                .expect("an Ed25519 public key is 32 bytes"),
        )
    }

    /// The seed, for iroh's endpoint key (the same key).
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        SignatureBytes(
            self.pair
                .sign(message)
                .as_ref()
                .try_into()
                .expect("an Ed25519 signature is 64 bytes"),
        )
    }

    /// Requests GitHub's certificate for this key (in Actions only).
    pub async fn certify(&mut self) -> Result<&Certificate, crate::github::TokenError> {
        let key = self.public();
        let token = crate::github::request_token(&KeyAudience(&key)).await?;
        Ok(self.certificate.insert(Certificate { key, token }))
    }

    /// Uses a certificate obtained elsewhere (tests).
    pub fn with_certificate(mut self, token: String) -> Identity {
        self.certificate = Some(Certificate {
            key: self.public(),
            token,
        });
        self
    }

    pub fn certificate(&self) -> Option<&Certificate> {
        self.certificate.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let id = Identity::from_seed([7; 32]).unwrap();
        let sig = id.sign(b"hello");
        assert!(id.public().verify(b"hello", &sig).is_ok());
        assert!(id.public().verify(b"hellp", &sig).is_err());
        let other = Identity::from_seed([8; 32]).unwrap();
        assert!(other.public().verify(b"hello", &sig).is_err());
        assert_eq!(
            id.public().to_string().parse::<PublicKey>().unwrap(),
            id.public()
        );
    }
}
