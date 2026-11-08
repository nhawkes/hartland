//! Batch statements and signed envelopes.
//!
//! A batch statement is an in-toto v1 Statement listing (action digest,
//! result digest) pairs produced by one worker. Its signature is a GitHub
//! Actions OIDC token whose audience is `hartland-attest:sha256:<hex>` of the
//! exact statement bytes, so GitHub's signature over the token covers the
//! statement.
//!
//! Wire types (`Raw*`) are private; what callers get has been parsed: a
//! `Batch` maps each action to its result, and a `Signed<T>` exists only
//! once the envelope has verified against a keyring.

use crate::cert::{CertError, Certificate, Identity, SignatureBytes};
use crate::digest::{ActionId, Digest, Sha256};
use crate::jwt::{self, Jwks};
use crate::keyring::{Keyring, Signer, TrustError};
use monostate::MustBe;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

pub const ENVELOPE_MEDIA_TYPE: &str = "application/vnd.hartland.attestation.v0+json";

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("envelope is not JSON of the expected shape: {0}")]
    Envelope(serde_json::Error),
    #[error("envelope has no signatures")]
    Unsigned,
    #[error("no signature verifies: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    NoValidSignature(Vec<SignatureError>),
    #[error("signed payload is not a valid statement: {0}")]
    Statement(serde_json::Error),
    #[error("statement names {claimed} but the builder ran for {actual}")]
    WrongRepository { claimed: String, actual: String },
    #[error("statement names commit {claimed} but the builder ran on {actual:?}")]
    WrongCommit {
        claimed: crate::digest::GitSha,
        actual: Option<crate::digest::GitSha>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("unsupported signature kind")]
    UnsupportedKind,
    #[error(transparent)]
    Jwt(#[from] jwt::JwtError),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error(transparent)]
    Certificate(#[from] CertError),
}

/// The OIDC audience that binds a token to exact payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Audience(pub Sha256);

impl Audience {
    const PREFIX: &str = "hartland-attest:sha256:";

    pub fn of(payload: &[u8]) -> Audience {
        Audience(Sha256::of(payload))
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", Audience::PREFIX, self.0)
    }
}

impl FromStr for Audience {
    type Err = crate::digest::ParseError;
    fn from_str(s: &str) -> Result<Audience, Self::Err> {
        let hex = s
            .strip_prefix(Audience::PREFIX)
            .ok_or_else(|| crate::digest::ParseError::Prefixed(s.to_string()))?;
        Ok(Audience(hex.parse()?))
    }
}

// ---- statements -----------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Subject {
    pub name: String,
    pub digest: SubjectDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SubjectDigest {
    pub sha256: Sha256,
}

/// One signed fact: this action's result has this digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    pub action: Digest,
    pub result: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RawStatement {
    #[serde(rename = "_type")]
    type_: MustBe!("https://in-toto.io/Statement/v1"),
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: MustBe!("https://github.com/nhawkes/hartland/attest/action-results/v0"),
    predicate: RawPredicate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RawPredicate {
    results: Vec<Pair>,
}

#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error("subjects do not match results")]
    SubjectMismatch,
    #[error("action {0} listed twice")]
    Duplicate(ActionId),
}

/// A batch statement: each action's signed result digest. Subjects are the
/// action digests, so a lookup by action finds the batch that vouches for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawStatement", into = "RawStatement")]
pub struct Batch {
    pub results: BTreeMap<ActionId, Vouched>,
}

/// What a batch says about one action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vouched {
    pub action_size: u64,
    pub result: Digest,
}

impl Batch {
    pub fn new(pairs: impl IntoIterator<Item = Pair>) -> Batch {
        Batch {
            results: pairs
                .into_iter()
                .map(|p| {
                    (
                        ActionId(p.action.hash),
                        Vouched {
                            action_size: p.action.size,
                            result: p.result,
                        },
                    )
                })
                .collect(),
        }
    }

    /// The exact bytes that get signed.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a batch serialises")
    }

    /// Is `result` (serialised) what this batch signed for `action`?
    pub fn vouches(&self, action: &ActionId, result: &[u8]) -> bool {
        self.results
            .get(action)
            .is_some_and(|s| s.result.matches(result))
    }
}

impl TryFrom<RawStatement> for Batch {
    type Error = BatchError;
    fn try_from(raw: RawStatement) -> Result<Batch, BatchError> {
        if raw.subject.len() != raw.predicate.results.len() {
            return Err(BatchError::SubjectMismatch);
        }
        let mut results = BTreeMap::new();
        for (s, p) in raw.subject.iter().zip(&raw.predicate.results) {
            if s.digest.sha256 != p.action.hash {
                return Err(BatchError::SubjectMismatch);
            }
            let action = ActionId(p.action.hash);
            if results
                .insert(
                    action,
                    Vouched {
                        action_size: p.action.size,
                        result: p.result,
                    },
                )
                .is_some()
            {
                return Err(BatchError::Duplicate(action));
            }
        }
        Ok(Batch { results })
    }
}

impl From<Batch> for RawStatement {
    fn from(b: Batch) -> RawStatement {
        // BTreeMap order: sorted by action digest, as signed.
        let results: Vec<Pair> = b
            .results
            .iter()
            .map(|(a, s)| Pair {
                action: Digest {
                    hash: a.0,
                    size: s.action_size,
                },
                result: s.result,
            })
            .collect();
        RawStatement {
            type_: MustBe!("https://in-toto.io/Statement/v1"),
            subject: results
                .iter()
                .map(|p| Subject {
                    name: "action".to_string(),
                    digest: SubjectDigest {
                        sha256: p.action.hash,
                    },
                })
                .collect(),
            predicate_type: MustBe!("https://github.com/nhawkes/hartland/attest/action-results/v0"),
            predicate: RawPredicate { results },
        }
    }
}

// ---- envelopes ------------------------------------------------------------

/// One signature over an envelope's payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Signature {
    /// A GitHub Actions OIDC token whose audience is the payload's digest.
    GithubActionsOidc { token: String },
    /// A key certified by a GitHub Actions OIDC token (see `cert`), and
    /// that key's Ed25519 signature over the payload.
    #[serde(rename = "hartland-certified-key-v0")]
    CertifiedKey {
        certificate: Certificate,
        signature: SignatureBytes,
    },
    #[serde(other)]
    Unsupported,
}

/// The stored, signed form. `payload` is the exact statement bytes.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "mediaType")]
    media_type: MustBe!("application/vnd.hartland.attestation.v0+json"),
    #[serde(rename = "payloadType")]
    payload_type: MustBe!("application/vnd.in-toto+json"),
    #[serde_as(as = "Base64")]
    payload: Vec<u8>,
    signatures: Vec<Signature>,
}

/// A statement whose envelope verified, and who signed it.
#[derive(Clone, Debug)]
pub struct Signed<T> {
    pub statement: T,
    pub signer: Signer,
}

impl Envelope {
    pub fn new(payload: Vec<u8>, token: String) -> Envelope {
        Envelope {
            media_type: MustBe!("application/vnd.hartland.attestation.v0+json"),
            payload_type: MustBe!("application/vnd.in-toto+json"),
            payload,
            signatures: vec![Signature::GithubActionsOidc { token }],
        }
    }

    /// Signs `payload` with a certified key.
    pub fn signed_by(payload: Vec<u8>, identity: &Identity) -> Result<Envelope, CertError> {
        let certificate = identity
            .certificate()
            .cloned()
            .ok_or(CertError::Uncertified)?;
        let signature = identity.sign(&payload);
        Ok(Envelope {
            media_type: MustBe!("application/vnd.hartland.attestation.v0+json"),
            payload_type: MustBe!("application/vnd.in-toto+json"),
            payload,
            signatures: vec![Signature::CertifiedKey {
                certificate,
                signature,
            }],
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Envelope, VerifyError> {
        serde_json::from_slice(bytes).map_err(VerifyError::Envelope)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("an envelope serialises")
    }

    /// Some signature must come from a builder the keyring trusts, on a
    /// hosted runner, and cover these exact payload bytes: either a token
    /// whose audience is their digest, or a certified key's signature over
    /// them. Then the payload must parse as `T`.
    pub fn verify<T: DeserializeOwned>(
        &self,
        jwks: &Jwks,
        keyring: &Keyring,
    ) -> Result<Signed<T>, VerifyError> {
        if self.signatures.is_empty() {
            return Err(VerifyError::Unsigned);
        }
        let audience = Audience::of(&self.payload);
        let mut errors = Vec::new();
        for sig in &self.signatures {
            let checked = match sig {
                Signature::GithubActionsOidc { token } => jwt::verify(token, jwks)
                    .map_err(SignatureError::from)
                    .and_then(|c| keyring.accept(&c, &audience).map_err(SignatureError::from)),
                Signature::CertifiedKey {
                    certificate,
                    signature,
                } => certificate
                    .key
                    .verify(&self.payload, signature)
                    .and_then(|()| certificate.verify(jwks, keyring))
                    .map_err(SignatureError::from),
                Signature::Unsupported => Err(SignatureError::UnsupportedKind),
            };
            match checked {
                Ok(signer) => {
                    let statement =
                        serde_json::from_slice(&self.payload).map_err(VerifyError::Statement)?;
                    return Ok(Signed { statement, signer });
                }
                Err(e) => errors.push(e),
            }
        }
        Err(VerifyError::NoValidSignature(errors))
    }
}

/// Signs `payload` with a token minted for its audience (in Actions only).
pub async fn sign(payload: Vec<u8>) -> Result<Envelope, crate::github::TokenError> {
    let token = crate::github::request_token(&Audience::of(&payload)).await?;
    Ok(Envelope::new(payload, token))
}
