//! Batch statements and signed envelopes.
//!
//! A batch statement is an in-toto v1 Statement listing (action digest,
//! result digest) pairs produced by one worker. Its signature is a GitHub
//! Actions OIDC token whose audience is `hartland-attest:sha256:<hex>` of the
//! exact statement bytes, so GitHub's signature over the token covers the
//! statement.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://github.com/nhawkes/hartland/attest/action-results/v0";
pub const ENVELOPE_MEDIA_TYPE: &str = "application/vnd.hartland.attestation.v0+json";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const AUDIENCE_PREFIX: &str = "hartland-attest:sha256:";
pub const SIGNATURE_KIND: &str = "github-actions-oidc";

/// A REAPI-style digest: lowercase hex sha256 and size in bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest {
    pub hash: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: Digest,
    pub result: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    pub results: Vec<ActionResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Predicate,
}

impl Statement {
    /// Builds a statement whose subjects are the action digests, so a lookup
    /// by action digest finds the batch that vouches for it.
    pub fn new(mut results: Vec<ActionResult>) -> Statement {
        results.sort_by(|a, b| a.action.hash.cmp(&b.action.hash));
        let subject = results
            .iter()
            .map(|r| Subject {
                name: "action".to_string(),
                digest: [("sha256".to_string(), r.action.hash.clone())].into(),
            })
            .collect();
        Statement {
            type_: STATEMENT_TYPE.to_string(),
            subject,
            predicate_type: PREDICATE_TYPE.to_string(),
            predicate: Predicate { results },
        }
    }

    pub fn check(&self) -> Result<(), String> {
        if self.type_ != STATEMENT_TYPE {
            return Err(format!("unexpected statement type {}", self.type_));
        }
        if self.predicate_type != PREDICATE_TYPE {
            return Err(format!("unexpected predicate type {}", self.predicate_type));
        }
        if self.subject.len() != self.predicate.results.len() {
            return Err("subjects do not match results".to_string());
        }
        for (s, r) in self.subject.iter().zip(&self.predicate.results) {
            check_hex(&r.action.hash)?;
            check_hex(&r.result.hash)?;
            if s.digest.get("sha256") != Some(&r.action.hash) {
                return Err(format!("subject does not match action {}", r.action.hash));
            }
        }
        Ok(())
    }
}

pub fn check_hex(h: &str) -> Result<(), String> {
    if h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        Ok(())
    } else {
        Err(format!("not a lowercase sha256 hex digest: {h}"))
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    d.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// The OIDC audience that binds a token to these exact bytes.
pub fn audience_for(payload: &[u8]) -> String {
    format!("{AUDIENCE_PREFIX}{}", sha256_hex(payload))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub kind: String,
    /// The GitHub Actions OIDC token (a JWT).
    pub token: String,
}

/// The stored, signed form. `payload` is the exact statement bytes, base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<Signature>,
}

impl Envelope {
    pub fn new(payload: &[u8], token: String) -> Envelope {
        Envelope {
            media_type: ENVELOPE_MEDIA_TYPE.to_string(),
            payload_type: PAYLOAD_TYPE.to_string(),
            payload: STANDARD.encode(payload),
            signatures: vec![Signature { kind: SIGNATURE_KIND.to_string(), token }],
        }
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>, String> {
        if self.media_type != ENVELOPE_MEDIA_TYPE {
            return Err(format!("unexpected envelope media type {}", self.media_type));
        }
        if self.payload_type != PAYLOAD_TYPE {
            return Err(format!("unexpected payload type {}", self.payload_type));
        }
        STANDARD.decode(&self.payload).map_err(|e| format!("bad payload encoding: {e}"))
    }
}
