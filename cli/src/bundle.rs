//! Signed batches in transportable form: the envelope (signed statement) plus
//! a bundle holding the exact result bytes it vouches for and the blobs each
//! result needs. Both the first tier and the registry index carry them.
//!
//! A bundle is untrusted: `VerifiedBatch::accept` keeps only entries whose
//! bytes the verified statement signed.

use crate::attest::{Batch, Envelope, VerifyError};
use crate::digest::{ActionId, BatchId, Sha256};
use crate::jwt::Jwks;
use crate::keyring::Keyring;
use crate::reapi::re;
use bytes::Bytes;
use prost::Message as _;
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::collections::BTreeSet;

#[derive(serde::Serialize, serde::Deserialize)]
struct Bundle {
    entries: Vec<BundleEntry>,
}

#[serde_as]
#[derive(serde::Serialize, serde::Deserialize)]
struct BundleEntry {
    action: ActionId,
    /// The exact ActionResult bytes the statement signs.
    #[serde_as(as = "Base64")]
    result: Vec<u8>,
    blobs: BTreeSet<Sha256>,
}

/// A trusted result: from a verified batch, or executed here.
#[derive(Clone, Debug)]
pub struct CachedResult {
    pub action: ActionId,
    pub result: re::ActionResult,
    /// Every blob the result needs (outputs, trees and their files, logs).
    pub blobs: BTreeSet<Sha256>,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("bundle is not valid: {0}")]
    Bundle(serde_json::Error),
}

/// A batch whose envelope verified, with the results it vouches for.
pub struct VerifiedBatch {
    pub id: BatchId,
    pub envelope: Bytes,
    pub results: Vec<CachedResult>,
}

impl VerifiedBatch {
    /// Verifies `envelope` and keeps the bundle entries whose bytes it signed.
    pub fn accept(
        envelope: Bytes,
        bundle: &[u8],
        jwks: &Jwks,
        keyring: &Keyring,
    ) -> Result<VerifiedBatch, BundleError> {
        let batch: Batch = Envelope::parse(&envelope)?.verify(jwks, keyring)?.statement;
        let bundle: Bundle = serde_json::from_slice(bundle).map_err(BundleError::Bundle)?;
        let results = bundle
            .entries
            .into_iter()
            .filter(|e| batch.vouches(&e.action, &e.result))
            .filter_map(|e| {
                Some(CachedResult {
                    action: e.action,
                    result: re::ActionResult::decode(e.result.as_slice()).ok()?,
                    blobs: e.blobs,
                })
            })
            .collect();
        Ok(VerifiedBatch {
            id: BatchId(Sha256::of(&envelope)),
            envelope,
            results,
        })
    }
}

pub fn bundle_bytes<'a>(results: impl IntoIterator<Item = &'a CachedResult>) -> Bytes {
    let b = Bundle {
        entries: results
            .into_iter()
            .map(|r| BundleEntry {
                action: r.action,
                result: r.result.encode_to_vec(),
                blobs: r.blobs.clone(),
            })
            .collect(),
    };
    serde_json::to_vec(&b).expect("a bundle serialises").into()
}
