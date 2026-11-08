//! The first cache tier: a directory of signed batches and their blobs, which
//! the trusted builder saves and restores with GitHub's Actions cache (fast,
//! two operations per job, branch-scoped) in front of the registry.
//!
//! Its contents are untrusted (any workflow in the repository can write the
//! Actions cache): every batch is verified against the keyring on load, every
//! blob against its digest on read, and nothing here is ever treated as a
//! result without its signed statement.
//!
//! Layout:  batches/<batch id>.envelope   the signed envelope
//!          batches/<batch id>.bundle     results + referenced blobs
//!          blobs/<shard>/<sha256>        content-addressed blobs
//!          outbox/<sha256>.json          registry writes still to do

use crate::bundle::VerifiedBatch;
use crate::cas::{Blob, Cas, write_atomic};
use crate::digest::{BatchId, Sha256};
use crate::jwt::Jwks;
use crate::keyring::Keyring;
use bytes::Bytes;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

pub struct L1 {
    blobs: Cas,
    batches: PathBuf,
    outbox: PathBuf,
    tmp: PathBuf,
}

/// A queued plan and the file it came from (removed once done).
pub struct Queued<T> {
    pub plan: T,
    path: PathBuf,
}

impl L1 {
    pub async fn open(dir: PathBuf) -> std::io::Result<L1> {
        let (batches, outbox, tmp) = (dir.join("batches"), dir.join("outbox"), dir.join("tmp"));
        for d in [&batches, &outbox] {
            tokio::fs::create_dir_all(d).await?;
        }
        Ok(L1 {
            blobs: Cas::open(dir.join("blobs"), tmp.clone()).await?,
            batches,
            outbox,
            tmp,
        })
    }

    pub fn blobs(&self) -> &Cas {
        &self.blobs
    }

    fn batch_file(&self, id: &BatchId, ext: &str) -> PathBuf {
        self.batches.join(format!("{id}.{ext}"))
    }

    pub async fn write_batch(
        &self,
        id: &BatchId,
        envelope: Bytes,
        bundle: Bytes,
    ) -> std::io::Result<()> {
        write_atomic(&self.tmp, &self.batch_file(id, "envelope"), envelope).await?;
        write_atomic(&self.tmp, &self.batch_file(id, "bundle"), bundle).await
    }

    /// Batch ids present, newest first.
    async fn batch_ids(&self) -> std::io::Result<Vec<BatchId>> {
        let mut found: Vec<(Option<SystemTime>, BatchId)> = Vec::new();
        let mut rd = tokio::fs::read_dir(&self.batches).await?;
        while let Some(e) = rd.next_entry().await? {
            let Some(id) = e
                .file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".envelope"))
                .and_then(|h| h.parse().ok())
            else {
                continue;
            };
            found.push((e.metadata().await?.modified().ok(), id));
        }
        found.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
        Ok(found.into_iter().map(|(_, id)| id).collect())
    }

    /// Every batch that verifies, newest first. Anything else is skipped.
    pub async fn load(&self, jwks: &Jwks, keyring: &Keyring) -> Vec<VerifiedBatch> {
        let mut out = Vec::new();
        for id in self.batch_ids().await.unwrap_or_default() {
            let (Ok(envelope), Ok(bundle)) = (
                tokio::fs::read(self.batch_file(&id, "envelope")).await,
                tokio::fs::read(self.batch_file(&id, "bundle")).await,
            ) else {
                continue;
            };
            match VerifiedBatch::accept(envelope.into(), &bundle, jwks, keyring) {
                Ok(v) if v.id == id => out.push(v),
                Ok(_) => {
                    tracing::warn!(batch = %id, "first tier: envelope does not match its name; skipped")
                }
                Err(e) => {
                    tracing::warn!(batch = %id, error = %e, "first tier: batch does not verify; skipped")
                }
            }
        }
        out
    }

    /// Keeps the newest `keep` batches plus `also`, and the blobs they need.
    pub async fn prune(
        &self,
        keep: usize,
        also: &HashSet<BatchId>,
        jwks: &Jwks,
        keyring: &Keyring,
    ) -> std::io::Result<()> {
        let batches = self.load(jwks, keyring).await;
        let kept: Vec<&VerifiedBatch> = batches
            .iter()
            .enumerate()
            .filter(|(i, b)| *i < keep || also.contains(&b.id))
            .map(|(_, b)| b)
            .collect();
        let kept_ids: HashSet<BatchId> = kept.iter().map(|b| b.id).collect();
        let live: HashSet<Sha256> = kept
            .iter()
            .flat_map(|b| b.results.iter().flat_map(|r| r.blobs.iter().copied()))
            .collect();
        let mut rd = tokio::fs::read_dir(&self.batches).await?;
        while let Some(e) = rd.next_entry().await? {
            let id = e
                .file_name()
                .to_str()
                .and_then(|n| n.split('.').next())
                .and_then(|h| h.parse::<BatchId>().ok());
            if !id.is_some_and(|id| kept_ids.contains(&id)) {
                tokio::fs::remove_file(e.path()).await?;
            }
        }
        self.blobs.retain(&live).await
    }

    pub async fn put_blob(&self, blob: &Blob) -> std::io::Result<()> {
        self.blobs.put(blob).await
    }

    /// Queues a plan for `hartland proxy promote`.
    pub async fn enqueue<T: Serialize>(&self, plan: &T) -> std::io::Result<()> {
        let bytes = Bytes::from(serde_json::to_vec(plan).map_err(std::io::Error::other)?);
        write_atomic(
            &self.tmp,
            &self.outbox.join(format!("{}.json", Sha256::of(&bytes))),
            bytes,
        )
        .await
    }

    /// Queued plans. Unreadable ones are dropped with a warning.
    pub async fn queued<T: DeserializeOwned>(&self) -> std::io::Result<Vec<Queued<T>>> {
        let mut out = Vec::new();
        let mut rd = tokio::fs::read_dir(&self.outbox).await?;
        while let Some(e) = rd.next_entry().await? {
            match serde_json::from_slice(&tokio::fs::read(e.path()).await?) {
                Ok(plan) => out.push(Queued {
                    plan,
                    path: e.path(),
                }),
                Err(err) => {
                    tracing::warn!(path = %e.path().display(), error = %err, "unreadable outbox plan: dropped");
                    tokio::fs::remove_file(e.path()).await?;
                }
            }
        }
        Ok(out)
    }

    pub async fn done<T>(&self, q: Queued<T>) -> std::io::Result<()> {
        tokio::fs::remove_file(q.path).await
    }
}
