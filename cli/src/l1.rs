//! The first cache tier: a directory of signed batches and their blobs, which
//! the trusted builder saves and restores with GitHub's Actions cache (fast,
//! two operations per job, branch-scoped) in front of the registry.
//!
//! Its contents are untrusted (any workflow in the repository can write the
//! Actions cache): every batch is verified against the keyring on load, every
//! blob against its digest on read, and nothing here is ever treated as a
//! result without its signed statement.
//!
//! Layout:  batches/<envelope hash>.envelope   the signed envelope
//!          batches/<envelope hash>.bundle     results + referenced blobs
//!          blobs/<hh>/<hash>                  content-addressed blobs
//!          outbox/<name>.json                 registry writes still to do

use crate::attest::{Envelope, sha256_hex};
use crate::jwt::Jwks;
use crate::keyring::Keyring;
use crate::reapi::re;
use base64::Engine as _;
use prost::Message as _;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Bundle {
    pub entries: Vec<BundleEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BundleEntry {
    pub action: String,
    /// base64 of the exact ActionResult bytes the statement signs.
    pub result: String,
    pub blobs: Vec<String>,
}

/// A verified batch: results whose bytes match the signed statement.
pub struct VerifiedBatch {
    pub envelope_hash: String,
    pub envelope: Vec<u8>,
    pub results: Vec<(String, re::ActionResult, Vec<String>)>,
}

/// Checks a bundle against its verified envelope; keeps matching entries.
pub fn accept(envelope_hash: &str, envelope: &[u8], bundle: &[u8], jwks: &Jwks, keyring: &Keyring) -> Option<VerifiedBatch> {
    let env: Envelope = serde_json::from_slice(envelope).ok()?;
    let (statement, _signer) = crate::verify_envelope(&env, jwks, keyring).ok()?;
    let signed: HashMap<String, String> = statement.predicate.results.into_iter().map(|p| (p.action.hash, p.result.hash)).collect();
    let bundle: Bundle = serde_json::from_slice(bundle).ok()?;
    let mut results = Vec::new();
    for e in bundle.entries {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&e.result) else { continue };
        if signed.get(&e.action).map(String::as_str) != Some(sha256_hex(&bytes).as_str()) {
            continue;
        }
        let Ok(r) = re::ActionResult::decode(bytes.as_slice()) else { continue };
        results.push((e.action, r, e.blobs));
    }
    Some(VerifiedBatch { envelope_hash: envelope_hash.to_string(), envelope: envelope.to_vec(), results })
}

pub fn bundle_bytes(entries: &[(String, re::ActionResult, Vec<String>)]) -> Result<Vec<u8>, String> {
    let b = Bundle {
        entries: entries
            .iter()
            .map(|(a, r, blobs)| BundleEntry {
                action: a.clone(),
                result: base64::engine::general_purpose::STANDARD.encode(r.encode_to_vec()),
                blobs: blobs.clone(),
            })
            .collect(),
    };
    serde_json::to_vec(&b).map_err(|e| e.to_string())
}

pub struct L1 {
    dir: PathBuf,
}

impl L1 {
    pub async fn open(dir: PathBuf) -> Result<L1, String> {
        for d in ["batches", "blobs", "tmp", "outbox"] {
            tokio::fs::create_dir_all(dir.join(d)).await.map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        Ok(L1 { dir })
    }

    fn blob_path(&self, hash: &str) -> PathBuf {
        self.dir.join("blobs").join(&hash[..2.min(hash.len())]).join(hash)
    }

    async fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<(), String> {
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            return Ok(());
        }
        if let Some(p) = path.parent() {
            tokio::fs::create_dir_all(p).await.map_err(|e| e.to_string())?;
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = self.dir.join("tmp").join(format!("{}-{n}", std::process::id()));
        tokio::fs::write(&tmp, data).await.map_err(|e| e.to_string())?;
        tokio::fs::rename(&tmp, path).await.map_err(|e| e.to_string())
    }

    pub async fn has_blob(&self, hash: &str) -> bool {
        crate::attest::check_hex(hash).is_ok() && tokio::fs::try_exists(self.blob_path(hash)).await.unwrap_or(false)
    }

    /// Digest-checked: a tampered file reads as absent.
    pub async fn get_blob(&self, hash: &str) -> Option<Vec<u8>> {
        crate::attest::check_hex(hash).ok()?;
        let b = tokio::fs::read(self.blob_path(hash)).await.ok()?;
        (sha256_hex(&b) == hash).then_some(b)
    }

    pub async fn put_blob(&self, hash: &str, data: &[u8]) -> Result<(), String> {
        self.write_atomic(&self.blob_path(hash), data).await
    }

    pub async fn write_batch(&self, envelope_hash: &str, envelope: &[u8], bundle: &[u8]) -> Result<(), String> {
        let b = self.dir.join("batches");
        self.write_atomic(&b.join(format!("{envelope_hash}.envelope")), envelope).await?;
        self.write_atomic(&b.join(format!("{envelope_hash}.bundle")), bundle).await
    }

    /// Queues a registry plan (opaque JSON) for `hartland promote`.
    pub async fn write_outbox(&self, plan: &[u8]) -> Result<(), String> {
        let name = format!("{}.json", sha256_hex(plan));
        self.write_atomic(&self.dir.join("outbox").join(name), plan).await
    }

    /// Queued plans, with their paths (remove once done).
    pub async fn outbox(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let Ok(mut rd) = tokio::fs::read_dir(self.dir.join("outbox")).await else { return out };
        while let Ok(Some(e)) = rd.next_entry().await {
            if let Ok(b) = tokio::fs::read(e.path()).await {
                out.push((e.path(), b));
            }
        }
        out
    }

    /// Envelope hashes the outbox still refers to (kept by `prune`).
    async fn outbox_batches(&self) -> HashSet<String> {
        let mut out = HashSet::new();
        for (_, b) in self.outbox().await {
            if let Ok(serde_json::Value::Array(jobs)) = serde_json::from_slice(&b) {
                out.extend(jobs.iter().filter_map(|j| j.get("envelope")?.as_str().map(str::to_string)));
            }
        }
        out
    }

    /// Every batch that verifies, newest first.
    pub async fn load(&self, jwks: &Jwks, keyring: &Keyring) -> Vec<VerifiedBatch> {
        let mut found = Vec::new();
        let Ok(mut rd) = tokio::fs::read_dir(self.dir.join("batches")).await else { return Vec::new() };
        while let Ok(Some(e)) = rd.next_entry().await {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(hash) = name.strip_suffix(".envelope") else { continue };
            let modified = e.metadata().await.ok().and_then(|m| m.modified().ok());
            found.push((modified, hash.to_string()));
        }
        found.sort_by(|a, b| b.0.cmp(&a.0));
        let mut out = Vec::new();
        for (_, hash) in found {
            let b = self.dir.join("batches");
            let (Ok(env), Ok(bundle)) =
                (tokio::fs::read(b.join(format!("{hash}.envelope"))).await, tokio::fs::read(b.join(format!("{hash}.bundle"))).await)
            else {
                continue;
            };
            if sha256_hex(&env) != hash {
                continue;
            }
            if let Some(v) = accept(&hash, &env, &bundle, jwks, keyring) {
                out.push(v);
            }
        }
        out
    }

    /// Keeps the newest `keep` batches, any the outbox still needs, and the
    /// blobs they reference.
    pub async fn prune(&self, keep: usize, jwks: &Jwks, keyring: &Keyring) -> Result<(), String> {
        let batches = self.load(jwks, keyring).await;
        let queued = self.outbox_batches().await;
        let b = self.dir.join("batches");
        let mut live = HashSet::new();
        let mut kept = HashSet::new();
        for (i, v) in batches.iter().enumerate() {
            if i >= keep && !queued.contains(&v.envelope_hash) {
                continue;
            }
            kept.insert(v.envelope_hash.clone());
            for (_, _, blobs) in &v.results {
                live.extend(blobs.iter().cloned());
            }
        }
        let mut rd = tokio::fs::read_dir(&b).await.map_err(|e| e.to_string())?;
        while let Ok(Some(e)) = rd.next_entry().await {
            let name = e.file_name().to_string_lossy().into_owned();
            let hash = name.split('.').next().unwrap_or("");
            if !kept.contains(hash) {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
        let mut shards = tokio::fs::read_dir(self.dir.join("blobs")).await.map_err(|e| e.to_string())?;
        while let Ok(Some(shard)) = shards.next_entry().await {
            let Ok(mut files) = tokio::fs::read_dir(shard.path()).await else { continue };
            while let Ok(Some(f)) = files.next_entry().await {
                if !live.contains(&f.file_name().to_string_lossy().into_owned()) {
                    let _ = tokio::fs::remove_file(f.path()).await;
                }
            }
        }
        Ok(())
    }
}
