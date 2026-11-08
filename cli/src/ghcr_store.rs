//! A `Store` backed by container registries, trusting only signed results.
//!
//! Layout in a namespace such as `ghcr.io/<owner>/hartland-cache`:
//!   * CAS blobs are registry blobs (REAPI and OCI digests are both sha256).
//!   * An action-cache entry is a manifest tagged with the action hash. Its
//!     config is the exact serialised ActionResult; its layers are every blob
//!     the result needs (so the registry keeps them) plus the signed batch
//!     envelope; the annotation `ANN_ENVELOPE` names the envelope.
//!
//! Reads: action results only if the envelope verifies against the keyring and
//! its statement maps this action to the sha256 of this exact config blob; an
//! accepted result's blobs are fetched at once, so existence checks stay local.
//! Writes: kept locally, then `publish` signs one batch with the job's OIDC
//! token and pushes everything to the writable namespace.

use crate::attest::{ActionResult as Pair, Digest, Envelope, Statement, sha256_hex};
use crate::jwt::Jwks;
use crate::keyring::Keyring;
use crate::oci::{MANIFEST_MEDIA_TYPE, Registry};
use crate::proxy::{DiskStore, EMPTY_SHA256, Store};
use crate::reapi::re;
use futures::{StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

pub const ARTIFACT_TYPE: &str = "application/vnd.hartland.action-result.v0";
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.hartland.reapi.action-result.v2+proto";
pub const ENVELOPE_MEDIA_TYPE: &str = crate::attest::ENVELOPE_MEDIA_TYPE;
pub const ANN_ENVELOPE: &str = "dev.hartland.envelope";

/// Requests in flight to the registry (GHCR: ~1.1 s per small blob upload
/// sequentially, ~90 ms effective at 16).
const REGISTRY_CONCURRENCY: usize = 16;
const READ_ATTEMPTS: u32 = 3;

pub struct GhcrStore {
    local: DiskStore,
    /// Namespaces to read from, in order.
    readers: Vec<Registry>,
    /// Where `publish` pushes; None outside a signing-capable job.
    writer: Option<Registry>,
    keyring: Keyring,
    jwks: Jwks,
    /// Results written during this run, awaiting a signed batch.
    pending: Mutex<Vec<(String, i64, re::ActionResult)>>,
    /// Envelope digest -> verified statement pairs (action -> result hash).
    verified: Mutex<HashMap<String, HashMap<String, String>>>,
}

/// GHCR blob reads go via a redirect to separate storage; one early read
/// failed transiently in testing, so reads are retried with backoff.
async fn get_blob_retrying(reg: &Registry, hash: &str) -> Result<Vec<u8>, String> {
    let mut last = String::new();
    for attempt in 0..READ_ATTEMPTS {
        match reg.get_blob(hash).await {
            Ok(b) => return Ok(b),
            Err(e) => last = e,
        }
        tokio::time::sleep(std::time::Duration::from_millis(200 << attempt)).await;
    }
    Err(last)
}

impl GhcrStore {
    pub fn new(local: DiskStore, readers: Vec<Registry>, writer: Option<Registry>, keyring: Keyring, jwks: Jwks) -> GhcrStore {
        GhcrStore { local, readers, writer, keyring, jwks, pending: Mutex::new(Vec::new()), verified: Mutex::new(HashMap::new()) }
    }

    async fn fetch_blob(&self, hash: &str) -> Option<Vec<u8>> {
        for r in &self.readers {
            if let Ok(b) = get_blob_retrying(r, hash).await {
                // get_blob checks the digest; keep a local copy.
                let _ = self.local.put_blob(hash, &b).await;
                return Some(b);
            }
        }
        None
    }

    /// Verifies an envelope once per run and returns its action -> result map.
    async fn verified_pairs(&self, reg: &Registry, envelope_hash: &str) -> Option<HashMap<String, String>> {
        if let Some(p) = self.verified.lock().ok()?.get(envelope_hash) {
            return Some(p.clone());
        }
        let bytes = get_blob_retrying(reg, envelope_hash).await.ok()?;
        let env: Envelope = serde_json::from_slice(&bytes).ok()?;
        let (statement, _signer) = crate::verify_envelope(&env, &self.jwks, &self.keyring).ok()?;
        let pairs: HashMap<String, String> =
            statement.predicate.results.into_iter().map(|p| (p.action.hash, p.result.hash)).collect();
        self.verified.lock().ok()?.insert(envelope_hash.to_string(), pairs.clone());
        Some(pairs)
    }

    async fn lookup(&self, reg: &Registry, action: &str) -> Option<re::ActionResult> {
        let reply = reg.get_manifest(action).await.ok()?;
        if reply.status != 200 {
            return None;
        }
        let m: serde_json::Value = serde_json::from_slice(&reply.body).ok()?;
        if m.get("artifactType")?.as_str()? != ARTIFACT_TYPE {
            return None;
        }
        let env_hash = m.pointer(&format!("/annotations/{}", ANN_ENVELOPE.replace('/', "~1")))?.as_str()?.strip_prefix("sha256:")?;
        let config_hash = m.pointer("/config/digest")?.as_str()?.strip_prefix("sha256:")?;
        let pairs = self.verified_pairs(reg, env_hash).await?;
        if pairs.get(action).map(String::as_str) != Some(config_hash) {
            return None;
        }
        let bytes = get_blob_retrying(reg, config_hash).await.ok()?;
        let result = re::ActionResult::decode(bytes.as_slice()).ok()?;
        if self.prefetch(&result).await { Some(result) } else { None }
    }

    /// Downloads a verified result's blobs into the local store.
    async fn prefetch(&self, r: &re::ActionResult) -> bool {
        let mut first: Vec<String> = r.output_files.iter().filter_map(|f| f.digest.as_ref().map(|d| d.hash.clone())).collect();
        first.extend(r.stdout_digest.iter().chain(r.stderr_digest.iter()).map(|d| d.hash.clone()));
        let trees: Vec<String> = r.output_directories.iter().filter_map(|d| d.tree_digest.as_ref().map(|t| t.hash.clone())).collect();
        first.extend(trees.iter().cloned());
        if !self.fetch_all(first).await {
            return false;
        }
        let mut second = Vec::new();
        for t in &trees {
            let Some(bytes) = self.local.get_blob(t).await else { return false };
            let Ok(tree) = re::Tree::decode(bytes.as_slice()) else { return false };
            for d in tree.root.iter().chain(tree.children.iter()) {
                second.extend(d.files.iter().filter_map(|f| f.digest.as_ref().map(|d| d.hash.clone())));
            }
        }
        self.fetch_all(second).await
    }

    async fn fetch_all(&self, hashes: Vec<String>) -> bool {
        futures::stream::iter(hashes)
            .map(|h| async move { self.local.has_blob(&h).await || self.fetch_blob(&h).await.is_some() })
            .buffer_unordered(REGISTRY_CONCURRENCY)
            .all(|ok| async move { ok })
            .await
    }

    /// Signs everything written this run as one batch and pushes it.
    /// Returns the number of results published.
    pub async fn publish(&self) -> Result<usize, String> {
        let pending: Vec<_> = std::mem::take(&mut *self.pending.lock().map_err(|_| "poisoned")?);
        if pending.is_empty() {
            return Ok(0);
        }
        let writer = self.writer.as_ref().ok_or("results pending but no writable namespace configured")?;
        let mut pairs = Vec::new();
        let mut configs = Vec::new();
        for (action, size, result) in &pending {
            let bytes = result.encode_to_vec();
            pairs.push(Pair {
                action: Digest { hash: action.clone(), size: *size as u64 },
                result: Digest { hash: sha256_hex(&bytes), size: bytes.len() as u64 },
            });
            configs.push(bytes);
        }
        let statement = Statement::new(pairs);
        let payload = crate::statement_bytes(&statement);
        let token = crate::github::request_token(&crate::attest::audience_for(&payload)).await?;
        let envelope = serde_json::to_vec(&Envelope::new(&payload, token)).map_err(|e| e.to_string())?;
        let env_hash = writer.put_blob(&envelope).await?;

        // Every distinct blob once, then the configs, then the manifests.
        let mut referenced = Vec::new();
        let mut all: BTreeSet<String> = BTreeSet::new();
        for (_, _, result) in &pending {
            let r = self.referenced_blobs(result).await?;
            all.extend(r.iter().cloned());
            referenced.push(r);
        }
        let sizes: HashMap<String, usize> = futures::stream::iter(all)
            .map(|h| async move {
                let data = self.local.get_blob(&h).await.ok_or_else(|| format!("blob {h} missing locally"))?;
                writer.put_blob(&data).await?;
                Ok::<_, String>((h, data.len()))
            })
            .buffer_unordered(REGISTRY_CONCURRENCY)
            .try_collect()
            .await?;
        futures::stream::iter(&configs)
            .map(|c| writer.put_blob(c))
            .buffer_unordered(REGISTRY_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;

        let mut manifests = Vec::new();
        for (((action, _, _), config), refs) in pending.iter().zip(&configs).zip(&referenced) {
            let mut layers: Vec<serde_json::Value> = refs
                .iter()
                .map(|h| serde_json::json!({"mediaType": "application/octet-stream", "digest": format!("sha256:{h}"), "size": sizes[h]}))
                .collect();
            layers.push(serde_json::json!({"mediaType": ENVELOPE_MEDIA_TYPE, "digest": format!("sha256:{env_hash}"), "size": envelope.len()}));
            let manifest = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": MANIFEST_MEDIA_TYPE,
                "artifactType": ARTIFACT_TYPE,
                "config": {"mediaType": CONFIG_MEDIA_TYPE, "digest": format!("sha256:{}", sha256_hex(config)), "size": config.len()},
                "layers": layers,
                "annotations": {ANN_ENVELOPE: format!("sha256:{env_hash}")},
            });
            manifests.push((action.clone(), serde_json::to_vec(&manifest).map_err(|e| e.to_string())?));
        }
        futures::stream::iter(&manifests)
            .map(|(a, m)| writer.put_manifest(a, MANIFEST_MEDIA_TYPE, m))
            .buffer_unordered(REGISTRY_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;
        Ok(pending.len())
    }

    /// Every blob an action result needs: outputs, stdout/stderr, and for each
    /// output directory its Tree blob and every file inside it.
    async fn referenced_blobs(&self, r: &re::ActionResult) -> Result<BTreeSet<String>, String> {
        let mut out = BTreeSet::new();
        out.extend(r.output_files.iter().filter_map(|f| f.digest.as_ref().map(|d| d.hash.clone())));
        out.extend(r.stdout_digest.iter().chain(r.stderr_digest.iter()).map(|d| d.hash.clone()));
        for dir in &r.output_directories {
            let Some(td) = &dir.tree_digest else { continue };
            out.insert(td.hash.clone());
            let bytes = self.local.get_blob(&td.hash).await.ok_or_else(|| format!("tree {} missing locally", td.hash))?;
            let tree = re::Tree::decode(bytes.as_slice()).map_err(|e| format!("bad tree {}: {e}", td.hash))?;
            for d in tree.root.iter().chain(tree.children.iter()) {
                out.extend(d.files.iter().filter_map(|f| f.digest.as_ref().map(|d| d.hash.clone())));
            }
        }
        out.remove(EMPTY_SHA256);
        Ok(out)
    }
}

#[async_trait::async_trait]
impl Store for GhcrStore {
    /// Local only: blobs of accepted remote results are prefetched, and
    /// anything else buck2 simply uploads.
    async fn has_blob(&self, hash: &str) -> bool {
        self.local.has_blob(hash).await
    }

    async fn get_blob(&self, hash: &str) -> Option<Vec<u8>> {
        match self.local.get_blob(hash).await {
            Some(b) => Some(b),
            None => self.fetch_blob(hash).await,
        }
    }

    async fn put_blob(&self, hash: &str, data: &[u8]) -> Result<(), String> {
        self.local.put_blob(hash, data).await
    }

    async fn get_action_result(&self, action: &str) -> Option<re::ActionResult> {
        // Results produced in this run are trusted; they get signed on publish.
        if let Some(r) = self.local.get_action_result(action).await {
            return Some(r);
        }
        for reg in &self.readers {
            if let Some(r) = self.lookup(reg, action).await {
                return Some(r);
            }
        }
        None
    }

    async fn put_action_result(&self, action: &str, action_size: i64, result: &re::ActionResult) -> Result<(), String> {
        self.local.put_action_result(action, action_size, result).await?;
        self.pending.lock().map_err(|_| "poisoned")?.push((action.to_string(), action_size, result.clone()));
        Ok(())
    }
}
