//! A `Store` backed by container registries (and optionally a first-tier
//! directory saved in GitHub's Actions cache), trusting only signed results.
//!
//! Registry layout in a namespace such as `ghcr.io/<owner>/hartland-cache`:
//!   * CAS blobs are registry blobs (REAPI and OCI digests are both sha256).
//!   * An action-cache entry is a manifest tagged with the action hash. Its
//!     config is the exact serialised ActionResult; its layers are every blob
//!     the result needs (so the registry keeps them) plus the signed batch
//!     envelope; the annotation `ANN_ENVELOPE` names the envelope.
//!   * `hartland-index` lists (envelope, bundle) pairs for recent batches, so
//!     a reader loads a batch with one request instead of one per action.
//!
//! Trust: a result is served only if its batch envelope verifies against the
//! keyring and the signed statement maps the action to the sha256 of these
//! exact result bytes. Blobs are content-addressed and digest-checked.
//!
//! Writes: kept locally; `publish` signs one batch with the job's OIDC token,
//! writes it to the first tier, and promotes to the registry per `Promote`.

use crate::attest::{ActionResult as Pair, Digest, Envelope, Statement, sha256_hex};
use crate::jwt::Jwks;
use crate::keyring::Keyring;
use crate::l1::{self, L1};
use crate::oci::{MANIFEST_MEDIA_TYPE, Registry};
use crate::proxy::{DiskStore, EMPTY_SHA256, Store};
use crate::reapi::re;
use futures::{StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

pub const ARTIFACT_TYPE: &str = "application/vnd.hartland.action-result.v0";
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.hartland.reapi.action-result.v2+proto";
pub const ENVELOPE_MEDIA_TYPE: &str = crate::attest::ENVELOPE_MEDIA_TYPE;
pub const ANN_ENVELOPE: &str = "dev.hartland.envelope";
pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.hartland.batch-bundle.v0+json";
pub const INDEX_ARTIFACT_TYPE: &str = "application/vnd.hartland.index.v0";
pub const INDEX_TAG: &str = "hartland-index";
const INDEX_MAX_BATCHES: usize = 50;
const L1_MAX_BATCHES: usize = 100;
const REGISTRY_CONCURRENCY: usize = 16;
const READ_ATTEMPTS: u32 = 3;

/// Which results go to the registry (the shared, durable tier).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Promote {
    /// Everything: builds of the default branch.
    All,
    /// Only results reused from the first tier, i.e. built by an earlier run
    /// and needed again: worth sharing.
    Reused,
    /// Nothing.
    None,
}

impl std::str::FromStr for Promote {
    type Err = String;
    fn from_str(s: &str) -> Result<Promote, String> {
        match s {
            "all" => Ok(Promote::All),
            "reused" => Ok(Promote::Reused),
            "none" => Ok(Promote::None),
            o => Err(format!("--promote wants all|reused|none, got {o}")),
        }
    }
}

type Entry = (String, re::ActionResult, Vec<String>);

pub struct GhcrStore {
    local: DiskStore,
    readers: Vec<Registry>,
    writer: Option<Registry>,
    keyring: Keyring,
    jwks: Jwks,
    l1: Option<L1>,
    promote: Promote,
    /// Results executed this run, awaiting a signed batch.
    pending: Mutex<Vec<(String, i64, re::ActionResult)>>,
    /// Envelope digest -> verified statement pairs (per-action lookups).
    verified: Mutex<HashMap<String, HashMap<String, String>>>,
    /// Verified results from indexes and the first tier.
    indexed: Mutex<HashMap<String, re::ActionResult>>,
    /// Blobs verified results reference: present, fetched on demand.
    known: Mutex<HashSet<String>>,
    /// Registry results served via per-action lookup, by envelope: re-indexed.
    reindex: Mutex<HashMap<String, HashMap<String, re::ActionResult>>>,
    /// First-tier results: action -> envelope hash, and the envelopes.
    l1_origin: Mutex<HashMap<String, String>>,
    l1_envelopes: Mutex<HashMap<String, Vec<u8>>>,
    /// First-tier results served this run (candidates for promotion).
    reused: Mutex<HashSet<String>>,
    /// Registry results: action -> envelope hash; and those served this run,
    /// which are written through to the first tier.
    registry_origin: Mutex<HashMap<String, String>>,
    served_remote: Mutex<HashSet<String>>,
}

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

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl GhcrStore {
    pub fn new(local: DiskStore, readers: Vec<Registry>, writer: Option<Registry>, keyring: Keyring, jwks: Jwks) -> GhcrStore {
        GhcrStore {
            local,
            readers,
            writer,
            keyring,
            jwks,
            l1: None,
            promote: Promote::All,
            pending: Mutex::default(),
            verified: Mutex::default(),
            indexed: Mutex::default(),
            known: Mutex::default(),
            reindex: Mutex::default(),
            l1_origin: Mutex::default(),
            l1_envelopes: Mutex::default(),
            reused: Mutex::default(),
            registry_origin: Mutex::default(),
            served_remote: Mutex::default(),
        }
    }

    pub fn with_l1(mut self, l1: Option<L1>, promote: Promote) -> GhcrStore {
        self.l1 = l1;
        self.promote = promote;
        self
    }

    fn accept_batch(&self, v: l1::VerifiedBatch, from_l1: bool) -> usize {
        let n = v.results.len();
        let (mut idx, mut known) = (lock(&self.indexed), lock(&self.known));
        for (action, result, blobs) in v.results {
            known.extend(blobs);
            if from_l1 {
                lock(&self.l1_origin).insert(action.clone(), v.envelope_hash.clone());
            } else {
                lock(&self.registry_origin).entry(action.clone()).or_insert_with(|| v.envelope_hash.clone());
            }
            idx.entry(action).or_insert(result);
        }
        if from_l1 {
            lock(&self.l1_envelopes).insert(v.envelope_hash, v.envelope);
        }
        n
    }

    /// Loads the first tier, then every reader's index. Returns the number of
    /// verified results now servable.
    pub async fn load(&self) -> usize {
        if let Some(l1) = &self.l1 {
            for v in l1.load(&self.jwks, &self.keyring).await {
                self.accept_batch(v, true);
            }
        }
        for reg in &self.readers {
            let Ok(reply) = reg.get_manifest(INDEX_TAG).await else { continue };
            if reply.status != 200 {
                continue;
            }
            let Ok(m) = serde_json::from_slice::<serde_json::Value>(&reply.body) else { continue };
            let layers: Vec<(String, String)> = m
                .get("layers")
                .and_then(|l| l.as_array())
                .map(|l| {
                    l.iter()
                        .filter_map(|x| Some((x.get("mediaType")?.as_str()?.to_string(), x.get("digest")?.as_str()?.strip_prefix("sha256:")?.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let batches: Vec<(String, String)> = layers
                .windows(2)
                .filter(|w| w[0].0 == ENVELOPE_MEDIA_TYPE && w[1].0 == BUNDLE_MEDIA_TYPE)
                .map(|w| (w[0].1.clone(), w[1].1.clone()))
                .collect();
            futures::stream::iter(batches)
                .map(|(env, bundle)| async move {
                    let (Ok(e), Ok(b)) = (get_blob_retrying(reg, &env).await, get_blob_retrying(reg, &bundle).await) else { return };
                    if sha256_hex(&e) != env {
                        return;
                    }
                    if let Some(v) = l1::accept(&env, &e, &b, &self.jwks, &self.keyring) {
                        let _ = self.local.put_blob(&env, &e).await;
                        self.accept_batch(v, false);
                    }
                })
                .buffer_unordered(4)
                .collect::<Vec<()>>()
                .await;
        }
        lock(&self.indexed).len()
    }

    /// local -> first tier -> registries (keeping a local copy).
    async fn any_blob(&self, hash: &str) -> Option<Vec<u8>> {
        if let Some(b) = self.local.get_blob(hash).await {
            return Some(b);
        }
        if let Some(l1) = &self.l1 {
            if let Some(b) = l1.get_blob(hash).await {
                let _ = self.local.put_blob(hash, &b).await;
                return Some(b);
            }
        }
        for r in &self.readers {
            if let Ok(b) = get_blob_retrying(r, hash).await {
                let _ = self.local.put_blob(hash, &b).await;
                return Some(b);
            }
        }
        None
    }

    async fn verified_pairs(&self, reg: &Registry, envelope_hash: &str) -> Option<HashMap<String, String>> {
        if let Some(p) = lock(&self.verified).get(envelope_hash) {
            return Some(p.clone());
        }
        let bytes = get_blob_retrying(reg, envelope_hash).await.ok()?;
        let _ = self.local.put_blob(envelope_hash, &bytes).await;
        let env: Envelope = serde_json::from_slice(&bytes).ok()?;
        let (statement, _signer) = crate::verify_envelope(&env, &self.jwks, &self.keyring).ok()?;
        let pairs: HashMap<String, String> = statement.predicate.results.into_iter().map(|p| (p.action.hash, p.result.hash)).collect();
        lock(&self.verified).insert(envelope_hash.to_string(), pairs.clone());
        Some(pairs)
    }

    /// The slow path: one action's manifest from a registry.
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
        // Its manifest's layers retain every blob it needs: present.
        if let Some(layers) = m.get("layers").and_then(|l| l.as_array()) {
            let mut known = lock(&self.known);
            for l in layers {
                if let Some(h) = l.get("digest").and_then(|d| d.as_str()).and_then(|d| d.strip_prefix("sha256:")) {
                    known.insert(h.to_string());
                }
            }
        }
        lock(&self.reindex).entry(env_hash.to_string()).or_default().insert(action.to_string(), result.clone());
        lock(&self.indexed).insert(action.to_string(), result.clone());
        lock(&self.registry_origin).entry(action.to_string()).or_insert_with(|| env_hash.to_string());
        lock(&self.served_remote).insert(action.to_string());
        Some(result)
    }

    /// Every blob an action result needs: outputs, stdout/stderr, and for each
    /// output directory its Tree and every file inside it.
    async fn referenced_blobs(&self, r: &re::ActionResult) -> Result<Vec<String>, String> {
        let mut out = BTreeSet::new();
        out.extend(r.output_files.iter().filter_map(|f| f.digest.as_ref().map(|d| d.hash.clone())));
        out.extend(r.stdout_digest.iter().chain(r.stderr_digest.iter()).map(|d| d.hash.clone()));
        for dir in &r.output_directories {
            let Some(td) = &dir.tree_digest else { continue };
            out.insert(td.hash.clone());
            let bytes = self.any_blob(&td.hash).await.ok_or_else(|| format!("tree {} unavailable", td.hash))?;
            let tree = re::Tree::decode(bytes.as_slice()).map_err(|e| format!("bad tree {}: {e}", td.hash))?;
            for d in tree.root.iter().chain(tree.children.iter()) {
                out.extend(d.files.iter().filter_map(|f| f.digest.as_ref().map(|d| d.hash.clone())));
            }
        }
        out.remove(EMPTY_SHA256);
        Ok(out.into_iter().collect())
    }

    /// Pushes a signed batch to a registry: envelope, blobs, results,
    /// per-action manifests, bundle, index entry.
    async fn push_batch(&self, writer: &Registry, env_hash: &str, envelope: &[u8], entries: &[Entry]) -> Result<(), String> {
        writer.put_blob(envelope).await?;
        let all: BTreeSet<String> = entries.iter().flat_map(|(_, _, b)| b.iter().cloned()).collect();
        let sizes: HashMap<String, usize> = futures::stream::iter(all)
            .map(|h| async move {
                let data = self.any_blob(&h).await.ok_or_else(|| format!("blob {h} unavailable"))?;
                writer.put_blob(&data).await?;
                Ok::<_, String>((h, data.len()))
            })
            .buffer_unordered(REGISTRY_CONCURRENCY)
            .try_collect()
            .await?;
        let configs: Vec<Vec<u8>> = entries.iter().map(|(_, r, _)| r.encode_to_vec()).collect();
        futures::stream::iter(&configs).map(|c| writer.put_blob(c)).buffer_unordered(REGISTRY_CONCURRENCY).try_collect::<Vec<_>>().await?;
        let mut manifests = Vec::new();
        for ((action, _, blobs), config) in entries.iter().zip(&configs) {
            let mut layers: Vec<serde_json::Value> = blobs
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
        let bundle = l1::bundle_bytes(entries)?;
        let bundle_hash = writer.put_blob(&bundle).await?;
        self.append_index(writer, (env_hash, envelope.len()), (&bundle_hash, bundle.len())).await
    }

    /// Read-modify-write of the index manifest. Concurrent publishers can
    /// drop each other's entry; per-action manifests still serve as fallback.
    async fn append_index(&self, writer: &Registry, envelope: (&str, usize), bundle: (&str, usize)) -> Result<(), String> {
        let mut layers: Vec<serde_json::Value> = match writer.get_manifest(INDEX_TAG).await {
            Ok(r) if r.status == 200 => serde_json::from_slice::<serde_json::Value>(&r.body)
                .ok()
                .and_then(|m| m.get("layers").and_then(|l| l.as_array()).cloned())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        layers.push(serde_json::json!({"mediaType": ENVELOPE_MEDIA_TYPE, "digest": format!("sha256:{}", envelope.0), "size": envelope.1}));
        layers.push(serde_json::json!({"mediaType": BUNDLE_MEDIA_TYPE, "digest": format!("sha256:{}", bundle.0), "size": bundle.1}));
        let keep = INDEX_MAX_BATCHES * 2;
        if layers.len() > keep {
            layers.drain(..layers.len() - keep);
        }
        let empty = writer.put_blob(b"{}").await?;
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST_MEDIA_TYPE,
            "artifactType": INDEX_ARTIFACT_TYPE,
            "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": format!("sha256:{empty}"), "size": 2},
            "layers": layers,
        });
        writer.put_manifest(INDEX_TAG, MANIFEST_MEDIA_TYPE, &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?).await?;
        Ok(())
    }

    /// Writes a batch (and its blobs) to the first tier.
    async fn save_l1(&self, env_hash: &str, envelope: &[u8], entries: &[Entry]) -> Result<(), String> {
        let Some(l1) = &self.l1 else { return Ok(()) };
        let all: BTreeSet<String> = entries.iter().flat_map(|(_, _, b)| b.iter().cloned()).collect();
        futures::stream::iter(all)
            .map(|h| async move {
                let data = self.any_blob(&h).await.ok_or_else(|| format!("blob {h} unavailable"))?;
                l1.put_blob(&h, &data).await
            })
            .buffer_unordered(32)
            .try_collect::<Vec<()>>()
            .await?;
        l1.write_batch(env_hash, envelope, &l1::bundle_bytes(entries)?).await
    }

    /// Signs this run's new results as one batch, saves it to the first
    /// tier, and promotes to the registry per policy. Returns the number of
    /// new results signed.
    pub async fn publish(&self) -> Result<usize, String> {
        let pending: Vec<_> = std::mem::take(&mut *lock(&self.pending));
        let mut new_batch = None;
        if !pending.is_empty() {
            if self.writer.is_none() && self.l1.is_none() {
                return Err("results pending but nowhere to publish them".to_string());
            }
            let mut pairs = Vec::new();
            let mut entries = Vec::new();
            for (action, size, result) in &pending {
                let bytes = result.encode_to_vec();
                pairs.push(Pair {
                    action: Digest { hash: action.clone(), size: *size as u64 },
                    result: Digest { hash: sha256_hex(&bytes), size: bytes.len() as u64 },
                });
                entries.push((action.clone(), result.clone(), self.referenced_blobs(result).await?));
            }
            let payload = crate::statement_bytes(&Statement::new(pairs));
            let token = crate::github::request_token(&crate::attest::audience_for(&payload)).await?;
            let envelope = serde_json::to_vec(&Envelope::new(&payload, token)).map_err(|e| e.to_string())?;
            let env_hash = sha256_hex(&envelope);
            self.save_l1(&env_hash, &envelope, &entries).await?;
            new_batch = Some((env_hash, envelope, entries));
        }

        if let Some(writer) = &self.writer {
            // Registry results served via the slow path: index them.
            let groups: Vec<(String, HashMap<String, re::ActionResult>)> = std::mem::take(&mut *lock(&self.reindex)).into_iter().collect();
            for (env_hash, results) in groups {
                let Some(envelope) = self.local.get_blob(&env_hash).await else { continue };
                let mut entries = Vec::new();
                for (a, r) in results {
                    let blobs = self.referenced_blobs(&r).await?;
                    entries.push((a, r, blobs));
                }
                let bundle = l1::bundle_bytes(&entries)?;
                let bundle_hash = writer.put_blob(&bundle).await?;
                self.append_index(writer, (&env_hash, envelope.len()), (&bundle_hash, bundle.len())).await?;
                eprintln!("hartland proxy: indexed {} previously signed result(s)", entries.len());
            }

            if self.promote == Promote::All {
                if let Some((env_hash, envelope, entries)) = &new_batch {
                    self.push_batch(writer, env_hash, envelope, entries).await?;
                }
            }
            if self.promote != Promote::None {
                // First-tier results reused this run, under their own envelopes.
                let reused: Vec<String> = std::mem::take(&mut *lock(&self.reused)).into_iter().collect();
                let mut by_env: HashMap<String, Vec<String>> = HashMap::new();
                for a in reused {
                    if let Some(env) = lock(&self.l1_origin).get(&a).cloned() {
                        by_env.entry(env).or_default().push(a);
                    }
                }
                for (env_hash, actions) in by_env {
                    let Some(envelope) = lock(&self.l1_envelopes).get(&env_hash).cloned() else { continue };
                    let mut entries = Vec::new();
                    for a in actions {
                        let Some(r) = lock(&self.indexed).get(&a).cloned() else { continue };
                        let blobs = self.referenced_blobs(&r).await?;
                        entries.push((a, r, blobs));
                    }
                    self.push_batch(writer, &env_hash, &envelope, &entries).await?;
                    eprintln!("hartland proxy: promoted {} reused result(s) to the registry", entries.len());
                }
            }
        }
        // Write registry results served this run through to the first tier,
        // under their own envelopes, so the next run needs no registry reads.
        if self.l1.is_some() {
            let served: Vec<String> = std::mem::take(&mut *lock(&self.served_remote)).into_iter().collect();
            let mut by_env: HashMap<String, Vec<String>> = HashMap::new();
            for a in served {
                if let Some(env) = lock(&self.registry_origin).get(&a).cloned() {
                    by_env.entry(env).or_default().push(a);
                }
            }
            for (env_hash, actions) in by_env {
                let Some(envelope) = self.local.get_blob(&env_hash).await else { continue };
                let mut entries = Vec::new();
                for a in actions {
                    let Some(r) = lock(&self.indexed).get(&a).cloned() else { continue };
                    let blobs = self.referenced_blobs(&r).await?;
                    entries.push((a, r, blobs));
                }
                self.save_l1(&env_hash, &envelope, &entries).await?;
            }
        }
        if let Some(l1) = &self.l1 {
            l1.prune(L1_MAX_BATCHES, &self.jwks, &self.keyring).await?;
        }
        Ok(pending.len())
    }
}

#[async_trait::async_trait]
impl Store for GhcrStore {
    /// Local, first tier, or referenced by a verified result (fetched on
    /// demand); anything else buck2 simply uploads.
    async fn has_blob(&self, hash: &str) -> bool {
        if self.local.has_blob(hash).await || lock(&self.known).contains(hash) {
            return true;
        }
        match &self.l1 {
            Some(l1) => l1.has_blob(hash).await,
            None => false,
        }
    }

    async fn get_blob(&self, hash: &str) -> Option<Vec<u8>> {
        self.any_blob(hash).await
    }

    async fn put_blob(&self, hash: &str, data: &[u8]) -> Result<(), String> {
        self.local.put_blob(hash, data).await
    }

    async fn get_action_result(&self, action: &str) -> Option<re::ActionResult> {
        // Results produced in this run are trusted; they get signed on publish.
        if let Some(r) = self.local.get_action_result(action).await {
            return Some(r);
        }
        if let Some(r) = lock(&self.indexed).get(action).cloned() {
            if lock(&self.l1_origin).contains_key(action) {
                lock(&self.reused).insert(action.to_string());
            } else if lock(&self.registry_origin).contains_key(action) {
                lock(&self.served_remote).insert(action.to_string());
            }
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
        lock(&self.pending).push((action.to_string(), action_size, result.clone()));
        Ok(())
    }
}
