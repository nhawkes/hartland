//! A `Store` backed by container registries, trusting only signed results.
//!
//! Layout in a namespace such as `ghcr.io/<owner>/hartland-cache`:
//!   * CAS blobs are registry blobs (REAPI and OCI digests are both sha256).
//!   * An action-cache entry is a manifest tagged with the action hash. Its
//!     config is the exact serialised ActionResult; its layers are every blob
//!     the result needs (so the registry keeps them) plus the signed batch
//!     envelope; the annotation `ANN_ENVELOPE` names the envelope.
//!
//! Reads: blobs from anywhere (content-addressed, digest-checked); action
//! results only if the envelope verifies against the keyring and its
//! statement maps this action to the sha256 of this exact config blob.
//! Writes: kept locally, then `publish` signs one batch with the job's OIDC
//! token and pushes everything to the writable namespace.

use crate::attest::{ActionResult as Pair, Digest, Envelope, Statement, sha256_hex};
use crate::jwt::Jwks;
use crate::keyring::Keyring;
use crate::oci::{MANIFEST_MEDIA_TYPE, Registry};
use crate::proxy::{DiskStore, EMPTY_SHA256, Store};
use crate::reapi::re;
use prost::Message as _;
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

pub const ARTIFACT_TYPE: &str = "application/vnd.hartland.action-result.v0";
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.hartland.reapi.action-result.v2+proto";
pub const ENVELOPE_MEDIA_TYPE: &str = crate::attest::ENVELOPE_MEDIA_TYPE;
pub const ANN_ENVELOPE: &str = "dev.hartland.envelope";

pub struct GhcrStore {
    local: DiskStore,
    /// Namespaces to read from, in order (usually the keyring's builders'
    /// callers, then our own).
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

impl GhcrStore {
    pub fn new(local: DiskStore, readers: Vec<Registry>, writer: Option<Registry>, keyring: Keyring, jwks: Jwks) -> GhcrStore {
        GhcrStore { local, readers, writer, keyring, jwks, pending: Mutex::new(Vec::new()), verified: Mutex::new(HashMap::new()) }
    }

    fn fetch_blob(&self, hash: &str) -> Option<Vec<u8>> {
        for r in &self.readers {
            if let Ok(b) = r.get_blob(hash) {
                // get_blob checks the digest; keep a local copy.
                let _ = self.local.put_blob(hash, &b);
                return Some(b);
            }
        }
        None
    }

    /// Verifies an envelope once per run and returns its action -> result map.
    fn verified_pairs(&self, reg: &Registry, envelope_hash: &str) -> Option<HashMap<String, String>> {
        if let Some(p) = self.verified.lock().ok()?.get(envelope_hash) {
            return Some(p.clone());
        }
        let bytes = reg.get_blob(envelope_hash).ok()?;
        let env: Envelope = serde_json::from_slice(&bytes).ok()?;
        let (statement, _signer) = crate::verify_envelope(&env, &self.jwks, &self.keyring).ok()?;
        let pairs: HashMap<String, String> =
            statement.predicate.results.into_iter().map(|p| (p.action.hash, p.result.hash)).collect();
        self.verified.lock().ok()?.insert(envelope_hash.to_string(), pairs.clone());
        Some(pairs)
    }

    fn lookup(&self, reg: &Registry, action: &str) -> Option<re::ActionResult> {
        let reply = reg.get_manifest(action).ok()?;
        if reply.status != 200 {
            return None;
        }
        let m: serde_json::Value = serde_json::from_slice(&reply.body).ok()?;
        if m.get("artifactType")?.as_str()? != ARTIFACT_TYPE {
            return None;
        }
        let env_hash = m.pointer(&format!("/annotations/{}", ANN_ENVELOPE.replace('/', "~1")))?.as_str()?.strip_prefix("sha256:")?;
        let config_hash = m.pointer("/config/digest")?.as_str()?.strip_prefix("sha256:")?;
        let pairs = self.verified_pairs(reg, env_hash)?;
        if pairs.get(action).map(String::as_str) != Some(config_hash) {
            return None;
        }
        let bytes = reg.get_blob(config_hash).ok()?;
        re::ActionResult::decode(bytes.as_slice()).ok()
    }

    /// Signs everything written this run as one batch and pushes it.
    /// Returns the number of results published.
    pub fn publish(&self) -> Result<usize, String> {
        let writer = self.writer.as_ref().ok_or("no writable namespace configured")?;
        let pending: Vec<_> = std::mem::take(&mut *self.pending.lock().map_err(|_| "poisoned")?);
        if pending.is_empty() {
            return Ok(0);
        }
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
        let token = crate::github::request_token(&crate::attest::audience_for(&payload))?;
        let envelope = serde_json::to_vec(&Envelope::new(&payload, token)).map_err(|e| e.to_string())?;
        let env_hash = writer.put_blob(&envelope)?;

        for ((action, _, result), config) in pending.iter().zip(&configs) {
            let config_hash = writer.put_blob(config)?;
            let mut layers = Vec::new();
            for hash in self.referenced_blobs(result)? {
                let data = self.local.get_blob(&hash).ok_or_else(|| format!("output blob {hash} missing locally"))?;
                writer.put_blob(&data)?;
                layers.push(serde_json::json!({"mediaType": "application/octet-stream", "digest": format!("sha256:{hash}"), "size": data.len()}));
            }
            layers.push(serde_json::json!({"mediaType": ENVELOPE_MEDIA_TYPE, "digest": format!("sha256:{env_hash}"), "size": envelope.len()}));
            let manifest = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": MANIFEST_MEDIA_TYPE,
                "artifactType": ARTIFACT_TYPE,
                "config": {"mediaType": CONFIG_MEDIA_TYPE, "digest": format!("sha256:{config_hash}"), "size": config.len()},
                "layers": layers,
                "annotations": {ANN_ENVELOPE: format!("sha256:{env_hash}")},
            });
            writer.put_manifest(action, MANIFEST_MEDIA_TYPE, &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?)?;
        }
        Ok(pending.len())
    }

    /// Every blob an action result needs: outputs, stdout/stderr, and for each
    /// output directory its Tree blob and every file inside it.
    fn referenced_blobs(&self, r: &re::ActionResult) -> Result<BTreeSet<String>, String> {
        let mut out = BTreeSet::new();
        for f in &r.output_files {
            if let Some(d) = &f.digest {
                out.insert(d.hash.clone());
            }
        }
        for d in r.stdout_digest.iter().chain(r.stderr_digest.iter()) {
            out.insert(d.hash.clone());
        }
        for dir in &r.output_directories {
            let Some(td) = &dir.tree_digest else { continue };
            out.insert(td.hash.clone());
            let bytes = self.local.get_blob(&td.hash).ok_or_else(|| format!("tree {} missing locally", td.hash))?;
            let tree = re::Tree::decode(bytes.as_slice()).map_err(|e| format!("bad tree {}: {e}", td.hash))?;
            for d in tree.root.iter().chain(tree.children.iter()) {
                for f in &d.files {
                    if let Some(fd) = &f.digest {
                        out.insert(fd.hash.clone());
                    }
                }
            }
        }
        out.remove(EMPTY_SHA256);
        Ok(out)
    }
}

impl Store for GhcrStore {
    fn has_blob(&self, hash: &str) -> bool {
        self.local.has_blob(hash) || self.readers.iter().any(|r| r.blob_exists(hash).unwrap_or(false))
    }

    fn get_blob(&self, hash: &str) -> Option<Vec<u8>> {
        self.local.get_blob(hash).or_else(|| self.fetch_blob(hash))
    }

    fn put_blob(&self, hash: &str, data: &[u8]) -> Result<(), String> {
        self.local.put_blob(hash, data)
    }

    fn get_action_result(&self, action: &str) -> Option<re::ActionResult> {
        // Results produced in this run are trusted; they get signed on publish.
        if let Some(r) = self.local.get_action_result(action) {
            return Some(r);
        }
        self.readers.iter().find_map(|reg| self.lookup(reg, action))
    }

    fn put_action_result(&self, action: &str, action_size: i64, result: &re::ActionResult) -> Result<(), String> {
        self.local.put_action_result(action, action_size, result)?;
        self.pending.lock().map_err(|_| "poisoned")?.push((action.to_string(), action_size, result.clone()));
        Ok(())
    }
}
