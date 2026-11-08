//! A `Store` backed by container registries (and optionally a first-tier
//! directory saved in GitHub's Actions cache), trusting only signed results.
//!
//! Registry layout in a namespace such as `ghcr.io/<owner>/hartland-cache`:
//!   * CAS blobs are registry blobs (REAPI and OCI digests are both sha256).
//!   * An action-cache entry is a manifest tagged with the action digest. Its
//!     config is the exact serialised ActionResult; its layers are every blob
//!     the result needs (so the registry keeps them) plus the signed batch
//!     envelope, which the annotation `ANN_ENVELOPE` names.
//!   * `hartland-index` lists (envelope, bundle) pairs for recent batches, so
//!     a reader loads a batch with one request instead of one per action.
//!
//! Trust: a result is served only if its batch envelope verifies against the
//! keyring and the signed statement maps the action to the sha256 of these
//! exact result bytes. Blobs are content-addressed and digest-checked.
//!
//! Writes: kept locally; `publish` signs one batch with the job's OIDC token,
//! saves it to the first tier, and plans what the registry should receive
//! (per `Promote`). With a first tier the plan is queued in its outbox, for
//! `drain_outbox` to push after the build, off its critical path.

use crate::attest::{Batch, Envelope, Pair};
use crate::bundle::{CachedResult, VerifiedBatch, bundle_bytes};
use crate::cas::Blob;
use crate::digest::{ActionDigest, ActionId, BatchId, Digest, Sha256};
use crate::jwt::Jwks;
use crate::keyring::Keyring;
use crate::l1::L1;
use crate::oci::{Reference, Registry, Tag};
use crate::proxy::{DiskStore, Store, StoreError, direct_blobs};
use crate::reapi::re;
use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use futures::{StreamExt as _, TryStreamExt as _};
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageManifest, ImageManifestBuilder, MediaType,
};
use prost::Message as _;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

const ARTIFACT_TYPE: &str = "application/vnd.hartland.action-result.v0";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.hartland.reapi.action-result.v2+proto";
const ENVELOPE_MEDIA_TYPE: &str = crate::attest::ENVELOPE_MEDIA_TYPE;
const ANN_ENVELOPE: &str = "dev.hartland.envelope";
const BUNDLE_MEDIA_TYPE: &str = "application/vnd.hartland.batch-bundle.v0+json";
const INDEX_ARTIFACT_TYPE: &str = "application/vnd.hartland.index.v0";
const INDEX_TAG: &str = "hartland-index";
const INDEX_MAX_BATCHES: usize = 50;
const L1_MAX_BATCHES: usize = 100;
const REGISTRY_CONCURRENCY: usize = 16;

/// Which results go to the registry (the shared, durable tier).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Promote {
    /// Everything: builds of the default branch.
    All,
    /// Only results reused from the first tier, i.e. built by an earlier run
    /// and needed again: worth sharing.
    Reused,
    /// Nothing.
    None,
}

/// What the registry holds of a result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InRegistry {
    No,
    /// Listed in an index: a reader finds it with one request per batch.
    Indexed,
    /// Only its per-action manifest: worth indexing once used.
    ManifestOnly,
}

/// A trusted result and what we know about where it is.
struct Known {
    result: CachedResult,
    batch: BatchId,
    in_first_tier: bool,
    in_registry: InRegistry,
    built_here: bool,
    /// Served to a client this run.
    used: bool,
}

/// Registry writes to make: batches (restricted to some actions) to push in
/// full, and batches already pushed whose entries only need indexing.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Plan {
    push: BTreeMap<BatchId, BTreeSet<ActionId>>,
    index: BTreeMap<BatchId, BTreeSet<ActionId>>,
}

impl Plan {
    fn is_empty(&self) -> bool {
        self.push.is_empty() && self.index.is_empty()
    }

    fn results(&self) -> usize {
        self.push
            .values()
            .chain(self.index.values())
            .map(BTreeSet::len)
            .sum()
    }

    fn batches(&self) -> impl Iterator<Item = BatchId> + '_ {
        self.push.keys().chain(self.index.keys()).copied()
    }

    /// Unions plans. Pushing a batch indexes it too, so indexing a batch
    /// that is also pushed is dropped.
    fn merge(plans: impl IntoIterator<Item = Plan>) -> Plan {
        let mut out = Plan::default();
        for p in plans {
            for (b, a) in p.push {
                out.push.entry(b).or_default().extend(a);
            }
            for (b, a) in p.index {
                out.index.entry(b).or_default().extend(a);
            }
        }
        out.index.retain(|b, _| !out.push.contains_key(b));
        out
    }
}

/// Results this process executed, awaiting a signed batch.
struct Pending {
    action: ActionDigest,
    result: re::ActionResult,
}

pub struct GhcrStore {
    local: DiskStore,
    readers: Vec<Registry>,
    writer: Option<Registry>,
    keyring: Keyring,
    jwks: Jwks,
    l1: Option<L1>,
    promote: Promote,
    pending: Mutex<Vec<Pending>>,
    known: DashMap<ActionId, Known>,
    envelopes: DashMap<BatchId, Bytes>,
    /// Blobs that known results reference: present somewhere, fetched on
    /// demand.
    referenced: DashSet<Sha256>,
    /// Verified statements, for per-action registry lookups.
    statements: DashMap<BatchId, Arc<Batch>>,
    /// Every reader's index has been read (see `load_registry`).
    registry_loaded: OnceCell<()>,
}

fn descriptor(media_type: &str, digest: Sha256, size: usize) -> Descriptor {
    DescriptorBuilder::default()
        .media_type(MediaType::Other(media_type.to_string()))
        .digest(digest.oci())
        .size(size as u64)
        .build()
        .expect("a descriptor with media type, digest and size")
}

impl GhcrStore {
    pub fn new(
        local: DiskStore,
        readers: Vec<Registry>,
        writer: Option<Registry>,
        keyring: Keyring,
        jwks: Jwks,
    ) -> GhcrStore {
        GhcrStore {
            local,
            readers,
            writer,
            keyring,
            jwks,
            l1: None,
            promote: Promote::All,
            pending: Mutex::default(),
            known: DashMap::new(),
            envelopes: DashMap::new(),
            referenced: DashSet::new(),
            statements: DashMap::new(),
            registry_loaded: OnceCell::new(),
        }
    }

    pub fn with_first_tier(self, l1: L1, promote: Promote) -> GhcrStore {
        GhcrStore {
            l1: Some(l1),
            promote,
            ..self
        }
    }

    pub fn known(&self) -> usize {
        self.known.len()
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Vec<Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records a verified batch from the first tier or a registry index.
    fn absorb(&self, batch: VerifiedBatch, from_first_tier: bool) {
        for r in batch.results {
            for h in &r.blobs {
                self.referenced.insert(*h);
            }
            self.known
                .entry(r.action)
                .and_modify(|k| {
                    if from_first_tier {
                        k.in_first_tier = true;
                    } else {
                        k.in_registry = InRegistry::Indexed;
                    }
                })
                .or_insert_with(|| Known {
                    result: r,
                    batch: batch.id,
                    in_first_tier: from_first_tier,
                    in_registry: if from_first_tier {
                        InRegistry::No
                    } else {
                        InRegistry::Indexed
                    },
                    built_here: false,
                    used: false,
                });
        }
        self.envelopes.insert(batch.id, batch.envelope);
    }

    /// Loads the first tier: enough to start serving. Registry indexes are
    /// needed only on a first-tier miss and when publishing, so they can be
    /// read in the background (`load_registry`).
    pub async fn load_first_tier(&self) {
        if let Some(l1) = &self.l1 {
            for b in l1.load(&self.jwks, &self.keyring).await {
                self.absorb(b, true);
            }
            tracing::info!(results = self.known.len(), "first tier loaded");
        }
    }

    /// Reads every reader's index, once; concurrent callers wait for the
    /// same read.
    pub async fn load_registry(&self) {
        self.registry_loaded
            .get_or_init(|| self.read_indexes())
            .await;
    }

    async fn read_indexes(&self) {
        let started = tokio::time::Instant::now();
        for reg in &self.readers {
            let index = match reg
                .get_manifest(&Reference::Tag(INDEX_TAG.parse().expect("a valid tag")))
                .await
            {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(registry = %reg.name(), error = %e, "cannot read index");
                    continue;
                }
            };
            let pairs: Vec<(Sha256, Sha256)> = index
                .layers()
                .windows(2)
                .filter(|w| {
                    w[0].media_type().to_string() == ENVELOPE_MEDIA_TYPE
                        && w[1].media_type().to_string() == BUNDLE_MEDIA_TYPE
                })
                .filter_map(|w| {
                    Some((
                        Sha256::from_oci(w[0].digest()).ok()?,
                        Sha256::from_oci(w[1].digest()).ok()?,
                    ))
                })
                .collect();
            futures::stream::iter(pairs)
                .for_each_concurrent(4, |(envelope, bundle)| async move {
                    let (Ok(Some(e)), Ok(Some(b))) = (reg.get_blob(&envelope).await, reg.get_blob(&bundle).await) else { return };
                    match VerifiedBatch::accept(e, &b, &self.jwks, &self.keyring) {
                        Ok(v) => self.absorb(v, false),
                        Err(err) => tracing::warn!(batch = %envelope, error = %err, "index batch does not verify; skipped"),
                    }
                })
                .await;
        }
        tracing::info!(results = self.known.len(), elapsed = ?started.elapsed(), "registry indexes loaded");
    }

    /// local -> first tier -> registries (keeping a local copy).
    async fn any_blob(&self, hash: &Sha256) -> Option<Blob> {
        if let Some(b) = self.local.get_blob(hash).await {
            return Some(b);
        }
        let mut found = None;
        if let Some(l1) = &self.l1 {
            found = l1.blobs().get(hash).await;
        }
        for r in &self.readers {
            if found.is_some() {
                break;
            }
            found = r
                .get_blob(hash)
                .await
                .ok()
                .flatten()
                .and_then(|data| Blob::check_hash(*hash, data).ok());
        }
        let blob = found?;
        let _ = self.local.put_blob(&blob).await;
        Some(blob)
    }

    async fn need_blob(&self, hash: &Sha256) -> Result<Blob, StoreError> {
        self.any_blob(hash)
            .await
            .ok_or(StoreError::Unavailable(*hash))
    }

    async fn statement(&self, reg: &Registry, id: BatchId) -> Option<Arc<Batch>> {
        if let Some(b) = self.statements.get(&id) {
            return Some(b.clone());
        }
        let bytes = reg.get_blob(&id.0).await.ok()??;
        let batch: Arc<Batch> = Arc::new(
            Envelope::parse(&bytes)
                .ok()?
                .verify(&self.jwks, &self.keyring)
                .ok()?
                .statement,
        );
        self.envelopes.insert(id, bytes);
        self.statements.insert(id, batch.clone());
        Some(batch)
    }

    /// The slow path: one action's manifest from a registry.
    async fn lookup(&self, reg: &Registry, action: ActionId) -> Option<re::ActionResult> {
        let m = reg
            .get_manifest(&Reference::Tag(Tag::from(action.0)))
            .await
            .ok()??;
        if m.artifact_type()
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(ARTIFACT_TYPE)
        {
            return None;
        }
        let batch_id = BatchId(
            m.annotations()
                .as_ref()?
                .get(ANN_ENVELOPE)?
                .strip_prefix("sha256:")?
                .parse()
                .ok()?,
        );
        let config = Sha256::from_oci(m.config().digest()).ok()?;
        let statement = self.statement(reg, batch_id).await?;
        let bytes = reg.get_blob(&config).await.ok()??;
        if !statement.vouches(&action, &bytes) {
            return None;
        }
        let result = re::ActionResult::decode(bytes).ok()?;
        // The manifest's layers retain every blob the result needs.
        let blobs: BTreeSet<Sha256> = m
            .layers()
            .iter()
            .filter_map(|l| Sha256::from_oci(l.digest()).ok())
            .filter(|h| *h != batch_id.0)
            .collect();
        for h in &blobs {
            self.referenced.insert(*h);
        }
        self.known.insert(
            action,
            Known {
                result: CachedResult {
                    action,
                    result: result.clone(),
                    blobs,
                },
                batch: batch_id,
                in_first_tier: false,
                in_registry: InRegistry::ManifestOnly,
                built_here: false,
                used: true,
            },
        );
        Some(result)
    }

    /// Every blob an action result needs: outputs, stdout/stderr, and for each
    /// output directory its Tree and every file inside it.
    async fn referenced_blobs(&self, r: &re::ActionResult) -> Result<BTreeSet<Sha256>, StoreError> {
        let mut out = direct_blobs(r)?;
        for dir in &r.output_directories {
            let tree = Digest::try_from(dir.tree_digest.as_ref())?.hash;
            let tree = re::Tree::decode(self.need_blob(&tree).await?.into_data())?;
            for d in tree.root.iter().chain(&tree.children) {
                for f in &d.files {
                    out.insert(Digest::try_from(f.digest.as_ref())?.hash);
                }
            }
        }
        out.remove(&Sha256::EMPTY);
        Ok(out)
    }

    fn results_of<'a>(&self, actions: impl IntoIterator<Item = &'a ActionId>) -> Vec<CachedResult> {
        actions
            .into_iter()
            .filter_map(|a| self.known.get(a).map(|k| k.result.clone()))
            .collect()
    }

    async fn envelope(&self, id: &BatchId) -> Option<Bytes> {
        if let Some(e) = self.envelopes.get(id) {
            return Some(e.clone());
        }
        self.any_blob(&id.0).await.map(Blob::into_data)
    }

    /// Pushes a signed batch: envelope, blobs, results, per-action
    /// manifests, bundle, index entry.
    async fn push_batch(
        &self,
        writer: &Registry,
        id: BatchId,
        envelope: Bytes,
        results: &[CachedResult],
    ) -> Result<(), StoreError> {
        let envelope_layer = descriptor(
            ENVELOPE_MEDIA_TYPE,
            writer.put_blob(envelope.clone()).await?,
            envelope.len(),
        );
        let all: BTreeSet<Sha256> = results
            .iter()
            .flat_map(|r| r.blobs.iter().copied())
            .collect();
        let sizes: HashMap<Sha256, usize> = futures::stream::iter(all)
            .map(|h| async move {
                let blob = self.need_blob(&h).await?;
                let size = blob.data().len();
                writer.put_blob(blob.into_data()).await?;
                Ok::<_, StoreError>((h, size))
            })
            .buffer_unordered(REGISTRY_CONCURRENCY)
            .try_collect()
            .await?;
        futures::stream::iter(results)
            .map(|r| async {
                let config = Bytes::from(r.result.encode_to_vec());
                let config_digest = writer.put_blob(config.clone()).await?;
                let mut layers: Vec<Descriptor> = r
                    .blobs
                    .iter()
                    .map(|h| descriptor("application/octet-stream", *h, sizes[h]))
                    .collect();
                layers.push(envelope_layer.clone());
                let manifest = ImageManifestBuilder::default()
                    .schema_version(2u32)
                    .media_type(MediaType::ImageManifest)
                    .artifact_type(MediaType::Other(ARTIFACT_TYPE.to_string()))
                    .config(descriptor(CONFIG_MEDIA_TYPE, config_digest, config.len()))
                    .layers(layers)
                    .annotations(HashMap::from([(
                        ANN_ENVELOPE.to_string(),
                        format!("sha256:{id}"),
                    )]))
                    .build()
                    .expect("a complete manifest");
                writer
                    .put_manifest(&Reference::Tag(Tag::from(r.action.0)), &manifest)
                    .await?;
                Ok::<_, StoreError>(())
            })
            .buffer_unordered(REGISTRY_CONCURRENCY)
            .try_collect::<Vec<()>>()
            .await?;
        self.index_batch(writer, id, envelope, results).await
    }

    /// Adds a batch's bundle to the index (read-modify-write: concurrent
    /// publishers can drop each other's entry; per-action manifests remain).
    async fn index_batch(
        &self,
        writer: &Registry,
        id: BatchId,
        envelope: Bytes,
        results: &[CachedResult],
    ) -> Result<(), StoreError> {
        let bundle = bundle_bytes(results);
        let bundle_layer = descriptor(
            BUNDLE_MEDIA_TYPE,
            writer.put_blob(bundle.clone()).await?,
            bundle.len(),
        );
        let envelope_layer = descriptor(ENVELOPE_MEDIA_TYPE, id.0, envelope.len());
        let tag = Reference::Tag(INDEX_TAG.parse().expect("a valid tag"));
        let mut layers: Vec<Descriptor> = writer
            .get_manifest(&tag)
            .await?
            .map(|m| m.layers().clone())
            .unwrap_or_default();
        if layers
            .windows(2)
            .any(|w| w[0] == envelope_layer && w[1] == bundle_layer)
        {
            return Ok(());
        }
        layers.extend([envelope_layer, bundle_layer]);
        let excess = layers.len().saturating_sub(INDEX_MAX_BATCHES * 2);
        layers.drain(..excess);
        let empty = writer.put_blob(Bytes::from_static(b"{}")).await?;
        let index: ImageManifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .artifact_type(MediaType::Other(INDEX_ARTIFACT_TYPE.to_string()))
            .config(descriptor("application/vnd.oci.empty.v1+json", empty, 2))
            .layers(layers)
            .build()
            .expect("a complete manifest");
        writer.put_manifest(&tag, &index).await?;
        Ok(())
    }

    /// Writes a batch (and the blobs its results need) to the first tier.
    async fn save_first_tier(
        &self,
        l1: &L1,
        id: BatchId,
        envelope: Bytes,
        results: &[CachedResult],
    ) -> Result<(), StoreError> {
        let all: BTreeSet<Sha256> = results
            .iter()
            .flat_map(|r| r.blobs.iter().copied())
            .collect();
        futures::stream::iter(all)
            .map(|h| async move { Ok::<_, StoreError>(l1.put_blob(&self.need_blob(&h).await?).await?) })
            .buffer_unordered(32)
            .try_collect::<Vec<()>>()
            .await?;
        Ok(l1.write_batch(&id, envelope, bundle_bytes(results)).await?)
    }

    /// Signs the results executed so far as one batch.
    async fn sign_pending(&self) -> Result<usize, StoreError> {
        let pending: Vec<Pending> = std::mem::take(&mut *self.pending());
        if pending.is_empty() {
            return Ok(0);
        }
        if self.writer.is_none() && self.l1.is_none() {
            return Err(StoreError::Nowhere);
        }
        let pairs = pending.iter().map(|p| Pair {
            action: p.action.into(),
            result: Digest::of(&p.result.encode_to_vec()),
        });
        let envelope = Bytes::from(
            crate::attest::sign(Batch::new(pairs).to_bytes())
                .await?
                .to_bytes(),
        );
        let id = BatchId(Sha256::of(&envelope));
        let mut results = Vec::with_capacity(pending.len());
        for p in pending {
            let blobs = self.referenced_blobs(&p.result).await?;
            results.push(CachedResult {
                action: p.action.id,
                result: p.result,
                blobs,
            });
        }
        if let Some(l1) = &self.l1 {
            self.save_first_tier(l1, id, envelope.clone(), &results)
                .await?;
        }
        let n = results.len();
        self.envelopes.insert(id, envelope);
        for r in results {
            self.known.insert(
                r.action,
                Known {
                    result: r,
                    batch: id,
                    in_first_tier: self.l1.is_some(),
                    in_registry: InRegistry::No,
                    built_here: true,
                    used: false,
                },
            );
        }
        tracing::info!(results = n, batch = %id, "signed new results");
        Ok(n)
    }

    /// Plans registry writes per policy and marks them as planned, so a
    /// later publish does not plan them again.
    fn plan(&self) -> Plan {
        let mut plan = Plan::default();
        let mut skipped = 0;
        for mut k in self.known.iter_mut() {
            let push = match (self.promote, k.in_registry) {
                (_, InRegistry::Indexed | InRegistry::ManifestOnly) => {
                    skipped += usize::from(k.used && k.in_first_tier && !k.built_here);
                    false
                }
                (_, InRegistry::No) if self.l1.is_none() => k.built_here,
                (Promote::All, InRegistry::No) => k.built_here || (k.used && k.in_first_tier),
                (Promote::Reused, InRegistry::No) => k.used && k.in_first_tier && !k.built_here,
                (Promote::None, InRegistry::No) => false,
            };
            if push {
                plan.push.entry(k.batch).or_default().insert(*k.key());
                k.in_registry = InRegistry::Indexed;
            } else if k.used && k.in_registry == InRegistry::ManifestOnly {
                plan.index.entry(k.batch).or_default().insert(*k.key());
                k.in_registry = InRegistry::Indexed;
            }
        }
        if skipped > 0 {
            tracing::info!(
                results = skipped,
                "reused results already in a registry: not promoted"
            );
        }
        plan
    }

    /// Writes registry results served this run through to the first tier,
    /// under their own envelopes, so the next run needs no registry reads.
    async fn write_through(&self, l1: &L1) -> Result<(), StoreError> {
        let mut by_batch: BTreeMap<BatchId, Vec<ActionId>> = BTreeMap::new();
        for k in self.known.iter().filter(|k| k.used && !k.in_first_tier) {
            by_batch.entry(k.batch).or_default().push(*k.key());
        }
        let mut written = 0;
        for (id, actions) in &by_batch {
            let Some(envelope) = self.envelope(id).await else {
                continue;
            };
            let results = self.results_of(actions);
            self.save_first_tier(l1, *id, envelope, &results).await?;
            written += results.len();
            for a in actions {
                if let Some(mut k) = self.known.get_mut(a) {
                    k.in_first_tier = true;
                }
            }
        }
        if written > 0 {
            tracing::info!(
                results = written,
                batches = by_batch.len(),
                "first tier: wrote through registry results"
            );
        }
        Ok(())
    }

    /// Signs new results, saves them to the first tier, and sends the
    /// registry what policy says: queued in the first tier's outbox if there
    /// is one, else written now. Returns the number of new results signed.
    pub async fn publish(&self) -> Result<usize, StoreError> {
        // Planning compares against the registry indexes.
        self.load_registry().await;
        let signed = self.sign_pending().await?;
        let plan = self.plan();
        match &self.l1 {
            Some(l1) => {
                self.write_through(l1).await?;
                if !plan.is_empty() {
                    l1.enqueue(&plan).await?;
                    tracing::info!(
                        results = plan.results(),
                        "registry promotion queued in the first-tier outbox"
                    );
                }
                let queued: HashSet<BatchId> = l1
                    .queued::<Plan>()
                    .await?
                    .iter()
                    .flat_map(|q| q.plan.batches().collect::<Vec<_>>())
                    .collect();
                l1.prune(L1_MAX_BATCHES, &queued, &self.jwks, &self.keyring)
                    .await?;
            }
            None => self.run(plan).await?,
        }
        Ok(signed)
    }

    /// Pushes every plan queued in the first tier's outbox (merged, so
    /// repeats cost nothing), removing each once done. Call
    /// `load_first_tier` first: only verified results are sent.
    pub async fn drain_outbox(&self) -> Result<usize, StoreError> {
        let Some(l1) = &self.l1 else { return Ok(0) };
        let mut queued = l1.queued::<Plan>().await?;
        let plan = Plan::merge(queued.iter_mut().map(|q| std::mem::take(&mut q.plan)));
        let n = plan.results();
        self.run(plan).await?;
        for q in queued {
            l1.done(q).await?;
        }
        Ok(n)
    }

    async fn run(&self, plan: Plan) -> Result<(), StoreError> {
        let Some(writer) = &self.writer else {
            return Ok(());
        };
        let Plan { push, index } = Plan::merge([plan]);
        for (jobs, pushing) in [(push, true), (index, false)] {
            for (id, actions) in jobs {
                let Some(envelope) = self.envelope(&id).await else {
                    tracing::warn!(batch = %id, "envelope unavailable: skipped");
                    continue;
                };
                let results = self.results_of(&actions);
                if results.is_empty() {
                    continue;
                }
                if pushing {
                    self.push_batch(writer, id, envelope, &results).await?;
                } else {
                    self.index_batch(writer, id, envelope, &results).await?;
                }
                tracing::info!(results = results.len(), batch = %id, pushed = pushing, "registry updated");
            }
        }
        Ok(())
    }

    /// A known result, marked as used.
    fn serve_known(&self, action: &ActionId) -> Option<re::ActionResult> {
        let mut k = self.known.get_mut(action)?;
        k.used = true;
        Some(k.result.result.clone())
    }
}

#[async_trait::async_trait]
impl Store for GhcrStore {
    /// Local, first tier, or referenced by a verified result (fetched on
    /// demand); anything else buck2 simply uploads.
    async fn has_blob(&self, hash: &Sha256) -> bool {
        if self.local.has_blob(hash).await || self.referenced.contains(hash) {
            return true;
        }
        match &self.l1 {
            Some(l1) => l1.blobs().contains(hash).await,
            None => false,
        }
    }

    async fn get_blob(&self, hash: &Sha256) -> Option<Blob> {
        self.any_blob(hash).await
    }

    async fn put_blob(&self, blob: &Blob) -> Result<(), StoreError> {
        self.local.put_blob(blob).await
    }

    async fn get_action_result(&self, action: &ActionId) -> Option<re::ActionResult> {
        // Results produced in this run are trusted; they get signed on publish.
        if let Some(r) = self.local.get_action_result(action).await {
            return Some(r);
        }
        if let Some(r) = self.serve_known(action) {
            return Some(r);
        }
        // A first-tier miss: wait for the registry indexes (usually already
        // read in the background), then fall back to per-action lookup.
        self.load_registry().await;
        if let Some(r) = self.serve_known(action) {
            return Some(r);
        }
        for reg in &self.readers {
            if let Some(r) = self.lookup(reg, *action).await {
                return Some(r);
            }
        }
        None
    }

    async fn put_action_result(
        &self,
        action: ActionDigest,
        result: &re::ActionResult,
    ) -> Result<(), StoreError> {
        self.local.put_action_result(action, result).await?;
        self.pending().push(Pending {
            action,
            result: result.clone(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Sha256 {
        Sha256::of(&[n])
    }

    #[test]
    fn merge_unions_and_drops_indexing_covered_by_a_push() {
        let (b1, b2) = (BatchId(id(1)), BatchId(id(2)));
        let (a, b, c, x) = (
            ActionId(id(10)),
            ActionId(id(11)),
            ActionId(id(12)),
            ActionId(id(13)),
        );
        let p = |push: &[(BatchId, &[ActionId])], index: &[(BatchId, &[ActionId])]| Plan {
            push: push
                .iter()
                .map(|(k, v)| (*k, v.iter().copied().collect()))
                .collect(),
            index: index
                .iter()
                .map(|(k, v)| (*k, v.iter().copied().collect()))
                .collect(),
        };
        let merged = Plan::merge([
            p(&[(b1, &[a, b])], &[(b1, &[a]), (b2, &[x])]),
            p(&[(b1, &[b, c])], &[]),
        ]);
        assert_eq!(merged, p(&[(b1, &[a, b, c])], &[(b2, &[x])]));
        // Round-trips through the outbox format.
        assert_eq!(
            serde_json::from_slice::<Plan>(&serde_json::to_vec(&merged).unwrap()).unwrap(),
            merged
        );
    }
}
