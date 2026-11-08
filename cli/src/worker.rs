//! Scale-out: a coordinator (the job running buck2 and the signing proxy)
//! hands actions to workers (separate runs of the same trusted builder) over
//! iroh, and every result stays signed by the job that executed it.
//!
//! Trust is a chain of keys (see `cert`). Each job's iroh key is its
//! certified Ed25519 key. A worker joins by sending its certificate and a
//! signature, by that key, over membership of the coordinator's key; the
//! coordinator checks the certificate (trusted builder, hosted runner, its
//! own repository, a dispatched run), the signature, and that the key is
//! the one iroh authenticated. The worker checks the coordinator's
//! certificate in turn, including the run it was dispatched by.
//!
//! Protocol: one bidirectional stream per request, each message a JSON
//! header (length-prefixed) followed by a raw body. The coordinator sends
//! `Execute` and `Flush`; the worker fetches inputs (`GetBlob`), uploads
//! outputs (`PutBlob`) and, when idle or asked, sends its signed batch.
//!
//! No idle compute: a worker exits after `idle` without work, signing what it
//! ran first.

use crate::attest::{Batch, Envelope, Pair};
use crate::cas::Blob;
use crate::cert::{Certificate, Identity, PublicKey, SignatureBytes};
use crate::digest::{ActionDigest, Digest, Sha256};
use crate::jwt::Jwks;
use crate::keyring::{Keyring, Repository, Signer};
use crate::proxy::{DiskStore, Store, StoreError};
use crate::reapi::re;
use bytes::Bytes;
use crossbeam_queue::SegQueue;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use prost::Message as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub const ALPN: &[u8] = b"hartland/worker/0";
const MAX_HEADER: usize = 64 << 10;
const MAX_BODY: usize = 1 << 30;

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("connection: {0}")]
    Connection(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("refused: {0}")]
    Refused(String),
    #[error(transparent)]
    Cert(#[from] crate::cert::CertError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Token(#[from] crate::github::TokenError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn conn_err(e: impl std::fmt::Display) -> PeerError {
    PeerError::Connection(e.to_string())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Request {
    /// Worker to coordinator, first: who I am, and that I serve you.
    Join {
        certificate: Certificate,
        membership: SignatureBytes,
        slots: usize,
    },
    /// Coordinator to worker.
    Execute { action: Digest },
    /// Coordinator to worker: sign what you have run so far.
    Flush,
    /// Worker to coordinator.
    GetBlob { hash: Sha256 },
    /// Worker to coordinator; body is the blob.
    PutBlob { digest: Digest },
    /// Worker to coordinator; body is a signed envelope.
    Signed,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Response {
    Welcome {
        certificate: Certificate,
    },
    /// Body: the serialised ActionResult. `cacheable` when the worker kept
    /// it for its signed batch (succeeded, and the action allows caching).
    Executed {
        cacheable: bool,
    },
    Failed {
        error: String,
    },
    /// Body: a signed envelope, or empty if there is nothing to sign.
    Batch,
    /// Body: the blob.
    Blob,
    Missing,
    Ok,
    Refused {
        reason: String,
    },
}

async fn write_msg<T: serde::Serialize>(
    send: &mut SendStream,
    header: &T,
    body: &[u8],
) -> Result<(), PeerError> {
    let h = serde_json::to_vec(header)?;
    send.write_all(&u32::try_from(h.len()).map_err(conn_err)?.to_be_bytes())
        .await
        .map_err(conn_err)?;
    send.write_all(&h).await.map_err(conn_err)?;
    send.write_all(body).await.map_err(conn_err)?;
    send.finish().map_err(conn_err)?;
    Ok(())
}

async fn read_msg<T: serde::de::DeserializeOwned>(
    recv: &mut RecvStream,
) -> Result<(T, Bytes), PeerError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(conn_err)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_HEADER {
        return Err(PeerError::Protocol(format!("header of {len} bytes")));
    }
    let mut h = vec![0u8; len];
    recv.read_exact(&mut h).await.map_err(conn_err)?;
    let body = recv.read_to_end(MAX_BODY).await.map_err(conn_err)?;
    Ok((serde_json::from_slice(&h)?, Bytes::from(body)))
}

async fn call(
    conn: &Connection,
    req: &Request,
    body: &[u8],
) -> Result<(Response, Bytes), PeerError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(conn_err)?;
    write_msg(&mut send, req, body).await?;
    read_msg(&mut recv).await
}

/// What a worker signs to join a build.
fn membership(coordinator: &PublicKey) -> Vec<u8> {
    format!("hartland-member:{coordinator}").into_bytes()
}

/// A coordinator's address from its key alone: iroh finds the rest.
pub fn endpoint_addr(key: &PublicKey) -> Result<EndpointAddr, PeerError> {
    let id =
        EndpointId::from_bytes(key.as_bytes()).map_err(|e| PeerError::Protocol(e.to_string()))?;
    Ok(EndpointAddr::from(id))
}

fn key_of(id: EndpointId) -> PublicKey {
    PublicKey::from_bytes(*id.as_bytes())
}

/// Which network to use: n0's relays and DNS (hosted runners), or direct
/// local addresses only (tests).
#[derive(Clone, Copy, Debug)]
pub enum Network {
    N0,
    Local,
}

pub async fn bind(identity: &Identity, network: Network) -> Result<Endpoint, PeerError> {
    let secret = iroh::SecretKey::from_bytes(identity.seed());
    let ep = match network {
        Network::N0 => Endpoint::builder(iroh::endpoint::presets::N0),
        Network::Local => Endpoint::builder(iroh::endpoint::presets::Minimal),
    }
    .secret_key(secret)
    .alpns(vec![ALPN.to_vec()])
    .bind()
    .await
    .map_err(conn_err)?;
    if matches!(network, Network::N0) {
        ep.online().await;
    }
    Ok(ep)
}

/// What both sides require of each other.
pub struct PeerTrust {
    pub keyring: Keyring,
    pub jwks: Jwks,
    /// Peers must run for this repository.
    pub repository: Repository,
}

impl PeerTrust {
    fn check(&self, cert: &Certificate, key: &PublicKey) -> Result<Signer, PeerError> {
        if cert.key != *key {
            return Err(PeerError::Refused("certificate is for another key".into()));
        }
        let signer = cert.verify(&self.jwks, &self.keyring)?;
        if signer.repository != self.repository {
            return Err(PeerError::Refused(format!(
                "peer runs for {}, not {}",
                signer.repository, self.repository
            )));
        }
        Ok(signer)
    }
}

// ---- coordinator ----------------------------------------------------------

struct Member {
    conn: Connection,
    slots: usize,
    busy: AtomicUsize,
}

/// The coordinator's view of its workers.
pub struct Pool {
    identity: Identity,
    trust: PeerTrust,
    store: Arc<dyn Store>,
    members: papaya::HashMap<PublicKey, Arc<Member>>,
    /// Workers admitted so far (for the dispatcher's accounting).
    joined: AtomicUsize,
    /// Signalled when a worker joins or a worker slot frees.
    freed: Notify,
}

/// A reserved worker slot; released on drop.
pub struct Slot {
    member: Arc<Member>,
    pool: Arc<Pool>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.member.busy.fetch_sub(1, Ordering::AcqRel);
        self.pool.freed.notify_waiters();
    }
}

impl Pool {
    pub fn new(identity: Identity, trust: PeerTrust, store: Arc<dyn Store>) -> Arc<Pool> {
        Arc::new(Pool {
            identity,
            trust,
            store,
            members: papaya::HashMap::new(),
            joined: AtomicUsize::new(0),
            freed: Notify::new(),
        })
    }

    pub fn key(&self) -> PublicKey {
        self.identity.public()
    }

    /// Worker slots: (busy, total).
    pub fn load(&self) -> (usize, usize) {
        self.members.pin().values().fold((0, 0), |(b, t), m| {
            (b + m.busy.load(Ordering::Acquire), t + m.slots)
        })
    }

    /// Workers connected now.
    pub fn members(&self) -> usize {
        self.members.len()
    }

    /// Workers admitted since the start.
    pub fn joined(&self) -> usize {
        self.joined.load(Ordering::Acquire)
    }

    /// Waits until a worker joins or a slot frees.
    pub async fn changed(&self) {
        self.freed.notified().await;
    }

    /// A free worker slot, if any.
    pub fn reserve(self: &Arc<Pool>) -> Option<Slot> {
        for m in self.members.pin().values() {
            let mut busy = m.busy.load(Ordering::Acquire);
            while busy < m.slots {
                match m
                    .busy
                    .compare_exchange(busy, busy + 1, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => {
                        return Some(Slot {
                            member: m.clone(),
                            pool: self.clone(),
                        });
                    }
                    Err(now) => busy = now,
                }
            }
        }
        None
    }

    /// Runs `action` on the reserved worker. The result is the worker's own;
    /// it is signed by the worker, in its batch.
    /// Returns the result and whether it may be cached.
    pub async fn execute(
        &self,
        slot: &Slot,
        action: ActionDigest,
    ) -> Result<(re::ActionResult, bool), PeerError> {
        match call(
            &slot.member.conn,
            &Request::Execute {
                action: action.into(),
            },
            &[],
        )
        .await?
        {
            (Response::Executed { cacheable }, body) => {
                let r = re::ActionResult::decode(body)
                    .map_err(|e| PeerError::Protocol(e.to_string()))?;
                Ok((r, cacheable))
            }
            (Response::Failed { error }, _) => Err(PeerError::Refused(error)),
            (other, _) => Err(PeerError::Protocol(format!("unexpected {other:?}"))),
        }
    }

    /// Asks every worker to sign what it has run; hands the batches to the
    /// store. Returns the number of results accepted.
    pub async fn flush(&self) -> usize {
        let members: Vec<(PublicKey, Arc<Member>)> = self
            .members
            .pin()
            .iter()
            .map(|(k, m)| (*k, m.clone()))
            .collect();
        let mut accepted = 0;
        for (key, m) in members {
            match call(&m.conn, &Request::Flush, &[]).await {
                Ok((Response::Batch, body)) if !body.is_empty() => {
                    accepted += self.accept_batch(&key, body).await
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(worker = %key, error = %e, "flush failed"),
            }
        }
        accepted
    }

    async fn accept_batch(&self, worker: &PublicKey, envelope: Bytes) -> usize {
        match self.store.accept_worker_batch(envelope, worker).await {
            Ok(n) => {
                tracing::info!(worker = %worker, results = n, "worker batch accepted");
                n
            }
            Err(e) => {
                tracing::warn!(worker = %worker, error = %e, "worker batch refused");
                0
            }
        }
    }

    /// Accepts workers until the endpoint closes.
    pub async fn serve(self: Arc<Pool>, endpoint: Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            let pool = self.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        return tracing::warn!(error = %e, "incoming worker connection failed");
                    }
                };
                let key = key_of(conn.remote_id());
                match pool.admit(&conn, &key).await {
                    Ok(slots) => {
                        tracing::info!(worker = %key, slots, "worker joined");
                        pool.members.pin().insert(
                            key,
                            Arc::new(Member {
                                conn: conn.clone(),
                                slots,
                                busy: AtomicUsize::new(0),
                            }),
                        );
                        pool.joined.fetch_add(1, Ordering::AcqRel);
                        pool.freed.notify_waiters();
                        pool.serve_member(&conn, &key).await;
                        pool.members.pin().remove(&key);
                        tracing::info!(worker = %key, "worker left");
                    }
                    Err(e) => {
                        tracing::warn!(worker = %key, error = %e, "worker refused");
                        conn.close(1u32.into(), b"refused");
                    }
                }
            });
        }
    }

    /// The join handshake: certificate, dispatched run, membership.
    async fn admit(&self, conn: &Connection, key: &PublicKey) -> Result<usize, PeerError> {
        let (mut send, mut recv) = conn.accept_bi().await.map_err(conn_err)?;
        let (req, _) = read_msg::<Request>(&mut recv).await?;
        let Request::Join {
            certificate,
            membership: sig,
            slots,
        } = req
        else {
            return Err(PeerError::Protocol("expected join".into()));
        };
        let checked = self.trust.check(&certificate, key).and_then(|signer| {
            if signer.event != "workflow_dispatch" {
                return Err(PeerError::Refused(format!(
                    "worker run started by {}, not a dispatch",
                    signer.event
                )));
            }
            key.verify(&membership(&self.key()), &sig)?;
            Ok(())
        });
        match checked {
            Ok(()) => {
                let mine = self
                    .identity
                    .certificate()
                    .cloned()
                    .ok_or(crate::cert::CertError::Uncertified)?;
                write_msg(&mut send, &Response::Welcome { certificate: mine }, &[]).await?;
                Ok(slots.clamp(1, 64))
            }
            Err(e) => {
                write_msg(
                    &mut send,
                    &Response::Refused {
                        reason: e.to_string(),
                    },
                    &[],
                )
                .await?;
                Err(e)
            }
        }
    }

    /// Serves a member's requests: inputs, outputs, signed batches.
    async fn serve_member(&self, conn: &Connection, key: &PublicKey) {
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let result: Result<(), PeerError> = async {
                let (req, body) = read_msg::<Request>(&mut recv).await?;
                match req {
                    Request::GetBlob { hash } => match self.store.get_blob(&hash).await {
                        Some(b) => write_msg(&mut send, &Response::Blob, b.data()).await,
                        None => write_msg(&mut send, &Response::Missing, &[]).await,
                    },
                    Request::PutBlob { digest } => {
                        let blob = Blob::check(digest, body)
                            .map_err(|e| PeerError::Refused(e.to_string()))?;
                        self.store.put_blob(&blob).await?;
                        write_msg(&mut send, &Response::Ok, &[]).await
                    }
                    Request::Signed => {
                        self.accept_batch(key, body).await;
                        write_msg(&mut send, &Response::Ok, &[]).await
                    }
                    other => Err(PeerError::Protocol(format!("unexpected {other:?}"))),
                }
            }
            .await;
            if let Err(e) = result {
                tracing::warn!(worker = %key, error = %e, "worker request failed");
            }
        }
    }
}

// ---- worker ---------------------------------------------------------------

/// Runs one action against a store: the sandbox executor in production.
#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    async fn run(&self, action: ActionDigest) -> Result<re::ActionResult, String>;
}

#[async_trait::async_trait]
impl Runner for crate::execute::Executor {
    async fn run(&self, action: ActionDigest) -> Result<re::ActionResult, String> {
        self.execute(action).await.map_err(|e| e.to_string())
    }
}

/// The worker's store: local disk, filled from the coordinator on demand;
/// outputs are uploaded as they are written; results are kept for signing.
pub struct RemoteStore {
    local: DiskStore,
    conn: Connection,
    ran: SegQueue<(ActionDigest, re::ActionResult)>,
    /// Actions whose results were kept for signing.
    kept: papaya::HashSet<crate::digest::ActionId>,
}

#[async_trait::async_trait]
impl Store for RemoteStore {
    async fn has_blob(&self, hash: &Sha256) -> bool {
        self.local.has_blob(hash).await
    }

    async fn get_blob(&self, hash: &Sha256) -> Option<Blob> {
        if let Some(b) = self.local.get_blob(hash).await {
            return Some(b);
        }
        let (Response::Blob, data) = call(&self.conn, &Request::GetBlob { hash: *hash }, &[])
            .await
            .ok()?
        else {
            return None;
        };
        let blob = Blob::check_hash(*hash, data).ok()?;
        let _ = self.local.put_blob(&blob).await;
        Some(blob)
    }

    async fn put_blob(&self, blob: &Blob) -> Result<(), StoreError> {
        self.local.put_blob(blob).await?;
        match call(
            &self.conn,
            &Request::PutBlob {
                digest: blob.digest(),
            },
            blob.data(),
        )
        .await
        {
            Ok((Response::Ok, _)) => Ok(()),
            Ok((other, _)) => Err(StoreError::Io(std::io::Error::other(format!(
                "upload refused: {other:?}"
            )))),
            Err(e) => Err(StoreError::Io(std::io::Error::other(e.to_string()))),
        }
    }

    async fn get_action_result(&self, _: &crate::digest::ActionId) -> Option<re::ActionResult> {
        None
    }

    async fn put_action_result(
        &self,
        action: ActionDigest,
        result: &re::ActionResult,
    ) -> Result<(), StoreError> {
        self.local.put_action_result(action, result).await?;
        self.kept.pin().insert(action.id);
        self.ran.push((action, result.clone()));
        Ok(())
    }
}

impl RemoteStore {
    /// Signs everything run since the last batch; `None` if nothing was.
    fn sign_batch(&self, identity: &Identity) -> Result<Option<Bytes>, PeerError> {
        let ran: Vec<(ActionDigest, re::ActionResult)> =
            std::iter::from_fn(|| self.ran.pop()).collect();
        if ran.is_empty() {
            return Ok(None);
        }
        let pairs = ran.iter().map(|(a, r)| Pair {
            action: (*a).into(),
            result: Digest::of(&r.encode_to_vec()),
        });
        Ok(Some(
            Envelope::signed_by(Batch::new(pairs).to_bytes(), identity)?
                .to_bytes()
                .into(),
        ))
    }
}

pub struct WorkerConfig {
    /// Certified (see `Identity::certify`).
    pub identity: Identity,
    pub coordinator: EndpointAddr,
    /// The coordinator's run, from the dispatch inputs.
    pub coordinator_run: String,
    pub trust: PeerTrust,
    pub dir: PathBuf,
    pub slots: usize,
    pub idle: Duration,
    pub network: Network,
}

/// Joins the coordinator, runs what it sends, and exits once idle for
/// `idle`, sending its signed batch first.
pub async fn run_worker(
    config: WorkerConfig,
    runner: impl FnOnce(Arc<dyn Store>) -> Arc<dyn Runner>,
) -> Result<usize, PeerError> {
    let ep = bind(&config.identity, config.network).await?;
    let conn = ep
        .connect(config.coordinator.clone(), ALPN)
        .await
        .map_err(conn_err)?;
    let coordinator = key_of(conn.remote_id());

    // Join: our certificate and membership of this coordinator.
    let certificate = config
        .identity
        .certificate()
        .cloned()
        .ok_or(crate::cert::CertError::Uncertified)?;
    let join = Request::Join {
        certificate,
        membership: config.identity.sign(&membership(&coordinator)),
        slots: config.slots,
    };
    match call(&conn, &join, &[]).await? {
        (Response::Welcome { certificate }, _) => {
            let signer = config.trust.check(&certificate, &coordinator)?;
            if signer.run_id != config.coordinator_run {
                return Err(PeerError::Refused(format!(
                    "coordinator is run {}, not {}",
                    signer.run_id, config.coordinator_run
                )));
            }
            tracing::info!(coordinator = %coordinator, run = %signer.run_id, "joined");
        }
        (Response::Refused { reason }, _) => return Err(PeerError::Refused(reason)),
        (other, _) => return Err(PeerError::Protocol(format!("unexpected {other:?}"))),
    }

    let store = Arc::new(RemoteStore {
        local: DiskStore::open(config.dir.clone())
            .await
            .map_err(StoreError::from)?,
        conn: conn.clone(),
        ran: SegQueue::new(),
        kept: papaya::HashSet::new(),
    });
    let runner = runner(store.clone());
    let slots = Arc::new(tokio::sync::Semaphore::new(config.slots.max(1)));
    let started = Instant::now();
    let last_work = Arc::new(AtomicU64::new(0));
    let busy = Arc::new(AtomicUsize::new(0));
    let executed = Arc::new(AtomicUsize::new(0));
    let identity = Arc::new(config.identity);

    loop {
        let idle_for = started
            .elapsed()
            .saturating_sub(Duration::from_millis(last_work.load(Ordering::Acquire)));
        if busy.load(Ordering::Acquire) == 0 && idle_for >= config.idle {
            tracing::info!(idle = ?idle_for, "idle: signing and leaving");
            break;
        }
        let accepted = tokio::select! {
            a = conn.accept_bi() => a,
            () = tokio::time::sleep(Duration::from_secs(1)) => continue,
        };
        let Ok((mut send, mut recv)) = accepted else {
            tracing::info!("coordinator closed the connection");
            break;
        };
        let (store, runner, slots, last_work, busy, executed, identity) = (
            store.clone(),
            runner.clone(),
            slots.clone(),
            last_work.clone(),
            busy.clone(),
            executed.clone(),
            identity.clone(),
        );
        busy.fetch_add(1, Ordering::AcqRel);
        tokio::spawn(async move {
            let outcome: Result<(), PeerError> = async {
                let (req, _) = read_msg::<Request>(&mut recv).await?;
                match req {
                    Request::Execute { action } => {
                        let _slot = slots.acquire_owned().await.map_err(conn_err)?;
                        let action = ActionDigest::from(action);
                        match runner.run(action).await {
                            Ok(r) => {
                                executed.fetch_add(1, Ordering::AcqRel);
                                let cacheable = store.kept.pin().contains(&action.id);
                                write_msg(
                                    &mut send,
                                    &Response::Executed { cacheable },
                                    &r.encode_to_vec(),
                                )
                                .await
                            }
                            Err(error) => {
                                write_msg(&mut send, &Response::Failed { error }, &[]).await
                            }
                        }
                    }
                    Request::Flush => {
                        let batch = store.sign_batch(&identity)?.unwrap_or_default();
                        write_msg(&mut send, &Response::Batch, &batch).await
                    }
                    other => Err(PeerError::Protocol(format!("unexpected {other:?}"))),
                }
            }
            .await;
            if let Err(e) = outcome {
                tracing::warn!(error = %e, "request failed");
            }
            last_work.store(started.elapsed().as_millis() as u64, Ordering::Release);
            busy.fetch_sub(1, Ordering::AcqRel);
        });
    }

    // Sign what we ran before leaving, so the results can be published.
    if let Some(batch) = store.sign_batch(&identity)?
        && let Err(e) = call(&conn, &Request::Signed, &batch).await
    {
        tracing::warn!(error = %e, "could not hand over the final batch");
    }
    conn.close(0u32.into(), b"idle");
    ep.close().await;
    Ok(executed.load(Ordering::Acquire))
}
