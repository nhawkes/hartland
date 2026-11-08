//! A Remote Execution API server: CAS, action cache, ByteStream, capabilities
//! and (with an executor) execution. Everything is async: storage backends do
//! network and disk I/O, and nothing may stall the gRPC server (buck2's
//! keepalives time out if it does).
//!
//! Requests are parsed at the boundary: digests become `Digest`s and uploads
//! become `Blob`s (checked against their digest) before any store sees them.

use crate::cas::{Blob, Cas};
use crate::digest::{ActionDigest, ActionId, Digest, ParseError, Sha256};
use crate::reapi::bs::byte_stream_server::{ByteStream, ByteStreamServer};
use crate::reapi::bs::{
    QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest, ReadResponse, WriteRequest,
    WriteResponse,
};
use crate::reapi::google::longrunning::{Operation, operation};
use crate::reapi::google::rpc;
use crate::reapi::re;
use crate::reapi::re::action_cache_server::{ActionCache, ActionCacheServer};
use crate::reapi::re::capabilities_server::{Capabilities, CapabilitiesServer};
use crate::reapi::re::content_addressable_storage_server::{
    ContentAddressableStorage, ContentAddressableStorageServer,
};
use bytes::{Bytes, BytesMut};
use futures::stream::BoxStream;
use futures::{StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tonic::{Request, Response, Status, Streaming};

const MAX_BATCH_BYTES: i64 = 4 << 20;
const MAX_MESSAGE_BYTES: usize = 64 << 20;
const READ_CHUNK: usize = 1 << 20;
/// Concurrent store operations per request (e.g. FindMissingBlobs batches).
const STORE_CONCURRENCY: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Registry(#[from] crate::oci::OciError),
    #[error(transparent)]
    Signing(#[from] crate::github::TokenError),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    #[error("blob {0:?} unavailable")]
    Unavailable(Sha256),
    #[error("results pending but nowhere to publish them")]
    Nowhere,
    #[error("refused: {0}")]
    Refused(String),
}

#[async_trait::async_trait]
pub trait Store: Send + Sync + 'static {
    async fn has_blob(&self, hash: &Sha256) -> bool;
    async fn get_blob(&self, hash: &Sha256) -> Option<Blob>;
    async fn put_blob(&self, blob: &Blob) -> Result<(), StoreError>;
    async fn get_action_result(&self, action: &ActionId) -> Option<re::ActionResult>;
    async fn put_action_result(
        &self,
        action: ActionDigest,
        result: &re::ActionResult,
    ) -> Result<(), StoreError>;

    /// A result a worker executed for this build: usable now, but signed by
    /// the worker (in its batch), never by this store's owner.
    async fn put_worker_result(
        &self,
        action: ActionDigest,
        result: &re::ActionResult,
    ) -> Result<(), StoreError> {
        self.put_action_result(action, result).await
    }

    /// A worker's signed batch. Stores that publish nothing ignore it.
    async fn accept_worker_batch(
        &self,
        _envelope: bytes::Bytes,
        _worker: &crate::cert::PublicKey,
    ) -> Result<usize, StoreError> {
        Ok(0)
    }
}

/// Blobs and action results on local disk.
pub struct DiskStore {
    cas: Cas,
    ac: PathBuf,
    tmp: PathBuf,
}

impl DiskStore {
    pub async fn open(root: PathBuf) -> std::io::Result<DiskStore> {
        let (ac, tmp) = (root.join("ac"), root.join("tmp"));
        tokio::fs::create_dir_all(&ac).await?;
        Ok(DiskStore {
            cas: Cas::open(root.join("cas"), tmp.clone()).await?,
            ac,
            tmp,
        })
    }
}

#[async_trait::async_trait]
impl Store for DiskStore {
    async fn has_blob(&self, hash: &Sha256) -> bool {
        self.cas.contains(hash).await
    }
    async fn get_blob(&self, hash: &Sha256) -> Option<Blob> {
        self.cas.get(hash).await
    }
    async fn put_blob(&self, blob: &Blob) -> Result<(), StoreError> {
        Ok(self.cas.put(blob).await?)
    }
    async fn get_action_result(&self, action: &ActionId) -> Option<re::ActionResult> {
        let bytes = tokio::fs::read(self.ac.join(action.to_string()))
            .await
            .ok()?;
        re::ActionResult::decode(bytes.as_slice()).ok()
    }
    async fn put_action_result(
        &self,
        action: ActionDigest,
        result: &re::ActionResult,
    ) -> Result<(), StoreError> {
        Ok(crate::cas::write_atomic(
            &self.tmp,
            &self.ac.join(action.id.to_string()),
            result.encode_to_vec().into(),
        )
        .await?)
    }
}

/// Every blob an action result names directly (outputs, output trees,
/// stdout and stderr).
pub fn direct_blobs(r: &re::ActionResult) -> Result<BTreeSet<Sha256>, ParseError> {
    r.output_files
        .iter()
        .filter_map(|f| f.digest.as_ref())
        .chain(
            r.output_directories
                .iter()
                .filter_map(|d| d.tree_digest.as_ref()),
        )
        .chain(r.stdout_digest.iter())
        .chain(r.stderr_digest.iter())
        .map(|d| Digest::try_from(d).map(|d| d.hash))
        .collect()
}

/// Every blob an action result names directly is present.
pub async fn outputs_present(store: &dyn Store, r: &re::ActionResult) -> bool {
    let Ok(blobs) = direct_blobs(r) else {
        return false;
    };
    futures::stream::iter(blobs)
        .map(|h| async move { store.has_blob(&h).await })
        .buffer_unordered(STORE_CONCURRENCY)
        .all(|present| async move { present })
        .await
}

impl From<ParseError> for Status {
    fn from(e: ParseError) -> Status {
        Status::invalid_argument(e.to_string())
    }
}

impl From<StoreError> for Status {
    fn from(e: StoreError) -> Status {
        Status::internal(e.to_string())
    }
}

fn rpc_status(code: tonic::Code, message: String) -> Option<rpc::Status> {
    Some(rpc::Status {
        code: code as i32,
        message,
        details: vec![],
    })
}

fn ok_status() -> Option<rpc::Status> {
    Some(rpc::Status::default())
}

#[derive(Clone)]
pub struct Proxy {
    store: Arc<dyn Store>,
    /// With an executor, the proxy runs actions in the sandbox and refuses
    /// client UpdateActionResult: only results of actions it ran itself may
    /// be vouched for.
    executor: Option<Arc<crate::execute::Executor>>,
    /// Bounds concurrent local executions (buck2 submits hundreds at once).
    exec_slots: Arc<tokio::sync::Semaphore>,
    /// Workers to hand actions to, when scaled out.
    pool: Option<Arc<crate::worker::Pool>>,
    /// Actions waiting for a local or worker slot (the demand for workers).
    queued: Arc<std::sync::atomic::AtomicUsize>,
}

impl Proxy {
    pub fn new(store: Arc<dyn Store>) -> Proxy {
        let cpus = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
        Proxy {
            store,
            executor: None,
            exec_slots: Arc::new(tokio::sync::Semaphore::new(cpus)),
            pool: None,
            queued: Arc::default(),
        }
    }

    /// Hands actions to workers as well as running them locally.
    pub fn with_pool(self, pool: Arc<crate::worker::Pool>) -> Proxy {
        Proxy {
            pool: Some(pool),
            ..self
        }
    }

    /// Actions waiting for an execution slot right now.
    pub fn queued(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        self.queued.clone()
    }

    /// Runs an action on whichever is free first: a local slot or a worker.
    /// A worker that fails is not retried there; the action runs locally.
    async fn run(
        &self,
        executor: &crate::execute::Executor,
        action: ActionDigest,
    ) -> Result<re::ActionResult, String> {
        use std::sync::atomic::Ordering;
        self.queued.fetch_add(1, Ordering::AcqRel);
        let place = loop {
            if let Ok(local) = self.exec_slots.clone().try_acquire_owned() {
                break Ok(local);
            }
            if let Some(slot) = self.pool.as_ref().and_then(crate::worker::Pool::reserve) {
                break Err(slot);
            }
            match &self.pool {
                Some(pool) => {
                    tokio::select! {
                        p = self.exec_slots.clone().acquire_owned() => break Ok(p.map_err(|e| e.to_string())?),
                        () = pool.changed() => {}
                    }
                }
                None => {
                    break Ok(self
                        .exec_slots
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|e| e.to_string())?);
                }
            }
        };
        self.queued.fetch_sub(1, Ordering::AcqRel);
        match place {
            Ok(_local) => executor.execute(action).await.map_err(|e| e.to_string()),
            Err(slot) => {
                let pool = self
                    .pool
                    .as_ref()
                    .expect("a worker slot comes from the pool");
                match pool.execute(&slot, action).await {
                    Ok((r, cacheable)) if crate::proxy::outputs_present(&*self.store, &r).await => {
                        if cacheable {
                            self.store
                                .put_worker_result(action, &r)
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        Ok(r)
                    }
                    outcome => {
                        tracing::warn!(action = %action.id, ?outcome, "worker execution failed; running locally");
                        drop(slot);
                        let _local = self
                            .exec_slots
                            .clone()
                            .acquire_owned()
                            .await
                            .map_err(|e| e.to_string())?;
                        executor.execute(action).await.map_err(|e| e.to_string())
                    }
                }
            }
        }
    }

    pub fn with_executor(self, executor: crate::execute::Executor) -> Proxy {
        Proxy {
            executor: Some(Arc::new(executor)),
            ..self
        }
    }

    pub async fn serve(self, addr: std::net::SocketAddr) -> Result<(), tonic::transport::Error> {
        tonic::transport::Server::builder()
            .add_service(CapabilitiesServer::new(self.clone()))
            .add_service(
                ContentAddressableStorageServer::new(self.clone())
                    .max_decoding_message_size(MAX_MESSAGE_BYTES),
            )
            .add_service(ActionCacheServer::new(self.clone()))
            .add_service(re::execution_server::ExecutionServer::new(self.clone()))
            .add_service(ByteStreamServer::new(self).max_decoding_message_size(MAX_MESSAGE_BYTES))
            .serve(addr)
            .await
    }

    /// A result whose outputs are all present.
    async fn served_result(&self, action: &ActionId) -> Option<re::ActionResult> {
        let r = self.store.get_action_result(action).await?;
        outputs_present(&*self.store, &r).await.then_some(r)
    }
}

#[tonic::async_trait]
impl Capabilities for Proxy {
    async fn get_capabilities(
        &self,
        _: Request<re::GetCapabilitiesRequest>,
    ) -> Result<Response<re::ServerCapabilities>, Status> {
        use re::digest_function::Value as DigestFn;
        let semver = |major, minor| crate::reapi::build::bazel::semver::SemVer {
            major,
            minor,
            patch: 0,
            prerelease: String::new(),
        };
        Ok(Response::new(re::ServerCapabilities {
            cache_capabilities: Some(re::CacheCapabilities {
                digest_functions: vec![DigestFn::Sha256 as i32],
                action_cache_update_capabilities: Some(re::ActionCacheUpdateCapabilities {
                    update_enabled: true,
                }),
                max_batch_total_size_bytes: MAX_BATCH_BYTES,
                symlink_absolute_path_strategy:
                    re::symlink_absolute_path_strategy::Value::Disallowed as i32,
                ..Default::default()
            }),
            execution_capabilities: self.executor.as_ref().map(|_| re::ExecutionCapabilities {
                digest_function: DigestFn::Sha256 as i32,
                exec_enabled: true,
                digest_functions: vec![DigestFn::Sha256 as i32],
                ..Default::default()
            }),
            low_api_version: Some(semver(2, 0)),
            high_api_version: Some(semver(2, 12)),
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl ContentAddressableStorage for Proxy {
    async fn find_missing_blobs(
        &self,
        req: Request<re::FindMissingBlobsRequest>,
    ) -> Result<Response<re::FindMissingBlobsResponse>, Status> {
        let digests: Vec<Digest> = req
            .into_inner()
            .blob_digests
            .iter()
            .map(Digest::try_from)
            .collect::<Result<_, _>>()?;
        let store = &*self.store;
        let missing = futures::stream::iter(digests)
            .map(|d| async move { (!store.has_blob(&d.hash).await).then_some(d.into()) })
            .buffer_unordered(STORE_CONCURRENCY)
            .filter_map(futures::future::ready)
            .collect()
            .await;
        Ok(Response::new(re::FindMissingBlobsResponse {
            missing_blob_digests: missing,
        }))
    }

    async fn batch_update_blobs(
        &self,
        req: Request<re::BatchUpdateBlobsRequest>,
    ) -> Result<Response<re::BatchUpdateBlobsResponse>, Status> {
        let store = &*self.store;
        let responses = futures::stream::iter(req.into_inner().requests)
            .map(|r| async move {
                let checked = Digest::try_from(r.digest.as_ref())
                    .map_err(|e| e.to_string())
                    .and_then(|d| Blob::check(d, r.data).map_err(|e| e.to_string()));
                let status = match checked {
                    Err(e) => rpc_status(tonic::Code::InvalidArgument, e),
                    Ok(blob) => match store.put_blob(&blob).await {
                        Ok(()) => ok_status(),
                        Err(e) => rpc_status(tonic::Code::Internal, e.to_string()),
                    },
                };
                re::batch_update_blobs_response::Response {
                    digest: r.digest,
                    status,
                }
            })
            .buffer_unordered(STORE_CONCURRENCY)
            .collect()
            .await;
        Ok(Response::new(re::BatchUpdateBlobsResponse { responses }))
    }

    async fn batch_read_blobs(
        &self,
        req: Request<re::BatchReadBlobsRequest>,
    ) -> Result<Response<re::BatchReadBlobsResponse>, Status> {
        let digests: Vec<Digest> = req
            .into_inner()
            .digests
            .iter()
            .map(Digest::try_from)
            .collect::<Result<_, _>>()?;
        let store = &*self.store;
        let responses = futures::stream::iter(digests)
            .map(|d| async move {
                let (data, status) = match store.get_blob(&d.hash).await {
                    Some(b) => (b.into_data(), ok_status()),
                    None => (
                        Bytes::new(),
                        rpc_status(tonic::Code::NotFound, format!("blob {} not found", d.hash)),
                    ),
                };
                re::batch_read_blobs_response::Response {
                    digest: Some(d.into()),
                    data,
                    compressor: 0,
                    status,
                }
            })
            .buffer_unordered(STORE_CONCURRENCY)
            .collect()
            .await;
        Ok(Response::new(re::BatchReadBlobsResponse { responses }))
    }

    type GetTreeStream = BoxStream<'static, Result<re::GetTreeResponse, Status>>;

    async fn get_tree(
        &self,
        _: Request<re::GetTreeRequest>,
    ) -> Result<Response<Self::GetTreeStream>, Status> {
        Err(Status::unimplemented("GetTree is not supported"))
    }

    async fn split_blob(
        &self,
        _: Request<re::SplitBlobRequest>,
    ) -> Result<Response<re::SplitBlobResponse>, Status> {
        Err(Status::unimplemented("SplitBlob is not supported"))
    }

    async fn splice_blob(
        &self,
        _: Request<re::SpliceBlobRequest>,
    ) -> Result<Response<re::SpliceBlobResponse>, Status> {
        Err(Status::unimplemented("SpliceBlob is not supported"))
    }
}

#[tonic::async_trait]
impl ActionCache for Proxy {
    async fn get_action_result(
        &self,
        req: Request<re::GetActionResultRequest>,
    ) -> Result<Response<re::ActionResult>, Status> {
        let action = ActionDigest::from(Digest::try_from(req.into_inner().action_digest.as_ref())?);
        match self.served_result(&action.id).await {
            Some(r) => Ok(Response::new(r)),
            None => Err(Status::not_found(format!(
                "no result for action {}",
                action.id
            ))),
        }
    }

    async fn update_action_result(
        &self,
        req: Request<re::UpdateActionResultRequest>,
    ) -> Result<Response<re::ActionResult>, Status> {
        if self.executor.is_some() {
            return Err(Status::permission_denied(
                "this proxy only stores results of actions it executed",
            ));
        }
        let req = req.into_inner();
        let action = ActionDigest::from(Digest::try_from(req.action_digest.as_ref())?);
        let result = req
            .action_result
            .ok_or_else(|| Status::invalid_argument("missing action_result"))?;
        if !outputs_present(&*self.store, &result).await {
            return Err(Status::failed_precondition(
                "action result references blobs not in the CAS",
            ));
        }
        self.store.put_action_result(action, &result).await?;
        Ok(Response::new(result))
    }
}

/// `{instance}/blobs/{hash}/{size}` or `{instance}/uploads/{uuid}/blobs/{hash}/{size}`.
struct ResourceName(Digest);

impl FromStr for ResourceName {
    type Err = Status;
    fn from_str(name: &str) -> Result<ResourceName, Status> {
        let bad = || Status::invalid_argument(format!("bad resource name {name}"));
        let mut rest = name.rsplit('/');
        let (Some(size), Some(hash), Some("blobs")) = (rest.next(), rest.next(), rest.next())
        else {
            return Err(bad());
        };
        Ok(ResourceName(Digest {
            hash: hash.parse()?,
            size: size.parse().map_err(|_| bad())?,
        }))
    }
}

#[tonic::async_trait]
impl ByteStream for Proxy {
    type ReadStream = BoxStream<'static, Result<ReadResponse, Status>>;

    async fn read(&self, req: Request<ReadRequest>) -> Result<Response<Self::ReadStream>, Status> {
        let req = req.into_inner();
        let ResourceName(digest) = req.resource_name.parse()?;
        let data = self
            .store
            .get_blob(&digest.hash)
            .await
            .ok_or_else(|| Status::not_found(format!("blob {} not found", digest.hash)))?
            .into_data();
        let start = usize::try_from(req.read_offset)
            .ok()
            .filter(|s| *s <= data.len())
            .ok_or_else(|| Status::out_of_range("bad offset"))?;
        let end = match usize::try_from(req.read_limit) {
            Ok(limit) if limit > 0 => (start + limit).min(data.len()),
            _ => data.len(),
        };
        let window = data.slice(start..end);
        let chunks: Vec<Result<ReadResponse, Status>> = if window.is_empty() {
            vec![Ok(ReadResponse { data: Bytes::new() })]
        } else {
            (0..window.len())
                .step_by(READ_CHUNK)
                .map(|i| {
                    Ok(ReadResponse {
                        data: window.slice(i..(i + READ_CHUNK).min(window.len())),
                    })
                })
                .collect()
        };
        Ok(Response::new(futures::stream::iter(chunks).boxed()))
    }

    async fn write(
        &self,
        req: Request<Streaming<WriteRequest>>,
    ) -> Result<Response<WriteResponse>, Status> {
        let mut stream = req.into_inner();
        let mut target: Option<Digest> = None;
        let mut data = BytesMut::new();
        while let Some(msg) = stream.try_next().await? {
            if target.is_none() {
                target = Some(msg.resource_name.parse::<ResourceName>()?.0);
            }
            if usize::try_from(msg.write_offset).ok() != Some(data.len()) {
                return Err(Status::invalid_argument("non-sequential write"));
            }
            data.extend_from_slice(&msg.data);
            if msg.finish_write {
                break;
            }
        }
        let digest = target.ok_or_else(|| Status::invalid_argument("empty write"))?;
        let blob = Blob::check(digest, data.freeze())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        self.store.put_blob(&blob).await?;
        Ok(Response::new(WriteResponse {
            committed_size: digest.size as i64,
        }))
    }

    async fn query_write_status(
        &self,
        req: Request<QueryWriteStatusRequest>,
    ) -> Result<Response<QueryWriteStatusResponse>, Status> {
        let ResourceName(digest) = req.into_inner().resource_name.parse()?;
        let complete = self.store.has_blob(&digest.hash).await;
        Ok(Response::new(QueryWriteStatusResponse {
            committed_size: if complete { digest.size as i64 } else { 0 },
            complete,
        }))
    }
}

fn any<M: prost::Name>(m: &M) -> prost_types::Any {
    prost_types::Any {
        type_url: M::type_url(),
        value: m.encode_to_vec(),
    }
}

#[tonic::async_trait]
impl re::execution_server::Execution for Proxy {
    type ExecuteStream = BoxStream<'static, Result<Operation, Status>>;
    type WaitExecutionStream = Self::ExecuteStream;

    async fn execute(
        &self,
        req: Request<re::ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let executor = self
            .executor
            .clone()
            .ok_or_else(|| Status::unimplemented("remote execution is not enabled"))?;
        let req = req.into_inner();
        let action = ActionDigest::from(Digest::try_from(req.action_digest.as_ref())?);

        let cached = if req.skip_cache_lookup {
            None
        } else {
            self.served_result(&action.id).await
        };
        let response = if let Some(r) = cached {
            re::ExecuteResponse {
                result: Some(r),
                cached_result: true,
                status: ok_status(),
                ..Default::default()
            }
        } else {
            match self.run(&executor, action).await {
                Ok(r) => re::ExecuteResponse {
                    result: Some(r),
                    status: ok_status(),
                    ..Default::default()
                },
                Err(e) => re::ExecuteResponse {
                    status: rpc_status(tonic::Code::Internal, e),
                    ..Default::default()
                },
            }
        };
        let metadata = re::ExecuteOperationMetadata {
            stage: re::execution_stage::Value::Completed as i32,
            action_digest: Some(Digest::from(action).into()),
            ..Default::default()
        };
        let op = Operation {
            name: format!("executions/{}", action.id),
            metadata: Some(any(&metadata)),
            done: true,
            result: Some(operation::Result::Response(any(&response))),
        };
        Ok(Response::new(futures::stream::iter([Ok(op)]).boxed()))
    }

    async fn wait_execution(
        &self,
        _: Request<re::WaitExecutionRequest>,
    ) -> Result<Response<Self::WaitExecutionStream>, Status> {
        Err(Status::unimplemented("executions complete within Execute"))
    }
}
