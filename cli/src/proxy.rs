//! A Remote Execution API cache server (CAS, action cache, ByteStream,
//! capabilities). buck2 talks to it with local execution and a remote cache.
//!
//! Storage is behind `Store`. `DiskStore` is the first backend; a registry
//! backend that only serves action-cache entries carried by a trusted signed
//! batch comes next. Every CAS write is checked against its claimed digest.

use crate::attest::sha256_hex;
use crate::reapi::bs::byte_stream_server::{ByteStream, ByteStreamServer};
use crate::reapi::bs::{QueryWriteStatusRequest, QueryWriteStatusResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use crate::reapi::google::rpc;
use crate::reapi::re;
use crate::reapi::re::action_cache_server::{ActionCache, ActionCacheServer};
use crate::reapi::re::capabilities_server::{Capabilities, CapabilitiesServer};
use crate::reapi::re::content_addressable_storage_server::{ContentAddressableStorage, ContentAddressableStorageServer};
use prost::Message as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MAX_BATCH_BYTES: i64 = 4 << 20;
const READ_CHUNK: usize = 1 << 20;

pub trait Store: Send + Sync + 'static {
    fn has_blob(&self, hash: &str) -> bool;
    fn get_blob(&self, hash: &str) -> Option<Vec<u8>>;
    /// `data` has already been checked against `hash`.
    fn put_blob(&self, hash: &str, data: &[u8]) -> Result<(), String>;
    fn get_action_result(&self, action: &str) -> Option<re::ActionResult>;
    /// `action_size` is the size of the serialised Action, for signed statements.
    fn put_action_result(&self, action: &str, action_size: i64, result: &re::ActionResult) -> Result<(), String>;
}

pub struct DiskStore {
    root: PathBuf,
}

impl DiskStore {
    pub fn new(root: PathBuf) -> Result<DiskStore, String> {
        for d in ["cas", "ac", "tmp"] {
            std::fs::create_dir_all(root.join(d)).map_err(|e| format!("{}: {e}", root.display()))?;
        }
        Ok(DiskStore { root })
    }

    fn cas_path(&self, hash: &str) -> PathBuf {
        self.root.join("cas").join(&hash[..2]).join(hash)
    }

    fn write_atomic(&self, path: &PathBuf, data: &[u8]) -> Result<(), String> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        // Unique per write: concurrent uploads of the same blob must not share
        // a temporary file (the loser's rename would find it gone).
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = self.root.join("tmp").join(format!("{}-{n}", std::process::id()));
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }
}

impl Store for DiskStore {
    fn has_blob(&self, hash: &str) -> bool {
        hash == EMPTY_SHA256 || self.cas_path(hash).exists()
    }
    fn get_blob(&self, hash: &str) -> Option<Vec<u8>> {
        if hash == EMPTY_SHA256 {
            return Some(Vec::new());
        }
        std::fs::read(self.cas_path(hash)).ok()
    }
    fn put_blob(&self, hash: &str, data: &[u8]) -> Result<(), String> {
        let p = self.cas_path(hash);
        if p.exists() { Ok(()) } else { self.write_atomic(&p, data) }
    }
    fn get_action_result(&self, action: &str) -> Option<re::ActionResult> {
        let bytes = std::fs::read(self.root.join("ac").join(action)).ok()?;
        re::ActionResult::decode(bytes.as_slice()).ok()
    }
    fn put_action_result(&self, action: &str, _action_size: i64, result: &re::ActionResult) -> Result<(), String> {
        self.write_atomic(&self.root.join("ac").join(action), &result.encode_to_vec())
    }
}

/// Runs store work on tokio's blocking pool: stores may do network I/O, and
/// must never stall the gRPC server (buck2's keepalives then time out).
async fn blocking<T: Send + 'static>(store: &Arc<dyn Store>, f: impl FnOnce(&dyn Store) -> T + Send + 'static) -> Result<T, Status> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || f(&*store)).await.map_err(|e| Status::internal(e.to_string()))
}

fn check_digest(d: &Option<re::Digest>) -> Result<(String, i64), Status> {
    let d = d.as_ref().ok_or_else(|| Status::invalid_argument("missing digest"))?;
    crate::attest::check_hex(&d.hash).map_err(Status::invalid_argument)?;
    if d.size_bytes < 0 {
        return Err(Status::invalid_argument("negative size"));
    }
    Ok((d.hash.clone(), d.size_bytes))
}

fn verify(hash: &str, size: i64, data: &[u8]) -> Result<(), Status> {
    if data.len() as i64 != size || sha256_hex(data) != hash {
        return Err(Status::invalid_argument(format!("data does not match digest {hash}/{size}")));
    }
    Ok(())
}

fn ok_status() -> Option<rpc::Status> {
    Some(rpc::Status { code: 0, message: String::new(), details: vec![] })
}

fn err_status(code: tonic::Code, msg: String) -> Option<rpc::Status> {
    Some(rpc::Status { code: code as i32, message: msg, details: vec![] })
}

#[derive(Clone)]
pub struct Proxy {
    store: Arc<dyn Store>,
    executor: Option<Arc<crate::execute::Executor>>,
    /// Bounds concurrent executions (buck2 submits hundreds at once).
    exec_slots: Arc<tokio::sync::Semaphore>,
    /// Accept UpdateActionResult from clients. Off when signing: only results
    /// of actions this proxy executed itself may be vouched for.
    accept_uploads: bool,
}

impl Proxy {
    pub fn new(store: Arc<dyn Store>) -> Proxy {
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
        Proxy { store, executor: None, exec_slots: Arc::new(tokio::sync::Semaphore::new(cpus)), accept_uploads: true }
    }

    /// Enables remote execution in the sandbox and refuses client-supplied
    /// action results.
    pub fn with_executor(mut self, executor: crate::execute::Executor) -> Proxy {
        self.executor = Some(Arc::new(executor));
        self.accept_uploads = false;
        self
    }

    pub async fn serve(self, addr: std::net::SocketAddr) -> Result<(), String> {
        tonic::transport::Server::builder()
            .add_service(CapabilitiesServer::new(self.clone()))
            .add_service(ContentAddressableStorageServer::new(self.clone()).max_decoding_message_size(64 << 20))
            .add_service(ActionCacheServer::new(self.clone()))
            .add_service(re::execution_server::ExecutionServer::new(self.clone()))
            .add_service(ByteStreamServer::new(self).max_decoding_message_size(64 << 20))
            .serve(addr)
            .await
            .map_err(|e| e.to_string())
    }
}

#[tonic::async_trait]
impl Capabilities for Proxy {
    async fn get_capabilities(&self, _: Request<re::GetCapabilitiesRequest>) -> Result<Response<re::ServerCapabilities>, Status> {
        use re::digest_function::Value as DigestFn;
        let semver = |major, minor| crate::reapi::build::bazel::semver::SemVer { major, minor, patch: 0, prerelease: String::new() };
        Ok(Response::new(re::ServerCapabilities {
            cache_capabilities: Some(re::CacheCapabilities {
                digest_functions: vec![DigestFn::Sha256 as i32],
                action_cache_update_capabilities: Some(re::ActionCacheUpdateCapabilities { update_enabled: true }),
                max_batch_total_size_bytes: MAX_BATCH_BYTES,
                symlink_absolute_path_strategy: re::symlink_absolute_path_strategy::Value::Disallowed as i32,
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
    async fn find_missing_blobs(&self, req: Request<re::FindMissingBlobsRequest>) -> Result<Response<re::FindMissingBlobsResponse>, Status> {
        let digests = req.into_inner().blob_digests;
        for d in &digests {
            check_digest(&Some(d.clone()))?;
        }
        let missing = blocking(&self.store, move |st| digests.into_iter().filter(|d| !st.has_blob(&d.hash)).collect()).await?;
        Ok(Response::new(re::FindMissingBlobsResponse { missing_blob_digests: missing }))
    }

    async fn batch_update_blobs(&self, req: Request<re::BatchUpdateBlobsRequest>) -> Result<Response<re::BatchUpdateBlobsResponse>, Status> {
        let requests = req.into_inner().requests;
        for r in &requests {
            check_digest(&r.digest)?;
        }
        let responses = blocking(&self.store, move |st| {
            requests
                .into_iter()
                .map(|r| {
                    let (hash, size) = (r.digest.as_ref().map(|d| d.hash.clone()).unwrap_or_default(), r.digest.as_ref().map(|d| d.size_bytes).unwrap_or(0));
                    let status = match verify(&hash, size, &r.data) {
                        Err(e) => err_status(tonic::Code::InvalidArgument, e.message().to_string()),
                        Ok(()) => match st.put_blob(&hash, &r.data) {
                            Ok(()) => ok_status(),
                            Err(e) => err_status(tonic::Code::Internal, e),
                        },
                    };
                    re::batch_update_blobs_response::Response { digest: r.digest, status }
                })
                .collect()
        })
        .await?;
        Ok(Response::new(re::BatchUpdateBlobsResponse { responses }))
    }

    async fn batch_read_blobs(&self, req: Request<re::BatchReadBlobsRequest>) -> Result<Response<re::BatchReadBlobsResponse>, Status> {
        let digests = req.into_inner().digests;
        for d in &digests {
            check_digest(&Some(d.clone()))?;
        }
        let responses = blocking(&self.store, move |st| {
            digests
                .into_iter()
                .map(|d| {
                    let (data, status) = match st.get_blob(&d.hash) {
                        Some(b) => (b, ok_status()),
                        None => (Vec::new(), err_status(tonic::Code::NotFound, format!("blob {} not found", d.hash))),
                    };
                    re::batch_read_blobs_response::Response { digest: Some(d), data, compressor: 0, status }
                })
                .collect()
        })
        .await?;
        Ok(Response::new(re::BatchReadBlobsResponse { responses }))
    }

    type GetTreeStream = Pin<Box<dyn Stream<Item = Result<re::GetTreeResponse, Status>> + Send>>;

    async fn get_tree(&self, _: Request<re::GetTreeRequest>) -> Result<Response<Self::GetTreeStream>, Status> {
        Err(Status::unimplemented("GetTree is not supported"))
    }

    async fn split_blob(&self, _: Request<re::SplitBlobRequest>) -> Result<Response<re::SplitBlobResponse>, Status> {
        Err(Status::unimplemented("SplitBlob is not supported"))
    }

    async fn splice_blob(&self, _: Request<re::SpliceBlobRequest>) -> Result<Response<re::SpliceBlobResponse>, Status> {
        Err(Status::unimplemented("SpliceBlob is not supported"))
    }
}

#[tonic::async_trait]
impl ActionCache for Proxy {
    async fn get_action_result(&self, req: Request<re::GetActionResultRequest>) -> Result<Response<re::ActionResult>, Status> {
        let (hash, _) = check_digest(&req.into_inner().action_digest)?;
        let h = hash.clone();
        // Only serve a result whose outputs are all present.
        match blocking(&self.store, move |st| st.get_action_result(&h).filter(|r| outputs_present(st, r))).await? {
            Some(r) => Ok(Response::new(r)),
            None => Err(Status::not_found(format!("no result for action {hash}"))),
        }
    }

    async fn update_action_result(&self, req: Request<re::UpdateActionResultRequest>) -> Result<Response<re::ActionResult>, Status> {
        if !self.accept_uploads {
            return Err(Status::permission_denied("this proxy only stores results of actions it executed"));
        }
        let req = req.into_inner();
        let (hash, size) = check_digest(&req.action_digest)?;
        let result = req.action_result.ok_or_else(|| Status::invalid_argument("missing action_result"))?;
        let r = result.clone();
        blocking(&self.store, move |st| {
            if !outputs_present(st, &r) {
                return Err(Status::failed_precondition("action result references blobs not in the CAS"));
            }
            st.put_action_result(&hash, size, &r).map_err(Status::internal)
        })
        .await??;
        Ok(Response::new(result))
    }
}

pub fn outputs_present(store: &dyn Store, r: &re::ActionResult) -> bool {
    let digests = r
        .output_files
        .iter()
        .filter_map(|f| f.digest.as_ref())
        .chain(r.output_directories.iter().filter_map(|d| d.tree_digest.as_ref()))
        .chain(r.stdout_digest.iter())
        .chain(r.stderr_digest.iter());
    digests.into_iter().all(|d| store.has_blob(&d.hash))
}

/// `{instance}/blobs/{hash}/{size}` or `{instance}/uploads/{uuid}/blobs/{hash}/{size}`.
fn parse_resource(name: &str) -> Result<(String, i64), Status> {
    let parts: Vec<&str> = name.split('/').collect();
    let i = parts.iter().rposition(|p| *p == "blobs").ok_or_else(|| Status::invalid_argument(format!("bad resource name {name}")))?;
    let (hash, size) = match (parts.get(i + 1), parts.get(i + 2)) {
        (Some(h), Some(s)) => (h.to_string(), s.parse::<i64>().map_err(|_| Status::invalid_argument("bad size"))?),
        _ => return Err(Status::invalid_argument(format!("bad resource name {name}"))),
    };
    crate::attest::check_hex(&hash).map_err(Status::invalid_argument)?;
    Ok((hash, size))
}

#[tonic::async_trait]
impl ByteStream for Proxy {
    type ReadStream = Pin<Box<dyn Stream<Item = Result<ReadResponse, Status>> + Send>>;

    async fn read(&self, req: Request<ReadRequest>) -> Result<Response<Self::ReadStream>, Status> {
        let req = req.into_inner();
        let (hash, _) = parse_resource(&req.resource_name)?;
        let h = hash.clone();
        let data = blocking(&self.store, move |st| st.get_blob(&h)).await?.ok_or_else(|| Status::not_found(format!("blob {hash} not found")))?;
        let start = usize::try_from(req.read_offset).map_err(|_| Status::out_of_range("bad offset"))?;
        if start > data.len() {
            return Err(Status::out_of_range("offset past end"));
        }
        let end = if req.read_limit > 0 { (start + req.read_limit as usize).min(data.len()) } else { data.len() };
        let chunks: Vec<Result<ReadResponse, Status>> = if start == end {
            vec![Ok(ReadResponse { data: Vec::new() })]
        } else {
            data[start..end].chunks(READ_CHUNK).map(|c| Ok(ReadResponse { data: c.to_vec() })).collect()
        };
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks))))
    }

    async fn write(&self, req: Request<Streaming<WriteRequest>>) -> Result<Response<WriteResponse>, Status> {
        let mut stream = req.into_inner();
        let mut target: Option<(String, i64)> = None;
        let mut data = Vec::new();
        while let Some(msg) = stream.next().await {
            let msg = msg?;
            if target.is_none() {
                target = Some(parse_resource(&msg.resource_name)?);
            }
            if msg.write_offset as usize != data.len() {
                return Err(Status::invalid_argument("non-sequential write"));
            }
            data.extend_from_slice(&msg.data);
            if msg.finish_write {
                break;
            }
        }
        let (hash, size) = target.ok_or_else(|| Status::invalid_argument("empty write"))?;
        verify(&hash, size, &data)?;
        let len = data.len() as i64;
        blocking(&self.store, move |st| st.put_blob(&hash, &data)).await?.map_err(Status::internal)?;
        Ok(Response::new(WriteResponse { committed_size: len }))
    }

    async fn query_write_status(&self, req: Request<QueryWriteStatusRequest>) -> Result<Response<QueryWriteStatusResponse>, Status> {
        let (hash, size) = parse_resource(&req.into_inner().resource_name)?;
        let complete = blocking(&self.store, move |st| st.has_blob(&hash)).await?;
        Ok(Response::new(QueryWriteStatusResponse { committed_size: if complete { size } else { 0 }, complete }))
    }
}

fn any<M: prost::Message>(type_name: &str, m: &M) -> prost_types::Any {
    prost_types::Any { type_url: format!("type.googleapis.com/{type_name}"), value: m.encode_to_vec() }
}

#[tonic::async_trait]
impl re::execution_server::Execution for Proxy {
    type ExecuteStream = Pin<Box<dyn Stream<Item = Result<crate::reapi::google::longrunning::Operation, Status>> + Send>>;
    type WaitExecutionStream = Self::ExecuteStream;

    async fn execute(&self, req: Request<re::ExecuteRequest>) -> Result<Response<Self::ExecuteStream>, Status> {
        use crate::reapi::google::longrunning::{Operation, operation};
        let executor = self.executor.clone().ok_or_else(|| Status::unimplemented("remote execution is not enabled"))?;
        let req = req.into_inner();
        let (hash, size) = check_digest(&req.action_digest)?;
        let digest = re::Digest { hash: hash.clone(), size_bytes: size };

        let cached = if req.skip_cache_lookup {
            None
        } else {
            let h = hash.clone();
            blocking(&self.store, move |st| st.get_action_result(&h).filter(|r| outputs_present(st, r))).await?
        };
        let (result, cached_result, status) = match cached {
            Some(r) => (Some(r), true, ok_status()),
            None => {
                let _slot = self.exec_slots.clone().acquire_owned().await.map_err(|e| Status::internal(e.to_string()))?;
                let d = digest.clone();
                match tokio::task::spawn_blocking(move || executor.execute(&d)).await {
                    Ok(Ok(r)) => (Some(r), false, ok_status()),
                    Ok(Err(e)) => (None, false, err_status(tonic::Code::Internal, e)),
                    Err(e) => (None, false, err_status(tonic::Code::Internal, e.to_string())),
                }
            }
        };
        let response = re::ExecuteResponse { result, cached_result, status, ..Default::default() };
        let metadata = re::ExecuteOperationMetadata {
            stage: re::execution_stage::Value::Completed as i32,
            action_digest: Some(digest),
            ..Default::default()
        };
        let op = Operation {
            name: format!("executions/{hash}"),
            metadata: Some(any("build.bazel.remote.execution.v2.ExecuteOperationMetadata", &metadata)),
            done: true,
            result: Some(operation::Result::Response(any("build.bazel.remote.execution.v2.ExecuteResponse", &response))),
        };
        Ok(Response::new(Box::pin(tokio_stream::iter(vec![Ok(op)]))))
    }

    async fn wait_execution(&self, _: Request<re::WaitExecutionRequest>) -> Result<Response<Self::WaitExecutionStream>, Status> {
        Err(Status::unimplemented("executions complete within Execute"))
    }
}
