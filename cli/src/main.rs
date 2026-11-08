#![forbid(unsafe_code)]

use anyhow::{Context as _, bail, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hartland::attest::{Batch, Envelope, Pair};
use hartland::cas::Blob;
use hartland::digest::{ActionDigest, Digest, GitSha, Sha256};
use hartland::ghcr_store::{GhcrStore, Promote};
use hartland::jwt::Jwks;
use hartland::keyring::{Keyring, Repository};
use hartland::oci::Registry;
use hartland::package::{Package, PackageStatement};
use hartland::proxy::{DiskStore, Proxy, Store};
use hartland::reapi::re;
use hartland::reapi::re::content_addressable_storage_client::ContentAddressableStorageClient;
use hartland::sandbox::RelPath;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

/// Attested builds anchored in GitHub-hosted runners.
#[derive(Parser)]
#[command(name = "hartland", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign and verify attestations.
    #[command(subcommand)]
    Attest(AttestCommand),
    /// Maintain the archive of GitHub's signing keys.
    #[command(subcommand)]
    Jwks(JwksCommand),
    /// Run actions in the sandbox.
    #[command(subcommand)]
    Sandbox(SandboxCommand),
    /// The Remote Execution API proxy and its test clients.
    #[command(subcommand)]
    Proxy(ProxyCommand),
}

#[derive(Args)]
struct Trust {
    #[arg(long)]
    keyring: PathBuf,
    #[arg(long)]
    jwks: PathBuf,
}

impl Trust {
    async fn load(&self) -> anyhow::Result<(Keyring, Jwks)> {
        Ok((
            read_json(&self.keyring).await?,
            read_json(&self.jwks).await?,
        ))
    }
}

/// `name=path`
#[derive(Clone)]
struct NamedFile {
    name: String,
    path: PathBuf,
}

impl FromStr for NamedFile {
    type Err = String;
    fn from_str(s: &str) -> Result<NamedFile, String> {
        let (name, path) = s
            .split_once('=')
            .ok_or_else(|| format!("want name=path, got {s}"))?;
        Ok(NamedFile {
            name: name.to_string(),
            path: path.into(),
        })
    }
}

#[derive(Subcommand)]
enum AttestCommand {
    /// Inside a GitHub Actions job: sign a batch of action results.
    Sign {
        /// JSON list of {action, result} digest pairs.
        #[arg(long)]
        results: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a batch envelope against a keyring and GitHub's key archive.
    Verify {
        #[arg(long)]
        envelope: PathBuf,
        #[command(flatten)]
        trust: Trust,
    },
    /// Inside a GitHub Actions job: sign a package attestation.
    Package {
        #[arg(long)]
        target: String,
        #[arg(long)]
        repository: Repository,
        #[arg(long)]
        commit: GitSha,
        #[arg(long)]
        out: PathBuf,
        #[arg(long = "output", required = true)]
        outputs: Vec<NamedFile>,
    },
    /// Verify a package attestation, optionally against files.
    VerifyPackage {
        #[arg(long)]
        envelope: PathBuf,
        #[command(flatten)]
        trust: Trust,
        #[arg(long = "output")]
        outputs: Vec<NamedFile>,
    },
}

#[derive(Subcommand)]
enum JwksCommand {
    /// Merge GitHub's current signing keys into the archive (never removes).
    Update {
        #[arg(long)]
        jwks: PathBuf,
    },
}

/// `K=V`
#[derive(Clone)]
struct EnvVar(String, String);

impl FromStr for EnvVar {
    type Err = String;
    fn from_str(s: &str) -> Result<EnvVar, String> {
        let (k, v) = s
            .split_once('=')
            .ok_or_else(|| format!("want K=V, got {s}"))?;
        Ok(EnvVar(k.to_string(), v.to_string()))
    }
}

#[derive(Subcommand)]
enum SandboxCommand {
    /// Prepare a GitHub-hosted runner for sandboxed actions (needs sudo).
    Setup,
    /// Run one action in the sandbox. The input directory is used in place;
    /// declared outputs are moved to --collect (same filesystem).
    Run {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        collect: PathBuf,
        #[arg(long = "output")]
        outputs: Vec<RelPath>,
        #[arg(long = "env")]
        env: Vec<EnvVar>,
        /// Run as the current user (local development).
        #[arg(long)]
        no_drop_user: bool,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Execute {
    /// As the sandbox uid (GitHub-hosted runners).
    Sandbox,
    /// bwrap as the current user (local development).
    Unprivileged,
}

/// A registry-backed store trusting only signed results. Credentials come
/// from REGISTRY_USER / REGISTRY_PASSWORD (in Actions: github.actor and
/// github.token).
#[derive(Args)]
struct RegistryArgs {
    /// e.g. ghcr.io
    #[arg(long, requires_all = ["keyring", "jwks"])]
    registry: Option<String>,
    /// Namespaces to read, comma-separated.
    #[arg(long, value_delimiter = ',', requires = "registry")]
    read: Vec<String>,
    /// Namespace to write.
    #[arg(long, requires = "registry")]
    write: Option<String>,
    #[arg(long, requires = "registry")]
    keyring: Option<PathBuf>,
    #[arg(long, requires = "registry")]
    jwks: Option<PathBuf>,
    /// First-tier directory (saved and restored with the Actions cache).
    #[arg(long, requires = "registry")]
    l1: Option<PathBuf>,
    /// What goes to the registry.
    #[arg(long, value_enum, default_value = "all", requires = "l1")]
    promote: Promote,
}

/// Scale-out: hand actions to workers dispatched on demand. Needs the
/// registry trust options, `GITHUB_TOKEN` with `actions: write`, and the
/// job's OIDC credentials.
#[derive(Args)]
struct ScaleArgs {
    /// The workflow file (in this repository) that runs workers.
    #[arg(long, requires_all = ["registry", "execute"])]
    worker_workflow: Option<String>,
    /// The ref to dispatch workers on.
    #[arg(long, requires = "worker_workflow")]
    worker_ref: Option<String>,
    /// Most workers at once.
    #[arg(long, default_value_t = 8)]
    max_workers: usize,
    /// Actions one worker runs at once.
    #[arg(long, default_value_t = 2)]
    worker_slots: usize,
}

#[derive(Subcommand)]
enum ProxyCommand {
    /// Serve the Remote Execution API.
    Serve {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long, value_enum)]
        execute: Option<Execute>,
        #[command(flatten)]
        registry: RegistryArgs,
        /// Seconds between publishes (and at shutdown).
        #[arg(long, default_value_t = 300)]
        publish_every: u64,
        #[command(flatten)]
        scale: ScaleArgs,
    },
    /// Join a coordinator as a worker (in a dispatched run): run the actions
    /// it sends in the sandbox, sign the results, leave when idle.
    Worker {
        #[arg(long)]
        dir: PathBuf,
        /// The coordinator's public key (from the dispatch inputs).
        #[arg(long)]
        coordinator: hartland::cert::PublicKey,
        /// The coordinator's run (from the dispatch inputs).
        #[arg(long)]
        coordinator_run: String,
        #[command(flatten)]
        trust: Trust,
        #[arg(long, value_enum, default_value = "sandbox")]
        execute: Execute,
        /// Actions to run at once.
        #[arg(long, default_value_t = 2)]
        slots: usize,
        /// Leave after this many seconds without work.
        #[arg(long, default_value_t = 60)]
        idle: u64,
    },
    /// Push the registry writes queued in the first tier's outbox (verified
    /// batches only), off the build's critical path.
    Promote {
        #[arg(long)]
        dir: PathBuf,
        #[command(flatten)]
        registry: RegistryArgs,
    },
    /// Test client: capabilities, upload, FindMissingBlobs.
    Check {
        #[arg(long)]
        addr: String,
    },
    /// Test client: upload a file.
    Put {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Test client: store a result for a synthetic action.
    AcPut {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        action: String,
    },
    /// Test client: look up a synthetic action's result.
    AcGet {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        action: String,
        #[arg(long, value_enum)]
        expect: Option<Expect>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Expect {
    Found,
    Missing,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Logs to stderr; RUST_LOG overrides (e.g. RUST_LOG=hartland=debug).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run(Cli::parse().command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Attest(c) => attest(c).await,
        Command::Jwks(JwksCommand::Update { jwks }) => jwks_update(&jwks).await,
        Command::Sandbox(SandboxCommand::Setup) => Ok(hartland::sandbox::setup().await?),
        Command::Sandbox(SandboxCommand::Run {
            input,
            collect,
            outputs,
            env,
            no_drop_user,
            argv,
        }) => sandbox_run(&input, &collect, &outputs, env, !no_drop_user, &argv).await,
        Command::Proxy(c) => proxy(c).await,
    }
}

async fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| path.display().to_string())?;
    serde_json::from_slice(&bytes).with_context(|| path.display().to_string())
}

async fn write_json<T: serde::Serialize>(path: &Path, v: &T) -> anyhow::Result<()> {
    let mut s = serde_json::to_string_pretty(v)?;
    s.push('\n');
    tokio::fs::write(path, s)
        .await
        .with_context(|| path.display().to_string())
}

fn print_json(v: &impl serde::Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

// ---- attestations ---------------------------------------------------------

async fn hash_file(path: &Path) -> anyhow::Result<Sha256> {
    Ok(Sha256::of(
        &tokio::fs::read(path)
            .await
            .with_context(|| path.display().to_string())?,
    ))
}

async fn attest(c: AttestCommand) -> anyhow::Result<()> {
    match c {
        AttestCommand::Sign { results, out } => {
            let pairs: Vec<Pair> = read_json(&results).await?;
            let batch = Batch::new(pairs);
            write_json(&out, &hartland::attest::sign(batch.to_bytes()).await?).await?;
            tracing::info!(results = batch.results.len(), "signed");
        }
        AttestCommand::Verify { envelope, trust } => {
            let (keyring, jwks) = trust.load().await?;
            let signed = read_json::<Envelope>(&envelope)
                .await?
                .verify::<Batch>(&jwks, &keyring)?;
            let results: BTreeMap<String, Digest> = signed
                .statement
                .results
                .iter()
                .map(|(a, v)| (a.to_string(), v.result))
                .collect();
            print_json(&serde_json::json!({"signer": signed.signer, "results": results}))?;
        }
        AttestCommand::Package {
            target,
            repository,
            commit,
            out,
            outputs,
        } => {
            let mut digests = BTreeMap::new();
            for f in &outputs {
                digests.insert(f.name.clone(), hash_file(&f.path).await?);
            }
            let statement = PackageStatement::new(
                Package {
                    target,
                    repository,
                    commit,
                },
                digests,
            )?;
            write_json(&out, &hartland::attest::sign(statement.to_bytes()).await?).await?;
            tracing::info!(target = %statement.package.target, outputs = statement.outputs.len(), "attested package");
        }
        AttestCommand::VerifyPackage {
            envelope,
            trust,
            outputs,
        } => {
            let (keyring, jwks) = trust.load().await?;
            let signed = hartland::package::verify(&read_json(&envelope).await?, &jwks, &keyring)?;
            let st = &signed.statement;
            for f in &outputs {
                let want = st.outputs.get(&f.name).with_context(|| {
                    format!(
                        "{} is not an attested output of {}",
                        f.name, st.package.target
                    )
                })?;
                let got = hash_file(&f.path).await?;
                ensure!(
                    got == *want,
                    "{} does not match the attested {}: {got} != {want}",
                    f.path.display(),
                    f.name
                );
            }
            print_json(&serde_json::json!({
                "package": st.package, "outputs": st.outputs, "signer": signed.signer, "files_checked": outputs.len(),
            }))?;
        }
    }
    Ok(())
}

async fn jwks_update(path: &Path) -> anyhow::Result<()> {
    let mut archive: Jwks = if tokio::fs::try_exists(path).await? {
        read_json(path).await?
    } else {
        Jwks::default()
    };
    let added = archive.merge(hartland::github::fetch_jwks().await?)?;
    write_json(path, &archive).await?;
    tracing::info!(added, archived = archive.len(), "jwks updated");
    Ok(())
}

// ---- sandbox --------------------------------------------------------------

async fn sandbox_run(
    input: &Path,
    collect: &Path,
    outputs: &[RelPath],
    env: Vec<EnvVar>,
    drop_user: bool,
    argv: &[String],
) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(collect).await?;
    let env: Vec<(String, String)> = env.into_iter().map(|EnvVar(k, v)| (k, v)).collect();
    let outcome = hartland::sandbox::exec(&hartland::sandbox::Spec {
        input,
        argv,
        env: &env,
        workdir: None,
        outputs,
        collect,
        drop_user,
        ro_binds: &[],
    })
    .await?;
    std::io::stdout().write_all(&outcome.stdout)?;
    std::io::stderr().write_all(&outcome.stderr)?;
    ensure!(
        outcome.missing.is_empty(),
        "missing outputs: {}",
        outcome
            .missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    ensure!(
        outcome.exit_code == 0,
        "action exited with {}",
        outcome.exit_code
    );
    Ok(())
}

// ---- proxy ----------------------------------------------------------------

/// Under the system temp dir: the sandbox uid must be able to traverse to
/// its scratch directories and the read-only directory cache.
async fn with_execution(
    proxy: Proxy,
    store: Arc<dyn Store>,
    execute: Option<Execute>,
) -> anyhow::Result<Proxy> {
    let Some(execute) = execute else {
        return Ok(proxy);
    };
    Ok(proxy.with_executor(executor(store, execute).await?))
}

/// The sandbox executor. Its scratch is under the system temp dir: the
/// sandbox uid must be able to traverse to its directories.
async fn executor(
    store: Arc<dyn Store>,
    execute: Execute,
) -> anyhow::Result<hartland::execute::Executor> {
    let scratch = std::env::temp_dir().join(format!("hartland-exec-{}", std::process::id()));
    tokio::fs::create_dir_all(&scratch).await?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o755)).await?;
    }
    let drop_user = matches!(execute, Execute::Sandbox);
    tracing::info!(
        sandbox = if drop_user { "uid" } else { "unprivileged" },
        "remote execution enabled"
    );
    Ok(hartland::execute::Executor::new(store, drop_user, scratch))
}

fn env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

/// Coordinator side of scale-out: a certified key, an iroh endpoint, the
/// worker pool and the dispatcher.
async fn scale_out(
    scale: &ScaleArgs,
    proxy: Proxy,
    store: Arc<dyn Store>,
    keyring: Keyring,
    jwks: Jwks,
) -> anyhow::Result<(Proxy, Option<Arc<hartland::worker::Pool>>)> {
    let Some(workflow) = &scale.worker_workflow else {
        return Ok((proxy, None));
    };
    let mut identity = hartland::cert::Identity::generate()?;
    identity.certify().await?;
    let repository = env("GITHUB_REPOSITORY")?;
    let trust = hartland::worker::PeerTrust {
        keyring,
        jwks,
        repository: repository.parse()?,
    };
    let ep = hartland::worker::bind(&identity, hartland::worker::Network::N0).await?;
    let key = identity.public();
    let pool = hartland::worker::Pool::new(identity, trust, store);
    tokio::spawn(pool.clone().serve(ep));
    let proxy = proxy.with_pool(pool.clone());
    let dispatcher = hartland::dispatch::Dispatcher {
        repository,
        workflow: workflow.clone(),
        git_ref: match &scale.worker_ref {
            Some(r) => r.clone(),
            None => env("GITHUB_REF_NAME")?,
        },
        token: env("GITHUB_TOKEN")?,
        coordinator: key,
        coordinator_run: env("GITHUB_RUN_ID")?,
        max_workers: scale.max_workers,
        worker_slots: scale.worker_slots,
    };
    tokio::spawn(dispatcher.run(pool.clone(), proxy.queued()));
    tracing::info!(coordinator = %key, max_workers = scale.max_workers, "scale-out enabled");
    Ok((proxy, Some(pool)))
}

fn registry_credentials() -> Option<(String, String)> {
    Some((
        std::env::var("REGISTRY_USER").ok()?,
        std::env::var("REGISTRY_PASSWORD").ok()?,
    ))
}

async fn open_registry(host: &str, repo: &str) -> anyhow::Result<Registry> {
    let mut r = Registry::new(host, repo);
    if let Some((user, password)) = registry_credentials() {
        r.login(&user, &password)
            .await
            .with_context(|| format!("log in to {host}/{repo}"))?;
    }
    Ok(r)
}

async fn ghcr_store(disk: DiskStore, a: &RegistryArgs) -> anyhow::Result<GhcrStore> {
    let host = a.registry.as_deref().context("--registry is required")?;
    let mut readers = Vec::new();
    for repo in &a.read {
        readers.push(open_registry(host, repo).await?);
    }
    let writer = match &a.write {
        Some(repo) => Some(open_registry(host, repo).await?),
        None => None,
    };
    let trust = Trust {
        keyring: a.keyring.clone().context("--keyring is required")?,
        jwks: a.jwks.clone().context("--jwks is required")?,
    };
    let (keyring, jwks) = trust.load().await?;
    let store = GhcrStore::new(disk, readers, writer, keyring, jwks);
    Ok(match &a.l1 {
        Some(dir) => store.with_first_tier(hartland::l1::L1::open(dir.clone()).await?, a.promote),
        None => store,
    })
}

fn report_publish(r: Result<usize, hartland::proxy::StoreError>) {
    if let Err(e) = r {
        tracing::error!(error = %e, "publish failed");
    }
}

async fn proxy(c: ProxyCommand) -> anyhow::Result<()> {
    match c {
        ProxyCommand::Serve {
            dir,
            listen,
            execute,
            registry,
            publish_every,
            scale,
        } => {
            let disk = DiskStore::open(dir).await?;
            if registry.registry.is_none() {
                tracing::info!(addr = %listen, store = "disk", "listening");
                let store: Arc<dyn Store> = Arc::new(disk);
                return Ok(with_execution(Proxy::new(store.clone()), store, execute)
                    .await?
                    .serve(listen)
                    .await?);
            }
            serve_registry(
                listen,
                execute,
                Arc::new(ghcr_store(disk, &registry).await?),
                publish_every,
                &registry,
                &scale,
            )
            .await
        }
        ProxyCommand::Worker {
            dir,
            coordinator,
            coordinator_run,
            trust,
            execute,
            slots,
            idle,
        } => {
            hartland::sandbox::setup().await?;
            let (keyring, jwks) = trust.load().await?;
            let mut identity = hartland::cert::Identity::generate()?;
            identity.certify().await?;
            let config = hartland::worker::WorkerConfig {
                identity,
                coordinator: hartland::worker::endpoint_addr(&coordinator)?,
                coordinator_run,
                trust: hartland::worker::PeerTrust {
                    keyring,
                    jwks,
                    repository: env("GITHUB_REPOSITORY")?.parse()?,
                },
                dir,
                slots,
                idle: std::time::Duration::from_secs(idle),
                network: hartland::worker::Network::N0,
            };
            // The executor is built on the worker's store, which the worker
            // sets up once it has joined.
            let runner = move |store: Arc<dyn Store>| -> Arc<dyn hartland::worker::Runner> {
                Arc::new(LazyExecutor {
                    store,
                    execute,
                    executor: tokio::sync::OnceCell::new(),
                })
            };
            let executed = hartland::worker::run_worker(config, runner).await?;
            tracing::info!(executed, "worker done");
            Ok(())
        }
        ProxyCommand::Promote { dir, registry } => {
            ensure!(
                registry.l1.is_some() && registry.write.is_some(),
                "promote needs --l1 and --write"
            );
            let store = ghcr_store(DiskStore::open(dir).await?, &registry).await?;
            let started = std::time::Instant::now();
            store.load_first_tier().await;
            let n = store.drain_outbox().await?;
            tracing::info!(results = n, elapsed = ?started.elapsed(), "promoted the outbox to the registry");
            Ok(())
        }
        ProxyCommand::Check { addr } => proxy_check(&addr).await,
        ProxyCommand::Put { addr, file } => {
            let d = upload(&addr, tokio::fs::read(&file).await?).await?;
            println!("{}/{}", d.hash, d.size);
            Ok(())
        }
        ProxyCommand::AcPut { addr, action } => ac_put(&addr, &action).await,
        ProxyCommand::AcGet {
            addr,
            action,
            expect,
        } => ac_get(&addr, &action, expect).await,
    }
}

/// The sandbox executor, created on first use (its setup is async).
struct LazyExecutor {
    store: Arc<dyn Store>,
    execute: Execute,
    executor: tokio::sync::OnceCell<hartland::execute::Executor>,
}

#[async_trait::async_trait]
impl hartland::worker::Runner for LazyExecutor {
    async fn run(&self, action: ActionDigest) -> Result<re::ActionResult, String> {
        let executor = self
            .executor
            .get_or_try_init(|| executor(self.store.clone(), self.execute))
            .await
            .map_err(|e| format!("{e:#}"))?;
        executor.execute(action).await.map_err(|e| e.to_string())
    }
}

async fn serve_registry(
    listen: SocketAddr,
    execute: Option<Execute>,
    store: Arc<GhcrStore>,
    publish_every: u64,
    registry: &RegistryArgs,
    scale: &ScaleArgs,
) -> anyhow::Result<()> {
    // Serve from the first tier at once; read the registry indexes in the
    // background (misses and publishing wait for them).
    store.load_first_tier().await;
    tracing::info!(
        results = store.known(),
        "serving; registry indexes loading in the background"
    );
    tokio::spawn({
        let store = store.clone();
        async move { store.load_registry().await }
    });
    tracing::info!(addr = %listen, store = "registry", "listening");
    let dyn_store: Arc<dyn Store> = store.clone();
    let proxy = with_execution(Proxy::new(dyn_store.clone()), dyn_store.clone(), execute).await?;
    let trust = Trust {
        keyring: registry.keyring.clone().context("--keyring is required")?,
        jwks: registry.jwks.clone().context("--jwks is required")?,
    };
    let (keyring, jwks) = trust.load().await?;
    let (proxy, pool) = scale_out(scale, proxy, dyn_store, keyring, jwks).await?;
    let serve = proxy.serve(listen);
    // Workers' results are signed by the workers: collect their batches
    // before every publish.
    let publish = |store: Arc<GhcrStore>, pool: Option<Arc<hartland::worker::Pool>>| async move {
        if let Some(pool) = pool {
            pool.flush().await;
        }
        report_publish(store.publish().await);
    };
    let periodic = {
        let (store, pool) = (store.clone(), pool.clone());
        async move {
            let mut tick =
                tokio::time::interval(std::time::Duration::from_secs(publish_every.max(1)));
            tick.tick().await;
            loop {
                tick.tick().await;
                publish(store.clone(), pool.clone()).await;
            }
        }
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = serve => r?,
        () = periodic => {}
        r = tokio::signal::ctrl_c() => r?,
        _ = term.recv() => {}
    }
    tracing::info!("shutting down; publishing pending results");
    publish(store, pool).await;
    Ok(())
}

// ---- test clients ---------------------------------------------------------

async fn cas_client(
    addr: &str,
) -> anyhow::Result<ContentAddressableStorageClient<tonic::transport::Channel>> {
    Ok(ContentAddressableStorageClient::connect(addr.to_string())
        .await
        .with_context(|| format!("connect {addr}"))?
        .max_decoding_message_size(64 << 20)
        .max_encoding_message_size(64 << 20))
}

async fn upload(addr: &str, data: Vec<u8>) -> anyhow::Result<Digest> {
    let blob = Blob::new(data);
    cas_client(addr)
        .await?
        .batch_update_blobs(re::BatchUpdateBlobsRequest {
            requests: vec![re::batch_update_blobs_request::Request {
                digest: Some(blob.digest().into()),
                data: blob.data().clone(),
                compressor: 0,
            }],
            ..Default::default()
        })
        .await?;
    Ok(blob.digest())
}

async fn proxy_check(addr: &str) -> anyhow::Result<()> {
    let mut caps = re::capabilities_client::CapabilitiesClient::connect(addr.to_string()).await?;
    let c = caps
        .get_capabilities(re::GetCapabilitiesRequest::default())
        .await?;
    println!(
        "capabilities: {:?}",
        c.into_inner()
            .cache_capabilities
            .map(|c| c.digest_functions)
    );
    let digest = upload(addr, b"hartland proxy check".to_vec()).await?;
    let missing = cas_client(addr)
        .await?
        .find_missing_blobs(re::FindMissingBlobsRequest {
            blob_digests: vec![digest.into()],
            ..Default::default()
        })
        .await?;
    println!(
        "missing after upload: {}",
        missing.into_inner().missing_blob_digests.len()
    );
    Ok(())
}

fn synthetic_action(name: &str) -> ActionDigest {
    Digest::of(format!("hartland test action {name}").as_bytes()).into()
}

async fn ac_put(addr: &str, name: &str) -> anyhow::Result<()> {
    let action = synthetic_action(name);
    let out = upload(addr, format!("output of {name}").into_bytes()).await?;
    let result = re::ActionResult {
        output_files: vec![re::OutputFile {
            path: "out.txt".into(),
            digest: Some(out.into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    re::action_cache_client::ActionCacheClient::connect(addr.to_string())
        .await?
        .update_action_result(re::UpdateActionResultRequest {
            action_digest: Some(Digest::from(action).into()),
            action_result: Some(result),
            ..Default::default()
        })
        .await?;
    println!("stored {}", action.id);
    Ok(())
}

async fn ac_get(addr: &str, name: &str, expect: Option<Expect>) -> anyhow::Result<()> {
    let action = synthetic_action(name);
    let mut ac = re::action_cache_client::ActionCacheClient::connect(addr.to_string()).await?;
    let request = re::GetActionResultRequest {
        action_digest: Some(Digest::from(action).into()),
        ..Default::default()
    };
    let found = match ac.get_action_result(request).await {
        Ok(_) => Expect::Found,
        Err(s) if s.code() == tonic::Code::NotFound => Expect::Missing,
        Err(s) => bail!("unexpected: {s}"),
    };
    println!(
        "{} {}",
        action.id,
        if found == Expect::Found {
            "found"
        } else {
            "missing"
        }
    );
    if let Some(want) = expect {
        ensure!(
            found == want,
            "expected {}",
            if want == Expect::Found {
                "found"
            } else {
                "missing"
            }
        );
    }
    Ok(())
}
