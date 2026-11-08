//! Spike: a coordinator job dispatches a worker as a separate workflow run,
//! and the two prove to each other, by a chain of keys, that they are the
//! trusted builder serving the same build.
//!
//! Each job holds one Ed25519 key, which is also its iroh endpoint key, and
//! one OIDC token whose audience is `hartland-key:<public key>`: GitHub's
//! certificate that the trusted builder, on a hosted runner, running for
//! repository R in run N, holds that key.
//!
//! * The coordinator dispatches the worker with its public key and run id as
//!   inputs, then waits.
//! * The worker dials the coordinator by key (iroh's handshake proves the
//!   key), receives the coordinator's certificate and checks it: trusted
//!   builder, hosted runner, its own repository, the run named in its inputs.
//! * The worker sends its certificate and a signature, by its key, over
//!   "member of <coordinator key>". The coordinator checks the certificate
//!   (trusted builder, hosted runner, its own repository) and the signature.
//!
//! Both report the claims GitHub put in the other's token, the path taken
//! and a short transfer. Hard deadlines: an absent peer costs minutes.

#![forbid(unsafe_code)]

use anyhow::{Context as _, ensure};
use clap::{Parser, Subcommand};
use hartland::digest::GitSha;
use hartland::jwt::Jwks;
use hartland::keyring::{Claims, Keyring, Signer, Workflow};
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, Signature};
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const ALPN: &[u8] = b"hartland/spike-chain/0";
const PAYLOAD_BYTES: usize = 64 << 20;
const CHUNK: usize = 1 << 20;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    role: Role,
    /// The builder workflow both sides must be running.
    #[arg(long)]
    workflow: Workflow,
    /// The builder commit both sides must be running.
    #[arg(long)]
    commit: GitSha,
    #[arg(long)]
    jwks: PathBuf,
    /// Report file (JSON).
    #[arg(long)]
    out: PathBuf,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 240)]
    deadline: u64,
}

#[derive(Subcommand)]
enum Role {
    /// Bind, write our key to `key_file` (for the dispatch step), wait for
    /// one worker.
    Coordinator {
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Dial the coordinator named in our dispatch inputs.
    Worker {
        #[arg(long)]
        coordinator: EndpointId,
        #[arg(long)]
        coordinator_run: String,
    },
}

/// The audience by which GitHub certifies that a job holds a key.
struct KeyAudience(EndpointId);

impl fmt::Display for KeyAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hartland-key:{}", self.0)
    }
}

/// What a worker signs to join a build.
fn membership(coordinator: EndpointId) -> Vec<u8> {
    format!("hartland-member:{coordinator}").into_bytes()
}

/// The claims worth seeing, as GitHub issued them.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Observed {
    repository: Option<String>,
    run_id: Option<String>,
    event_name: Option<String>,
    r#ref: Option<String>,
    workflow_ref: Option<String>,
    job_workflow_ref: Option<String>,
    job_workflow_sha: Option<String>,
    runner_environment: Option<String>,
    actor: Option<String>,
}

struct Trust {
    keyring: Keyring,
    jwks: Jwks,
    repository: String,
}

impl Trust {
    /// A certificate: the trusted builder, on a hosted runner, for our own
    /// repository, holding `key`.
    fn check(&self, token: &str, key: EndpointId) -> anyhow::Result<(Signer, Observed)> {
        let claims: Claims = hartland::jwt::verify(token, &self.jwks)?;
        let signer = self.keyring.accept(&claims, &KeyAudience(key))?;
        ensure!(signer.repository.to_string() == self.repository, "peer runs for {}, not {}", signer.repository, self.repository);
        let observed: Observed = hartland::jwt::verify(token, &self.jwks)?;
        Ok((signer, observed))
    }
}

#[derive(serde::Serialize, Default)]
struct Report {
    role: &'static str,
    key: String,
    peer: Option<Observed>,
    checks: Vec<String>,
    connect_ms: Option<u128>,
    /// (seconds since connect, selected path is direct, rtt ms) samples.
    paths: Vec<(f64, bool, u128)>,
    mbit_per_s: Option<f64>,
    error: Option<String>,
}

fn sample(conn: &Connection, since: Instant, into: &mut Vec<(f64, bool, u128)>) {
    if let Some(p) = conn.paths().iter().find(|p| p.is_selected()) {
        into.push((since.elapsed().as_secs_f64(), p.is_ip(), p.rtt().as_millis()));
    }
}

async fn send_msg(conn: &Connection, bytes: &[u8]) -> anyhow::Result<()> {
    let mut s = conn.open_uni().await?;
    s.write_all(bytes).await?;
    s.finish()?;
    s.stopped().await?;
    Ok(())
}

async fn recv_msg(conn: &Connection) -> anyhow::Result<Vec<u8>> {
    Ok(conn.accept_uni().await?.read_to_end(64 << 10).await?)
}

async fn coordinator(trust: &Trust, report: &mut Report, ep: &Endpoint, key_file: &PathBuf) -> anyhow::Result<()> {
    let certificate = hartland::github::request_token(&KeyAudience(ep.id())).await?;
    tokio::fs::write(key_file, ep.id().to_string()).await?;
    tracing::info!("key published for dispatch; waiting for a worker");

    let conn = ep.accept().await.context("endpoint closed")?.await?;
    let started = Instant::now();
    let worker = conn.remote_id();
    send_msg(&conn, certificate.as_bytes()).await?;

    let worker_cert = String::from_utf8(recv_msg(&conn).await?)?;
    let (signer, observed) = trust.check(&worker_cert, worker)?;
    report.checks.push(format!("worker certificate: {}@{} for {} run {}", signer.workflow, signer.commit, signer.repository, signer.run_id));
    ensure!(observed.event_name.as_deref() == Some("workflow_dispatch"), "worker run was not dispatched: {:?}", observed.event_name);
    report.checks.push("worker run was dispatched (event_name workflow_dispatch)".into());
    let sig = Signature::try_from(recv_msg(&conn).await?.as_slice())?;
    worker.verify(&membership(ep.id()), &sig)?;
    report.checks.push("worker signed membership of this coordinator with its certified key".into());
    report.peer = Some(observed);
    send_msg(&conn, b"accepted").await?;

    let mut data = conn.accept_uni().await?;
    let (t, mut total, mut buf) = (Instant::now(), 0usize, vec![0u8; CHUNK]);
    while let Some(n) = data.read(&mut buf).await? {
        total += n;
    }
    sample(&conn, started, &mut report.paths);
    report.mbit_per_s = Some(total as f64 * 8.0 / 1e6 / t.elapsed().as_secs_f64());
    conn.closed().await;
    Ok(())
}

async fn worker(trust: &Trust, report: &mut Report, ep: &Endpoint, coordinator: EndpointId, coordinator_run: &str) -> anyhow::Result<()> {
    let certificate = hartland::github::request_token(&KeyAudience(ep.id())).await?;
    let t = Instant::now();
    // By key alone: iroh finds the address through n0's DNS, and its
    // handshake proves the peer holds the key.
    let conn = ep.connect(EndpointAddr::from(coordinator), ALPN).await?;
    report.connect_ms = Some(t.elapsed().as_millis());
    let started = Instant::now();
    sample(&conn, started, &mut report.paths);

    let coord_cert = String::from_utf8(recv_msg(&conn).await?)?;
    let (signer, observed) = trust.check(&coord_cert, coordinator)?;
    ensure!(signer.run_id == coordinator_run, "coordinator is run {}, not {}", signer.run_id, coordinator_run);
    report.checks.push(format!("coordinator certificate: {}@{} for {} run {}", signer.workflow, signer.commit, signer.repository, signer.run_id));
    report.peer = Some(observed);

    send_msg(&conn, certificate.as_bytes()).await?;
    send_msg(&conn, &ep.secret_key().sign(&membership(coordinator)).to_bytes()).await?;
    ensure!(recv_msg(&conn).await? == b"accepted", "coordinator refused us");
    report.checks.push("coordinator accepted our membership".into());

    let mut data = conn.open_uni().await?;
    let chunk = vec![0x5au8; CHUNK];
    let t = Instant::now();
    for _ in 0..PAYLOAD_BYTES / CHUNK {
        data.write_all(&chunk).await?;
    }
    data.finish()?;
    data.stopped().await?;
    sample(&conn, started, &mut report.paths);
    report.mbit_per_s = Some(PAYLOAD_BYTES as f64 * 8.0 / 1e6 / t.elapsed().as_secs_f64());
    conn.close(0u32.into(), b"done");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let trust = Trust {
        keyring: Keyring::trusting(cli.workflow.clone(), [cli.commit]),
        jwks: serde_json::from_slice(&tokio::fs::read(&cli.jwks).await?)?,
        repository: std::env::var("GITHUB_REPOSITORY")?,
    };
    let ep = Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()]).bind().await?;
    ep.online().await;
    let role = match cli.role {
        Role::Coordinator { .. } => "coordinator",
        Role::Worker { .. } => "worker",
    };
    let mut report = Report { role, key: ep.id().to_string(), ..Report::default() };
    let work = async {
        match &cli.role {
            Role::Coordinator { key_file } => coordinator(&trust, &mut report, &ep, key_file).await,
            Role::Worker { coordinator: c, coordinator_run } => worker(&trust, &mut report, &ep, *c, coordinator_run).await,
        }
    };
    report.error = match tokio::time::timeout(Duration::from_secs(cli.deadline), work).await {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(format!("{e:#}")),
        Err(_) => Some(format!("gave up after {} s", cli.deadline)),
    };
    ep.close().await;
    let json = serde_json::to_string(&report)?;
    tokio::fs::write(&cli.out, &json).await?;
    println!("{json}");
    Ok(())
}
