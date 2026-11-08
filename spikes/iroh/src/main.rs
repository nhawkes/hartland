//! Spike: can two GitHub-hosted runners in one workflow run reach each other
//! over iroh, and can they authenticate each other with OIDC tokens alone?
//!
//! `listen` binds an endpoint, mints a token whose audience names its
//! endpoint key, and publishes both to a run-specific GHCR tag. `connect`
//! reads that, checks the listener's token, dials, and sends its own token,
//! which the listener checks. Then `connect` streams a fixed payload and
//! both sides report the path (direct or relayed), RTT and throughput.
//!
//! Neither side waits for long: each has a hard deadline and exits as soon
//! as the test is done, so an absent peer costs minutes, not hours.

#![forbid(unsafe_code)]

use anyhow::{Context as _, bail, ensure};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use hartland::digest::{GitSha, Sha256};
use hartland::jwt::Jwks;
use hartland::keyring::{Claims, Keyring, Signer, Workflow};
use hartland::oci::{Reference, Registry, Tag};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use oci_spec::image::{DescriptorBuilder, ImageManifestBuilder, MediaType};
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const ALPN: &[u8] = b"hartland/spike-peer/0";
const RENDEZVOUS_MEDIA_TYPE: &str = "application/vnd.hartland.spike.rendezvous.v0+json";
const PAYLOAD_BYTES: usize = 256 << 20;
const CHUNK: usize = 1 << 20;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    role: Role,
    /// GHCR namespace for the rendezvous tag, e.g. owner/hartland-spike-cache.
    #[arg(long)]
    namespace: String,
    /// The workflow both peers must be running (owner/repo/.github/workflows/x.yml).
    #[arg(long)]
    workflow: Workflow,
    /// The workflow commit both peers must be running.
    #[arg(long)]
    commit: GitSha,
    /// This run's id: peers must belong to the same run.
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    jwks: PathBuf,
    /// Report file (JSON).
    #[arg(long)]
    out: PathBuf,
    /// Give up after this many seconds.
    #[arg(long, default_value_t = 180)]
    deadline: u64,
}

#[derive(Subcommand)]
enum Role {
    Listen,
    Connect,
}

/// The audience binding an OIDC token to one iroh endpoint key.
struct PeerAudience(EndpointId);

impl fmt::Display for PeerAudience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hartland-peer:{}", self.0)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Rendezvous {
    addr: EndpointAddr,
    token: String,
}

struct Trust {
    keyring: Keyring,
    jwks: Jwks,
    run_id: String,
}

impl Trust {
    /// The token must come from the trusted workflow, on a hosted runner,
    /// in this run, bound to `peer`'s key.
    fn check(&self, token: &str, peer: EndpointId) -> anyhow::Result<Signer> {
        let claims: Claims = hartland::jwt::verify(token, &self.jwks)?;
        let signer = self.keyring.accept(&claims, &PeerAudience(peer))?;
        ensure!(signer.run_id == self.run_id, "peer is from run {}, not {}", signer.run_id, self.run_id);
        Ok(signer)
    }
}

#[derive(serde::Serialize, Default)]
struct Report {
    role: &'static str,
    endpoint: String,
    direct_addrs: Vec<String>,
    relay: Option<String>,
    peer_verified: Option<String>,
    rendezvous_wait_ms: Option<u128>,
    connect_ms: Option<u128>,
    /// (seconds since connect, selected path is direct, rtt ms) samples.
    paths: Vec<(f64, bool, u128)>,
    bytes: usize,
    transfer_ms: Option<u128>,
    mbit_per_s: Option<f64>,
    error: Option<String>,
}

fn rendezvous_tag(run_id: &str) -> Tag {
    format!("spike-iroh-{run_id}").parse().expect("a run id makes a valid tag")
}

async fn registry(namespace: &str) -> anyhow::Result<Registry> {
    let mut r = Registry::new("ghcr.io", namespace);
    let (user, password) = (std::env::var("REGISTRY_USER")?, std::env::var("REGISTRY_PASSWORD")?);
    r.login(&user, &password).await?;
    Ok(r)
}

async fn publish(reg: &Registry, tag: Tag, r: &Rendezvous) -> anyhow::Result<()> {
    let body = Bytes::from(serde_json::to_vec(r)?);
    let layer = reg.put_blob(body.clone()).await?;
    let empty = reg.put_blob(Bytes::from_static(b"{}")).await?;
    let descriptor = |media: &str, d: Sha256, size: usize| {
        DescriptorBuilder::default().media_type(MediaType::Other(media.to_string())).digest(d.oci()).size(size as u64).build()
    };
    let manifest = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(descriptor("application/vnd.oci.empty.v1+json", empty, 2)?)
        .layers(vec![descriptor(RENDEZVOUS_MEDIA_TYPE, layer, body.len())?])
        .build()?;
    reg.put_manifest(&Reference::Tag(tag), &manifest).await?;
    Ok(())
}

async fn fetch(reg: &Registry, tag: &Tag) -> anyhow::Result<Option<Rendezvous>> {
    let Some(m) = reg.get_manifest(&Reference::Tag(tag.clone())).await? else { return Ok(None) };
    let layer = m.layers().first().context("rendezvous manifest has no layer")?;
    let data = reg.get_blob(&Sha256::from_oci(layer.digest())?).await?.context("rendezvous blob missing")?;
    Ok(Some(serde_json::from_slice(&data)?))
}

async fn bind() -> anyhow::Result<Endpoint> {
    let ep = Endpoint::builder(presets::N0).alpns(vec![ALPN.to_vec()]).bind().await?;
    ep.online().await;
    Ok(ep)
}

fn describe(ep: &Endpoint, role: &'static str) -> Report {
    let addr = ep.addr();
    Report {
        role,
        endpoint: ep.id().to_string(),
        direct_addrs: addr.ip_addrs().map(ToString::to_string).collect(),
        relay: addr.relay_urls().next().map(ToString::to_string),
        ..Report::default()
    }
}

fn sample(conn: &iroh::endpoint::Connection, since: Instant, into: &mut Vec<(f64, bool, u128)>) {
    if let Some(p) = conn.paths().iter().find(|p| p.is_selected()) {
        into.push((since.elapsed().as_secs_f64(), p.is_ip(), p.rtt().as_millis()));
    }
}

async fn listen(cli: &Cli, trust: &Trust, report: &mut Report, ep: &Endpoint) -> anyhow::Result<()> {
    let token = hartland::github::request_token(&PeerAudience(ep.id())).await?;
    let reg = registry(&cli.namespace).await?;
    publish(&reg, rendezvous_tag(&cli.run_id), &Rendezvous { addr: ep.addr(), token }).await?;
    tracing::info!("published rendezvous; waiting for a peer");

    let incoming = ep.accept().await.context("endpoint closed")?;
    let conn = incoming.await?;
    let started = Instant::now();
    let (mut send, mut recv) = conn.accept_bi().await?;
    let peer_token = String::from_utf8(recv.read_to_end(16 << 10).await?)?;
    let signer = trust.check(&peer_token, conn.remote_id())?;
    report.peer_verified = Some(format!("{}@{} run {}", signer.workflow, signer.commit, signer.run_id));
    send.write_all(b"ok").await?;
    send.finish()?;

    let mut data = conn.accept_uni().await?;
    let t = Instant::now();
    let mut total = 0usize;
    let mut buf = vec![0u8; CHUNK];
    while let Some(n) = data.read(&mut buf).await? {
        total += n;
        if total % (32 << 20) < n {
            sample(&conn, started, &mut report.paths);
        }
    }
    let ms = t.elapsed().as_millis().max(1);
    sample(&conn, started, &mut report.paths);
    report.bytes = total;
    report.transfer_ms = Some(ms);
    report.mbit_per_s = Some(total as f64 * 8.0 / 1e6 / (ms as f64 / 1e3));
    conn.closed().await;
    Ok(())
}

async fn connect(cli: &Cli, trust: &Trust, report: &mut Report, ep: &Endpoint) -> anyhow::Result<()> {
    let reg = registry(&cli.namespace).await?;
    let tag = rendezvous_tag(&cli.run_id);
    let waited = Instant::now();
    let rendezvous = loop {
        if let Some(r) = fetch(&reg, &tag).await? {
            break r;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    report.rendezvous_wait_ms = Some(waited.elapsed().as_millis());
    let listener = trust.check(&rendezvous.token, rendezvous.addr.id)?;
    tracing::info!(listener = %listener.run_id, "listener's token verified; dialling");

    let t = Instant::now();
    let conn = ep.connect(rendezvous.addr, ALPN).await?;
    report.connect_ms = Some(t.elapsed().as_millis());
    let started = Instant::now();
    sample(&conn, started, &mut report.paths);
    report.peer_verified = Some(format!("{}@{} run {}", listener.workflow, listener.commit, listener.run_id));

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(hartland::github::request_token(&PeerAudience(ep.id())).await?.as_bytes()).await?;
    send.finish()?;
    if recv.read_to_end(16).await? != b"ok" {
        bail!("listener refused our token");
    }

    let mut data = conn.open_uni().await?;
    let chunk = vec![0x5au8; CHUNK];
    let t = Instant::now();
    for i in 0..PAYLOAD_BYTES / CHUNK {
        data.write_all(&chunk).await?;
        if i % 32 == 0 {
            sample(&conn, started, &mut report.paths);
        }
    }
    data.finish()?;
    data.stopped().await?;
    let ms = t.elapsed().as_millis().max(1);
    sample(&conn, started, &mut report.paths);
    report.bytes = PAYLOAD_BYTES;
    report.transfer_ms = Some(ms);
    report.mbit_per_s = Some(PAYLOAD_BYTES as f64 * 8.0 / 1e6 / (ms as f64 / 1e3));
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
        run_id: cli.run_id.clone(),
    };
    let ep = bind().await?;
    let role = match cli.role {
        Role::Listen => "listen",
        Role::Connect => "connect",
    };
    let mut report = describe(&ep, role);
    let work = async {
        match cli.role {
            Role::Listen => listen(&cli, &trust, &mut report, &ep).await,
            Role::Connect => connect(&cli, &trust, &mut report, &ep).await,
        }
    };
    let outcome = tokio::time::timeout(Duration::from_secs(cli.deadline), work).await;
    if let Some(e) = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(format!("{e:#}")),
        Err(_) => Some(format!("gave up after {} s", cli.deadline)),
    } {
        report.error = Some(e);
    }
    ep.close().await;
    let json = serde_json::to_string(&report)?;
    tokio::fs::write(&cli.out, &json).await?;
    println!("{json}");
    Ok(())
}
