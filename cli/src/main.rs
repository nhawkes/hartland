use futures::StreamExt as _;
use hartland::attest::{ActionResult, Envelope, Statement, sha256_hex};
use hartland::jwt::Jwks;
use hartland::keyring::Keyring;
use hartland::reapi::re;
use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "usage:
  hartland attest sign --results <results.json> --out <envelope.json>
      Inside a GitHub Actions job: sign a batch of action results.
  hartland attest verify --envelope <envelope.json> --keyring <keyring.json> --jwks <jwks.json>
      Verify an envelope against a keyring and GitHub's key archive.
  hartland attest package --target T --repository R --commit C --out <envelope.json> --output name=path...
      Inside a GitHub Actions job: sign a package attestation.
  hartland attest verify-package --envelope e --keyring k --jwks j [--output name=path...]
      Verify a package attestation, optionally against files.
  hartland jwks update --jwks <jwks.json>
      Merge GitHub's current signing keys into the archive (never removes).
  hartland sandbox setup
      Prepare a GitHub-hosted runner for sandboxed actions (needs sudo).
  hartland sandbox run --input <dir> --collect <dir> [--output <path>]... [--env K=V]... [--no-drop-user] -- <argv>...
      Run one action in the sandbox; copy declared outputs to --collect.
  hartland proxy serve --dir <store> --listen <addr:port> [--execute sandbox|unprivileged]
                       [--registry ghcr.io --read ns[,ns] [--write ns] --keyring k --jwks j [--publish-every secs]]
      Serve the Remote Execution API.
  hartland proxy check|put|ac-put|ac-get --addr <url> ...
      Test clients.
  hartland oci probe|retag ...
      Registry spikes and test helpers.";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hartland: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = match args {
        [a, b, rest @ ..] => (format!("{a} {b}"), rest),
        _ => return Err(USAGE.to_string()),
    };
    match cmd.as_str() {
        "attest sign" => attest_sign(&flags(rest)?).await,
        "attest verify" => attest_verify(&flags(rest)?).await,
        "attest package" | "attest verify-package" => package_cmd(&cmd, rest).await,
        "jwks update" => jwks_update(&flags(rest)?).await,
        "sandbox setup" => hartland::sandbox::setup().await,
        "sandbox run" => sandbox_run(rest).await,
        "proxy serve" => proxy_serve(&flags(rest)?).await,
        "proxy check" => proxy_check(&flags(rest)?).await,
        "proxy put" => proxy_put(&flags(rest)?).await,
        "proxy ac-put" | "proxy ac-get" => proxy_ac(cmd == "proxy ac-put", &flags(rest)?).await,
        "oci probe" => oci_probe(&flags(rest)?).await,
        "oci retag" => oci_retag(&flags(rest)?).await,
        _ => Err(USAGE.to_string()),
    }
}

fn flags(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let k = a.strip_prefix("--").ok_or_else(|| format!("unexpected argument {a}\n{USAGE}"))?;
        let v = it.next().ok_or_else(|| format!("--{k} needs a value"))?;
        out.insert(k.to_string(), v.clone());
    }
    Ok(out)
}

fn need<'a>(f: &'a HashMap<String, String>, k: &str) -> Result<&'a str, String> {
    f.get(k).map(String::as_str).ok_or_else(|| format!("missing --{k}\n{USAGE}"))
}

async fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = tokio::fs::read(path).await.map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{path}: {e}"))
}

async fn write_json<T: serde::Serialize>(path: &str, v: &T) -> Result<(), String> {
    let mut s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    s.push('\n');
    tokio::fs::write(path, s).await.map_err(|e| format!("{path}: {e}"))
}

fn print_json(v: &serde_json::Value) -> Result<(), String> {
    println!("{}", serde_json::to_string_pretty(v).map_err(|e| e.to_string())?);
    Ok(())
}

fn registry_credentials() -> Result<(String, String), String> {
    Ok((
        std::env::var("REGISTRY_USER").map_err(|_| "REGISTRY_USER not set")?,
        std::env::var("REGISTRY_PASSWORD").map_err(|_| "REGISTRY_PASSWORD not set")?,
    ))
}

// ---- attestations ---------------------------------------------------------

async fn attest_sign(f: &HashMap<String, String>) -> Result<(), String> {
    let results: Vec<ActionResult> = read_json(need(f, "results")?).await?;
    let statement = Statement::new(results);
    statement.check()?;
    let payload = hartland::statement_bytes(&statement);
    let token = hartland::github::request_token(&hartland::attest::audience_for(&payload)).await?;
    write_json(need(f, "out")?, &Envelope::new(&payload, token)).await?;
    eprintln!("signed {} results", statement.predicate.results.len());
    Ok(())
}

async fn attest_verify(f: &HashMap<String, String>) -> Result<(), String> {
    let env: Envelope = read_json(need(f, "envelope")?).await?;
    let keyring: Keyring = read_json(need(f, "keyring")?).await?;
    let jwks: Jwks = read_json(need(f, "jwks")?).await?;
    let (statement, signer) = hartland::verify_envelope(&env, &jwks, &keyring)?;
    print_json(&serde_json::json!({"signer": signer, "results": statement.predicate.results}))
}

async fn package_cmd(cmd: &str, args: &[String]) -> Result<(), String> {
    use hartland::package::{Package, PackageStatement};
    let mut single = HashMap::new();
    let mut outputs = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let k = a.strip_prefix("--").ok_or_else(|| format!("unexpected argument {a}\n{USAGE}"))?;
        let v = it.next().ok_or_else(|| format!("--{k} needs a value"))?;
        if k == "output" {
            let (name, path) = v.split_once('=').ok_or_else(|| format!("--output wants name=path, got {v}"))?;
            outputs.push((name.to_string(), path.to_string()));
        } else {
            single.insert(k.to_string(), v.clone());
        }
    }
    async fn hash(path: &str) -> Result<String, String> {
        Ok(sha256_hex(&tokio::fs::read(path).await.map_err(|e| format!("{path}: {e}"))?))
    }
    if cmd == "attest package" {
        let mut digests = std::collections::BTreeMap::new();
        for (name, path) in &outputs {
            digests.insert(name.clone(), hash(path).await?);
        }
        let st = PackageStatement::new(
            Package {
                target: need(&single, "target")?.to_string(),
                repository: need(&single, "repository")?.to_string(),
                commit: need(&single, "commit")?.to_string(),
            },
            digests,
        );
        st.check()?;
        let payload = hartland::package::statement_bytes(&st);
        let token = hartland::github::request_token(&hartland::attest::audience_for(&payload)).await?;
        write_json(need(&single, "out")?, &Envelope::new(&payload, token)).await?;
        eprintln!("attested {} ({} outputs)", st.predicate.target, st.subject.len());
        return Ok(());
    }
    let env: Envelope = read_json(need(&single, "envelope")?).await?;
    let keyring: Keyring = read_json(need(&single, "keyring")?).await?;
    let jwks: Jwks = read_json(need(&single, "jwks")?).await?;
    let (st, signer) = hartland::package::verify(&env, &jwks, &keyring)?;
    for (name, path) in &outputs {
        let want = st.digest_of(name).ok_or_else(|| format!("{name} is not an attested output of {}", st.predicate.target))?;
        let got = hash(path).await?;
        if got != want {
            return Err(format!("{path} does not match the attested {name}: {got} != {want}"));
        }
    }
    print_json(&serde_json::json!({"package": st.predicate, "outputs": st.subject, "signer": signer, "files_checked": outputs.len()}))
}

async fn jwks_update(f: &HashMap<String, String>) -> Result<(), String> {
    let path = need(f, "jwks")?;
    let mut archive: Jwks = if tokio::fs::try_exists(path).await.unwrap_or(false) { read_json(path).await? } else { Jwks::default() };
    let added = archive.merge(&hartland::github::fetch_jwks().await?)?;
    write_json(path, &archive).await?;
    eprintln!("{added} new key(s); {} in archive", archive.keys.len());
    Ok(())
}

// ---- sandbox --------------------------------------------------------------

async fn sandbox_run(args: &[String]) -> Result<(), String> {
    let split = args.iter().position(|a| a == "--").ok_or_else(|| format!("missing -- before argv\n{USAGE}"))?;
    let (opts, argv) = (&args[..split], &args[split + 1..]);
    let (mut input, mut collect, mut outputs, mut env, mut drop_user) = (None, None, Vec::new(), Vec::new(), true);
    let mut it = opts.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--input" => input = Some(val()?),
            "--collect" => collect = Some(val()?),
            "--output" => outputs.push(val()?),
            "--env" => {
                let kv = val()?;
                let (k, v) = kv.split_once('=').ok_or_else(|| format!("--env wants K=V, got {kv}"))?;
                env.push((k.to_string(), v.to_string()));
            }
            "--no-drop-user" => drop_user = false,
            _ => return Err(format!("unexpected argument {a}\n{USAGE}")),
        }
    }
    let input = input.ok_or("missing --input")?;
    let collect = collect.ok_or("missing --collect")?;
    let outcome = hartland::sandbox::exec(&hartland::sandbox::Spec {
        input: std::path::Path::new(&input),
        argv,
        env: &env,
        workdir: "",
        outputs: &outputs,
        collect: std::path::Path::new(&collect),
        drop_user,
        take_input: false,
        ro_binds: &[],
    })
    .await?;
    use std::io::Write as _;
    std::io::stdout().write_all(&outcome.stdout).map_err(|e| e.to_string())?;
    std::io::stderr().write_all(&outcome.stderr).map_err(|e| e.to_string())?;
    if !outcome.missing.is_empty() {
        return Err(format!("missing outputs: {}", outcome.missing.join(", ")));
    }
    if outcome.exit_code != 0 {
        return Err(format!("action exited with {}", outcome.exit_code));
    }
    Ok(())
}

// ---- proxy ----------------------------------------------------------------

/// `--execute sandbox` runs actions as the sandbox uid (runners);
/// `--execute unprivileged` runs bwrap as the current user (local dev).
async fn with_execution(
    f: &HashMap<String, String>,
    proxy: hartland::proxy::Proxy,
    store: Arc<dyn hartland::proxy::Store>,
) -> Result<hartland::proxy::Proxy, String> {
    let drop_user = match f.get("execute").map(String::as_str) {
        None => return Ok(proxy),
        Some("sandbox") => true,
        Some("unprivileged") => false,
        Some(o) => return Err(format!("--execute wants sandbox|unprivileged, got {o}")),
    };
    // Under the system temp dir: the sandbox uid must be able to traverse to
    // its scratch directories and the read-only directory cache.
    let scratch = std::env::temp_dir().join(format!("hartland-exec-{}", std::process::id()));
    tokio::fs::create_dir_all(&scratch).await.map_err(|e| e.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o755)).await.map_err(|e| e.to_string())?;
    }
    eprintln!("hartland proxy: remote execution enabled ({})", if drop_user { "sandbox uid" } else { "unprivileged" });
    Ok(proxy.with_executor(hartland::execute::Executor::new(store, drop_user, scratch)))
}

/// Registry-backed store; credentials from REGISTRY_USER / REGISTRY_PASSWORD
/// (in Actions: github.actor / github.token).
async fn ghcr_store(f: &HashMap<String, String>, disk: hartland::proxy::DiskStore) -> Result<hartland::ghcr_store::GhcrStore, String> {
    use hartland::oci::Registry;
    let host = need(f, "registry")?;
    let creds = registry_credentials().ok();
    let open = |repo: String| {
        let creds = creds.clone();
        async move {
            let mut r = Registry::new(host, &repo);
            if let Some((u, p)) = creds {
                r.login(&u, &p).await?;
            }
            Ok::<_, String>(r)
        }
    };
    let mut readers = Vec::new();
    for repo in need(f, "read")?.split(',').filter(|s| !s.is_empty()) {
        readers.push(open(repo.to_string()).await?);
    }
    let writer = match f.get("write") {
        Some(w) => Some(open(w.clone()).await?),
        None => None,
    };
    let keyring: Keyring = read_json(need(f, "keyring")?).await?;
    let jwks: Jwks = read_json(need(f, "jwks")?).await?;
    Ok(hartland::ghcr_store::GhcrStore::new(disk, readers, writer, keyring, jwks))
}

fn report_publish(r: Result<usize, String>) {
    match r {
        Ok(0) => {}
        Ok(n) => eprintln!("hartland proxy: published {n} signed result(s)"),
        Err(e) => eprintln!("hartland proxy: publish failed: {e}"),
    }
}

async fn proxy_serve(f: &HashMap<String, String>) -> Result<(), String> {
    let disk = hartland::proxy::DiskStore::new(need(f, "dir")?.into()).await?;
    let addr: std::net::SocketAddr = need(f, "listen")?.parse().map_err(|e| format!("--listen: {e}"))?;
    if f.get("registry").is_none() {
        eprintln!("hartland proxy (disk) listening on {addr}");
        let store: Arc<dyn hartland::proxy::Store> = Arc::new(disk);
        return with_execution(f, hartland::proxy::Proxy::new(store.clone()), store).await?.serve(addr).await;
    }
    let store = Arc::new(ghcr_store(f, disk).await?);
    let every: u64 = f.get("publish-every").map(|s| s.parse()).transpose().map_err(|e| format!("--publish-every: {e}"))?.unwrap_or(300);
    eprintln!("hartland proxy (registry) listening on {addr}");
    let dyn_store: Arc<dyn hartland::proxy::Store> = store.clone();
    let serve = with_execution(f, hartland::proxy::Proxy::new(dyn_store.clone()), dyn_store).await?.serve(addr);
    let periodic = {
        let store = store.clone();
        async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(every.max(1)));
            tick.tick().await;
            loop {
                tick.tick().await;
                report_publish(store.publish().await);
            }
        }
    };
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        r = serve => r?,
        _ = periodic => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    eprintln!("hartland proxy: shutting down; publishing pending results");
    report_publish(store.publish().await);
    Ok(())
}

async fn cas_client(addr: &str) -> Result<re::content_addressable_storage_client::ContentAddressableStorageClient<tonic::transport::Channel>, String> {
    Ok(re::content_addressable_storage_client::ContentAddressableStorageClient::connect(addr.to_string())
        .await
        .map_err(|e| format!("connect {addr}: {e}"))?
        .max_decoding_message_size(64 << 20)
        .max_encoding_message_size(64 << 20))
}

async fn upload(addr: &str, data: Vec<u8>) -> Result<re::Digest, String> {
    let digest = re::Digest { hash: sha256_hex(&data), size_bytes: data.len() as i64 };
    cas_client(addr)
        .await?
        .batch_update_blobs(re::BatchUpdateBlobsRequest {
            requests: vec![re::batch_update_blobs_request::Request { digest: Some(digest.clone()), data, compressor: 0 }],
            ..Default::default()
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(digest)
}

async fn proxy_put(f: &HashMap<String, String>) -> Result<(), String> {
    let data = tokio::fs::read(need(f, "file")?).await.map_err(|e| e.to_string())?;
    let d = upload(need(f, "addr")?, data).await?;
    println!("{}/{}", d.hash, d.size_bytes);
    Ok(())
}

async fn proxy_check(f: &HashMap<String, String>) -> Result<(), String> {
    let addr = need(f, "addr")?;
    let mut caps = re::capabilities_client::CapabilitiesClient::connect(addr.to_string()).await.map_err(|e| format!("connect: {e}"))?;
    let c = caps.get_capabilities(re::GetCapabilitiesRequest::default()).await.map_err(|e| e.to_string())?;
    println!("capabilities: {:?}", c.into_inner().cache_capabilities.map(|c| c.digest_functions));
    let digest = upload(addr, b"hartland proxy check".to_vec()).await?;
    let missing = cas_client(addr)
        .await?
        .find_missing_blobs(re::FindMissingBlobsRequest { blob_digests: vec![digest], ..Default::default() })
        .await
        .map_err(|e| e.to_string())?;
    println!("missing after upload: {}", missing.into_inner().missing_blob_digests.len());
    Ok(())
}

/// Test client: `ac-put --action <name>` stores a result for a synthetic
/// action; `ac-get --action <name> --expect found|missing` checks it.
async fn proxy_ac(put: bool, f: &HashMap<String, String>) -> Result<(), String> {
    let addr = need(f, "addr")?;
    let name = need(f, "action")?;
    let action = format!("hartland test action {name}").into_bytes();
    let action_digest = re::Digest { hash: sha256_hex(&action), size_bytes: action.len() as i64 };
    let mut ac = re::action_cache_client::ActionCacheClient::connect(addr.to_string()).await.map_err(|e| e.to_string())?;
    if put {
        let out_digest = upload(addr, format!("output of {name}").into_bytes()).await?;
        let result = re::ActionResult {
            output_files: vec![re::OutputFile { path: "out.txt".into(), digest: Some(out_digest), ..Default::default() }],
            ..Default::default()
        };
        ac.update_action_result(re::UpdateActionResultRequest { action_digest: Some(action_digest.clone()), action_result: Some(result), ..Default::default() })
            .await
            .map_err(|e| e.to_string())?;
        println!("stored {}", action_digest.hash);
        return Ok(());
    }
    let found = match ac.get_action_result(re::GetActionResultRequest { action_digest: Some(action_digest.clone()), ..Default::default() }).await {
        Ok(_) => true,
        Err(s) if s.code() == tonic::Code::NotFound => false,
        Err(s) => return Err(format!("unexpected: {s}")),
    };
    println!("{} {}", action_digest.hash, if found { "found" } else { "missing" });
    match f.get("expect").map(String::as_str) {
        Some("found") if !found => Err("expected found".to_string()),
        Some("missing") if found => Err("expected missing".to_string()),
        _ => Ok(()),
    }
}

// ---- registry spikes ------------------------------------------------------

async fn logged_in(f: &HashMap<String, String>, repo: &str) -> Result<hartland::oci::Registry, String> {
    let (user, pass) = registry_credentials()?;
    let mut reg = hartland::oci::Registry::new(need(f, "registry")?, repo);
    reg.login(&user, &pass).await?;
    Ok(reg)
}

/// Test helper: copy a manifest to another tag (e.g. to forge an entry).
async fn oci_retag(f: &HashMap<String, String>) -> Result<(), String> {
    let reg = logged_in(f, need(f, "repo")?).await?;
    let m = reg.get_manifest(need(f, "from")?).await?;
    if m.status != 200 {
        return Err(format!("get manifest: {}", m.status));
    }
    let media = m.header("Content-Type").unwrap_or(hartland::oci::MANIFEST_MEDIA_TYPE).to_string();
    println!("{}", reg.put_manifest(need(f, "to")?, &media, &m.body).await?);
    Ok(())
}

/// Spike: how well does a registry (GHCR) work as an action cache?
async fn oci_probe(f: &HashMap<String, String>) -> Result<(), String> {
    use hartland::oci::{MANIFEST_MEDIA_TYPE, Registry};
    use serde_json::json;
    use std::time::Instant;

    let repo = need(f, "repo")?;
    let count: usize = need(f, "count")?.parse().map_err(|e| format!("--count: {e}"))?;
    let parallel: usize = f.get("parallel").map(|p| p.parse()).transpose().map_err(|e| format!("--parallel: {e}"))?.unwrap_or(1).max(1);
    let salt = f.get("salt").cloned().unwrap_or_default();
    let anon = Registry::new(need(f, "registry")?, repo);
    let reg = logged_in(f, repo).await?;
    let mut report = serde_json::Map::new();
    report.insert("parallel".into(), json!(parallel));

    // 1. Many small blobs, `parallel` in flight.
    let start = Instant::now();
    let results: Vec<Result<String, String>> = futures::stream::iter(0..count)
        .map(|i| {
            let (reg, salt) = (&reg, &salt);
            async move { reg.put_blob(format!("hartland probe blob {salt} {i}").as_bytes()).await }
        })
        .buffer_unordered(parallel)
        .collect()
        .await;
    let ms = start.elapsed().as_millis();
    let failures: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).take(5).collect();
    let mut hashes: Vec<String> = results.iter().filter_map(|r| r.as_ref().ok().cloned()).collect();
    hashes.sort();
    report.insert("blobs_pushed".into(), json!(hashes.len()));
    report.insert("blob_failures".into(), json!(failures));
    report.insert("blob_push_ms_total".into(), json!(ms));
    report.insert("blob_push_ms_each".into(), json!(ms as f64 / count.max(1) as f64));
    let start = Instant::now();
    let exists = futures::stream::iter(&hashes)
        .map(|h| reg.blob_exists(h))
        .buffer_unordered(parallel)
        .filter(|r| futures::future::ready(matches!(r, Ok(true))))
        .count()
        .await;
    report.insert("blob_exists_ms_each".into(), json!(start.elapsed().as_millis() as f64 / hashes.len().max(1) as f64));
    report.insert("blobs_found".into(), json!(exists));
    if let Some(h) = hashes.first() {
        let r = reg.get_blob(h).await;
        report.insert("blob_roundtrip_ok".into(), json!(r.is_ok()));
        if let Err(e) = r {
            report.insert("blob_roundtrip_error".into(), json!(e.chars().take(400).collect::<String>()));
        }
        if let Ok(raw) = reg.get_blob_raw(h).await {
            report.insert("blob_get_status".into(), json!(raw.status));
            report.insert("blob_get_location_host".into(), json!(raw.header("Location").map(|l| l.split('/').nth(2).unwrap_or("").to_string())));
        }
    }

    // 2. A cache entry: manifest tagged with the action digest.
    let empty = reg.put_blob(b"{}").await?;
    let layer = |h: &String| json!({"mediaType": "application/octet-stream", "digest": format!("sha256:{h}"), "size": format!("hartland probe blob {salt} 0").len()});
    let entry = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": "application/vnd.hartland.action-result.v0",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": format!("sha256:{empty}"), "size": 2},
        "layers": hashes.iter().take(1).map(layer).collect::<Vec<_>>(),
    });
    let entry_bytes = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
    let action_tag = sha256_hex(format!("hartland probe action {salt}").as_bytes());
    let entry_digest = reg.put_manifest(&action_tag, MANIFEST_MEDIA_TYPE, &entry_bytes).await?;
    report.insert("entry_digest".into(), json!(entry_digest));
    let got = reg.get_manifest(&action_tag).await?;
    report.insert("entry_by_tag_status".into(), json!(got.status));
    report.insert("entry_by_tag_same_bytes".into(), json!(got.body == entry_bytes));

    // 3. A signature artifact attached via `subject`, then referrers.
    let sig_blob = reg.put_blob(format!("probe signature {salt}").as_bytes()).await?;
    let sig = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": "application/vnd.hartland.attestation.v0+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": format!("sha256:{empty}"), "size": 2},
        "layers": [{"mediaType": "application/vnd.hartland.attestation.v0+json", "digest": format!("sha256:{sig_blob}"), "size": format!("probe signature {salt}").len()}],
        "subject": {"mediaType": MANIFEST_MEDIA_TYPE, "digest": entry_digest, "size": entry_bytes.len()},
    });
    let sig_bytes = serde_json::to_vec(&sig).map_err(|e| e.to_string())?;
    match reg.put_manifest(&format!("sha256:{}", sha256_hex(&sig_bytes)), MANIFEST_MEDIA_TYPE, &sig_bytes).await {
        Ok(d) => report.insert("sig_put".into(), json!(d)),
        Err(e) => report.insert("sig_put_error".into(), json!(e)),
    };
    let refs = reg.referrers(&entry_digest).await?;
    report.insert("referrers_status".into(), json!(refs.status));
    report.insert("referrers_body".into(), json!(String::from_utf8_lossy(&refs.body).chars().take(600).collect::<String>()));
    let rate: Vec<_> = refs.headers.iter().filter(|(k, _)| k.to_ascii_lowercase().contains("ratelimit")).collect();
    report.insert("ratelimit_headers".into(), json!(rate));

    // 4. Anonymous read (private packages should refuse).
    report.insert("anonymous_manifest_status".into(), json!(anon.get_manifest(&action_tag).await?.status));
    print_json(&serde_json::Value::Object(report))
}
