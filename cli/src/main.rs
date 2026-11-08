use hartland::attest::{ActionResult, Envelope, Statement};
use hartland::jwt::Jwks;
use hartland::keyring::Keyring;
use std::collections::HashMap;
use std::process::ExitCode;

const USAGE: &str = "usage:
  hartland attest sign --results <results.json> --out <envelope.json>
      Inside a GitHub Actions job: sign a batch of action results.
  hartland attest verify --envelope <envelope.json> --keyring <keyring.json> --jwks <jwks.json>
      Verify an envelope against a keyring and GitHub's key archive.
  hartland jwks update --jwks <jwks.json>
      Merge GitHub's current signing keys into the archive (never removes).
  hartland sandbox setup
      Prepare a GitHub-hosted runner for sandboxed actions (needs sudo).
  hartland sandbox run --input <dir> --collect <dir> [--output <path>]... [--env K=V]... [--no-drop-user] -- <argv>...
      Run one action in the sandbox; copy declared outputs to --collect.
  hartland proxy serve --dir <store> --listen <addr:port>
      Serve the Remote Execution API cache (CAS, action cache, ByteStream).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hartland: {e}");
            ExitCode::FAILURE
        }
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

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{path}: {e}"))
}

fn write_json<T: serde::Serialize>(path: &str, v: &T) -> Result<(), String> {
    let mut s = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    s.push('\n');
    std::fs::write(path, s).map_err(|e| format!("{path}: {e}"))
}

fn sandbox_run(args: &[String]) -> Result<(), String> {
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
        outputs: &outputs,
        collect: std::path::Path::new(&collect),
        drop_user,
    })?;
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

/// Spike: how well does a registry (GHCR) work as an action cache?
/// Credentials come from REGISTRY_USER / REGISTRY_PASSWORD.
fn oci_probe(f: &HashMap<String, String>) -> Result<(), String> {
    use hartland::attest::sha256_hex;
    use hartland::oci::{MANIFEST_MEDIA_TYPE, Registry};
    use serde_json::json;
    use std::time::Instant;

    let host = need(f, "registry")?;
    let repo = need(f, "repo")?;
    let count: usize = need(f, "count")?.parse().map_err(|e| format!("--count: {e}"))?;
    let salt = f.get("salt").cloned().unwrap_or_default();
    let user = std::env::var("REGISTRY_USER").map_err(|_| "REGISTRY_USER not set")?;
    let pass = std::env::var("REGISTRY_PASSWORD").map_err(|_| "REGISTRY_PASSWORD not set")?;
    let mut report = serde_json::Map::new();

    let anon = Registry::new(host, repo);
    let mut reg = Registry::new(host, repo);
    reg.login(host, &user, &pass)?;

    // 1. Many small blobs, uploaded by `parallel` threads.
    let parallel: usize = f.get("parallel").map(|p| p.parse()).transpose().map_err(|e| format!("--parallel: {e}"))?.unwrap_or(1).max(1);
    report.insert("parallel".into(), json!(parallel));
    let start = Instant::now();
    let results: Vec<Result<String, String>> = std::thread::scope(|s| {
        let reg = &reg;
        let salt = &salt;
        let handles: Vec<_> = (0..parallel)
            .map(|t| {
                s.spawn(move || {
                    (t..count)
                        .step_by(parallel)
                        .map(|i| reg.put_blob(format!("hartland probe blob {salt} {i}").as_bytes()))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    });
    let (mut hashes, mut failures) = (Vec::new(), Vec::new());
    for r in results {
        match r {
            Ok(h) => hashes.push(h),
            Err(e) => failures.push(e),
        }
    }
    hashes.sort();
    let ms = start.elapsed().as_millis();
    report.insert("blobs_pushed".into(), json!(hashes.len()));
    report.insert("blob_failures".into(), json!(failures.iter().take(5).collect::<Vec<_>>()));
    report.insert("blob_push_ms_total".into(), json!(ms));
    report.insert("blob_push_ms_each".into(), json!(ms as f64 / count.max(1) as f64));
    let start = Instant::now();
    let exists = hashes.iter().filter(|h| reg.blob_exists(h).unwrap_or(false)).count();
    report.insert("blob_exists_ms_each".into(), json!(start.elapsed().as_millis() as f64 / hashes.len().max(1) as f64));
    report.insert("blobs_found".into(), json!(exists));
    if let Some(h) = hashes.first() {
        let r = reg.get_blob(h);
        report.insert("blob_roundtrip_ok".into(), json!(r.is_ok()));
        if let Err(e) = r {
            report.insert("blob_roundtrip_error".into(), json!(e.chars().take(400).collect::<String>()));
        }
        // Raw status of the blob GET, without following redirects.
        if let Ok(raw) = reg.get_blob_raw(h) {
            report.insert("blob_get_status".into(), json!(raw.status));
            report.insert("blob_get_location_host".into(), json!(raw.header("Location").map(|l| l.split('/').nth(2).unwrap_or("").to_string())));
        }
    }

    // 2. A cache entry: manifest tagged with the action digest.
    let empty = reg.put_blob(b"{}")?;
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
    let entry_digest = reg.put_manifest(&action_tag, MANIFEST_MEDIA_TYPE, &entry_bytes)?;
    report.insert("entry_digest".into(), json!(entry_digest));
    let got = reg.get_manifest(&action_tag)?;
    report.insert("entry_by_tag_status".into(), json!(got.status));
    report.insert("entry_by_tag_same_bytes".into(), json!(got.body == entry_bytes));

    // 3. A signature artifact attached via `subject`, then referrers.
    let sig_blob = reg.put_blob(format!("probe signature {salt}").as_bytes())?;
    let sig = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": "application/vnd.hartland.attestation.v0+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": format!("sha256:{empty}"), "size": 2},
        "layers": [{"mediaType": "application/vnd.hartland.attestation.v0+json", "digest": format!("sha256:{sig_blob}"), "size": format!("probe signature {salt}").len()}],
        "subject": {"mediaType": MANIFEST_MEDIA_TYPE, "digest": entry_digest, "size": entry_bytes.len()},
    });
    let sig_bytes = serde_json::to_vec(&sig).map_err(|e| e.to_string())?;
    let sig_digest = format!("sha256:{}", sha256_hex(&sig_bytes));
    match reg.put_manifest(&sig_digest, MANIFEST_MEDIA_TYPE, &sig_bytes) {
        Ok(d) => {
            report.insert("sig_put".into(), json!(d));
        }
        Err(e) => {
            report.insert("sig_put_error".into(), json!(e));
        }
    }
    let refs = reg.referrers(&entry_digest)?;
    report.insert("referrers_status".into(), json!(refs.status));
    report.insert("referrers_body".into(), json!(String::from_utf8_lossy(&refs.body).chars().take(600).collect::<String>()));
    let rate: Vec<_> = refs.headers.iter().filter(|(k, _)| k.to_ascii_lowercase().contains("ratelimit")).collect();
    report.insert("ratelimit_headers".into(), json!(rate));

    // 4. Anonymous read (private packages should refuse).
    report.insert("anonymous_manifest_status".into(), json!(anon.get_manifest(&action_tag)?.status));

    println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = match args {
        [a, b, rest @ ..] => (format!("{a} {b}"), rest),
        _ => return Err(USAGE.to_string()),
    };
    match cmd.as_str() {
        "sandbox setup" => return hartland::sandbox::setup(),
        "sandbox run" => return sandbox_run(rest),
        "oci probe" => return oci_probe(&flags(rest)?),
        "proxy put" => {
            let f = flags(rest)?;
            let addr = need(&f, "addr")?.to_string();
            let data = std::fs::read(need(&f, "file")?).map_err(|e| e.to_string())?;
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            return rt.block_on(async move {
                use hartland::reapi::re;
                let digest = re::Digest { hash: hartland::attest::sha256_hex(&data), size_bytes: data.len() as i64 };
                let mut cas = re::content_addressable_storage_client::ContentAddressableStorageClient::connect(addr)
                    .await
                    .map_err(|e| e.to_string())?
                    .max_decoding_message_size(64 << 20)
                    .max_encoding_message_size(64 << 20);
                cas.batch_update_blobs(re::BatchUpdateBlobsRequest {
                    requests: vec![re::batch_update_blobs_request::Request { digest: Some(digest.clone()), data, compressor: 0 }],
                    ..Default::default()
                })
                .await
                .map_err(|e| e.to_string())?;
                println!("{}/{}", digest.hash, digest.size_bytes);
                Ok(())
            });
        }
        "proxy check" => {
            let f = flags(rest)?;
            let addr = need(&f, "addr")?.to_string();
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            return rt.block_on(async move {
                use hartland::reapi::re;
                let mut caps = re::capabilities_client::CapabilitiesClient::connect(addr.clone()).await.map_err(|e| format!("connect: {e}"))?;
                let c = caps.get_capabilities(re::GetCapabilitiesRequest::default()).await.map_err(|e| e.to_string())?;
                println!("capabilities: {:?}", c.into_inner().cache_capabilities.map(|c| c.digest_functions));
                let mut cas = re::content_addressable_storage_client::ContentAddressableStorageClient::connect(addr).await.map_err(|e| e.to_string())?;
                let data = b"hartland proxy check".to_vec();
                let digest = re::Digest { hash: hartland::attest::sha256_hex(&data), size_bytes: data.len() as i64 };
                cas.batch_update_blobs(re::BatchUpdateBlobsRequest {
                    requests: vec![re::batch_update_blobs_request::Request { digest: Some(digest.clone()), data, compressor: 0 }],
                    ..Default::default()
                })
                .await
                .map_err(|e| e.to_string())?;
                let missing = cas
                    .find_missing_blobs(re::FindMissingBlobsRequest { blob_digests: vec![digest], ..Default::default() })
                    .await
                    .map_err(|e| e.to_string())?;
                println!("missing after upload: {}", missing.into_inner().missing_blob_digests.len());
                Ok(())
            });
        }
        "proxy serve" => {
            let f = flags(rest)?;
            let store = hartland::proxy::DiskStore::new(need(&f, "dir")?.into())?;
            let addr = need(&f, "listen")?.parse().map_err(|e| format!("--listen: {e}"))?;
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            eprintln!("hartland proxy listening on {addr}");
            return rt.block_on(hartland::proxy::Proxy::new(std::sync::Arc::new(store)).serve(addr));
        }
        _ => {}
    }
    let f = flags(rest)?;
    match cmd.as_str() {
        "attest sign" => {
            let results: Vec<ActionResult> = read_json(need(&f, "results")?)?;
            let statement = Statement::new(results);
            statement.check()?;
            let payload = hartland::statement_bytes(&statement);
            let token = hartland::github::request_token(&hartland::attest::audience_for(&payload))?;
            write_json(need(&f, "out")?, &Envelope::new(&payload, token))?;
            eprintln!("signed {} results", statement.predicate.results.len());
            Ok(())
        }
        "attest verify" => {
            let env: Envelope = read_json(need(&f, "envelope")?)?;
            let keyring: Keyring = read_json(need(&f, "keyring")?)?;
            let jwks: Jwks = read_json(need(&f, "jwks")?)?;
            let (statement, signer) = hartland::verify_envelope(&env, &jwks, &keyring)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "signer": signer,
                    "results": statement.predicate.results,
                }))
                .map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "jwks update" => {
            let path = need(&f, "jwks")?;
            let mut archive: Jwks = if std::path::Path::new(path).exists() { read_json(path)? } else { Jwks::default() };
            let added = archive.merge(&hartland::github::fetch_jwks()?)?;
            write_json(path, &archive)?;
            eprintln!("{added} new key(s); {} in archive", archive.keys.len());
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    }
}
