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
      Run one action in the sandbox; copy declared outputs to --collect.";

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

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = match args {
        [a, b, rest @ ..] => (format!("{a} {b}"), rest),
        _ => return Err(USAGE.to_string()),
    };
    match cmd.as_str() {
        "sandbox setup" => return hartland::sandbox::setup(),
        "sandbox run" => return sandbox_run(rest),
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
