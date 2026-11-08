//! Running one build action in isolation from the worker.
//!
//! The worker holds the OIDC request credentials; an action is untrusted code
//! from the caller's repository. Each action therefore runs:
//!   * as a dedicated unprivileged uid (no sudo, cannot read the worker's
//!     /proc entries or the runner's home);
//!   * under bubblewrap with every namespace unshared: no network, own PIDs;
//!   * on an empty tmpfs root with only its scratch directory (at /work),
//!     read-only input mounts, /proc, /dev and /tmp: no host files at all.
//!     Actions run pinned static tools that arrive as inputs;
//!   * with an empty environment apart from what the action declares.
//!
//! Ubuntu 24.04 runners block unprivileged user namespaces via AppArmor;
//! `setup` lifts that (the runner user has sudo) and creates the uid.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

pub const SANDBOX_USER: &str = "hlsandbox";
pub const WORKDIR: &str = "/work";

pub struct Spec<'a> {
    /// Directory whose contents become the action's working root.
    pub input: &'a Path,
    /// argv[0] is resolved inside the sandbox, e.g. `/work/bin/sh`.
    pub argv: &'a [String],
    pub env: &'a [(String, String)],
    /// Working directory relative to the input root ("" for the root).
    pub workdir: &'a str,
    /// Output paths relative to the working directory.
    pub outputs: &'a [String],
    /// Where collected outputs are copied, at the same relative paths.
    pub collect: &'a Path,
    /// Run as `SANDBOX_USER` via sudo. False only for local development.
    pub drop_user: bool,
    /// `input` is a private directory the caller will discard: use it as the
    /// scratch directory in place instead of copying it.
    pub take_input: bool,
    /// (host directory, path under the working root) mounted read-only.
    pub ro_binds: &'a [(PathBuf, String)],
}

pub struct Outcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Declared outputs that the action did not produce.
    pub missing: Vec<String>,
}

async fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd.output().await.map_err(|e| format!("{cmd:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

async fn sudo(args: &[&str]) -> Result<(), String> {
    run(Command::new("sudo").arg("-n").args(args)).await
}

async fn succeeds(cmd: &mut Command) -> bool {
    matches!(cmd.stdout(Stdio::null()).stderr(Stdio::null()).status().await, Ok(s) if s.success())
}

/// One-off runner preparation. Idempotent.
///
/// bubblewrap is not on the GitHub runner image, so it comes from Ubuntu's
/// archive here. That widens the trust base to Ubuntu's mirror; replace with a
/// pinned static build from our own toolchain.
pub async fn setup() -> Result<(), String> {
    if !succeeds(Command::new("bwrap").arg("--version")).await {
        sudo(&["apt-get", "install", "-qy", "bubblewrap"]).await?;
    }
    sudo(&["sysctl", "-q", "kernel.apparmor_restrict_unprivileged_userns=0"]).await?;
    if !succeeds(Command::new("id").arg(SANDBOX_USER)).await {
        sudo(&["useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", SANDBOX_USER]).await?;
    }
    Ok(())
}

fn check_relative(p: &str) -> Result<(), String> {
    let path = Path::new(p);
    if path.is_absolute() || path.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return Err(format!("output path must be relative and normal: {p}"));
    }
    Ok(())
}

pub async fn exec(spec: &Spec<'_>) -> Result<Outcome, String> {
    for o in spec.outputs {
        check_relative(o)?;
    }
    if !spec.workdir.is_empty() {
        check_relative(spec.workdir)?;
    }
    if spec.argv.is_empty() {
        return Err("empty argv".to_string());
    }
    let scratch = if spec.take_input { spec.input.to_path_buf() } else { make_scratch(&std::env::temp_dir()).await? };
    let result = exec_in(spec, &scratch).await;
    // Always reclaim and delete the scratch directory.
    if spec.drop_user {
        let _ = sudo(&["rm", "-rf", &scratch.display().to_string()]).await;
    } else {
        let _ = tokio::fs::remove_dir_all(&scratch).await;
    }
    result
}

async fn make_scratch(base: &Path) -> Result<PathBuf, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = base.join(format!("hartland-action-{}-{n}", std::process::id()));
    tokio::fs::create_dir(&p).await.map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(p)
}

async fn exec_in(spec: &Spec<'_>, scratch: &Path) -> Result<Outcome, String> {
    let s = scratch.display().to_string();
    if !spec.take_input {
        // cp -a keeps modes and symlinks; the tree is ours (worker-owned).
        run(Command::new("cp").arg("-a").arg(format!("{}/.", spec.input.display())).arg(scratch)).await?;
    }
    if spec.drop_user {
        sudo(&["chown", "-R", &format!("{SANDBOX_USER}:{SANDBOX_USER}"), &s]).await?;
    }

    let mut cmd = if spec.drop_user {
        let mut c = Command::new("sudo");
        c.args(["-n", "-u", SANDBOX_USER, "--", "env", "-i", "bwrap"]);
        c
    } else {
        Command::new("bwrap")
    };
    cmd.args(["--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"])
        .args(["--tmpfs", "/", "--bind", &s, WORKDIR, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
    for (host, rel) in spec.ro_binds {
        cmd.arg("--ro-bind").arg(host).arg(format!("{WORKDIR}/{rel}"));
    }
    let chdir = format!("{WORKDIR}/{}", spec.workdir).trim_end_matches('/').to_string();
    cmd.args(["--chdir", &chdir, "--clearenv"]);
    for (k, v) in spec.env {
        cmd.args(["--setenv", k, v]);
    }
    cmd.arg("--").args(spec.argv).stdin(Stdio::null()).kill_on_drop(true);
    let out = cmd.output().await.map_err(|e| format!("cannot start sandbox: {e}"))?;

    if spec.drop_user {
        let me = format!("{}:{}", id("-u").await, id("-g").await);
        sudo(&["chown", "-R", &me, &s]).await?;
    }
    let mut missing = Vec::new();
    for o in spec.outputs {
        let src = scratch.join(spec.workdir).join(o);
        // symlink_metadata: never follow a link the action planted.
        match tokio::fs::symlink_metadata(&src).await {
            Ok(_) => {
                let dst = spec.collect.join(o);
                if let Some(parent) = dst.parent() {
                    tokio::fs::create_dir_all(parent).await.map_err(|e| format!("{}: {e}", parent.display()))?;
                }
                run(Command::new("cp").arg("-a").arg(&src).arg(&dst)).await?;
            }
            Err(_) => missing.push(o.clone()),
        }
    }
    Ok(Outcome { exit_code: out.status.code().unwrap_or(-1), stdout: out.stdout, stderr: out.stderr, missing })
}

async fn id(flag: &str) -> String {
    match Command::new("id").arg(flag).output().await {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => String::new(),
    }
}
