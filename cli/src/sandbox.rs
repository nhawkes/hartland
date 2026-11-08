//! Running one build action in isolation from the worker.
//!
//! The worker holds the OIDC request credentials; an action is untrusted code
//! from the caller's repository. Each action therefore runs:
//!   * as a dedicated unprivileged uid (no sudo, cannot read the worker's
//!     /proc entries or the runner's home);
//!   * under bubblewrap with every namespace unshared: no network, own PIDs;
//!   * on an empty tmpfs root with only its scratch directory (at /work),
//!     /proc, /dev and /tmp: no host files at all. Actions run pinned static
//!     tools that arrive as inputs, so they need nothing from the host;
//!   * with an empty environment apart from what the action declares.
//!
//! Ubuntu 24.04 runners block unprivileged user namespaces via AppArmor;
//! `setup` lifts that (the runner user has sudo) and creates the uid.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const SANDBOX_USER: &str = "hlsandbox";
pub const WORKDIR: &str = "/work";

pub struct Spec<'a> {
    /// Directory whose contents become the action's working directory.
    pub input: &'a Path,
    /// argv[0] is resolved inside the sandbox, e.g. `/work/bin/sh`.
    pub argv: &'a [String],
    pub env: &'a [(String, String)],
    /// Output paths relative to the working directory.
    pub outputs: &'a [String],
    /// Where collected outputs are copied, at the same relative paths.
    pub collect: &'a Path,
    /// Run as `SANDBOX_USER` via sudo. False only for local development,
    /// where the caller is already unprivileged.
    pub drop_user: bool,
}

pub struct Outcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Declared outputs that the action did not produce.
    pub missing: Vec<String>,
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn sudo(args: &[&str]) -> Result<(), String> {
    run(Command::new("sudo").arg("-n").args(args))
}

/// One-off runner preparation. Idempotent.
///
/// bubblewrap is not on the GitHub runner image, so it comes from Ubuntu's
/// archive here. That widens the trust base to Ubuntu's mirror; replace with a
/// pinned static build from our own toolchain.
pub fn setup() -> Result<(), String> {
    let have_bwrap = Command::new("bwrap").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status();
    if !matches!(have_bwrap, Ok(s) if s.success()) {
        sudo(&["apt-get", "install", "-qy", "bubblewrap"])?;
    }
    sudo(&["sysctl", "-q", "kernel.apparmor_restrict_unprivileged_userns=0"])?;
    let exists = Command::new("id").arg(SANDBOX_USER).stdout(Stdio::null()).stderr(Stdio::null()).status();
    if !matches!(exists, Ok(s) if s.success()) {
        sudo(&["useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", SANDBOX_USER])?;
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

fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    // cp -a keeps modes and symlinks; the tree is ours (worker-owned) here.
    run(Command::new("cp").arg("-a").arg(format!("{}/.", from.display())).arg(to))
}

pub fn exec(spec: &Spec) -> Result<Outcome, String> {
    for o in spec.outputs {
        check_relative(o)?;
    }
    if spec.argv.is_empty() {
        return Err("empty argv".to_string());
    }
    let base = std::env::temp_dir();
    let scratch = make_scratch(&base)?;
    let result = exec_in(spec, &scratch);
    // Always reclaim and delete the scratch directory.
    if spec.drop_user {
        let _ = sudo(&["rm", "-rf", &scratch.display().to_string()]);
    } else {
        let _ = std::fs::remove_dir_all(&scratch);
    }
    result
}

fn make_scratch(base: &Path) -> Result<PathBuf, String> {
    for n in 0..1000u32 {
        let p = base.join(format!("hartland-action-{}-{n}", std::process::id()));
        match std::fs::create_dir(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
    }
    Err("could not create scratch directory".to_string())
}

fn exec_in(spec: &Spec, scratch: &Path) -> Result<Outcome, String> {
    let s = scratch.display().to_string();
    copy_tree(spec.input, scratch)?;
    if spec.drop_user {
        sudo(&["chown", "-R", &format!("{SANDBOX_USER}:{SANDBOX_USER}"), &s])?;
    }

    let mut cmd = if spec.drop_user {
        let mut c = Command::new("sudo");
        c.args(["-n", "-u", SANDBOX_USER, "--", "env", "-i", "bwrap"]);
        c
    } else {
        Command::new("bwrap")
    };
    cmd.args(["--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"])
        .args(["--tmpfs", "/", "--bind", &s, WORKDIR, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
        .args(["--chdir", WORKDIR, "--clearenv"]);
    for (k, v) in spec.env {
        cmd.args(["--setenv", k, v]);
    }
    cmd.arg("--").args(spec.argv).stdin(Stdio::null());
    let out = cmd.output().map_err(|e| format!("cannot start sandbox: {e}"))?;

    if spec.drop_user {
        let me = format!("{}:{}", uid(), gid());
        sudo(&["chown", "-R", &me, &s])?;
    }
    let mut missing = Vec::new();
    for o in spec.outputs {
        let src = scratch.join(o);
        // symlink_metadata: never follow a link the action planted.
        match std::fs::symlink_metadata(&src) {
            Ok(_) => {
                let dst = spec.collect.join(o);
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
                }
                run(Command::new("cp").arg("-a").arg(&src).arg(&dst))?;
            }
            Err(_) => missing.push(o.clone()),
        }
    }
    Ok(Outcome { exit_code: out.status.code().unwrap_or(-1), stdout: out.stdout, stderr: out.stderr, missing })
}

fn id_of(flag: &str) -> String {
    Command::new("id")
        .arg(flag)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn uid() -> String {
    id_of("-u")
}

fn gid() -> String {
    id_of("-g")
}
