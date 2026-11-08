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

use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use tokio::process::Command;

pub const SANDBOX_USER: &str = "hlsandbox";
pub const WORKDIR: &str = "/work";

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("{command}: {source}")]
    Spawn {
        command: String,
        source: std::io::Error,
    },
    #[error("{command} failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Path(#[from] BadPath),
    #[error("empty argv")]
    EmptyArgv,
}

#[derive(Debug, thiserror::Error)]
#[error("not a normal relative path: {0:?}")]
pub struct BadPath(String);

/// A non-empty relative path of normal components only: no `..`, no root,
/// no `.`. Safe to join onto a directory we control.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct RelPath(PathBuf);

impl FromStr for RelPath {
    type Err = BadPath;
    fn from_str(s: &str) -> Result<RelPath, BadPath> {
        let p = Path::new(s.trim_end_matches('/'));
        let normal = p.components().next().is_some()
            && p.components().all(|c| matches!(c, Component::Normal(_)));
        if normal {
            Ok(RelPath(p.to_path_buf()))
        } else {
            Err(BadPath(s.to_string()))
        }
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(f)
    }
}

impl AsRef<Path> for RelPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl RelPath {
    /// Every proper ancestor, outermost first (`a/b/c` gives `a`, `a/b`).
    pub fn ancestors(&self) -> impl Iterator<Item = RelPath> + '_ {
        let mut v: Vec<RelPath> = self
            .0
            .ancestors()
            .skip(1)
            .filter(|a| !a.as_os_str().is_empty())
            .map(|a| RelPath(a.to_path_buf()))
            .collect();
        v.reverse();
        v.into_iter()
    }

    pub fn join(&self, other: &RelPath) -> RelPath {
        RelPath(self.0.join(&other.0))
    }
}

pub struct Spec<'a> {
    /// Directory whose contents become the action's working root. Used in
    /// place: the action may change it, and outputs are moved out of it into
    /// `collect` (which must be on the same filesystem).
    pub input: &'a Path,
    /// argv[0] is resolved inside the sandbox, e.g. `/work/bin/sh`.
    pub argv: &'a [String],
    pub env: &'a [(String, String)],
    pub workdir: Option<&'a RelPath>,
    /// Output paths relative to the working directory.
    pub outputs: &'a [RelPath],
    /// Where collected outputs are copied, at the same relative paths.
    pub collect: &'a Path,
    /// Run as `SANDBOX_USER` via sudo. False only for local development.
    pub drop_user: bool,
    /// (host directory, path under the working root) mounted read-only.
    pub ro_binds: &'a [(PathBuf, RelPath)],
}

pub struct Outcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Declared outputs that the action did not produce.
    pub missing: Vec<RelPath>,
}

async fn run(cmd: &mut Command) -> Result<(), SandboxError> {
    let command = format!("{:?}", cmd.as_std());
    let out = cmd.output().await.map_err(|source| SandboxError::Spawn {
        command: command.clone(),
        source,
    })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(SandboxError::Failed {
            command,
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }
}

async fn sudo(args: &[&str]) -> Result<(), SandboxError> {
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
pub async fn setup() -> Result<(), SandboxError> {
    if !succeeds(Command::new("bwrap").arg("--version")).await {
        sudo(&["apt-get", "install", "-qy", "bubblewrap"]).await?;
    }
    sudo(&[
        "sysctl",
        "-q",
        "kernel.apparmor_restrict_unprivileged_userns=0",
    ])
    .await?;
    if nix::unistd::User::from_name(SANDBOX_USER)
        .ok()
        .flatten()
        .is_none()
    {
        sudo(&[
            "useradd",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            SANDBOX_USER,
        ])
        .await?;
    }
    Ok(())
}

pub async fn exec(spec: &Spec<'_>) -> Result<Outcome, SandboxError> {
    if spec.argv.is_empty() {
        return Err(SandboxError::EmptyArgv);
    }
    let result = exec_in(spec).await;
    if result.is_err() && spec.drop_user {
        // Leave nothing the caller cannot delete.
        let _ = reclaim(spec.input).await;
    }
    result
}

/// Gives the tree back to us after the sandbox uid owned it.
async fn reclaim(dir: &Path) -> Result<(), SandboxError> {
    let me = format!("{}:{}", nix::unistd::getuid(), nix::unistd::getgid());
    sudo(&["chown", "-R", &me, &dir.display().to_string()]).await
}

async fn exec_in(spec: &Spec<'_>) -> Result<Outcome, SandboxError> {
    let scratch = spec.input.display().to_string();
    if spec.drop_user {
        sudo(&[
            "chown",
            "-R",
            &format!("{SANDBOX_USER}:{SANDBOX_USER}"),
            &scratch,
        ])
        .await?;
    }
    let mut cmd = if spec.drop_user {
        let mut c = Command::new("sudo");
        c.args(["-n", "-u", SANDBOX_USER, "--", "env", "-i", "bwrap"]);
        c
    } else {
        Command::new("bwrap")
    };
    cmd.args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
    ])
    .args([
        "--tmpfs", "/", "--bind", &scratch, WORKDIR, "--proc", "/proc", "--dev", "/dev", "--tmpfs",
        "/tmp",
    ]);
    let work = Path::new(WORKDIR);
    for (host, rel) in spec.ro_binds {
        cmd.arg("--ro-bind").arg(host).arg(work.join(rel));
    }
    cmd.arg("--chdir")
        .arg(spec.workdir.map_or(work.to_path_buf(), |w| work.join(w)))
        .arg("--clearenv");
    for (k, v) in spec.env {
        cmd.args(["--setenv", k, v]);
    }
    cmd.arg("--")
        .args(spec.argv)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let out = cmd.output().await.map_err(|source| SandboxError::Spawn {
        command: "bwrap".to_string(),
        source,
    })?;

    if spec.drop_user {
        reclaim(spec.input).await?;
    }
    let root = spec
        .workdir
        .map_or(spec.input.to_path_buf(), |w| spec.input.join(w));
    let mut missing = Vec::new();
    for o in spec.outputs {
        let src = root.join(o);
        // symlink_metadata: never follow a link the action planted.
        if tokio::fs::symlink_metadata(&src).await.is_err() {
            missing.push(o.clone());
            continue;
        }
        let dst = spec.collect.join(o);
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&src, &dst).await?;
    }
    Ok(Outcome {
        exit_code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: out.stderr,
        missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths() {
        assert!("a/b".parse::<RelPath>().is_ok());
        assert!("a/b/".parse::<RelPath>().is_ok());
        for bad in ["", "/a", "../a", "a/../b", "./a"] {
            assert!(bad.parse::<RelPath>().is_err(), "{bad}");
        }
        let p: RelPath = "a/b/c".parse().unwrap();
        assert_eq!(
            p.ancestors().map(|a| a.to_string()).collect::<Vec<_>>(),
            ["a", "a/b"]
        );
    }
}
