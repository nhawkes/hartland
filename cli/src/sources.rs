//! Sources pinned by git commit.
//!
//! Upstream bytes enter a build only through buck2's downloader, checked
//! against a pinned sha256. A project without release tarballs is pinned by
//! commit instead: [`Store::fetch`] has the seed Zig's package manager fetch
//! the commit (outside any build action; Zig checks git's object hashes and
//! prints its own hash of the tree), turns the tree into a canonical archive
//! and keeps it in a store, `<store>/git/<sha256>.tar`, which [`serve`]
//! offers to buck2 over localhost HTTP. The archive's sha256 is the pin, so
//! its format is part of every pin and must never change silently.
//!
//! # The canonical archive, format version 1 ([`FORMAT_VERSION`])
//!
//! An uncompressed POSIX ustar stream of the commit's tree, written with the
//! `tar` crate:
//!
//! - Every entry is under one top-level directory, `<name>-<commit[:7]>`,
//!   where `<name>` is the last path segment of the repository URL without
//!   `.git` (as gitweb names its snapshots). It is the first entry.
//! - Then every directory, regular file and symlink of the tree, sorted by
//!   full path, bytewise. A directory sorts by its path without a trailing
//!   slash, so it precedes its contents. Paths are encoded by the `tar`
//!   crate's `Header::set_path`: `/`-separated, no trailing slash.
//! - Headers: ustar magic `ustar\0` and version `00`; mtime, uid and gid 0;
//!   user and group names empty; device numbers zero. Mode 0755 for
//!   directories, 0644 for files, 0755 for files with git's executable bit,
//!   0777 for symlinks, whose target is encoded by `Header::set_link_name`.
//! - No pax headers. A path or symlink target too long for ustar (a path
//!   over 100 bytes that cannot be split into a 155-byte prefix and a
//!   100-byte name) is preceded by a GNU long-name (`L`) or long-link (`K`)
//!   entry named `././@LongLink`, mode 0644, mtime/uid/gid 0, as the `tar`
//!   crate writes it.
//! - The stream ends with two zero blocks and is not padded further.
//!
//! The unit test `archive_format_is_stable` pins the sha256 of a small
//! archive: if it changes, so does every pin. A deliberate change of format
//! bumps [`FORMAT_VERSION`] and every `pinned_git` sha256 with it.
//!
//! # From Zig's fetch to the archive
//!
//! `zig fetch --debug-hash git+<url>#<commit>` (Zig 0.17.1) prints one line
//! per file and symlink with the sha256 its package hash is built from,
//! then the package hash. It keeps the package as a recompressed tarball
//! that drops the executable bit, and leaves its checkout in the cache's
//! `tmp/` directory; Zig's hash does not cover the executable bit either.
//! So the archive is made from that checkout (or from `p/<hash>/` where a
//! Zig keeps the package as a directory), after checking that it holds
//! exactly the files and symlinks of Zig's listing, each with Zig's hash.
//! Only the executable bit is taken from the checkout unchecked.
//!
//! A tree is refused if it has anything git cannot put in a tree: empty
//! directories (a submodule, whose content is not in the tree, or not a
//! git checkout), special files, or `.git` entries.

use crate::digest::{GitSha, Sha256, Sha256Context};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// The archive format described in the module documentation.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("not a git repository URL {url:?}: {reason}")]
    Url { url: String, reason: &'static str },
    #[error("{path}: {reason}")]
    Tree { path: PathBuf, reason: &'static str },
    #[error("zig fetch {url}#{commit} failed ({status}): {stderr}")]
    ZigFailed {
        url: GitUrl,
        commit: GitSha,
        status: std::process::ExitStatus,
        stderr: String,
    },
    #[error("unexpected output from zig fetch: {0:?}")]
    ZigOutput(String),
    #[error("zig fetch left no checkout to archive in {0}")]
    ZigCheckout(PathBuf),
    #[error("the checkout does not match Zig's listing at {path:?}: {reason}")]
    Listing { path: String, reason: &'static str },
    #[error("{url}#{commit}: Zig's hash is {got}, not the pinned {want}")]
    ZigMismatch {
        url: GitUrl,
        commit: GitSha,
        got: ZigHash,
        want: ZigHash,
    },
    #[error("archive of {commit} has sha256 {got}, not the pinned {want}")]
    Mismatch {
        commit: GitSha,
        got: Sha256,
        want: Sha256,
    },
    #[error(transparent)]
    Walk(#[from] walkdir::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A repository's https URL and the name its archive is prefixed with.
#[derive(Clone, Debug)]
pub struct GitUrl {
    /// Parsed as a URL once, kept as text.
    url: String,
    name: RepoName,
}

/// The last path segment of a repository URL without `.git`: one ordinary
/// path component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoName(String);

impl GitUrl {
    pub fn name(&self) -> &RepoName {
        &self.name
    }
}

impl FromStr for GitUrl {
    type Err = SourceError;
    fn from_str(s: &str) -> Result<GitUrl, SourceError> {
        let err = |reason| SourceError::Url {
            url: s.to_string(),
            reason,
        };
        let url = reqwest::Url::parse(s).map_err(|_| err("unparseable"))?;
        if url.scheme() != "https" {
            return Err(err("only https is supported"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(err("no query or fragment allowed"));
        }
        let last = url
            .path_segments()
            .and_then(|mut segments| segments.rfind(|s| !s.is_empty()))
            .unwrap_or("");
        let name = last.strip_suffix(".git").unwrap_or(last);
        let ordinary = |c: char| c.is_ascii_alphanumeric() || "._+-".contains(c);
        if name.is_empty() || name.starts_with('.') || !name.chars().all(ordinary) {
            return Err(err("no repository name in its path"));
        }
        Ok(GitUrl {
            name: RepoName(name.to_string()),
            url: url.into(),
        })
    }
}

impl fmt::Display for GitUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

impl fmt::Display for RepoName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The archive's top-level directory: `<name>-<commit[:7]>`.
pub fn archive_prefix(name: &RepoName, commit: GitSha) -> String {
    format!("{name}-{}", commit.short())
}

/// A Zig package hash, as `zig fetch` prints it (e.g.
/// `N-V-__8AAK0fgADQ5Uuo05p6YwlC3AxjD2Qs_hyjIbafy3hb`): also a directory
/// name in Zig's cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZigHash(String);

impl FromStr for ZigHash {
    type Err = SourceError;
    fn from_str(s: &str) -> Result<ZigHash, SourceError> {
        let ok = !s.is_empty()
            && s.len() <= 128
            && !s.starts_with('.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        if ok {
            Ok(ZigHash(s.to_string()))
        } else {
            Err(SourceError::ZigOutput(s.to_string()))
        }
    }
}

impl fmt::Display for ZigHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A path in a tree: relative, `/`-separated, ordinary components.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreePath(Vec<u8>);

impl TreePath {
    pub fn as_path(&self) -> &Path {
        Path::new(OsStr::from_bytes(&self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Dir,
    File { executable: bool },
    Symlink { target: Vec<u8> },
}

/// A directory read as a git tree: every member, sorted by path.
#[derive(Debug)]
pub struct Tree {
    root: PathBuf,
    members: Vec<(TreePath, Kind)>,
}

impl Tree {
    /// Reads `root`, refusing what a git tree cannot hold.
    pub fn read(root: &Path) -> Result<Tree, SourceError> {
        let refuse = |path: &Path, reason| SourceError::Tree {
            path: path.to_path_buf(),
            reason,
        };
        let mut members = Vec::new();
        for entry in walkdir::WalkDir::new(root).min_depth(1).follow_links(false) {
            let entry = entry?;
            let rel = entry
                .path()
                .strip_prefix(root)
                .expect("walkdir yields paths under its root");
            if entry.file_name() == ".git" {
                return Err(refuse(entry.path(), "a .git entry"));
            }
            let path = TreePath(rel.as_os_str().as_bytes().to_vec());
            let meta = entry.metadata()?;
            let kind = if meta.is_dir() {
                if std::fs::read_dir(entry.path())?.next().is_none() {
                    return Err(refuse(
                        entry.path(),
                        "empty directory (git trees have none: a submodule?)",
                    ));
                }
                Kind::Dir
            } else if meta.file_type().is_symlink() {
                Kind::Symlink {
                    target: std::fs::read_link(entry.path())?
                        .into_os_string()
                        .into_encoded_bytes(),
                }
            } else if meta.is_file() {
                Kind::File {
                    executable: meta.permissions().mode() & 0o100 != 0,
                }
            } else {
                return Err(refuse(entry.path(), "not a file, directory or symlink"));
            };
            members.push((path, kind));
        }
        members.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Tree {
            root: root.to_path_buf(),
            members,
        })
    }

    /// Checks that the tree holds exactly the files and symlinks Zig listed,
    /// with the content Zig hashed: a file's entry is
    /// sha256(path, 0, executable, content), a symlink's sha256(path,
    /// target). Zig 0.17.1 hashes every file as not executable, so either
    /// value of that byte is accepted.
    pub fn check(&self, listing: &ZigListing) -> Result<(), SourceError> {
        let mismatch = |path: &TreePath, reason| SourceError::Listing {
            path: String::from_utf8_lossy(&path.0).into_owned(),
            reason,
        };
        let mut listed = listing.entries.clone();
        for (path, kind) in &self.members {
            let (listed_kind, want) = match kind {
                Kind::Dir => continue,
                Kind::File { .. } | Kind::Symlink { .. } => listed
                    .remove(path)
                    .ok_or_else(|| mismatch(path, "not in Zig's listing"))?,
            };
            let ok = match (kind, listed_kind) {
                (Kind::File { .. }, ZigEntry::File) => {
                    let content = std::fs::read(self.root.join(path.as_path()))?;
                    [0u8, 1].iter().any(|x| {
                        let mut h = Sha256Context::default();
                        h.update(&path.0);
                        h.update(&[0, *x]);
                        h.update(&content);
                        h.finish() == want
                    })
                }
                (Kind::Symlink { target }, ZigEntry::Link) => {
                    let mut h = Sha256Context::default();
                    h.update(&path.0);
                    h.update(target);
                    h.finish() == want
                }
                _ => return Err(mismatch(path, "of a different kind")),
            };
            if !ok {
                return Err(mismatch(path, "content differs from Zig's hash"));
            }
        }
        match listed.keys().next() {
            Some(path) => Err(mismatch(path, "listed by Zig but not in the checkout")),
            None => Ok(()),
        }
    }

    /// Writes the canonical archive (see the module documentation).
    pub fn write_archive(&self, prefix: &str, out: impl Write) -> io::Result<()> {
        fn header(kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(kind);
            h.set_mode(mode);
            h.set_size(size);
            h.set_mtime(0);
            h.set_uid(0);
            h.set_gid(0);
            h
        }
        let mut tar = tar::Builder::new(out);
        let dir = |tar: &mut tar::Builder<_>, path: &Path| {
            tar.append_data(
                &mut header(tar::EntryType::Directory, 0o755, 0),
                path,
                io::empty(),
            )
        };
        let prefix = Path::new(prefix);
        dir(&mut tar, prefix)?;
        for (path, kind) in &self.members {
            let name = prefix.join(path.as_path());
            match kind {
                Kind::Dir => dir(&mut tar, &name)?,
                Kind::File { executable } => {
                    let f = std::fs::File::open(self.root.join(path.as_path()))?;
                    let len = f.metadata()?.len();
                    let mode = if *executable { 0o755 } else { 0o644 };
                    let mut h = header(tar::EntryType::Regular, mode, len);
                    tar.append_data(&mut h, &name, io::Read::take(f, len))?;
                }
                Kind::Symlink { target } => {
                    let mut h = header(tar::EntryType::Symlink, 0o777, 0);
                    tar.append_link(&mut h, &name, OsStr::from_bytes(target))?;
                }
            }
        }
        tar.into_inner()?.flush()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZigEntry {
    File,
    Link,
}

/// What `zig fetch --debug-hash` prints: the hash of every file and
/// symlink, then the package hash.
#[derive(Debug)]
pub struct ZigListing {
    entries: BTreeMap<TreePath, (ZigEntry, Sha256)>,
    hash: ZigHash,
}

impl ZigListing {
    pub fn hash(&self) -> &ZigHash {
        &self.hash
    }
}

impl FromStr for ZigListing {
    type Err = SourceError;
    fn from_str(s: &str) -> Result<ZigListing, SourceError> {
        let bad = |line: &str| SourceError::ZigOutput(line.to_string());
        let mut lines: Vec<&str> = s.lines().filter(|l| !l.is_empty()).collect();
        let hash = lines.pop().ok_or_else(|| bad(s))?.parse()?;
        let mut entries = BTreeMap::new();
        for line in lines {
            let (kind, rest) = line.split_once(": ").ok_or_else(|| bad(line))?;
            let kind = match kind {
                "file" => ZigEntry::File,
                "link" => ZigEntry::Link,
                _ => return Err(bad(line)),
            };
            let (digest, path) = rest.split_once(": ").ok_or_else(|| bad(line))?;
            let digest: Sha256 = digest.parse().map_err(|_| bad(line))?;
            let path = TreePath(path.as_bytes().to_vec());
            if entries.insert(path, (kind, digest)).is_some() {
                return Err(bad(line));
            }
        }
        Ok(ZigListing { entries, hash })
    }
}

/// Runs `zig fetch` with `cache` as its global cache (fresh and empty) and
/// returns its listing and the checkout it left.
pub fn zig_fetch(
    zig: &Path,
    cache: &Path,
    url: &GitUrl,
    commit: GitSha,
) -> Result<(ZigListing, PathBuf), SourceError> {
    let out = std::process::Command::new(zig)
        .arg("fetch")
        .arg("--debug-hash")
        .arg(format!("git+{url}#{commit}"))
        .env("ZIG_GLOBAL_CACHE_DIR", cache)
        .stdin(std::process::Stdio::null())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        return Err(SourceError::ZigFailed {
            url: url.clone(),
            commit,
            status: out.status,
            stderr,
        });
    }
    if !stderr.is_empty() {
        tracing::debug!(%stderr, "zig fetch");
    }
    let listing: ZigListing = String::from_utf8(out.stdout)
        .map_err(|e| SourceError::ZigOutput(String::from_utf8_lossy(e.as_bytes()).into_owned()))?
        .parse()?;
    let package = cache.join("p").join(listing.hash().to_string());
    if package.is_dir() {
        return Ok((listing, package));
    }
    // Zig 0.17.1: the checkout is the one directory left in tmp/.
    let tmp = cache.join("tmp");
    let mut dirs = std::fs::read_dir(&tmp)
        .map_err(|_| SourceError::ZigCheckout(tmp.clone()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<Vec<PathBuf>>>()?;
    match (dirs.pop(), dirs.is_empty()) {
        (Some(dir), true) if dir.is_dir() => Ok((listing, dir)),
        _ => Err(SourceError::ZigCheckout(tmp)),
    }
}

/// Hashes what passes through.
struct Hashing<W> {
    inner: W,
    hash: Sha256Context,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// What a fetch stored.
#[derive(Debug)]
pub struct Fetched {
    pub sha256: Sha256,
    /// None when archived from a directory, or already in the store.
    pub zig_hash: Option<ZigHash>,
}

/// `<store>/git/<sha256>.tar`: canonical archives by their sha256.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: PathBuf) -> Store {
        Store { root }
    }

    fn git_dir(&self) -> PathBuf {
        self.root.join("git")
    }

    pub fn path(&self, sha256: &Sha256) -> PathBuf {
        self.git_dir().join(format!("{sha256}.tar"))
    }

    /// Archives `tree` into the store and returns its sha256. With `want`,
    /// a different archive is an error and nothing is written. The file
    /// appears atomically (a temporary file, renamed).
    pub fn put(
        &self,
        tree: &Tree,
        name: &RepoName,
        commit: GitSha,
        want: Option<Sha256>,
    ) -> Result<Sha256, SourceError> {
        std::fs::create_dir_all(self.git_dir())?;
        let tmp = tempfile::NamedTempFile::new_in(self.git_dir())?;
        let got = {
            let mut out = Hashing {
                inner: io::BufWriter::new(tmp.as_file()),
                hash: Sha256Context::default(),
            };
            tree.write_archive(&archive_prefix(name, commit), &mut out)?;
            out.inner
                .into_inner()
                .map_err(io::Error::from)?
                .sync_all()?;
            out.hash.finish()
        };
        if let Some(want) = want.filter(|w| *w != got) {
            return Err(SourceError::Mismatch { commit, got, want });
        }
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        tmp.persist(self.path(&got)).map_err(|e| e.error)?;
        Ok(got)
    }

    fn has(&self, want: Option<Sha256>) -> Option<Sha256> {
        want.filter(|w| self.path(w).is_file())
    }

    /// Fetches `commit` with the seed `zig` and stores its archive. With
    /// `want` already in the store, does nothing.
    pub fn fetch(
        &self,
        zig: &Path,
        url: &GitUrl,
        commit: GitSha,
        want: Option<Sha256>,
        want_zig: Option<&ZigHash>,
    ) -> Result<Fetched, SourceError> {
        if let Some(sha256) = self.has(want) {
            tracing::info!(%url, %commit, %sha256, "already in the store");
            return Ok(Fetched {
                sha256,
                zig_hash: None,
            });
        }
        std::fs::create_dir_all(&self.root)?;
        // In the store, so on its filesystem; removed when done.
        let cache = tempfile::Builder::new()
            .prefix("zig-cache-")
            .tempdir_in(&self.root)?;
        tracing::info!(%url, %commit, "zig fetch");
        let (listing, checkout) = zig_fetch(zig, cache.path(), url, commit)?;
        let got = listing.hash().clone();
        tracing::info!(%url, %commit, zig_hash = %got, "fetched");
        if let Some(want) = want_zig.filter(|w| **w != got) {
            return Err(SourceError::ZigMismatch {
                url: url.clone(),
                commit,
                got,
                want: want.clone(),
            });
        }
        let tree = Tree::read(&checkout)?;
        tree.check(&listing)?;
        let sha256 = self.put(&tree, url.name(), commit, want)?;
        tracing::info!(%url, %commit, %sha256, "stored");
        Ok(Fetched {
            sha256,
            zig_hash: Some(got),
        })
    }

    /// Archives an already fetched tree (no Zig, no listing to check).
    pub fn from_dir(
        &self,
        dir: &Path,
        url: &GitUrl,
        commit: GitSha,
        want: Option<Sha256>,
    ) -> Result<Fetched, SourceError> {
        let sha256 = match self.has(want) {
            Some(sha256) => sha256,
            None => self.put(&Tree::read(dir)?, url.name(), commit, want)?,
        };
        tracing::info!(%url, %commit, %sha256, dir = %dir.display(), "stored");
        Ok(Fetched {
            sha256,
            zig_hash: None,
        })
    }
}

/// `hartland sources serve`: `GET` and `HEAD /git/<sha256>.tar` from the
/// store; 404 for anything else.
pub async fn serve(store: Store, listener: tokio::net::TcpListener) -> io::Result<()> {
    let app = axum::Router::new()
        .route("/git/{file}", axum::routing::get(get_archive))
        .method_not_allowed_fallback(not_found)
        .fallback(not_found)
        .with_state(store);
    tracing::info!(addr = %listener.local_addr()?, "serving sources");
    axum::serve(listener, app).await
}

/// Binds `listen` and serves.
pub async fn serve_at(store: Store, listen: SocketAddr) -> io::Result<()> {
    serve(store, tokio::net::TcpListener::bind(listen).await?).await
}

async fn not_found() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
}

/// `<sha256>.tar`, the only file name served.
struct ArchiveName(Sha256);

impl FromStr for ArchiveName {
    type Err = crate::digest::ParseError;
    fn from_str(s: &str) -> Result<ArchiveName, Self::Err> {
        s.strip_suffix(".tar")
            .unwrap_or_default()
            .parse()
            .map(ArchiveName)
    }
}

/// axum answers HEAD with this handler too, without the body.
async fn get_archive(
    axum::extract::State(store): axum::extract::State<Store>,
    axum::extract::Path(file): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse as _;
    let Ok(ArchiveName(sha256)) = file.parse() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let opened = async {
        let f = tokio::fs::File::open(store.path(&sha256)).await?;
        let len = f.metadata().await?.len();
        io::Result::Ok((f, len))
    };
    match opened.await {
        Ok((f, len)) => {
            tracing::debug!(%sha256, len, "serving");
            (
                [
                    (header::CONTENT_TYPE, "application/x-tar".to_string()),
                    (header::CONTENT_LENGTH, len.to_string()),
                ],
                axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(f)),
            )
                .into_response()
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(%sha256, error = %e, "cannot read archive");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "63e36e934e8f2bedf645303a90b64098e2af6c8f";

    /// a.txt, d/run.sh (executable), d/link -> ../a.txt, d/e/f.
    fn fixture(root: &Path) {
        std::fs::create_dir_all(root.join("d/e")).unwrap();
        std::fs::write(root.join("a.txt"), "hi\n").unwrap();
        std::fs::write(root.join("d/run.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            root.join("d/run.sh"),
            std::fs::Permissions::from_mode(0o775),
        )
        .unwrap();
        std::os::unix::fs::symlink("../a.txt", root.join("d/link")).unwrap();
        std::fs::write(root.join("d/e/f"), "x\n").unwrap();
    }

    fn archive(root: &Path) -> Vec<u8> {
        let url: GitUrl = "https://example.com/r.git".parse().unwrap();
        let commit: GitSha = COMMIT.parse().unwrap();
        let mut out = Vec::new();
        Tree::read(root)
            .unwrap()
            .write_archive(&archive_prefix(url.name(), commit), &mut out)
            .unwrap();
        out
    }

    /// The format is part of every pin: this sha256 must never change
    /// unless FORMAT_VERSION does.
    #[test]
    fn archive_format_is_stable() {
        assert_eq!(FORMAT_VERSION, 1);
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path());
        let tar = archive(dir.path());
        assert_eq!(
            Sha256::of(&tar).to_string(),
            "1095d3f78d352db796c0dc81030f69a547440cd912fe0e95e1dd975cb7a234fd"
        );
    }

    #[test]
    fn archive_lists_the_tree_in_order_with_canonical_headers() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path());
        let tar = archive(dir.path());
        let mut a = tar::Archive::new(tar.as_slice());
        let entries: Vec<(String, u32, tar::EntryType, Option<String>)> = a
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                assert_eq!(h.mtime().unwrap(), 0);
                assert_eq!(h.uid().unwrap(), 0);
                assert_eq!(h.gid().unwrap(), 0);
                assert_eq!(h.username_bytes(), Some(&b""[..]));
                assert!(h.as_ustar().is_some());
                (
                    e.path().unwrap().display().to_string(),
                    h.mode().unwrap(),
                    h.entry_type(),
                    e.link_name().unwrap().map(|l| l.display().to_string()),
                )
            })
            .collect();
        use tar::EntryType::{Directory, Regular, Symlink};
        let p = "r-63e36e9";
        assert_eq!(
            entries,
            vec![
                (p.into(), 0o755, Directory, None),
                (format!("{p}/a.txt"), 0o644, Regular, None),
                (format!("{p}/d"), 0o755, Directory, None),
                (format!("{p}/d/e"), 0o755, Directory, None),
                (format!("{p}/d/e/f"), 0o644, Regular, None),
                (
                    format!("{p}/d/link"),
                    0o777,
                    Symlink,
                    Some("../a.txt".into())
                ),
                (format!("{p}/d/run.sh"), 0o755, Regular, None),
            ]
        );
    }

    #[test]
    fn long_paths_are_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let long = "x".repeat(200);
        std::fs::write(dir.path().join(&long), "y").unwrap();
        let tar = archive(dir.path());
        assert_eq!(tar, archive(dir.path()));
        let mut a = tar::Archive::new(tar.as_slice());
        let names: Vec<String> = a
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["r-63e36e9".to_string(), format!("r-63e36e9/{long}")]
        );
    }

    #[test]
    fn refuses_what_git_trees_cannot_hold() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("submodule")).unwrap();
        assert!(matches!(
            Tree::read(dir.path()),
            Err(SourceError::Tree { .. })
        ));
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/HEAD"), "x").unwrap();
        assert!(matches!(
            Tree::read(dir.path()),
            Err(SourceError::Tree { .. })
        ));
    }

    /// Zig 0.17.1's output for the fixture, served as a git repository.
    const LISTING: &str = "\
file: 1fcce486437faf7ffd355efd191eeefcbe7d38a602805784db736b4ef6733f7e: a.txt
file: c2443e13a2637621cc2ef916077a6b84aef961520df2dd06520953aa4cd3a992: d/e/f
link: 33cb744b9b590eeeff856d45b5baad17ef227cc2d024777956df32435e5c21e1: d/link
file: 308cc4ff65bcbb85f2cf2047cd1bb3e4526242371fb37aaf49c36f9786828b69: d/run.sh
N-V-__8AAA8AAABTzqy0ZMCn36mHMaTo8ISmsoNvvGZ_NZla
";

    #[test]
    fn checks_the_tree_against_zigs_listing() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path());
        let listing: ZigListing = LISTING.parse().unwrap();
        assert_eq!(
            listing.hash().to_string(),
            "N-V-__8AAA8AAABTzqy0ZMCn36mHMaTo8ISmsoNvvGZ_NZla"
        );
        Tree::read(dir.path()).unwrap().check(&listing).unwrap();

        std::fs::write(dir.path().join("d/e/f"), "changed\n").unwrap();
        assert!(matches!(
            Tree::read(dir.path()).unwrap().check(&listing),
            Err(SourceError::Listing { .. })
        ));
        std::fs::write(dir.path().join("d/e/f"), "x\n").unwrap();
        std::fs::write(dir.path().join("extra"), "").unwrap();
        assert!(matches!(
            Tree::read(dir.path()).unwrap().check(&listing),
            Err(SourceError::Listing { .. })
        ));
        std::fs::remove_file(dir.path().join("extra")).unwrap();
        std::fs::remove_file(dir.path().join("a.txt")).unwrap();
        assert!(matches!(
            Tree::read(dir.path()).unwrap().check(&listing),
            Err(SourceError::Listing { .. })
        ));
    }

    #[test]
    fn parses_only_zigs_listing_format() {
        assert!("".parse::<ZigListing>().is_err());
        assert!("file: abc: a\nN-V-x".parse::<ZigListing>().is_err());
        assert!("dir: 00: a\nN-V-x".parse::<ZigListing>().is_err());
        assert!("N-V-x/../y".parse::<ZigListing>().is_err());
    }

    #[test]
    fn urls_name_their_archives() {
        let u: GitUrl = "https://repo.or.cz/libc-test.git".parse().unwrap();
        assert_eq!(u.name().to_string(), "libc-test");
        let u: GitUrl = "https://github.com/a/b/".parse().unwrap();
        assert_eq!(u.name().to_string(), "b");
        assert!("http://example.com/x.git".parse::<GitUrl>().is_err());
        assert!("git@example.com:x.git".parse::<GitUrl>().is_err());
        assert!("https://example.com/".parse::<GitUrl>().is_err());
        assert!("https://example.com/.git".parse::<GitUrl>().is_err());
        assert!("https://example.com/x.git#y".parse::<GitUrl>().is_err());
    }

    #[test]
    fn archive_names() {
        let s = Sha256::of(b"x");
        assert!(format!("{s}.tar").parse::<ArchiveName>().is_ok());
        assert!(s.to_string().parse::<ArchiveName>().is_err());
        assert!(format!("{s}.tar.gz").parse::<ArchiveName>().is_err());
        assert!("../x.tar".parse::<ArchiveName>().is_err());
    }
}
