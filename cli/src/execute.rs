//! Executes REAPI actions in the sandbox. The only source of results the
//! signing proxy will vouch for: it builds the input tree from the CAS itself,
//! runs the command as the sandbox uid with no network and no host files, and
//! hashes what comes out.
//!
//! Inputs: directories on the way to an output (or the working or scratch
//! directory) are written out per action; every other input subtree is
//! materialised once per digest into a read-only cache and bind-mounted (the
//! zig distribution alone is ~20k files).

use crate::cas::Blob;
use crate::digest::{ActionDigest, Digest, ParseError, Sha256};
use crate::proxy::{Store, StoreError};
use crate::reapi::re;
use crate::sandbox::{self, BadPath, RelPath, SandboxError};
use dashmap::DashMap;
use futures::future::BoxFuture;
use futures::{StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Files written concurrently while materialising one directory.
const WRITE_CONCURRENCY: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("{0} {1} not in the CAS")]
    Missing(&'static str, Sha256),
    #[error("bad {0}: {1}")]
    Decode(&'static str, prost::DecodeError),
    #[error("bad name in input tree: {0:?}")]
    BadName(String),
    #[error(transparent)]
    Digest(#[from] ParseError),
    #[error(transparent)]
    Path(#[from] BadPath),
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// One entry name in a Directory: a single normal path component.
fn entry(name: &str) -> Result<RelPath, ExecError> {
    match name.parse::<RelPath>() {
        Ok(p) if p.as_ref().components().count() == 1 => Ok(p),
        _ => Err(ExecError::BadName(name.to_string())),
    }
}

pub struct Executor {
    store: Arc<dyn Store>,
    /// Run actions as the sandbox uid (true on runners; false for local dev).
    drop_user: bool,
    scratch: PathBuf,
    /// Directory digest -> its read-only materialisation, filled exactly once.
    dircache: DashMap<Sha256, Arc<OnceCell<PathBuf>>>,
}

/// What an action declares, parsed.
struct Plan {
    workdir: Option<RelPath>,
    outputs: Vec<RelPath>,
    /// Input directories that must be real and writable: those on the way to
    /// an output, the working directory, buck2's scratch directory.
    writable: BTreeSet<RelPath>,
}

impl Plan {
    fn of(command: &re::Command) -> Result<Plan, ExecError> {
        let workdir: Option<RelPath> = Some(command.working_directory.trim_matches('/'))
            .filter(|w| !w.is_empty())
            .map(str::parse)
            .transpose()?;
        let paths: Vec<&String> = if command.output_paths.is_empty() {
            // Older clients (REAPI < 2.1) use the deprecated split fields.
            #[allow(deprecated)]
            command
                .output_files
                .iter()
                .chain(command.output_directories.iter())
                .collect()
        } else {
            command.output_paths.iter().collect()
        };
        let outputs: Vec<RelPath> = paths
            .into_iter()
            .map(|p| p.parse())
            .collect::<Result<_, _>>()?;
        let under_wd = |p: &RelPath| workdir.as_ref().map_or(p.clone(), |w| w.join(p));
        let scratch = command
            .environment_variables
            .iter()
            .filter(|v| v.name == "BUCK_SCRATCH_PATH" || v.name == "TMPDIR")
            .filter_map(|v| v.value.trim_matches('/').parse::<RelPath>().ok());
        let mut writable = BTreeSet::new();
        for o in outputs.iter().map(under_wd) {
            writable.extend(o.ancestors());
        }
        for s in scratch.map(|s| under_wd(&s)) {
            writable.extend(s.ancestors());
            writable.insert(s);
        }
        if let Some(w) = &workdir {
            writable.extend(w.ancestors());
            writable.insert(w.clone());
        }
        Ok(Plan {
            workdir,
            outputs,
            writable,
        })
    }
}

impl Executor {
    pub fn new(store: Arc<dyn Store>, drop_user: bool, scratch: PathBuf) -> Executor {
        Executor {
            store,
            drop_user,
            scratch,
            dircache: DashMap::new(),
        }
    }

    async fn blob(&self, d: Option<&re::Digest>, what: &'static str) -> Result<Blob, ExecError> {
        let d = Digest::try_from(d)?;
        let b = self
            .store
            .get_blob(&d.hash)
            .await
            .ok_or(ExecError::Missing(what, d.hash))?;
        if b.digest() != d {
            return Err(ExecError::Missing(what, d.hash));
        }
        Ok(b)
    }

    async fn decode<M: prost::Message + Default>(
        &self,
        d: Option<&re::Digest>,
        what: &'static str,
    ) -> Result<M, ExecError> {
        M::decode(self.blob(d, what).await?.into_data()).map_err(|e| ExecError::Decode(what, e))
    }

    async fn put(&self, data: impl Into<bytes::Bytes>) -> Result<re::Digest, ExecError> {
        let blob = Blob::new(data);
        self.store.put_blob(&blob).await?;
        Ok(blob.digest().into())
    }

    /// Runs one action; stores the result for signing if it succeeded and is
    /// cacheable.
    pub async fn execute(
        &self,
        action_digest: ActionDigest,
    ) -> Result<re::ActionResult, ExecError> {
        let action: re::Action = self
            .decode(Some(&Digest::from(action_digest).into()), "action")
            .await?;
        let command: re::Command = self
            .decode(action.command_digest.as_ref(), "command")
            .await?;

        let base = tempfile::Builder::new()
            .prefix("exec-")
            .tempdir_in(&self.scratch)?;
        let result = self.execute_in(base.path(), &action, &command).await;
        tokio::task::spawn_blocking(move || base.close())
            .await
            .map_err(std::io::Error::other)??;
        let result = result?;

        if result.exit_code == 0 && !action.do_not_cache {
            self.store.put_action_result(action_digest, &result).await?;
        }
        Ok(result)
    }

    async fn execute_in(
        &self,
        base: &Path,
        action: &re::Action,
        command: &re::Command,
    ) -> Result<re::ActionResult, ExecError> {
        let started = std::time::SystemTime::now();
        let plan = Plan::of(command)?;
        let (input, collect) = (base.join("in"), base.join("out"));
        tokio::fs::create_dir_all(&collect).await?;
        let binds = self
            .materialize_mixed(action.input_root_digest.as_ref(), &input, &plan.writable)
            .await?;

        // REAPI: the server creates the parent directories of outputs.
        let wd = plan
            .workdir
            .as_ref()
            .map_or(input.clone(), |w| input.join(w));
        for o in &plan.outputs {
            if let Some(parent) = o.as_ref().parent() {
                tokio::fs::create_dir_all(wd.join(parent)).await?;
            }
        }
        let env: Vec<(String, String)> = command
            .environment_variables
            .iter()
            .map(|v| (v.name.clone(), v.value.clone()))
            .collect();
        let outcome = sandbox::exec(&sandbox::Spec {
            input: &input,
            argv: &command.arguments,
            env: &env,
            workdir: plan.workdir.as_ref(),
            outputs: &plan.outputs,
            collect: &collect,
            drop_user: self.drop_user,
            ro_binds: &binds,
        })
        .await?;

        let mut result = re::ActionResult {
            exit_code: outcome.exit_code,
            stdout_digest: Some(self.put(outcome.stdout).await?),
            stderr_digest: Some(self.put(outcome.stderr).await?),
            // buck2 requires execution_metadata to be present.
            execution_metadata: Some(re::ExecutedActionMetadata {
                worker: "hartland-sandbox".to_string(),
                worker_start_timestamp: Some(started.into()),
                worker_completed_timestamp: Some(std::time::SystemTime::now().into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        for o in &plan.outputs {
            let p = collect.join(o);
            let Ok(meta) = tokio::fs::symlink_metadata(&p).await else {
                continue;
            };
            let path = o.to_string();
            if meta.file_type().is_symlink() {
                let target = tokio::fs::read_link(&p)
                    .await?
                    .to_string_lossy()
                    .into_owned();
                result.output_symlinks.push(re::OutputSymlink {
                    path,
                    target,
                    ..Default::default()
                });
            } else if meta.is_dir() {
                let mut children = BTreeMap::new();
                let root = self.directory(p, &mut children).await?;
                let root_digest = Digest::of(&root.encode_to_vec());
                let tree = re::Tree {
                    root: Some(root),
                    children: children.into_values().collect(),
                };
                result.output_directories.push(re::OutputDirectory {
                    path,
                    tree_digest: Some(self.put(tree.encode_to_vec()).await?),
                    root_directory_digest: Some(root_digest.into()),
                    ..Default::default()
                });
            } else {
                result.output_files.push(re::OutputFile {
                    path,
                    digest: Some(self.put(tokio::fs::read(&p).await?).await?),
                    is_executable: meta.permissions().mode() & 0o111 != 0,
                    ..Default::default()
                });
            }
        }
        Ok(result)
    }

    /// Writes the levels of the input tree that must be writable (and empty
    /// directories, which must stay writable); returns read-only mounts for
    /// every other subtree.
    async fn materialize_mixed(
        &self,
        root: Option<&re::Digest>,
        dir: &Path,
        writable: &BTreeSet<RelPath>,
    ) -> Result<Vec<(PathBuf, RelPath)>, ExecError> {
        let mut binds = Vec::new();
        let mut stack: Vec<(Option<re::Digest>, PathBuf, Option<RelPath>)> =
            vec![(root.cloned(), dir.to_path_buf(), None)];
        while let Some((d, dir, rel)) = stack.pop() {
            tokio::fs::create_dir_all(&dir).await?;
            let directory: re::Directory = self.decode(d.as_ref(), "directory").await?;
            self.write_files(&directory, &dir).await?;
            for sub in directory.directories {
                let name = entry(&sub.name)?;
                let sub_rel = rel.as_ref().map_or(name.clone(), |r| r.join(&name));
                let path = dir.join(&name);
                let empty = sub.digest.as_ref().is_some_and(|d| d.size_bytes == 0);
                if writable.contains(&sub_rel) || empty {
                    stack.push((sub.digest, path, Some(sub_rel)));
                } else {
                    let cached = self.cached_dir(sub.digest.as_ref()).await?;
                    tokio::fs::create_dir_all(&path).await?;
                    binds.push((cached, sub_rel));
                }
            }
        }
        Ok(binds)
    }

    /// A read-only copy of a directory by digest, materialised exactly once
    /// even when many actions want it at the same moment.
    async fn cached_dir(&self, d: Option<&re::Digest>) -> Result<PathBuf, ExecError> {
        let hash = Digest::try_from(d)?.hash;
        let cell = self.dircache.entry(hash).or_default().clone();
        cell.get_or_try_init(|| async {
            let root = self.scratch.join("dircache");
            let path = root.join(hash.to_string());
            if tokio::fs::try_exists(&path).await? {
                return Ok(path);
            }
            tokio::fs::create_dir_all(&root).await?;
            let staging = tempfile::Builder::new()
                .prefix("staging-")
                .tempdir_in(&root)?;
            let staged = staging.path().join("d");
            self.materialize(d, &staged).await?;
            tokio::fs::rename(&staged, &path).await?;
            tokio::task::spawn_blocking(move || staging.close())
                .await
                .map_err(std::io::Error::other)??;
            Ok::<_, ExecError>(path)
        })
        .await
        .cloned()
    }

    /// Writes the whole Directory tree rooted at `d` into `dir`.
    async fn materialize(&self, d: Option<&re::Digest>, dir: &Path) -> Result<(), ExecError> {
        let mut stack = vec![(d.cloned(), dir.to_path_buf())];
        while let Some((d, dir)) = stack.pop() {
            tokio::fs::create_dir_all(&dir).await?;
            let directory: re::Directory = self.decode(d.as_ref(), "directory").await?;
            self.write_files(&directory, &dir).await?;
            for sub in directory.directories {
                let name = entry(&sub.name)?;
                stack.push((sub.digest, dir.join(name)));
            }
        }
        Ok(())
    }

    async fn write_files(&self, directory: &re::Directory, dir: &Path) -> Result<(), ExecError> {
        // Owned entries: borrowed ones make the future's Send bound
        // higher-ranked, which rustc cannot prove.
        futures::stream::iter(directory.files.clone())
            .map(|f| async move {
                let path = dir.join(entry(&f.name)?);
                tokio::fs::write(
                    &path,
                    self.blob(f.digest.as_ref(), "file").await?.into_data(),
                )
                .await?;
                let mode = if f.is_executable { 0o755 } else { 0o644 };
                tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).await?;
                Ok::<_, ExecError>(())
            })
            .buffer_unordered(WRITE_CONCURRENCY)
            .try_collect::<Vec<()>>()
            .await?;
        for s in &directory.symlinks {
            tokio::fs::symlink(&s.target, dir.join(entry(&s.name)?)).await?;
        }
        Ok(())
    }

    /// The Directory for an output directory, uploading its files; every
    /// descendant Directory goes into `children`, by digest.
    fn directory<'a>(
        &'a self,
        dir: PathBuf,
        children: &'a mut BTreeMap<Sha256, re::Directory>,
    ) -> BoxFuture<'a, Result<re::Directory, ExecError>> {
        Box::pin(async move {
            let mut entries = Vec::new();
            let mut rd = tokio::fs::read_dir(&dir).await?;
            while let Some(e) = rd.next_entry().await? {
                entries.push(e);
            }
            entries.sort_by_key(tokio::fs::DirEntry::file_name);
            let mut d = re::Directory::default();
            for e in entries {
                let name = e.file_name().to_string_lossy().into_owned();
                let meta = tokio::fs::symlink_metadata(e.path()).await?;
                if meta.file_type().is_symlink() {
                    let target = tokio::fs::read_link(e.path())
                        .await?
                        .to_string_lossy()
                        .into_owned();
                    d.symlinks.push(re::SymlinkNode {
                        name,
                        target,
                        ..Default::default()
                    });
                } else if meta.is_dir() {
                    let sub = self.directory(e.path(), &mut *children).await?;
                    let digest = Digest::of(&sub.encode_to_vec());
                    children.insert(digest.hash, sub);
                    d.directories.push(re::DirectoryNode {
                        name,
                        digest: Some(digest.into()),
                    });
                } else {
                    d.files.push(re::FileNode {
                        name,
                        digest: Some(self.put(tokio::fs::read(e.path()).await?).await?),
                        is_executable: meta.permissions().mode() & 0o111 != 0,
                        ..Default::default()
                    });
                }
            }
            Ok(d)
        })
    }
}
