//! Executes REAPI actions in the sandbox. The only source of results the
//! signing proxy will vouch for: it builds the input tree from the CAS itself,
//! runs the command as the sandbox uid with no network and no host files, and
//! hashes what comes out.
//!
//! Inputs: directories on the way to an output (or the working or scratch
//! directory) are written out per action; every other input subtree is
//! materialised once per digest into a read-only cache and bind-mounted (the
//! zig distribution alone is ~20k files).

use crate::attest::sha256_hex;
use crate::proxy::Store;
use crate::reapi::re;
use crate::sandbox;
use futures::future::BoxFuture;
use futures::{StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

/// Files written concurrently while materialising one directory.
const WRITE_CONCURRENCY: usize = 32;

pub struct Executor {
    store: Arc<dyn Store>,
    /// Run actions as the sandbox uid (true on runners; false for local dev).
    drop_user: bool,
    scratch: PathBuf,
    /// Directory digest -> its read-only materialisation, filled exactly once.
    dircache: Mutex<HashMap<String, Arc<OnceCell<PathBuf>>>>,
}

fn digest_of(data: &[u8]) -> re::Digest {
    re::Digest { hash: sha256_hex(data), size_bytes: data.len() as i64 }
}

fn join_rel(a: &str, b: &str) -> String {
    if a.is_empty() { b.to_string() } else { format!("{a}/{b}") }
}

fn check_name(n: &str) -> Result<(), String> {
    if n.is_empty() || n == "." || n == ".." || n.contains('/') {
        Err(format!("bad name in input tree: {n:?}"))
    } else {
        Ok(())
    }
}

async fn fresh_dir(base: &Path, prefix: &str) -> Result<PathBuf, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = base.join(format!("{prefix}-{}-{n}", std::process::id()));
    tokio::fs::create_dir_all(&p).await.map_err(|e| e.to_string())?;
    Ok(p)
}

impl Executor {
    pub fn new(store: Arc<dyn Store>, drop_user: bool, scratch: PathBuf) -> Executor {
        Executor { store, drop_user, scratch, dircache: Mutex::new(HashMap::new()) }
    }

    async fn blob(&self, d: &Option<re::Digest>, what: &str) -> Result<Vec<u8>, String> {
        let d = d.as_ref().ok_or_else(|| format!("missing {what} digest"))?;
        let b = self.store.get_blob(&d.hash).await.ok_or_else(|| format!("{what} {} not in CAS", d.hash))?;
        if b.len() as i64 != d.size_bytes {
            return Err(format!("{what} {} has wrong size", d.hash));
        }
        Ok(b)
    }

    async fn put(&self, data: &[u8]) -> Result<re::Digest, String> {
        let d = digest_of(data);
        self.store.put_blob(&d.hash, data).await?;
        Ok(d)
    }

    /// Runs one action; stores the result for signing if it succeeded and is
    /// cacheable.
    pub async fn execute(&self, action_digest: &re::Digest) -> Result<re::ActionResult, String> {
        let action = re::Action::decode(self.blob(&Some(action_digest.clone()), "action").await?.as_slice()).map_err(|e| e.to_string())?;
        let command = re::Command::decode(self.blob(&action.command_digest, "command").await?.as_slice()).map_err(|e| e.to_string())?;

        let base = fresh_dir(&self.scratch, "exec").await?;
        let result = self.execute_in(&base, &action, &command).await;
        let _ = tokio::fs::remove_dir_all(&base).await;
        let result = result?;

        if result.exit_code == 0 && !action.do_not_cache {
            self.store.put_action_result(&action_digest.hash, action_digest.size_bytes, &result).await?;
        }
        Ok(result)
    }

    async fn execute_in(&self, base: &Path, action: &re::Action, command: &re::Command) -> Result<re::ActionResult, String> {
        let started = std::time::SystemTime::now();
        let input = base.join("in");
        let collect = base.join("out");
        tokio::fs::create_dir_all(&collect).await.map_err(|e| e.to_string())?;

        let outputs: Vec<String> = if !command.output_paths.is_empty() {
            command.output_paths.clone()
        } else {
            // Older clients (REAPI < 2.1) use the deprecated split fields.
            #[allow(deprecated)]
            command.output_files.iter().chain(command.output_directories.iter()).cloned().collect()
        };

        // Directories on the way to an output, the working directory or the
        // per-action scratch directory buck2 passes must be real and writable.
        let wd_rel = command.working_directory.trim_matches('/').to_string();
        let scratch_paths = command
            .environment_variables
            .iter()
            .filter(|v| v.name == "BUCK_SCRATCH_PATH" || v.name == "TMPDIR")
            .map(|v| join_rel(&join_rel(&wd_rel, v.value.trim_matches('/')), "x"));
        let mut keep = HashSet::new();
        for o in outputs.iter().map(|o| join_rel(&wd_rel, o)).chain(std::iter::once(join_rel(&wd_rel, "x"))).chain(scratch_paths) {
            let parts: Vec<&str> = o.split('/').collect();
            let mut acc = String::new();
            for part in &parts[..parts.len() - 1] {
                acc = join_rel(&acc, part);
                keep.insert(acc.clone());
            }
        }
        let binds = self.materialize_mixed(&action.input_root_digest, &input, &keep).await?;

        // REAPI: the server creates the parent directories of outputs.
        let wd = input.join(&command.working_directory);
        for o in &outputs {
            if let Some(parent) = Path::new(o).parent() {
                tokio::fs::create_dir_all(wd.join(parent)).await.map_err(|e| e.to_string())?;
            }
        }
        let env: Vec<(String, String)> = command.environment_variables.iter().map(|v| (v.name.clone(), v.value.clone())).collect();
        let outcome = sandbox::exec(&sandbox::Spec {
            input: &input,
            argv: &command.arguments,
            env: &env,
            workdir: &command.working_directory,
            outputs: &outputs,
            collect: &collect,
            drop_user: self.drop_user,
            take_input: true,
            ro_binds: &binds,
        })
        .await?;

        let mut result = re::ActionResult { exit_code: outcome.exit_code, ..Default::default() };
        // buck2 requires execution_metadata to be present.
        result.execution_metadata = Some(re::ExecutedActionMetadata {
            worker: "hartland-sandbox".to_string(),
            worker_start_timestamp: Some(started.into()),
            worker_completed_timestamp: Some(std::time::SystemTime::now().into()),
            ..Default::default()
        });
        result.stdout_digest = Some(self.put(&outcome.stdout).await?);
        result.stderr_digest = Some(self.put(&outcome.stderr).await?);
        for o in &outputs {
            let p = collect.join(o);
            let Ok(meta) = tokio::fs::symlink_metadata(&p).await else { continue };
            if meta.file_type().is_symlink() {
                let target = tokio::fs::read_link(&p).await.map_err(|e| e.to_string())?.to_string_lossy().into_owned();
                result.output_symlinks.push(re::OutputSymlink { path: o.clone(), target, ..Default::default() });
            } else if meta.is_dir() {
                let mut children = BTreeMap::new();
                let root = self.directory(p, &mut children).await?;
                let root_digest = digest_of(&root.encode_to_vec());
                let tree = re::Tree { root: Some(root), children: children.into_values().collect() };
                result.output_directories.push(re::OutputDirectory {
                    path: o.clone(),
                    tree_digest: Some(self.put(&tree.encode_to_vec()).await?),
                    root_directory_digest: Some(root_digest),
                    ..Default::default()
                });
            } else {
                let data = tokio::fs::read(&p).await.map_err(|e| e.to_string())?;
                result.output_files.push(re::OutputFile {
                    path: o.clone(),
                    digest: Some(self.put(&data).await?),
                    is_executable: meta.permissions().mode() & 0o111 != 0,
                    ..Default::default()
                });
            }
        }
        Ok(result)
    }

    /// Writes the levels of the input tree that lead to outputs (and empty
    /// directories, which must stay writable); returns read-only mounts for
    /// every other subtree.
    async fn materialize_mixed(&self, root: &Option<re::Digest>, dir: &Path, keep: &HashSet<String>) -> Result<Vec<(PathBuf, String)>, String> {
        let mut binds = Vec::new();
        let mut stack = vec![(root.clone(), dir.to_path_buf(), String::new())];
        while let Some((d, dir, rel)) = stack.pop() {
            tokio::fs::create_dir_all(&dir).await.map_err(|e| e.to_string())?;
            let directory = re::Directory::decode(self.blob(&d, "directory").await?.as_slice()).map_err(|e| e.to_string())?;
            self.write_files(&directory, &dir).await?;
            for sub in &directory.directories {
                check_name(&sub.name)?;
                let sub_rel = join_rel(&rel, &sub.name);
                let path = dir.join(&sub.name);
                let empty = sub.digest.as_ref().map(|d| d.size_bytes == 0).unwrap_or(false);
                if keep.contains(&sub_rel) || empty {
                    stack.push((sub.digest.clone(), path, sub_rel));
                } else {
                    let cached = self.cached_dir(&sub.digest).await?;
                    tokio::fs::create_dir_all(&path).await.map_err(|e| e.to_string())?;
                    binds.push((cached, sub_rel));
                }
            }
        }
        Ok(binds)
    }

    /// A read-only copy of a directory by digest, materialised exactly once
    /// even when many actions want it at the same moment.
    async fn cached_dir(&self, d: &Option<re::Digest>) -> Result<PathBuf, String> {
        let hash = d.as_ref().ok_or("missing directory digest")?.hash.clone();
        let cell = self.dircache.lock().map_err(|_| "poisoned")?.entry(hash.clone()).or_default().clone();
        cell.get_or_try_init(|| async {
            let root = self.scratch.join("dircache");
            let path = root.join(&hash);
            if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                return Ok(path);
            }
            let tmp = fresh_dir(&root, "staging").await?;
            let staged = tmp.join("d");
            self.materialize(d, &staged).await?;
            tokio::fs::rename(&staged, &path).await.map_err(|e| e.to_string())?;
            let _ = tokio::fs::remove_dir_all(&tmp).await;
            Ok::<_, String>(path)
        })
        .await
        .cloned()
    }

    /// Writes the whole Directory tree rooted at `d` into `dir`.
    async fn materialize(&self, d: &Option<re::Digest>, dir: &Path) -> Result<(), String> {
        let mut stack = vec![(d.clone(), dir.to_path_buf())];
        while let Some((d, dir)) = stack.pop() {
            tokio::fs::create_dir_all(&dir).await.map_err(|e| e.to_string())?;
            let directory = re::Directory::decode(self.blob(&d, "directory").await?.as_slice()).map_err(|e| e.to_string())?;
            self.write_files(&directory, &dir).await?;
            for sub in &directory.directories {
                check_name(&sub.name)?;
                stack.push((sub.digest.clone(), dir.join(&sub.name)));
            }
        }
        Ok(())
    }

    async fn write_files(&self, directory: &re::Directory, dir: &Path) -> Result<(), String> {
        // Owned entries: borrowed ones make the future's Send bound
        // higher-ranked, which rustc cannot prove.
        futures::stream::iter(directory.files.clone())
            .map(|f| async move {
                check_name(&f.name)?;
                let path = dir.join(&f.name);
                tokio::fs::write(&path, self.blob(&f.digest, "file").await?).await.map_err(|e| e.to_string())?;
                let mode = if f.is_executable { 0o755 } else { 0o644 };
                tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).await.map_err(|e| e.to_string())
            })
            .buffer_unordered(WRITE_CONCURRENCY)
            .try_collect::<Vec<()>>()
            .await?;
        for s in &directory.symlinks {
            check_name(&s.name)?;
            tokio::fs::symlink(&s.target, dir.join(&s.name)).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The Directory for an output directory, uploading its files; every
    /// descendant Directory goes into `children`.
    fn directory<'a>(&'a self, dir: PathBuf, children: &'a mut BTreeMap<String, re::Directory>) -> BoxFuture<'a, Result<re::Directory, String>> {
        Box::pin(async move {
            let mut entries = Vec::new();
            let mut rd = tokio::fs::read_dir(&dir).await.map_err(|e| e.to_string())?;
            while let Some(e) = rd.next_entry().await.map_err(|e| e.to_string())? {
                entries.push(e);
            }
            entries.sort_by_key(|e| e.file_name());
            let mut d = re::Directory::default();
            for e in entries {
                let name = e.file_name().to_string_lossy().into_owned();
                let meta = tokio::fs::symlink_metadata(e.path()).await.map_err(|e| e.to_string())?;
                if meta.file_type().is_symlink() {
                    let target = tokio::fs::read_link(e.path()).await.map_err(|e| e.to_string())?.to_string_lossy().into_owned();
                    d.symlinks.push(re::SymlinkNode { name, target, ..Default::default() });
                } else if meta.is_dir() {
                    let sub = self.directory(e.path(), &mut *children).await?;
                    let digest = digest_of(&sub.encode_to_vec());
                    children.insert(digest.hash.clone(), sub);
                    d.directories.push(re::DirectoryNode { name, digest: Some(digest) });
                } else {
                    let data = tokio::fs::read(e.path()).await.map_err(|e| e.to_string())?;
                    d.files.push(re::FileNode {
                        name,
                        digest: Some(self.put(&data).await?),
                        is_executable: meta.permissions().mode() & 0o111 != 0,
                        ..Default::default()
                    });
                }
            }
            Ok(d)
        })
    }
}
