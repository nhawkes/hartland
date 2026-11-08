//! Executes REAPI actions in the sandbox. The only source of results the
//! signing proxy will vouch for: it builds the input tree from the CAS itself,
//! runs the command as the sandbox uid with no network and no host files, and
//! hashes what comes out.

use crate::attest::sha256_hex;
use crate::proxy::Store;
use crate::reapi::re;
use crate::sandbox;
use prost::Message as _;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Executor {
    store: Arc<dyn Store>,
    /// Run actions as the sandbox uid (true on runners; false for local dev).
    drop_user: bool,
    scratch: PathBuf,
}

fn digest_of(data: &[u8]) -> re::Digest {
    re::Digest { hash: sha256_hex(data), size_bytes: data.len() as i64 }
}

impl Executor {
    pub fn new(store: Arc<dyn Store>, drop_user: bool, scratch: PathBuf) -> Executor {
        Executor { store, drop_user, scratch }
    }

    fn blob(&self, d: &Option<re::Digest>, what: &str) -> Result<Vec<u8>, String> {
        let d = d.as_ref().ok_or_else(|| format!("missing {what} digest"))?;
        let b = self.store.get_blob(&d.hash).ok_or_else(|| format!("{what} {} not in CAS", d.hash))?;
        if b.len() as i64 != d.size_bytes {
            return Err(format!("{what} {} has wrong size", d.hash));
        }
        Ok(b)
    }

    fn put(&self, data: &[u8]) -> Result<re::Digest, String> {
        let d = digest_of(data);
        self.store.put_blob(&d.hash, data)?;
        Ok(d)
    }

    /// Runs one action; stores the result for signing if it succeeded and is
    /// cacheable.
    pub fn execute(&self, action_digest: &re::Digest) -> Result<re::ActionResult, String> {
        let action = re::Action::decode(self.blob(&Some(action_digest.clone()), "action")?.as_slice()).map_err(|e| e.to_string())?;
        let command = re::Command::decode(self.blob(&action.command_digest, "command")?.as_slice()).map_err(|e| e.to_string())?;

        std::fs::create_dir_all(&self.scratch).map_err(|e| e.to_string())?;
        let base = tempdir(&self.scratch)?;
        let result = self.execute_in(&base, &action, &command);
        let _ = std::fs::remove_dir_all(&base);
        let result = result?;

        if result.exit_code == 0 && !action.do_not_cache {
            self.store.put_action_result(&action_digest.hash, action_digest.size_bytes, &result)?;
        }
        Ok(result)
    }

    fn execute_in(&self, base: &Path, action: &re::Action, command: &re::Command) -> Result<re::ActionResult, String> {
        let started = std::time::SystemTime::now();
        let input = base.join("in");
        let collect = base.join("out");
        std::fs::create_dir_all(&collect).map_err(|e| e.to_string())?;
        self.materialize(&action.input_root_digest, &input)?;

        let outputs: Vec<String> = if !command.output_paths.is_empty() {
            command.output_paths.clone()
        } else {
            // Older clients (REAPI < 2.1) use the deprecated split fields.
            #[allow(deprecated)]
            command.output_files.iter().chain(command.output_directories.iter()).cloned().collect()
        };
        // REAPI: the server creates the parent directories of outputs.
        let wd = input.join(&command.working_directory);
        for o in &outputs {
            if let Some(parent) = Path::new(o).parent() {
                std::fs::create_dir_all(wd.join(parent)).map_err(|e| e.to_string())?;
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
        })?;

        let mut result = re::ActionResult { exit_code: outcome.exit_code, ..Default::default() };
        // buck2 requires execution_metadata to be present.
        result.execution_metadata = Some(re::ExecutedActionMetadata {
            worker: "hartland-sandbox".to_string(),
            worker_start_timestamp: Some(started.into()),
            worker_completed_timestamp: Some(std::time::SystemTime::now().into()),
            ..Default::default()
        });
        result.stdout_digest = Some(self.put(&outcome.stdout)?);
        result.stderr_digest = Some(self.put(&outcome.stderr)?);
        for o in &outputs {
            let p = collect.join(o);
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&p).map_err(|e| e.to_string())?.to_string_lossy().into_owned();
                result.output_symlinks.push(re::OutputSymlink { path: o.clone(), target, ..Default::default() });
            } else if meta.is_dir() {
                let (tree, root) = self.tree(&p)?;
                let tree_digest = self.put(&tree.encode_to_vec())?;
                result.output_directories.push(re::OutputDirectory {
                    path: o.clone(),
                    tree_digest: Some(tree_digest),
                    root_directory_digest: Some(root),
                    ..Default::default()
                });
            } else {
                let data = std::fs::read(&p).map_err(|e| e.to_string())?;
                result.output_files.push(re::OutputFile {
                    path: o.clone(),
                    digest: Some(self.put(&data)?),
                    is_executable: meta.permissions().mode() & 0o111 != 0,
                    ..Default::default()
                });
            }
        }
        Ok(result)
    }

    /// Writes the Directory tree rooted at `d` into `dir`.
    fn materialize(&self, d: &Option<re::Digest>, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let directory = re::Directory::decode(self.blob(d, "directory")?.as_slice()).map_err(|e| e.to_string())?;
        for f in &directory.files {
            check_name(&f.name)?;
            let path = dir.join(&f.name);
            std::fs::write(&path, self.blob(&f.digest, "file")?).map_err(|e| e.to_string())?;
            let mode = if f.is_executable { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
        }
        for s in &directory.symlinks {
            check_name(&s.name)?;
            std::os::unix::fs::symlink(&s.target, dir.join(&s.name)).map_err(|e| e.to_string())?;
        }
        for sub in &directory.directories {
            check_name(&sub.name)?;
            self.materialize(&sub.digest, &dir.join(&sub.name))?;
        }
        Ok(())
    }

    /// Builds a Tree for an output directory, uploading its files.
    fn tree(&self, dir: &Path) -> Result<(re::Tree, re::Digest), String> {
        let mut children = BTreeMap::new();
        let root = self.directory(dir, &mut children)?;
        let root_digest = digest_of(&root.encode_to_vec());
        Ok((re::Tree { root: Some(root), children: children.into_values().collect() }, root_digest))
    }

    fn directory(&self, dir: &Path, children: &mut BTreeMap<String, re::Directory>) -> Result<re::Directory, String> {
        let mut entries: Vec<_> = std::fs::read_dir(dir).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        let mut d = re::Directory::default();
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let meta = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(e.path()).map_err(|e| e.to_string())?.to_string_lossy().into_owned();
                d.symlinks.push(re::SymlinkNode { name, target, ..Default::default() });
            } else if meta.is_dir() {
                let sub = self.directory(&e.path(), children)?;
                let bytes = sub.encode_to_vec();
                let digest = digest_of(&bytes);
                children.insert(digest.hash.clone(), sub);
                d.directories.push(re::DirectoryNode { name, digest: Some(digest) });
            } else {
                let data = std::fs::read(e.path()).map_err(|e| e.to_string())?;
                d.files.push(re::FileNode {
                    name,
                    digest: Some(self.put(&data)?),
                    is_executable: meta.permissions().mode() & 0o111 != 0,
                    ..Default::default()
                });
            }
        }
        Ok(d)
    }
}

fn check_name(n: &str) -> Result<(), String> {
    if n.is_empty() || n == "." || n == ".." || n.contains('/') {
        Err(format!("bad name in input tree: {n:?}"))
    } else {
        Ok(())
    }
}

fn tempdir(base: &Path) -> Result<PathBuf, String> {
    for n in 0..10_000u32 {
        let p = base.join(format!("exec-{}-{n}", std::process::id()));
        match std::fs::create_dir(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("no scratch directory".to_string())
}
