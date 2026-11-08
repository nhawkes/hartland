//! A content-addressed directory: `<root>/<shard>/<sha256>`. Writes are
//! atomic (temporary file, then rename) and reads are digest-checked, so a
//! tampered or truncated file reads as absent.

use crate::digest::{Digest, Sha256};
use bytes::Bytes;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Data known to match its digest. The only way into a store.
#[derive(Clone, Debug)]
pub struct Blob {
    digest: Digest,
    data: Bytes,
}

#[derive(Debug, thiserror::Error)]
#[error("data does not match digest {0:?}")]
pub struct Mismatch(pub Digest);

impl Blob {
    pub fn new(data: impl Into<Bytes>) -> Blob {
        let data = data.into();
        Blob {
            digest: Digest::of(&data),
            data,
        }
    }

    /// Data that claims to have `digest`: checked here, once.
    pub fn check(digest: Digest, data: impl Into<Bytes>) -> Result<Blob, Mismatch> {
        let data = data.into();
        if digest.matches(&data) {
            Ok(Blob { digest, data })
        } else {
            Err(Mismatch(digest))
        }
    }

    /// Data fetched by hash (size not known in advance).
    pub fn check_hash(hash: Sha256, data: impl Into<Bytes>) -> Result<Blob, Mismatch> {
        let data = data.into();
        Blob::check(
            Digest {
                hash,
                size: data.len() as u64,
            },
            data,
        )
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn hash(&self) -> Sha256 {
        self.digest.hash
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn into_data(self) -> Bytes {
        self.data
    }
}

/// Writes `data` to `path` atomically, via a temporary file in `tmp`.
pub async fn write_atomic(tmp: &Path, path: &Path, data: Bytes) -> std::io::Result<()> {
    let (tmp, path) = (tmp.to_path_buf(), path.to_path_buf());
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = tempfile::NamedTempFile::new_in(tmp)?;
        f.write_all(&data)?;
        f.persist(&path).map_err(|e| e.error)?;
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

pub struct Cas {
    root: PathBuf,
    tmp: PathBuf,
}

impl Cas {
    /// `tmp` must be on the same filesystem as `root`.
    pub async fn open(root: PathBuf, tmp: PathBuf) -> std::io::Result<Cas> {
        tokio::fs::create_dir_all(&root).await?;
        tokio::fs::create_dir_all(&tmp).await?;
        Ok(Cas { root, tmp })
    }

    fn path(&self, hash: &Sha256) -> PathBuf {
        self.root.join(hash.shard()).join(hash.to_string())
    }

    pub async fn contains(&self, hash: &Sha256) -> bool {
        *hash == Sha256::EMPTY
            || tokio::fs::try_exists(self.path(hash))
                .await
                .unwrap_or(false)
    }

    pub async fn get(&self, hash: &Sha256) -> Option<Blob> {
        if *hash == Sha256::EMPTY {
            return Some(Blob::new(Bytes::new()));
        }
        let data = tokio::fs::read(self.path(hash)).await.ok()?;
        Blob::check_hash(*hash, data).ok()
    }

    pub async fn put(&self, blob: &Blob) -> std::io::Result<()> {
        let path = self.path(&blob.hash());
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Ok(());
        }
        write_atomic(&self.tmp, &path, blob.data.clone()).await
    }

    /// Removes every blob not in `live`.
    pub async fn retain(&self, live: &std::collections::HashSet<Sha256>) -> std::io::Result<()> {
        let mut shards = tokio::fs::read_dir(&self.root).await?;
        while let Some(shard) = shards.next_entry().await? {
            let mut files = tokio::fs::read_dir(shard.path()).await?;
            while let Some(f) = files.next_entry().await? {
                let keep = f
                    .file_name()
                    .to_str()
                    .and_then(|n| n.parse::<Sha256>().ok())
                    .is_some_and(|h| live.contains(&h));
                if !keep {
                    tokio::fs::remove_file(f.path()).await?;
                }
            }
        }
        Ok(())
    }
}
