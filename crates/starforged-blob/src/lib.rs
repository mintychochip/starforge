//! Content-addressed blob store (spec §5.3): exact bytes in, lowercase BLAKE3 hex out.
//!
//! Layout is `<root>/<hash[0..2]>/<hash>`. Writes are atomic (temp file in the
//! same shard directory + rename, so readers never see a partial file) and
//! idempotent (re-putting identical bytes is a no-op success). Reads verify
//! that BLAKE3 of the stored bytes matches the requested hash.
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("i/o: {0}")]
    Io(String),
    #[error("blob not found: {0}")]
    NotFound(String),
    #[error("blob corrupt: {0}")]
    Corrupt(String),
}

pub type BlobResult<T> = Result<T, BlobError>;

/// Content address of one stored byte string. `key` is the opaque backend key
/// (the lowercase BLAKE3 hex); [`FsBlobStore::path_for`] derives the path from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef {
    pub hash: String,
    pub size: u64,
    pub key: String,
}

/// Object-safe so `Core` can hold `Arc<dyn BlobStore>` without generics
/// rippling. Boxed futures instead of `async_trait` (not a workspace dep).
pub trait BlobStore: Send + Sync + std::fmt::Debug + 'static {
    fn put<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = BlobResult<BlobRef>> + Send + 'a>>;
    fn get<'a>(
        &'a self,
        blob: &'a BlobRef,
    ) -> Pin<Box<dyn Future<Output = BlobResult<Vec<u8>>> + Send + 'a>>;
    fn get_by_hash<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = BlobResult<Vec<u8>>> + Send + 'a>>;
    fn delete<'a>(
        &'a self,
        blob: &'a BlobRef,
    ) -> Pin<Box<dyn Future<Output = BlobResult<()>> + Send + 'a>>;
    fn exists<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = BlobResult<bool>> + Send + 'a>>;
}

/// Filesystem [`BlobStore`]. Cheap to clone; share one per process.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    pub root: PathBuf,
}

impl FsBlobStore {
    pub fn new(root: PathBuf) -> Self {
        FsBlobStore { root }
    }

    /// `<root>/<hash[0..2]>/<hash>`; S3 backends implement `BlobStore` with
    /// the same key space later.
    pub fn path_for(&self, hash_hex: &str) -> PathBuf {
        let shard = hash_hex.get(..2).unwrap_or(hash_hex);
        self.root.join(shard).join(hash_hex)
    }

    fn validated_path(&self, hash_hex: &str) -> BlobResult<PathBuf> {
        if hash_hex.is_empty()
            || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit())
            || hash_hex.contains(['/', '\\'])
        {
            return Err(BlobError::NotFound(hash_hex.to_owned()));
        }
        Ok(self.path_for(hash_hex))
    }

    async fn read_verified(&self, hash: &str) -> BlobResult<Vec<u8>> {
        let path = self.validated_path(hash)?;
        let bytes = tokio::fs::read(&path).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => BlobError::NotFound(hash.to_owned()),
            _ => BlobError::Io(e.to_string()),
        })?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != hash {
            return Err(BlobError::Corrupt(hash.to_owned()));
        }
        Ok(bytes)
    }
}

impl BlobStore for FsBlobStore {
    fn put<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = BlobResult<BlobRef>> + Send + 'a>> {
        Box::pin(async move {
            let hash = blake3::hash(bytes).to_hex().to_string();
            let path = self.path_for(&hash);
            // Idempotent: identical bytes already stored is a no-op success.
            if tokio::fs::try_exists(&path)
                .await
                .map_err(|e| BlobError::Io(e.to_string()))?
            {
                return Ok(BlobRef {
                    hash: hash.clone(),
                    size: bytes.len() as u64,
                    key: hash,
                });
            }
            if let Some(shard) = path.parent() {
                tokio::fs::create_dir_all(shard)
                    .await
                    .map_err(|e| BlobError::Io(e.to_string()))?;
            }
            // Same-directory temp file + rename: readers never see a partial file.
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let tmp = path.with_extension(format!(
                "tmp-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            tokio::fs::write(&tmp, bytes)
                .await
                .map_err(|e| BlobError::Io(e.to_string()))?;
            // Concurrent identical puts rename the same bytes over each other; rename is atomic.
            tokio::fs::rename(&tmp, &path)
                .await
                .map_err(|e| BlobError::Io(e.to_string()))?;
            Ok(BlobRef {
                hash: hash.clone(),
                size: bytes.len() as u64,
                key: hash,
            })
        })
    }

    fn get<'a>(
        &'a self,
        blob: &'a BlobRef,
    ) -> Pin<Box<dyn Future<Output = BlobResult<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move { self.read_verified(&blob.hash).await })
    }

    fn get_by_hash<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = BlobResult<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move { self.read_verified(hash).await })
    }

    fn delete<'a>(
        &'a self,
        blob: &'a BlobRef,
    ) -> Pin<Box<dyn Future<Output = BlobResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let path = self.validated_path(&blob.hash)?;
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                // Idempotent: already gone is success.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(BlobError::Io(e.to_string())),
            }
            // Best-effort shard cleanup; ignore races with concurrent puts.
            if let Some(shard) = path.parent() {
                let _ = tokio::fs::remove_dir(shard).await;
            }
            Ok(())
        })
    }

    fn exists<'a>(
        &'a self,
        hash: &'a str,
    ) -> Pin<Box<dyn Future<Output = BlobResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            let Ok(path) = self.validated_path(hash) else {
                return Ok(false);
            };
            tokio::fs::try_exists(&path)
                .await
                .map_err(|e| BlobError::Io(e.to_string()))
        })
    }
}

/// Absolute blob file path for tests and the GC sweep.
pub fn blob_file_path(root: &Path, hash_hex: &str) -> PathBuf {
    FsBlobStore::new(root.to_path_buf()).path_for(hash_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_is_the_blake3_empty_tree() {
        assert_eq!(
            blake3::hash(b"").to_hex().to_string(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn path_shape_and_hex_reject_separators() {
        let store = FsBlobStore::new(PathBuf::from("/data/blobs"));
        let hash = blake3::hash(b"x").to_hex().to_string();
        assert_eq!(
            store.path_for(&hash),
            PathBuf::from("/data/blobs").join(&hash[..2]).join(&hash)
        );
        assert!(store.validated_path("../escape").is_err());
        assert!(store.validated_path("").is_err());
    }
}
