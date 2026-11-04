//! Filesystem blob store contract: content addressing, atomic writes, read verification.

use std::sync::Arc;

use starforged_blob::{BlobRef, BlobStore, FsBlobStore};

fn tmp_store() -> (tempfile::TempDir, FsBlobStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = FsBlobStore::new(dir.path().join("blobs"));
    (dir, store)
}

/// `(total files, temp files)` under the store root, recursing one shard level.
fn census(root: &std::path::Path) -> (usize, usize) {
    let mut total = 0;
    let mut tmps = 0;
    let Ok(shards) = std::fs::read_dir(root) else {
        return (0, 0);
    };
    for shard in shards.flatten() {
        let Ok(entries) = std::fs::read_dir(shard.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            total += 1;
            if entry.file_name().to_string_lossy().contains(".tmp-") {
                tmps += 1;
            }
        }
    }
    (total, tmps)
}

#[tokio::test]
async fn put_get_round_trip() {
    let (_dir, store) = tmp_store();
    let bytes = b"session segment bytes";
    let r = store.put(bytes).await.unwrap();
    assert_eq!(r.size, bytes.len() as u64);
    assert_eq!(r.hash, blake3::hash(bytes).to_hex().to_string());
    assert_eq!(r.key, r.hash);
    let back = store.get(&r).await.unwrap();
    assert_eq!(back, bytes);
    let by_hash = store.get_by_hash(&r.hash).await.unwrap();
    assert_eq!(by_hash, bytes);
}

#[tokio::test]
async fn put_twice_dedupes_to_one_file() {
    let (dir, store) = tmp_store();
    let bytes = b"dedup me";
    let a = store.put(bytes).await.unwrap();
    let b = store.put(bytes).await.unwrap();
    assert_eq!(a, b);
    let (total, tmps) = census(&dir.path().join("blobs"));
    assert_eq!((total, tmps), (1, 0));
}

#[tokio::test]
async fn identical_reput_after_read_still_succeeds() {
    let (_dir, store) = tmp_store();
    let bytes = b"re-put me";
    let a = store.put(bytes).await.unwrap();
    let _ = store.get(&a).await.unwrap();
    let b = store.put(bytes).await.unwrap();
    assert_eq!(a, b);
    assert_eq!(store.get(&b).await.unwrap(), bytes);
}

#[tokio::test]
async fn get_missing_is_not_found() {
    let (_dir, store) = tmp_store();
    let hash = blake3::hash(b"never stored").to_hex().to_string();
    let err = store.get_by_hash(&hash).await.unwrap_err();
    assert!(matches!(err, starforged_blob::BlobError::NotFound(_)));
    let ghost = BlobRef {
        hash: hash.clone(),
        size: 12,
        key: hash.clone(),
    };
    assert!(matches!(
        store.get(&ghost).await.unwrap_err(),
        starforged_blob::BlobError::NotFound(_)
    ));
}

#[tokio::test]
async fn corrupt_on_read() {
    let (_dir, store) = tmp_store();
    let r = store.put(b"original bytes").await.unwrap();
    std::fs::write(store.path_for(&r.hash), b"tampered bytes").unwrap();
    let err = store.get(&r).await.unwrap_err();
    assert!(
        matches!(err, starforged_blob::BlobError::Corrupt(_)),
        "{err:?}"
    );
    let err = store.get_by_hash(&r.hash).await.unwrap_err();
    assert!(
        matches!(err, starforged_blob::BlobError::Corrupt(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn delete_is_idempotent() {
    let (_dir, store) = tmp_store();
    let r = store.put(b"ephemeral").await.unwrap();
    assert!(store.exists(&r.hash).await.unwrap());
    store.delete(&r).await.unwrap();
    assert!(!store.exists(&r.hash).await.unwrap());
    // Second delete is a no-op success; reads now miss.
    store.delete(&r).await.unwrap();
    assert!(matches!(
        store.get(&r).await.unwrap_err(),
        starforged_blob::BlobError::NotFound(_)
    ));
}

#[tokio::test]
async fn exists_reports_presence() {
    let (_dir, store) = tmp_store();
    let missing = blake3::hash(b"absent").to_hex().to_string();
    assert!(!store.exists(&missing).await.unwrap());
    let r = store.put(b"present").await.unwrap();
    assert!(store.exists(&r.hash).await.unwrap());
}

#[tokio::test]
async fn empty_input_hashes_and_round_trips() {
    let (_dir, store) = tmp_store();
    let r = store.put(b"").await.unwrap();
    assert_eq!(
        r.hash,
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert_eq!(r.size, 0);
    assert_eq!(store.get(&r).await.unwrap(), b"");
}

#[tokio::test]
async fn shard_path_shape() {
    let (dir, store) = tmp_store();
    let r = store.put(b"sharded").await.unwrap();
    assert_eq!(
        store.path_for(&r.hash),
        dir.path().join("blobs").join(&r.hash[..2]).join(&r.hash)
    );
    assert!(store.path_for(&r.hash).is_file());
}

#[tokio::test]
async fn no_temp_files_left_behind() {
    let (dir, store) = tmp_store();
    for i in 0..8u32 {
        store.put(format!("payload {i}").as_bytes()).await.unwrap();
    }
    // Re-put everything; idempotent puts must not leak temp files either.
    for i in 0..8u32 {
        store.put(format!("payload {i}").as_bytes()).await.unwrap();
    }
    let (total, tmps) = census(&dir.path().join("blobs"));
    assert_eq!((total, tmps), (8, 0));
}

#[tokio::test]
async fn concurrent_puts_of_same_bytes_do_not_corrupt() {
    let (_dir, store) = tmp_store();
    let store = Arc::new(store);
    let bytes = b"racing bytes";
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let s = store.clone();
        tasks.push(tokio::spawn(async move { s.put(bytes).await }));
    }
    let mut refs = Vec::new();
    for t in tasks {
        refs.push(t.await.unwrap().unwrap());
    }
    for r in &refs {
        assert_eq!(*r, refs[0]);
    }
    // Every read after the race sees complete bytes.
    for _ in 0..4 {
        assert_eq!(store.get(&refs[0]).await.unwrap(), bytes);
    }
}

#[tokio::test]
async fn store_is_object_safe_behind_arc_dyn() {
    fn serve(store: Arc<dyn BlobStore>) -> Arc<dyn BlobStore> {
        store
    }
    let (_dir, store) = tmp_store();
    let dyned: Arc<dyn BlobStore> = serve(Arc::new(store));
    let r = dyned.put(b"through dyn").await.unwrap();
    assert!(dyned.exists(&r.hash).await.unwrap());
    assert_eq!(dyned.get_by_hash(&r.hash).await.unwrap(), b"through dyn");
    dyned.delete(&r).await.unwrap();
    assert!(!dyned.exists(&r.hash).await.unwrap());
}
