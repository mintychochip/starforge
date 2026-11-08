//! `releases`, `release_assets`: tagged releases and their attached files
//! (forge basics Phase 3).
//!
//! The data-access layer stays thin — no validation or permission checks
//! here (those live in `starforged-core`). Asset bytes live in the blob
//! store; `blob_hash` names the stored blob. Booleans are `0`/`1` integers.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRow {
    pub id: i64,
    pub repo_id: i64,
    pub tag: String,
    pub title: String,
    pub notes: String,
    pub draft: i64,
    pub prerelease: i64,
    pub author_id: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub published_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewRelease<'a> {
    pub repo_id: i64,
    pub tag: &'a str,
    pub title: &'a str,
    pub notes: &'a str,
    pub draft: bool,
    pub prerelease: bool,
    pub author_id: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub published_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct UpdateRelease<'a> {
    pub id: i64,
    pub title: &'a str,
    pub notes: &'a str,
    pub draft: bool,
    pub prerelease: bool,
    pub published_at: Option<i64>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAssetRow {
    pub id: i64,
    pub release_id: i64,
    pub name: String,
    pub size: i64,
    pub blob_hash: String,
    pub content_type: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewReleaseAsset<'a> {
    pub release_id: i64,
    pub name: &'a str,
    pub size: i64,
    pub blob_hash: &'a str,
    pub content_type: &'a str,
    pub created_at: i64,
}

macro_rules! select_release {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, tag, title, notes, draft, prerelease, author_id, created_at, updated_at, published_at FROM releases ",
            $tail
        )
    };
}

macro_rules! select_asset {
    ($tail:literal) => {
        concat!(
            "SELECT id, release_id, name, size, blob_hash, content_type, created_at FROM release_assets ",
            $tail
        )
    };
}

fn release_from_row(row: &AnyRow) -> DbResult<ReleaseRow> {
    Ok(ReleaseRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        tag: row.try_get("tag")?,
        title: row.try_get("title")?,
        notes: row.try_get("notes")?,
        draft: row.try_get("draft")?,
        prerelease: row.try_get("prerelease")?,
        author_id: row.try_get("author_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        published_at: row.try_get("published_at")?,
    })
}

fn asset_from_row(row: &AnyRow) -> DbResult<ReleaseAssetRow> {
    Ok(ReleaseAssetRow {
        id: row.try_get("id")?,
        release_id: row.try_get("release_id")?,
        name: row.try_get("name")?,
        size: row.try_get("size")?,
        blob_hash: row.try_get("blob_hash")?,
        content_type: row.try_get("content_type")?,
        created_at: row.try_get("created_at")?,
    })
}

fn bool_to_int(b: bool) -> i64 {
    i64::from(b)
}

/// Inserts a release; a duplicate `(repo_id, tag)` violates the unique
/// index (callers in `starforged-core` pre-check and report `Conflict`).
pub async fn insert_release(db: &Db, n: &NewRelease<'_>) -> DbResult<ReleaseRow> {
    let row = sqlx::query(
        "INSERT INTO releases (repo_id, tag, title, notes, draft, prerelease, author_id, created_at, updated_at, published_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         RETURNING id, repo_id, tag, title, notes, draft, prerelease, author_id, created_at, updated_at, published_at",
    )
    .bind(n.repo_id)
    .bind(n.tag)
    .bind(n.title)
    .bind(n.notes)
    .bind(bool_to_int(n.draft))
    .bind(bool_to_int(n.prerelease))
    .bind(n.author_id)
    .bind(n.created_at)
    .bind(n.updated_at)
    .bind(n.published_at)
    .fetch_one(db.pool())
    .await?;
    release_from_row(&row)
}

/// The release for `(repo_id, tag)`, if it exists.
pub async fn release_by_tag(db: &Db, repo_id: i64, tag: &str) -> DbResult<Option<ReleaseRow>> {
    let row = sqlx::query(select_release!("WHERE repo_id = $1 AND tag = $2"))
        .bind(repo_id)
        .bind(tag)
        .fetch_optional(db.read_pool())
        .await?;
    row.map(|row| release_from_row(&row)).transpose()
}

/// Releases of the repo, newest first.
pub async fn releases_for_repo(db: &Db, repo_id: i64) -> DbResult<Vec<ReleaseRow>> {
    let rows = sqlx::query(select_release!(
        "WHERE repo_id = $1 ORDER BY created_at DESC, id DESC"
    ))
    .bind(repo_id)
    .fetch_all(db.read_pool())
    .await?;
    rows.iter().map(release_from_row).collect()
}

/// Updates a release's title, notes, and flags; `published_at` is set
/// explicitly (the caller decides when a draft is published). False when
/// the release does not exist.
pub async fn update_release(db: &Db, n: &UpdateRelease<'_>) -> DbResult<Option<ReleaseRow>> {
    let row = sqlx::query(
        "UPDATE releases SET title = $1, notes = $2, draft = $3, prerelease = $4, published_at = $5, updated_at = $6 \
         WHERE id = $7 \
         RETURNING id, repo_id, tag, title, notes, draft, prerelease, author_id, created_at, updated_at, published_at",
    )
    .bind(n.title)
    .bind(n.notes)
    .bind(bool_to_int(n.draft))
    .bind(bool_to_int(n.prerelease))
    .bind(n.published_at)
    .bind(n.updated_at)
    .bind(n.id)
    .fetch_optional(db.pool())
    .await?;
    row.map(|row| release_from_row(&row)).transpose()
}

/// Deletes a release and cascades to its assets; false when it did not
/// exist. The git tag itself is untouched.
pub async fn delete_release(db: &Db, id: i64) -> DbResult<bool> {
    let done = sqlx::query("DELETE FROM releases WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Inserts one asset row; a duplicate `(release_id, name)` violates the
/// unique index (callers pre-check and report `Conflict`).
pub async fn insert_asset(db: &Db, n: &NewReleaseAsset<'_>) -> DbResult<ReleaseAssetRow> {
    let row = sqlx::query(
        "INSERT INTO release_assets (release_id, name, size, blob_hash, content_type, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, release_id, name, size, blob_hash, content_type, created_at",
    )
    .bind(n.release_id)
    .bind(n.name)
    .bind(n.size)
    .bind(n.blob_hash)
    .bind(n.content_type)
    .bind(n.created_at)
    .fetch_one(db.pool())
    .await?;
    asset_from_row(&row)
}

/// Assets of the release in insert order.
pub async fn assets_for_release(db: &Db, release_id: i64) -> DbResult<Vec<ReleaseAssetRow>> {
    let rows = sqlx::query(select_asset!("WHERE release_id = $1 ORDER BY id ASC"))
        .bind(release_id)
        .fetch_all(db.read_pool())
        .await?;
    rows.iter().map(asset_from_row).collect()
}

/// One asset of the release by name, if it exists.
pub async fn asset_by_name(
    db: &Db,
    release_id: i64,
    name: &str,
) -> DbResult<Option<ReleaseAssetRow>> {
    let row = sqlx::query(select_asset!("WHERE release_id = $1 AND name = $2"))
        .bind(release_id)
        .bind(name)
        .fetch_optional(db.read_pool())
        .await?;
    row.map(|row| asset_from_row(&row)).transpose()
}

/// Deletes one asset row; false when it was already gone.
pub async fn delete_asset(db: &Db, id: i64) -> DbResult<bool> {
    let done = sqlx::query("DELETE FROM release_assets WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(done.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    fn user(handle: &str) -> NewUser<'_> {
        NewUser {
            handle,
            display_name: "",
            email: None,
            email_verified: false,
            password_hash: None,
            is_admin: false,
        }
    }

    fn repo(owner_id: i64, name: &str) -> NewRepo<'_> {
        NewRepo {
            owner_id,
            name,
            description: "",
            visibility: "private",
            default_branch: "main",
        }
    }

    async fn setup() -> (TestDb, i64, i64) {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("rel-alice")).await.unwrap();
        let repo_id = repos::insert(&t.db, &repo(alice, "rel-demo"))
            .await
            .unwrap();
        (t, alice, repo_id)
    }

    fn release(repo_id: i64, tag: &'static str, created_at: i64) -> NewRelease<'static> {
        NewRelease {
            repo_id,
            tag,
            title: "",
            notes: "",
            draft: false,
            prerelease: false,
            author_id: None,
            created_at,
            updated_at: created_at,
            published_at: Some(created_at),
        }
    }

    fn asset(release_id: i64, name: &'static str) -> NewReleaseAsset<'static> {
        NewReleaseAsset {
            release_id,
            name,
            size: 4,
            blob_hash: "hash-a",
            content_type: "text/plain",
            created_at: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn insert_list_by_tag_and_unique_tag() {
        let (t, _alice, repo_id) = setup().await;
        let first = insert_release(&t.db, &release(repo_id, "v1.0.0", 1_700_000_100))
            .await
            .unwrap();
        insert_release(&t.db, &release(repo_id, "v2.0.0", 1_700_000_200))
            .await
            .unwrap();

        // Newest first.
        let listed = releases_for_repo(&t.db, repo_id).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].tag, "v2.0.0");
        assert_eq!(listed[1].tag, "v1.0.0");

        let by_tag = release_by_tag(&t.db, repo_id, "v1.0.0")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_tag.id, first.id);
        assert!(
            release_by_tag(&t.db, repo_id, "v9.9.9")
                .await
                .unwrap()
                .is_none()
        );

        // A second release for the same tag violates the unique index.
        assert!(
            insert_release(&t.db, &release(repo_id, "v1.0.0", 1_700_000_300))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn assets_insert_unique_and_delete_cascade() {
        let (t, _alice, repo_id) = setup().await;
        let rel = insert_release(&t.db, &release(repo_id, "v1.0.0", 1_700_000_100))
            .await
            .unwrap();
        let a = insert_asset(&t.db, &asset(rel.id, "app.tar.gz"))
            .await
            .unwrap();
        assert_eq!(a.release_id, rel.id);
        assert_eq!(assets_for_release(&t.db, rel.id).await.unwrap().len(), 1);
        assert_eq!(
            asset_by_name(&t.db, rel.id, "app.tar.gz")
                .await
                .unwrap()
                .unwrap()
                .id,
            a.id
        );
        assert!(
            asset_by_name(&t.db, rel.id, "missing")
                .await
                .unwrap()
                .is_none()
        );

        // A duplicate asset name violates the unique index.
        assert!(
            insert_asset(&t.db, &asset(rel.id, "app.tar.gz"))
                .await
                .is_err()
        );

        // Deleting a single asset keeps the release.
        assert!(delete_asset(&t.db, a.id).await.unwrap());
        assert!(assets_for_release(&t.db, rel.id).await.unwrap().is_empty());
        assert!(
            release_by_tag(&t.db, repo_id, "v1.0.0")
                .await
                .unwrap()
                .is_some()
        );

        // Deleting the release cascades to its assets.
        insert_asset(&t.db, &asset(rel.id, "app.tar.gz"))
            .await
            .unwrap();
        assert!(delete_release(&t.db, rel.id).await.unwrap());
        assert!(!delete_release(&t.db, rel.id).await.unwrap());
        assert!(assets_for_release(&t.db, rel.id).await.unwrap().is_empty());
    }
}
