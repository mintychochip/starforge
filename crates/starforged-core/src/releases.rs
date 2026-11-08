//! Releases (forge basics Phase 3): a tag with a title, Markdown notes,
//! draft/prerelease flags, and uploaded asset files.
//!
//! Reads need repository Read; drafts are visible only at Write and above.
//! Writes need Write, or Maintain when the tag matches a tag-protection
//! pattern. Archived and pull-mirror repositories refuse writes. Creating a
//! release for a missing tag creates a lightweight `refs/tags/<tag>` at the
//! target commit; deleting a release keeps the git tag. Asset bytes live in
//! the blob store, reference-counted in `blobs`; deletes only decrement the
//! count and the hourly sweep removes zero-ref blobs.

use starforged_db::now;
use starforged_db::protection as db_protection;
use starforged_db::releases as db_releases;
use starforged_db::sessions as db_sessions;
use starforged_git::refpolicy::pattern_matches;
use starforged_git::write as git_write;

use crate::accounts::User;
use crate::permission::Permission;
use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// The largest single release asset: 1 GiB.
pub const MAX_ASSET_BYTES: i64 = 1 << 30;

/// One uploaded file of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetView {
    pub id: i64,
    pub name: String,
    pub size: i64,
    pub content_type: String,
    pub created_at: i64,
}

/// One release with the commit its tag points at and its assets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseView {
    pub id: i64,
    pub tag: String,
    pub title: String,
    pub notes: String,
    pub draft: bool,
    pub prerelease: bool,
    pub commit_id: String,
    pub author: Option<String>,
    pub created_at: i64,
    pub published_at: Option<i64>,
    pub assets: Vec<AssetView>,
}

/// Create-release input: `target` names the branch, tag, or commit to tag
/// when the tag does not exist yet.
#[derive(Debug, Clone)]
pub struct ReleaseInput<'a> {
    pub tag: &'a str,
    pub target: Option<&'a str>,
    pub title: &'a str,
    pub notes: &'a str,
    pub draft: bool,
    pub prerelease: bool,
}

/// Update-release input: every field replaces the stored value.
#[derive(Debug, Clone)]
pub struct ReleaseEdit<'a> {
    pub title: &'a str,
    pub notes: &'a str,
    pub draft: bool,
    pub prerelease: bool,
}

/// One release-asset upload: the file name, its media type, and its bytes.
#[derive(Debug, Clone)]
pub struct AssetUpload<'a> {
    pub name: &'a str,
    pub content_type: &'a str,
    pub bytes: &'a [u8],
}

fn asset_view(row: &db_releases::ReleaseAssetRow) -> AssetView {
    AssetView {
        id: row.id,
        name: row.name.clone(),
        size: row.size,
        content_type: row.content_type.clone(),
        created_at: row.created_at,
    }
}

/// Validates one asset name: 1–255 chars, a single file name (no `/`, no
/// `..`, no whitespace or control characters).
fn validate_asset_name(name: &str) -> CoreResult<()> {
    if name.is_empty() || name.len() > 255 {
        return Err(CoreError::Invalid(
            "asset name must be 1-255 characters".into(),
        ));
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ')
    {
        return Err(CoreError::Invalid(format!(
            "asset name `{name}` must be a file name without path separators or `..`"
        )));
    }
    Ok(())
}

impl Core {
    /// Releases of the repository, newest first. Drafts are listed only for
    /// Write and above.
    pub async fn releases(
        &self,
        user: Option<&User>,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<ReleaseView>> {
        let access = self.repo_for(user, owner, repo).await?;
        let rows = db_releases::releases_for_repo(self.db(), access.repo.id).await?;
        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            if row.draft != 0 && access.permission < Permission::Write {
                continue;
            }
            views.push(self.release_view(&access, &row).await?);
        }
        Ok(views)
    }

    /// One release by tag. A draft below Write reads as `NotFound`.
    pub async fn release(
        &self,
        user: Option<&User>,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> CoreResult<ReleaseView> {
        let access = self.repo_for(user, owner, repo).await?;
        let row = self.release_row(&access, tag).await?;
        if row.draft != 0 && access.permission < Permission::Write {
            return Err(CoreError::NotFound);
        }
        self.release_view(&access, &row).await
    }

    /// Creates a release for `input.tag`. An existing tag is used as is (a
    /// given target must resolve to the same commit, else `Invalid`); a
    /// missing tag needs `target` and is created at that commit. A release
    /// for the tag already existing is `Conflict`.
    pub async fn create_release(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        input: &ReleaseInput<'_>,
    ) -> CoreResult<ReleaseView> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        self.ensure_release_writable(&access)?;
        self.check_tag_write(&access, input.tag).await?;
        if db_releases::release_by_tag(self.db(), access.repo.id, input.tag)
            .await?
            .is_some()
        {
            return Err(CoreError::Conflict(format!(
                "a release for tag '{}' already exists",
                input.tag
            )));
        }
        match self.tag_commit(access.repo.id, input.tag).await? {
            Some(existing) => {
                if let Some(target) = input.target {
                    let resolved = self.resolve_target(&access, target).await?;
                    if resolved != existing {
                        return Err(CoreError::Invalid(format!(
                            "target '{target}' does not match tag '{}'",
                            input.tag
                        )));
                    }
                }
            }
            None => {
                let Some(target) = input.target else {
                    return Err(CoreError::Invalid(format!(
                        "tag '{}' does not exist and no target was given",
                        input.tag
                    )));
                };
                let commit_id = self.resolve_target(&access, target).await?;
                let _repo_lock = self.repo_lock_shared(access.repo.id).await?;
                let repo_path = self.repo_path(access.repo.id);
                let tag = input.tag.to_owned();
                if let Err(err) = git_write::create_tag(&repo_path, &tag, &commit_id).await {
                    if self.tag_commit(access.repo.id, &tag).await?.is_some() {
                        return Err(CoreError::Conflict(format!("tag '{tag}' already exists")));
                    }
                    return Err(CoreError::Invalid(format!("invalid tag '{tag}': {err}")));
                }
            }
        };
        let stamp = now();
        let row = db_releases::insert_release(
            self.db(),
            &db_releases::NewRelease {
                repo_id: access.repo.id,
                tag: input.tag,
                title: input.title,
                notes: input.notes,
                draft: input.draft,
                prerelease: input.prerelease,
                author_id: Some(user.id),
                created_at: stamp,
                updated_at: stamp,
                published_at: (!input.draft).then_some(stamp),
            },
        )
        .await
        .map_err(|e| {
            if e.is_unique_violation() {
                CoreError::Conflict(format!("a release for tag '{}' already exists", input.tag))
            } else {
                CoreError::from(e)
            }
        })?;
        self.audit(
            Some(user.id),
            "release.create",
            &release_target(owner, repo, input.tag),
            input.title,
        )
        .await?;
        self.release_view(&access, &row).await
    }

    /// Updates a release's title, notes, and flags. Publishing a draft
    /// stamps `published_at`; unpublishing clears it.
    pub async fn update_release(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        tag: &str,
        edit: &ReleaseEdit<'_>,
    ) -> CoreResult<ReleaseView> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        self.ensure_release_writable(&access)?;
        self.check_tag_write(&access, tag).await?;
        let row = self.release_row(&access, tag).await?;
        let published_at = if edit.draft {
            None
        } else if row.draft != 0 {
            Some(now())
        } else {
            row.published_at
        };
        let updated = db_releases::update_release(
            self.db(),
            &db_releases::UpdateRelease {
                id: row.id,
                title: edit.title,
                notes: edit.notes,
                draft: edit.draft,
                prerelease: edit.prerelease,
                published_at,
                updated_at: now(),
            },
        )
        .await?
        .ok_or(CoreError::NotFound)?;
        self.audit(
            Some(user.id),
            "release.update",
            &release_target(owner, repo, tag),
            edit.title,
        )
        .await?;
        self.release_view(&access, &updated).await
    }

    /// Deletes a release and its asset rows, decrementing every asset's
    /// blob refcount. The git tag itself is kept.
    pub async fn delete_release(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        self.ensure_release_writable(&access)?;
        self.check_tag_write(&access, tag).await?;
        let row = self.release_row(&access, tag).await?;
        let assets = db_releases::assets_for_release(self.db(), row.id).await?;
        if !db_releases::delete_release(self.db(), row.id).await? {
            return Err(CoreError::NotFound);
        }
        for asset in &assets {
            db_sessions::blob_decref(self.db(), &asset.blob_hash).await?;
        }
        self.audit(
            Some(user.id),
            "release.delete",
            &release_target(owner, repo, tag),
            "",
        )
        .await?;
        Ok(())
    }

    /// Uploads one asset to a release: the bytes go to the blob store and
    /// the blob is reference-counted. A duplicate name is `Conflict`.
    pub async fn upload_release_asset(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        tag: &str,
        asset: &AssetUpload<'_>,
    ) -> CoreResult<AssetView> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        self.ensure_release_writable(&access)?;
        self.check_tag_write(&access, tag).await?;
        validate_asset_name(asset.name)?;
        if asset.bytes.len() as i64 > MAX_ASSET_BYTES {
            return Err(CoreError::Invalid(format!(
                "asset exceeds the {MAX_ASSET_BYTES}-byte cap"
            )));
        }
        let row = self.release_row(&access, tag).await?;
        if db_releases::asset_by_name(self.db(), row.id, asset.name)
            .await?
            .is_some()
        {
            return Err(CoreError::Conflict(format!(
                "release '{tag}' already has an asset named '{}'",
                asset.name
            )));
        }
        let blob = self
            .config()
            .blob_store
            .put(asset.bytes)
            .await
            .map_err(|e| CoreError::Internal(format!("asset blob store: {e}")))?;
        let size = asset.bytes.len() as i64;
        db_sessions::blob_incref(self.db(), &blob.hash, size, &blob.hash).await?;
        let inserted = match db_releases::insert_asset(
            self.db(),
            &db_releases::NewReleaseAsset {
                release_id: row.id,
                name: asset.name,
                size,
                blob_hash: &blob.hash,
                content_type: asset.content_type,
                created_at: now(),
            },
        )
        .await
        {
            Ok(asset) => asset,
            Err(e) => {
                let _ = db_sessions::blob_decref(self.db(), &blob.hash).await;
                return Err(if e.is_unique_violation() {
                    CoreError::Conflict(format!(
                        "release '{tag}' already has an asset named '{}'",
                        asset.name
                    ))
                } else {
                    CoreError::from(e)
                });
            }
        };
        self.audit(
            Some(user.id),
            "release.asset.upload",
            &asset_target(owner, repo, tag, asset.name),
            asset.content_type,
        )
        .await?;
        Ok(asset_view(&inserted))
    }

    /// Deletes one asset of a release, decrementing its blob refcount.
    pub async fn delete_release_asset(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        tag: &str,
        name: &str,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        self.ensure_release_writable(&access)?;
        self.check_tag_write(&access, tag).await?;
        let row = self.release_row(&access, tag).await?;
        let asset = db_releases::asset_by_name(self.db(), row.id, name)
            .await?
            .ok_or(CoreError::NotFound)?;
        if !db_releases::delete_asset(self.db(), asset.id).await? {
            return Err(CoreError::NotFound);
        }
        db_sessions::blob_decref(self.db(), &asset.blob_hash).await?;
        self.audit(
            Some(user.id),
            "release.asset.delete",
            &asset_target(owner, repo, tag, name),
            "",
        )
        .await?;
        Ok(())
    }

    /// Downloads one asset: its bytes and metadata. A draft release below
    /// Write reads as `NotFound`.
    pub async fn release_asset(
        &self,
        user: Option<&User>,
        owner: &str,
        repo: &str,
        tag: &str,
        name: &str,
    ) -> CoreResult<(AssetView, Vec<u8>)> {
        let access = self.repo_for(user, owner, repo).await?;
        let row = self.release_row(&access, tag).await?;
        if row.draft != 0 && access.permission < Permission::Write {
            return Err(CoreError::NotFound);
        }
        let asset = db_releases::asset_by_name(self.db(), row.id, name)
            .await?
            .ok_or(CoreError::NotFound)?;
        let bytes = self
            .config()
            .blob_store
            .get_by_hash(&asset.blob_hash)
            .await
            .map_err(|e| CoreError::Internal(format!("reading asset blob: {e}")))?;
        Ok((asset_view(&asset), bytes))
    }

    fn ensure_release_writable(&self, access: &RepoAccess) -> CoreResult<()> {
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        if access.repo.mirror {
            return Err(CoreError::Invalid(
                "this repository is a pull mirror".into(),
            ));
        }
        Ok(())
    }

    /// Tag-protection gate for release writes: a tag matching any
    /// protection pattern needs Maintain or above (like a tag push).
    async fn check_tag_write(&self, access: &RepoAccess, tag: &str) -> CoreResult<()> {
        if access.permission >= Permission::Maintain {
            return Ok(());
        }
        for row in db_protection::tag_protections_for_repo(self.db(), access.repo.id).await? {
            if pattern_matches(Some(row.pattern.as_str()), tag) {
                return Err(CoreError::Forbidden);
            }
        }
        Ok(())
    }

    async fn release_row(
        &self,
        access: &RepoAccess,
        tag: &str,
    ) -> CoreResult<db_releases::ReleaseRow> {
        db_releases::release_by_tag(self.db(), access.repo.id, tag)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// The commit `tag` points at, or `None` when the tag does not exist.
    async fn tag_commit(&self, repo_id: i64, tag: &str) -> CoreResult<Option<String>> {
        let repo_path = self.repo_path(repo_id);
        let tag = tag.to_owned();
        let tags = tokio::task::spawn_blocking(move || starforged_git::read::tag_list(&repo_path))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?
            .map_err(CoreError::from)?;
        Ok(tags
            .into_iter()
            .find(|t| t.name == tag)
            .map(|t| t.commit_id))
    }

    /// The commit `target` (branch, tag, or commit) names, or `Invalid`
    /// when it names nothing.
    async fn resolve_target(&self, access: &RepoAccess, target: &str) -> CoreResult<String> {
        match self.resolve(access, target).await {
            Ok(resolved) if resolved.path.is_empty() => Ok(resolved.commit_id),
            _ => Err(CoreError::Invalid(format!("unknown target '{target}'"))),
        }
    }

    async fn release_view(
        &self,
        access: &RepoAccess,
        row: &db_releases::ReleaseRow,
    ) -> CoreResult<ReleaseView> {
        let assets = db_releases::assets_for_release(self.db(), row.id)
            .await?
            .iter()
            .map(asset_view)
            .collect();
        let commit_id = self
            .tag_commit(access.repo.id, &row.tag)
            .await?
            .unwrap_or_default();
        let author = match row.author_id {
            Some(id) => self.user_by_id(id).await?.map(|u| u.handle),
            None => None,
        };
        Ok(ReleaseView {
            id: row.id,
            tag: row.tag.clone(),
            title: row.title.clone(),
            notes: row.notes.clone(),
            draft: row.draft != 0,
            prerelease: row.prerelease != 0,
            commit_id,
            author,
            created_at: row.created_at,
            published_at: row.published_at,
            assets,
        })
    }
}

fn release_target(owner: &str, repo: &str, tag: &str) -> String {
    format!("release:{owner}/{repo}#{tag}")
}

fn asset_target(owner: &str, repo: &str, tag: &str, name: &str) -> String {
    format!("release_asset:{owner}/{repo}#{tag}/{name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::{test_core, user};

    async fn setup() -> (Core, User, User, i64, crate::testing::Fixture) {
        let (core, fixture) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = core
            .create_repo(
                &alice,
                "alice",
                CreateRepo {
                    name: "proj".into(),
                    description: String::new(),
                    visibility: Visibility::Public,
                    readme: false,
                },
            )
            .await
            .unwrap();
        crate::testing::seed_branches(&core, repo.id, &["main"]);
        let bob = user(&core, "bob").await;
        (core, alice, bob, repo.id, fixture)
    }

    fn input<'a>(tag: &'a str, target: Option<&'a str>) -> ReleaseInput<'a> {
        ReleaseInput {
            tag,
            target,
            title: "First release",
            notes: "notes",
            draft: false,
            prerelease: false,
        }
    }

    #[tokio::test]
    async fn create_from_branch_target_creates_tag() {
        let (core, alice, _bob, _repo_id, _f) = setup().await;
        let view = core
            .create_release(&alice, "alice", "proj", &input("v1.0.0", Some("main")))
            .await
            .unwrap();
        assert_eq!(view.tag, "v1.0.0");
        assert!(!view.draft);
        assert!(view.published_at.is_some());
        assert_eq!(view.author.as_deref(), Some("alice"));
        assert!(!view.commit_id.is_empty());

        // The lightweight tag now points at main's commit.
        let access = core.repo_for(Some(&alice), "alice", "proj").await.unwrap();
        let tags = core.tag_list(&access).await.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "v1.0.0");
        assert_eq!(tags[0].commit_id, view.commit_id);
    }

    #[tokio::test]
    async fn existing_tag_with_different_target_is_invalid_and_second_release_conflicts() {
        let (core, alice, _bob, repo_id, _f) = setup().await;
        // Create a second branch tip via a tag on main by seeding another branch.
        crate::testing::seed_branches(&core, repo_id, &["main"]);
        let created = core
            .create_release(&alice, "alice", "proj", &input("v1.0.0", Some("main")))
            .await
            .unwrap();
        // Seed a new commit on main through a fresh branch, then reuse it as target.
        crate::testing::seed_branches(&core, repo_id, &["main", "other"]);
        let access = core.repo_for(Some(&alice), "alice", "proj").await.unwrap();
        let branches = core.branch_list(&access).await.unwrap();
        let other = branches.iter().find(|b| b.name == "other").unwrap();
        assert_ne!(other.tip.id, created.commit_id);

        let err = core
            .create_release(
                &alice,
                "alice",
                "proj",
                &ReleaseInput {
                    tag: "v1.0.0",
                    target: Some("other"),
                    ..input("v1.0.0", None)
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Conflict(_)),
            "second release is Conflict, got {err:?}"
        );

        // A different tag whose target disagrees with... use a fresh tag pointing at other:
        // create it directly in git, then a release with a mismatched target is Invalid.
        let repo_path = core.repo_path(access.repo.id);
        // main's commit:
        let main_tip = branches
            .iter()
            .find(|b| b.name == "main")
            .unwrap()
            .tip
            .id
            .clone();
        starforged_git::write::create_tag(&repo_path, "v2.0.0", &main_tip)
            .await
            .unwrap();
        let err = core
            .create_release(
                &alice,
                "alice",
                "proj",
                &ReleaseInput {
                    tag: "v2.0.0",
                    target: Some("other"),
                    ..input("v2.0.0", None)
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(_)), "got {err:?}");

        // Missing tag without a target is Invalid.
        let err = core
            .create_release(&alice, "alice", "proj", &input("v3.0.0", None))
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn read_user_cannot_create_and_does_not_see_drafts() {
        let (core, alice, bob, _repo_id, _f) = setup().await;
        let err = core
            .create_release(&bob, "alice", "proj", &input("v1.0.0", Some("main")))
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Forbidden), "got {err:?}");

        core.create_release(
            &alice,
            "alice",
            "proj",
            &ReleaseInput {
                draft: true,
                ..input("v1.0.0", Some("main"))
            },
        )
        .await
        .unwrap();

        // Bob (Read) does not see the draft in the list or by tag.
        assert!(
            core.releases(Some(&bob), "alice", "proj")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            core.release(Some(&bob), "alice", "proj", "v1.0.0").await,
            Err(CoreError::NotFound)
        ));
        // Alice (Admin) sees it.
        assert_eq!(
            core.releases(Some(&alice), "alice", "proj")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn protected_tag_needs_maintain() {
        let (core, alice, bob, _repo_id, _f) = setup().await;
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
            .await
            .unwrap();
        let access = core.repo_for(Some(&alice), "alice", "proj").await.unwrap();
        starforged_db::protection::insert_tag_protection(core.db(), access.repo.id, "v*", now())
            .await
            .unwrap();

        // Bob has Write but not Maintain: protected tags refuse him.
        let err = core
            .create_release(&bob, "alice", "proj", &input("v1.0.0", Some("main")))
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Forbidden), "got {err:?}");

        // Alice (owner, Admin) can.
        core.create_release(&alice, "alice", "proj", &input("v1.0.0", Some("main")))
            .await
            .unwrap();
        // An unprotected tag is fine for Bob.
        core.create_release(&bob, "alice", "proj", &input("release-1", Some("main")))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asset_validation_and_refcounts() {
        let (core, alice, _bob, repo_id, _f) = setup().await;
        core.create_release(&alice, "alice", "proj", &input("v1.0.0", Some("main")))
            .await
            .unwrap();

        for bad in ["../evil", "a/b", "", "a b"] {
            let upload = AssetUpload {
                name: bad,
                content_type: "text/plain",
                bytes: b"x",
            };
            let err = core
                .upload_release_asset(&alice, "alice", "proj", "v1.0.0", &upload)
                .await
                .unwrap_err();
            assert!(matches!(err, CoreError::Invalid(_)), "{bad}: {err:?}");
        }

        let upload = AssetUpload {
            name: "app.bin",
            content_type: "application/octet-stream",
            bytes: b"hello",
        };
        let asset = core
            .upload_release_asset(&alice, "alice", "proj", "v1.0.0", &upload)
            .await
            .unwrap();
        assert_eq!(asset.name, "app.bin");
        assert_eq!(asset.size, 5);

        // Duplicate name is Conflict.
        assert!(matches!(
            core.upload_release_asset(
                &alice,
                "alice",
                "proj",
                "v1.0.0",
                &AssetUpload {
                    name: "app.bin",
                    content_type: "text/plain",
                    bytes: b"x",
                },
            )
            .await,
            Err(CoreError::Conflict(_))
        ));

        let (_view, bytes) = core
            .release_asset(Some(&alice), "alice", "proj", "v1.0.0", "app.bin")
            .await
            .unwrap();
        assert_eq!(bytes, b"hello");

        // The blob is reference-counted; deleting the asset decrements it.
        let release_id = db_releases::release_by_tag(core.db(), repo_id, "v1.0.0")
            .await
            .unwrap()
            .unwrap()
            .id;
        let row = db_releases::asset_by_name(core.db(), release_id, "app.bin")
            .await
            .unwrap()
            .unwrap();
        let blob = db_sessions::blob_by_hash(core.db(), &row.blob_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.refcount, 1);

        core.delete_release_asset(&alice, "alice", "proj", "v1.0.0", "app.bin")
            .await
            .unwrap();
        let blob = db_sessions::blob_by_hash(core.db(), &row.blob_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.refcount, 0);

        // Deleting a release decrements its assets' refcounts too.
        core.upload_release_asset(
            &alice,
            "alice",
            "proj",
            "v1.0.0",
            &AssetUpload {
                name: "app2.bin",
                content_type: "text/plain",
                bytes: b"world",
            },
        )
        .await
        .unwrap();
        let row = db_releases::asset_by_name(core.db(), release_id, "app2.bin")
            .await
            .unwrap()
            .unwrap();
        let hash = row.blob_hash.clone();
        core.delete_release(&alice, "alice", "proj", "v1.0.0")
            .await
            .unwrap();
        let blob = db_sessions::blob_by_hash(core.db(), &hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.refcount, 0);
        // The git tag survives the release deletion.
        let access = core.repo_for(Some(&alice), "alice", "proj").await.unwrap();
        assert_eq!(core.tag_list(&access).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn update_publishes_a_draft() {
        let (core, alice, _bob, _repo_id, _f) = setup().await;
        core.create_release(
            &alice,
            "alice",
            "proj",
            &ReleaseInput {
                draft: true,
                title: "t",
                ..input("v1.0.0", Some("main"))
            },
        )
        .await
        .unwrap();
        let view = core
            .update_release(
                &alice,
                "alice",
                "proj",
                "v1.0.0",
                &ReleaseEdit {
                    title: "t2",
                    notes: "n",
                    draft: false,
                    prerelease: true,
                },
            )
            .await
            .unwrap();
        assert!(!view.draft);
        assert!(view.prerelease);
        assert!(view.published_at.is_some());
        assert_eq!(view.title, "t2");
    }
}
