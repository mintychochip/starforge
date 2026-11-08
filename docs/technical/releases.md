# Releases and archives

<!-- ste-sources
crates/starforged-core/src/releases.rs
crates/starforged-db/src/releases.rs
crates/starforged-web/src/pages/releases.rs
crates/starforged-api/src/releases.rs
crates/starforged-git/src/read.rs
crates/starforged-git/src/write.rs
-->

## Purpose

Core owns release rules and archive downloads. Git runs the archive command and creates tags. Web and API handlers stay thin.

## Scope

This page covers archives, releases, and release assets. Database tables live in [storage and database](storage-and-database.md). Web routes live in [web and auth](web-and-auth.md). API routes live in [http api](http-api.md).

## How it works

### Archives

Core resolves the revision with the branch, tag, and commit resolution. Unknown revisions return `NotFound`. The prefix equals the repository name plus the revision with each slash replaced by a dash. The filename equals the prefix plus the format ending.

```rust
prefix = format!("{}-{}", repo_name, rev.replace('/', "-"));
filename = format!("{prefix}.{}", format.extension());
```

Web serves the archive at `/{owner}/{repo}/archive/{*rest}`. API serves it at `GET /repos/{owner}/{repo}/archive/{*rest}` with `repo:read`. `ArchiveFormat::parse` splits the rest into revision and format. The split needs a non-empty revision and a known ending.

`stream_archive` runs `git archive` with the format, the prefix, and the commit id. Git 2.38 or newer compresses `tar.gz` itself. The function validates the object id first. A reaper task waits for the child and warns on failure.

```rust
git archive --format=zip --prefix=demo-main/ <commit_id>
```

`content_type` returns `application/zip` for zip and `application/gzip` for tar.gz. `Core::archive` returns `ArchiveDownload` with the child stdout, the filename, and the content type. The handler streams the stdout to the response.

### Releases

Reads need repository read access. `repo_for` returns `NotFound` without read access. Writes need write access through `require_repo`. A tag that matches a tag protection pattern needs maintain access.

Archived repositories refuse writes with `Invalid`. Pull mirror repositories also refuse writes with `Invalid`. The list returns newest first. Drafts appear only for write access or higher. A single draft answers `NotFound` below write access.

`create_release` uses an existing tag as it stands. A given target must resolve to the same commit. A mismatch returns `Invalid`. A missing tag requires a target. The target can name a branch, a tag, or a commit. An absent or unknown target returns `Invalid`.

`create_tag` validates the ref name first. It runs `update-ref` with an empty old value. The empty value refuses overwrite of an existing ref. A duplicate release answers `Conflict`. `published_at` equals now for non-draft releases. Drafts keep a null `published_at`.

`update_release` clears the draft flag and sets `published_at` on publish. `delete_release` removes the rows and keeps the git tag. Asset rows cascade from the release row. The code decrements each asset blob count before the delete.

### Release assets

Asset names allow 1 to 255 characters. The name must not contain a slash. The name must not contain a dot dot segment. Files can hold at most `MAX_ASSET_BYTES` bytes.

The cap equals 1 GiB. Oversize files return `Invalid`. Duplicate names return `Conflict`.

Upload writes bytes through `config().blob_store.put`. The code calls `blob_incref` for each new blob. Asset delete calls `blob_decref`. Release delete calls `blob_decref` for every asset. The code never deletes blob files directly. The hourly zero reference sweep removes empty blobs.

`release_asset` returns the asset view and the stored bytes. Views carry id, name, size, content type, and creation time. `ReleaseView` also carries the resolved commit id and the author handle. The author field stays optional.

Audit actions cover every write:

| Action | Meaning |
|---|---|
| `release.create` | One release created |
| `release.update` | One release edited |
| `release.delete` | One release deleted |
| `release.asset.upload` | One asset uploaded |
| `release.asset.delete` | One asset deleted |

### Web and API routes

Web routes list below:

| Method | Path |
|---|---|
| `GET` | `/{owner}/{repo}/archive/{*rest}` |
| `GET` | `/{owner}/{repo}/releases` |
| `GET` | `/{owner}/{repo}/releases/new` |
| `POST` | `/{owner}/{repo}/releases/new` |
| `GET` | `/{owner}/{repo}/releases/tag/{*tag}` |
| `GET` | `/{owner}/{repo}/releases/edit/{*tag}` |
| `POST` | `/{owner}/{repo}/releases/edit/{*tag}` |
| `POST` | `/{owner}/{repo}/releases/delete/{*tag}` |
| `POST` | `/{owner}/{repo}/releases/assets/{*tag}` |
| `POST` | `/{owner}/{repo}/releases/asset-delete/{*rest}` |
| `GET` | `/{owner}/{repo}/releases/download/{*rest}` |

The asset upload form carries the file field `asset` and the field `_csrf`. The `{*rest}` split uses the last slash. Tags can contain a slash. Asset names never contain a slash.

API routes list below:

| Method | Path | Result |
|---|---|---|
| `GET` | `/repos/{owner}/{repo}/archive/{*rest}` | Archive stream |
| `GET` | `/repos/{owner}/{repo}/releases` | Release list |
| `POST` | `/repos/{owner}/{repo}/releases` | `201` for one create |
| `GET` | `/repos/{owner}/{repo}/releases/{*tag}` | One release |
| `PATCH` | `/repos/{owner}/{repo}/releases/{*tag}` | One update |
| `DELETE` | `/repos/{owner}/{repo}/releases/{*tag}` | `204` for one delete |
| `PUT` | `/repos/{owner}/{repo}/release-assets/{*rest}` | `201` for one upload |
| `GET` | `/repos/{owner}/{repo}/release-assets/{*rest}` | Stored bytes |
| `DELETE` | `/repos/{owner}/{repo}/release-assets/{*rest}` | `204` for one delete |

`POST` releases need `repo:write`. The body carries tag, target, title, notes, draft, and prerelease. `PATCH` keeps a field when the body omits it. `PUT` uploads raw bytes and stores the request `Content-Type` header. Oversize uploads answer `413`. Asset download sends `Content-Disposition: attachment`.

## Interfaces

`ArchiveFormat` exposes `parse`, `extension`, and `content_type`. `stream_archive` returns child stdout. `Core::archive` returns `ArchiveDownload`.

`Core` exposes `releases`, `release`, `create_release`, `update_release`, `delete_release`, `upload_release_asset`, `delete_release_asset`, and `release_asset`. `create_tag` exposes lightweight tag creation with no overwrite. Core re-exports `ArchiveFormat` from content.

## Failure behavior

Unknown revisions answer `NotFound`. Unknown tags answer `NotFound`. Invalid targets and invalid names answer `Invalid`. Oversize assets answer `Invalid` in Core and `413` at the API layer. Duplicate releases and duplicate asset names answer `Conflict`.

Tag creation refuses overwrite at the git layer. Archived and pull mirror writes answer `Invalid`. Draft reads below write access answer `NotFound`.

## Verification

Unit tests cover `ArchiveFormat::parse` endings and empty revisions. Core tests cover draft visibility, tag creation, and asset caps. Web tests cover the routes and the last slash split. API tests cover status codes and the `413` limit.

## Related

Read [storage and database](storage-and-database.md) for migration `0042`. Read [web and auth](web-and-auth.md) for page routes. Read [http api](http-api.md) for API routes. Read [git hosting](git-hosting.md) for `git archive` and ref policy.

