# Archives and releases

Starforge lets you download a snapshot of a repository and publish releases with release assets.

## Download an archive

You can download the files at any branch, tag, or commit as a zip or a tar.gz archive. The web address is `/{owner}/{repo}/archive/{rest}` and the API address is `/repos/{owner}/{repo}/archive/{rest}` under `/api/v1`.

The ending of the address chooses the format. The address `main.zip` downloads a zip archive and `main.tar.gz` downloads a tar.gz archive. The name before the ending is the revision, and you can use a branch name, a tag name, or a commit id. An unknown revision returns a not found response.

The archive holds every file in the tree at that revision. The download name is the repository name, a dash, and the revision with every slash replaced by a dash, plus the format ending. A branch named `feature/x` in repository `demo` downloads as `demo-feature-x.zip`. Starforge builds the archive with `git archive` and sends it as a stream.

Reading an archive needs read access to the repository. The API route needs a token with the `repo:read` scope.

## Create a release

Open `/{owner}/{repo}/releases/new` to create a release. You type a tag, an optional target, a title, Markdown notes, and draft and prerelease flags on the form.

Creating a release needs write access to the repository. When a tag protection pattern matches the tag name, creating a release needs maintain access instead. Archived repositories and pull mirror repositories refuse every release write.

When the tag already exists, Starforge uses that tag as it stands. If you also give a target, the target must point at the same commit as the tag, and Starforge refuses the request with an invalid error when the commits differ.

When the tag does not exist, the target is required. The target can name a branch, a tag, or a commit, and Starforge refuses the request when the target is absent or unknown. Starforge creates the tag as a lightweight tag on the target commit. Tag creation never overwrites an existing ref, and a second release with the same tag is refused as a conflict.

A release created without the draft flag gets a published time equal to the creation time. A draft release has no published time. The list at `/{owner}/{repo}/releases` shows releases newest first. Draft releases appear only for users with write access or higher. Other readers never see drafts, and a single draft page answers not found for them.

Deleting a release removes the release and its assets but keeps the git tag. You can delete a release from its detail page at `/{owner}/{repo}/releases/tag/{tag}` with the delete form, or with the API delete route.

## Edit a release

Open `/{owner}/{repo}/releases/edit/{tag}` to change the title, notes, draft flag, and prerelease flag. Saving with the draft flag cleared publishes the release and sets the published time to the save time.

The API edits a release with `PATCH /repos/{owner}/{repo}/releases/{tag}`. The body can carry any subset of title, notes, draft, and prerelease. A missing field keeps its current value.

## Release assets

Each release can carry asset files. Upload from the release detail page with the multipart form, or through the API.

An asset name must hold 1 to 255 characters. The name must not contain a slash and must not be or contain a dot dot entry. An asset file can hold at most 1 GiB of bytes, and Starforge refuses larger files with an invalid error. A duplicate name inside one release is refused as a conflict.

Starforge stores the asset bytes in the blob store and counts references to each blob. Deleting an asset or a release drops the reference count. An hourly sweep removes blobs with zero references, so a deleted asset file disappears from disk after the sweep.

Downloading an asset uses `/{owner}/{repo}/releases/download/{tag}/{name}` on the web, or the API asset download route. The download sends the stored bytes as an attachment.

Deleting an asset uses the web delete form or the API delete route and answers with no content.

## Web routes

The web pages are:

- `GET /{owner}/{repo}/archive/{rest}` downloads a zip or tar.gz archive.
- `GET /{owner}/{repo}/releases` lists releases.
- `GET /{owner}/{repo}/releases/new` shows the create form.
- `POST /{owner}/{repo}/releases/new` creates a release.
- `GET /{owner}/{repo}/releases/tag/{tag}` shows one release with its assets.
- `GET /{owner}/{repo}/releases/edit/{tag}` shows the edit form.
- `POST /{owner}/{repo}/releases/edit/{tag}` saves the edit.
- `POST /{owner}/{repo}/releases/delete/{tag}` deletes a release.
- `POST /{owner}/{repo}/releases/assets/{tag}` uploads one asset from the multipart field `asset` with the CSRF field `_csrf`.
- `POST /{owner}/{repo}/releases/asset-delete/{tag}/{name}` deletes one asset.
- `GET /{owner}/{repo}/releases/download/{tag}/{name}` downloads one asset.

The asset split for the last two routes uses the last slash in the path. Tags can contain a slash, and asset names never contain a slash, so the split stays unambiguous.

## API routes

The API mirrors the web pages under `/api/v1`:

- `GET /repos/{owner}/{repo}/archive/{rest}` needs `repo:read` and downloads a zip or tar.gz archive.
- `GET /repos/{owner}/{repo}/releases` lists releases, newest first.
- `POST /repos/{owner}/{repo}/releases` needs `repo:write`, takes a JSON body with tag, optional target, title, notes, draft, and prerelease, and answers `201` with the new release.
- `GET /repos/{owner}/{repo}/releases/{tag}` shows one release.
- `PATCH /repos/{owner}/{repo}/releases/{tag}` edits title, notes, draft, and prerelease, and a missing field keeps its value.
- `DELETE /repos/{owner}/{repo}/releases/{tag}` deletes the release, keeps the git tag, and answers `204`.
- `PUT /repos/{owner}/{repo}/release-assets/{tag}/{name}` uploads raw bytes, stores the request `Content-Type` header, answers `413` past the 1 GiB cap, and answers `201` with the asset JSON.
- `GET /repos/{owner}/{repo}/release-assets/{tag}/{name}` returns the bytes with a `Content-Disposition: attachment` header.
- `DELETE /repos/{owner}/{repo}/release-assets/{tag}/{name}` deletes the asset and answers `204`.

Starforge writes an audit record for every release write under the actions `release.create`, `release.update`, `release.delete`, `release.asset.upload`, and `release.asset.delete`.
