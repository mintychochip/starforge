# Install

- git 2.38 or newer
- Rust 1.99.1 (pinned in `rust-toolchain.toml`; rustup installs it automatically)

```bash
cargo build --release
$BIN/starforged init --data-dir ./data
printf 'a long password\n' | $BIN/starforged admin user create --handle me --admin --password-stdin
$BIN/starforged serve
```

Open http://127.0.0.1:3000, sign in, create a token under **Settings → Tokens** and a repository under **New repository**, then:

```bash
git push http://me:<token>@127.0.0.1:3000/me/<repository>.git main
```

Static release tarballs (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) are built by `scripts/build-release.sh` (cargo-zigbuild, see its header) into `target/release-artifacts/` with SHA-256 sums. The OCI image is built from the `Containerfile` (Alpine 3, `git`, `openssh-client`, `ca-certificates`, `tini`, non-root `starforge` user, `/data` volume, ports 3000 and 2222); the entrypoint runs `starforged init` when `/data/starforged.toml` is missing, then `starforged serve`. `starforge` (the CLI) also distributes via cargo-dist installers and `cargo install --locked -p starforge-cli`.

## systemd

Each release tarball carries `starforged.service` next to the binaries.
The unit runs `starforged --config /etc/starforge/starforged.toml serve`
as user `starforge`, with `Restart=on-failure`, a private temporary
directory, a read-only system tree except for `/var/lib/starforge`, and
log output to the journal. The unit sets `GIT_CONFIG_GLOBAL=/dev/null`
so helper git processes ignore the user git configuration.

Create the user, the directories, and the configuration, then install
the binaries and the unit:

```bash
useradd --system --home-dir /var/lib/starforge --shell /usr/sbin/nologin starforge
install -d -o root -g root -m 0755 /etc/starforge
install -d -o starforge -g starforge -m 0750 /var/lib/starforge
install -m 0755 starforged starforge starforge-runner starforge-sandboxd /usr/local/bin/
install -m 0644 starforged.service /etc/systemd/system/starforged.service
install -m 0600 starforged.toml /etc/starforge/starforged.toml
systemctl daemon-reload
systemctl enable --now starforged
```

Set `storage.data_dir` to `/var/lib/starforge` in
`/etc/starforge/starforged.toml`. If scheduled backups use a backup
directory outside `/var/lib/starforge`, add that directory to
`ReadWritePaths=` in the unit and reload the unit.

Read logs and status with `journalctl -u starforged -f` and
`systemctl status starforged`. Restart the service after each
configuration change:

```bash
systemctl restart starforged
```

Public-instance hardening controls live in the configuration file:
`[limits]` holds `max_push_bytes`, `max_repo_bytes`, and
`git_per_ip_per_minute`; `[audit]` holds `retention_days`; and
`[backup]` holds `dir`, `interval_hours`, and `keep`. Every limit
defaults to 0, which disables it, except `backup.keep`, which
defaults to 7. See the backup page for scheduled backups and the
operations page for the exact behavior of each limit.
