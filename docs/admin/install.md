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
