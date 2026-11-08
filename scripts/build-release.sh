#!/usr/bin/env bash
# Build static starforged/starforge binaries for x86_64 and aarch64 musl
# with cargo-zigbuild (zig as the musl C toolchain), then tarball + SHA-256.
# Idempotent: safe to re-run; stale artifacts for the built targets are replaced.
set -euo pipefail
cd "$(dirname "$0")/.."

# cargo-zigbuild shells out to `zig`; the standard install location is
# ~/.local/bin/zig, which is not always on PATH.
if [[ -x "$HOME/.local/bin/zig" ]]; then
  export PATH="$HOME/.local/bin:$PATH"
fi

for tool in cargo zig; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool not found on PATH" >&2; exit 1; }
done
# cargo-zigbuild has no --version flag; --help succeeds when it is installed.
cargo zigbuild --help >/dev/null 2>&1 || { echo "error: cargo-zigbuild not installed (cargo install --locked cargo-zigbuild)" >&2; exit 1; }

VERSION="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; pkgs=json.load(sys.stdin)["packages"]; print(next(p["version"] for p in pkgs if p["name"] == "starforged"))')"

TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
OUT_DIR="target/release-artifacts"
# Binaries land in CARGO_TARGET_DIR when set; artifacts stay under the
# worktree's target/ so the Containerfile can COPY them from the context.
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
mkdir -p "$OUT_DIR"
# Delete stale artifacts so the Containerfile COPY glob
# (starforged-*-<target>.tar.gz) never matches more than one file.
rm -f "$OUT_DIR"/starforged-*.tar.gz "$OUT_DIR"/starforged-*-SHA256SUMS

for target in "${TARGETS[@]}"; do
  echo "==> building $target"
  cargo zigbuild --release --target "$target" -p starforged -p starforge-cli -p starforge-runner -p starforge-sandboxd

  stage="$OUT_DIR/$target"
  rm -rf "$stage"
  mkdir -p "$stage"
  cp "$TARGET_DIR/$target/release/starforged" "$TARGET_DIR/$target/release/starforge" "$TARGET_DIR/$target/release/starforge-runner" "$TARGET_DIR/$target/release/starforge-sandboxd" "$stage/"
  cp packaging/systemd/starforged.service "$stage/"
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - -C "$OUT_DIR" "$target" | gzip -n > "$OUT_DIR/starforged-$VERSION-$target.tar.gz"
  rm -rf "$stage"
done

# SHA-256 sums next to the tarballs.
(cd "$OUT_DIR" && sha256sum starforged-"$VERSION"-*.tar.gz > "starforged-$VERSION-SHA256SUMS")

echo "==> artifacts:"
ls -l "$OUT_DIR"
cat "$OUT_DIR/starforged-$VERSION-SHA256SUMS"
