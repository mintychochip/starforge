#!/bin/sh
# Starforge container entrypoint: init on first start, then serve.
# /data is the only volume; the config lives at /data/starforged.toml and
# data_dir is /data itself (config's storage.data_dir, repos, db, index).
set -eu

DATA_DIR="${STARFORGE_DATA_DIR:-/data}"
CONFIG="${STARFORGE_CONFIG:-$DATA_DIR/starforged.toml}"

mkdir -p "$DATA_DIR"

if [ ! -f "$CONFIG" ]; then
  echo "starforged: no config at $CONFIG; running init"
  starforged --config "$CONFIG" init \
    --data-dir "$DATA_DIR" \
    --http-addr "${STARFORGE_HTTP_ADDR:-0.0.0.0:3000}" \
    --base-url "${STARFORGE_BASE_URL:-http://127.0.0.1:3000}"
fi
# STARFORGE_BASE_URL / STARFORGE_HTTP_ADDR also change the running
# server on every start (they are mapped onto the config overrides
# STARFORGE__SERVER__BASE_URL / STARFORGE__SERVER__HTTP_ADDR that
# Config::load applies via apply_env), not only at init time.
[ -n "${STARFORGE_BASE_URL:-}" ] && export STARFORGE__SERVER__BASE_URL="$STARFORGE_BASE_URL"
[ -n "${STARFORGE_HTTP_ADDR:-}" ] && export STARFORGE__SERVER__HTTP_ADDR="$STARFORGE_HTTP_ADDR"

exec starforged --config "$CONFIG" serve
