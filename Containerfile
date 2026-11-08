# Starforge OCI image (plan M5d D2).
#
# Base: alpine:3 (musl matches the static musl binary). Runtime
# dependencies: git (>= 2.38 via apk), openssh-client (SSH remotes), and
# ca-certificates. tini is PID 1; the server runs as the non-root
# `starforge` user; /data is the only volume; ports 3000 (HTTP) and
# 2222 (SSH) are exposed.
#
# The image ships the static musl binaries built by
# `scripts/build-release.sh` (cargo-zigbuild). Build the binaries first,
# then:
#
#   podman build --build-arg STARFORGE_TARGET=x86_64-unknown-linux-musl \
#     -t starforge:0.1.0-pre.1 .
#   podman run --rm -p 3000:3000 -p 2222:2222 -v starforge-data:/data \
#     starforge:0.1.0-pre.1
#
# For aarch64, pass --build-arg STARFORGE_TARGET=aarch64-unknown-linux-musl
# (and a matching build host / --platform).
#
# The image tag is the version (see `scripts/build-release.sh`).
# Runtime env (set via `podman run -e`): STARFORGE_BASE_URL and
# STARFORGE_HTTP_ADDR are mapped by packaging/entrypoint.sh onto
# STARFORGE__SERVER__BASE_URL / STARFORGE__SERVER__HTTP_ADDR, which
# Config::load applies via apply_env on every start — so changing them
# later (e.g. behind a real hostname) takes effect without re-init.
# STARFORGE_CONFIG / STARFORGE_DATA_DIR override /data/starforged.toml
# and the data directory. See packaging/entrypoint.sh.

FROM docker.io/library/alpine:3

ARG STARFORGE_TARGET=x86_64-unknown-linux-musl

RUN apk add --no-cache git openssh-client ca-certificates tini \
  && adduser -D -s /sbin/nologin starforge \
  && mkdir -p /data \
  && chown starforge:starforge /data

# Static binaries (musl, statically linked via cargo-zigbuild; no runtime
# libc needed beyond alpine's base).
COPY target/release-artifacts/starforged-*-${STARFORGE_TARGET}.tar.gz /tmp/artifacts.tar.gz
RUN tar -xzf /tmp/artifacts.tar.gz -C /tmp \
  && install -m 0755 "/tmp/${STARFORGE_TARGET}/starforged" /usr/local/bin/starforged \
  && install -m 0755 "/tmp/${STARFORGE_TARGET}/starforge" /usr/local/bin/starforge \
  && install -m 0755 "/tmp/${STARFORGE_TARGET}/starforge-runner" /usr/local/bin/starforge-runner \
  && install -m 0755 "/tmp/${STARFORGE_TARGET}/starforge-sandboxd" /usr/local/bin/starforge-sandboxd \
  && rm -rf /tmp/artifacts.tar.gz "/tmp/${STARFORGE_TARGET}"

COPY packaging/entrypoint.sh /usr/local/bin/starforge-entrypoint
RUN chmod 0755 /usr/local/bin/starforge-entrypoint

USER starforge
WORKDIR /data
VOLUME ["/data"]
EXPOSE 3000 2222

ENV STARFORGE_CONFIG=/data/starforged.toml
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/starforge-entrypoint"]
