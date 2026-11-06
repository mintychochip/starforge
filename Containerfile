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
#     -t starforge:0.1.0 .
#   podman run --rm -p 3000:3000 -p 2222:2222 -v starforge-data:/data \
#     starforge:0.1.0
#
# For aarch64, pass --build-arg STARFORGE_TARGET=aarch64-unknown-linux-musl
# (and a matching build host / --platform).
#
# The image tag is the version (see `scripts/build-release.sh`).

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
  && rm -rf /tmp/artifacts.tar.gz "/tmp/${STARFORGE_TARGET}"

COPY packaging/entrypoint.sh /usr/local/bin/starforge-entrypoint
RUN chmod 0755 /usr/local/bin/starforge-entrypoint

USER starforge
WORKDIR /data
VOLUME ["/data"]
EXPOSE 3000 2222

ENV STARFORGE_CONFIG=/data/starforged.toml
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/starforge-entrypoint"]
