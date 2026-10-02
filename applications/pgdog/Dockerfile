# Both digests are multi-platform indexes (linux/amd64 and linux/arm64).
ARG UBUNTU_BASE=ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
ARG RUST_BASE=rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663

FROM ${RUST_BASE} AS toolchain

FROM ${UBUNTU_BASE} AS builder
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_TOOLCHAIN=1.96.1 \
    PATH=/usr/local/cargo/bin:${PATH}
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake clang pkg-config libssl-dev git mold ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=toolchain /usr/local/cargo /usr/local/cargo
COPY --from=toolchain /usr/local/rustup /usr/local/rustup
WORKDIR /build
COPY applications/pgdog/ /build/
ARG PGDOG_BUILD_REVISION=""
ARG FEATURES=""
ENV PGDOG_BUILD_REVISION=${PGDOG_BUILD_REVISION}
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    if [ -n "${FEATURES}" ]; then \
      cargo build --locked --release -p pgdog --no-default-features --features "${FEATURES}"; \
    else \
      cargo build --locked --release -p pgdog; \
    fi \
    && cargo build --locked --release -p pgdog-primary-only-tables

FROM ${UBUNTU_BASE} AS runtime
ENV DEBIAN_FRONTEND=noninteractive RUST_LOG=info \
    PATH=/usr/lib/postgresql/18/bin:${PATH}
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libssl3t64 \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl --fail --silent --show-error --location \
      https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && printf '%s\n' 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main' \
      > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends postgresql-client-18 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 10001 -g 10001 /pgdog
COPY --from=builder /build/target/release/pgdog /usr/local/bin/pgdog
COPY --from=builder /build/target/release/libpgdog_primary_only_tables.so /usr/lib/libpgdog_primary_only_tables.so
COPY LICENSE /usr/share/doc/fork-pgdog/LICENSE
ARG PGDOG_BUILD_REVISION=""
ARG VERSION=0.1.60
LABEL org.opencontainers.image.source="https://github.com/DevFun2026/fork-pgdog" \
      org.opencontainers.image.revision=${PGDOG_BUILD_REVISION} \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.licenses="AGPL-3.0-only"
WORKDIR /pgdog
USER 10001:10001
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/pgdog"]
