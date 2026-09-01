FROM rust:1.90 AS builder

WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config

RUN cargo build --release

FROM debian:bookworm-slim

# curl is here only for HEALTHCHECK, which has no other way to speak HTTP in a
# slim image. It buys nothing on Fly.io, which ignores Docker health checks and
# runs the ones declared in fly.toml, but docker-compose and plain `docker run`
# rely on it.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user. A fixed high UID and GID keep ownership predictable
# for bind mounts on the host. The group is created explicitly: `useradd --uid`
# alone picks the GID from the system range, so `USER 10001:10001` below would
# otherwise name a group that does not exist in /etc/group.
RUN groupadd --system --gid 10001 mostro \
    && useradd --system --no-create-home --shell /usr/sbin/nologin \
       --uid 10001 --gid 10001 mostro

COPY --from=builder /usr/src/app/target/release/mostro-push-backend /usr/local/bin/

# The token store is in memory, so the only thing the process ever writes is
# the UnifiedPush endpoint file, resolved relative to the working directory.
WORKDIR /app
RUN mkdir -p /app/data && chown -R 10001:10001 /app

# The Firebase service account is deliberately NOT copied in. Baking it into a
# layer publishes it to anyone who can pull the image, `docker save` included,
# with no need to run the container. Provide it at runtime instead, through
# FIREBASE_SERVICE_ACCOUNT_JSON or a file mounted at
# FIREBASE_SERVICE_ACCOUNT_PATH. See docs/deployment.md.

ENV RUST_LOG=info

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${SERVER_PORT:-8080}/api/health" || exit 1

CMD ["mostro-push-backend"]
