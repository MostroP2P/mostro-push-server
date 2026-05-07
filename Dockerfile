FROM rust:1.83 as builder

WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/mostro-push-backend /usr/local/bin/
COPY secrets/ /secrets/

ENV RUST_LOG=info

CMD ["mostro-push-backend"]
