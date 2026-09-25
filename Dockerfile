FROM rust:1.94.0-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY static ./static
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
WORKDIR /data
COPY --from=builder /app/target/release/token-refresh /usr/local/bin/token-refresh
EXPOSE 9876
CMD ["/usr/local/bin/token-refresh"]
