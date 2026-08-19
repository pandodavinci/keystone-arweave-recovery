FROM rust:1.85.1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release && cargo test --locked --release

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/keystone-arweave-checker /usr/local/bin/keystone-arweave-checker
COPY --from=builder /build/target/release/keystone-arweave-exporter /usr/local/bin/keystone-arweave-exporter
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/keystone-arweave-checker"]
