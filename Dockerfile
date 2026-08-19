FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release && cargo test --locked --release

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
COPY --from=builder /build/target/release/keystone-arweave-checker /usr/local/bin/keystone-arweave-checker
COPY --from=builder /build/target/release/keystone-arweave-exporter /usr/local/bin/keystone-arweave-exporter
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/keystone-arweave-checker"]
