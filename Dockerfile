FROM rust:1.94 AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y cmake clang musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY examples/ examples/
RUN cargo build --release --target x86_64-unknown-linux-musl \
    --bin meridian --example backend --example gen_certs --example client --example throughput

FROM alpine:3.21
LABEL org.opencontainers.image.title="Meridian"
LABEL org.opencontainers.image.description="QUIC-aware SNI proxy — routes TCP and UDP traffic by TLS Server Name Indication"
LABEL org.opencontainers.image.authors="Charles R. Portwood II <charlesportwoodii@erianna.com>"
LABEL org.opencontainers.image.source="https://github.com/alaydriem/meridian"
LABEL org.opencontainers.image.url="https://github.com/alaydriem/meridian"
LABEL org.opencontainers.image.documentation="https://github.com/alaydriem/meridian"
LABEL org.opencontainers.image.vendor="alaydriem"
LABEL org.opencontainers.image.base.name="alpine:3.21"
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/meridian /usr/local/bin/meridian
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/examples/backend /usr/local/bin/meridian-backend
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/examples/gen_certs /usr/local/bin/meridian-gen-certs
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/examples/client /usr/local/bin/meridian-client
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/examples/throughput /usr/local/bin/meridian-throughput
EXPOSE 443/tcp 443/udp 9443/tcp
ENTRYPOINT ["meridian"]
CMD ["--config", "/etc/meridian/config.hcl"]
