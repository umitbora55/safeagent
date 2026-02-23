# ── Build Stage ──────────────────────────────────
FROM rust:1.82-bookworm AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --bin safeagent && \
    strip target/release/safeagent

# ── Runtime Stage ────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash safeagent

COPY --from=builder /build/target/release/safeagent /usr/local/bin/safeagent

USER safeagent
WORKDIR /home/safeagent

# Data directory
RUN mkdir -p /home/safeagent/.local/share/safeagent
VOLUME /home/safeagent/.local/share/safeagent

# Web UI port
EXPOSE 18789

ENV RUST_LOG=info
ENV SAFEAGENT_DATA_DIR=/home/safeagent/.local/share/safeagent

ENTRYPOINT ["safeagent"]
CMD ["run"]
