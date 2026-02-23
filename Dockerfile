# ctrlscan Dockerfile
# Provides an isolated environment with all scanner tools pre-installed.
# Usage:
#   docker build -t ctrlscan .
#   docker run --rm -it \
#     -v ~/.ctrlscan:/root/.ctrlscan \
#     ctrlscan onboard

FROM golang:1.24-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o ctrlscan .

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Install scanner tools
ENV BIN_DIR=/usr/local/bin

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ${BIN_DIR} && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ${BIN_DIR} && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ${BIN_DIR} && \
    curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ${BIN_DIR}

COPY --from=builder /build/ctrlscan /usr/local/bin/ctrlscan

# Create non-root runtime user and ctrlscan home
RUN useradd --create-home --shell /bin/bash ctrlscan && \
    mkdir -p /home/ctrlscan/.ctrlscan/bin && \
    chown -R ctrlscan:ctrlscan /home/ctrlscan

USER ctrlscan
ENV HOME=/home/ctrlscan

VOLUME ["/home/ctrlscan/.ctrlscan"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ctrlscan --help >/dev/null || exit 1

ENTRYPOINT ["ctrlscan"]
CMD ["--help"]
