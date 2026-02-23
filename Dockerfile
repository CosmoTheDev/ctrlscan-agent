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

# Create ctrlscan home directory
RUN mkdir -p /root/.ctrlscan/bin

VOLUME ["/root/.ctrlscan"]

ENTRYPOINT ["ctrlscan"]
CMD ["--help"]
