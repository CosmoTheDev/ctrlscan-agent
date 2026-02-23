#!/usr/bin/env bash
# ctrlscan tool installer
# Downloads scanner binaries to ~/.ctrlscan/bin/
# Usage: ./install/tools.sh [--bin-dir <path>]

set -euo pipefail

BIN_DIR="${HOME}/.ctrlscan/bin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

mkdir -p "${BIN_DIR}"

echo "Installing scanner tools to ${BIN_DIR}"

# ── syft (SBOM generator, required by grype) ──────────────────────────────────
echo -n "  syft      ... "
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
  sh -s -- -b "${BIN_DIR}" 2>/dev/null && echo "done" || echo "FAILED"

# ── grype (SCA vulnerability scanner) ─────────────────────────────────────────
echo -n "  grype     ... "
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
  sh -s -- -b "${BIN_DIR}" 2>/dev/null && echo "done" || echo "FAILED"

# ── trufflehog (secret detection) ─────────────────────────────────────────────
echo -n "  trufflehog... "
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | \
  sh -s -- -b "${BIN_DIR}" 2>/dev/null && echo "done" || echo "FAILED"

# ── trivy (IaC misconfiguration) ──────────────────────────────────────────────
echo -n "  trivy     ... "
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
  sh -s -- -b "${BIN_DIR}" 2>/dev/null && echo "done" || echo "FAILED"

# ── opengrep (SAST) ───────────────────────────────────────────────────────────
echo -n "  opengrep  ... "
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64) ARCH="x86" ;;
  aarch64|arm64) ARCH="aarch64" ;;
esac

TAG="$(curl -sSfL https://api.github.com/repos/opengrep/opengrep/releases/latest 2>/dev/null | \
  grep '"tag_name"' | cut -d'"' -f4)"
if [[ -n "${TAG}" ]]; then
  URLS=()
  if [[ "${OS}" == "darwin" ]]; then
    if [[ "${ARCH}" == "aarch64" ]]; then
      URLS+=("https://github.com/opengrep/opengrep/releases/download/${TAG}/opengrep_osx_arm64")
    elif [[ "${ARCH}" == "x86" ]]; then
      URLS+=("https://github.com/opengrep/opengrep/releases/download/${TAG}/opengrep_osx_x86")
    fi
  elif [[ "${OS}" == "linux" ]]; then
    URLS+=("https://github.com/opengrep/opengrep/releases/download/${TAG}/opengrep_manylinux_${ARCH}")
    URLS+=("https://github.com/opengrep/opengrep/releases/download/${TAG}/opengrep_musllinux_${ARCH}")
  fi

  ok=0
  for URL in "${URLS[@]}"; do
    if curl -sSfL -o "${BIN_DIR}/opengrep" "${URL}" 2>/dev/null; then
      ok=1
      break
    fi
  done

  if [[ "${ok}" -eq 1 ]]; then
    chmod +x "${BIN_DIR}/opengrep"
    echo "done"
  else
    echo "FAILED (check https://github.com/opengrep/opengrep/releases)"
  fi
else
  echo "FAILED (could not fetch release tag)"
fi

echo ""
echo "Installation complete. Ensure ${BIN_DIR} is in your PATH:"
echo "  export PATH=\"${BIN_DIR}:\$PATH\""
