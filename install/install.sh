#!/usr/bin/env bash
# ctrlscan installer
# Preferred path: download a GitHub release artifact.
# Fallback path: build from source if Go is installed.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/CosmoTheDev/ctrlscan-agent/main/install/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --version v0.1.0
#   curl -fsSL .../install.sh | bash -s -- --build-from-source

set -euo pipefail

OWNER="CosmoTheDev"
REPO="ctrlscan-agent"
BIN_DIR="${HOME}/.ctrlscan/bin"
VERSION="latest"
BUILD_FROM_SOURCE=0

log() { printf '[ctrlscan-install] %s\n' "$*"; }
warn() { printf '[ctrlscan-install] warning: %s\n' "$*" >&2; }
die() { printf '[ctrlscan-install] error: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir)
      BIN_DIR="$2"; shift 2 ;;
    --version)
      VERSION="$2"; shift 2 ;;
    --build-from-source)
      BUILD_FROM_SOURCE=1; shift ;;
    --help|-h)
      cat <<'EOF'
ctrlscan installer
  --bin-dir <path>         install directory (default: ~/.ctrlscan/bin)
  --version <tag|latest>   GitHub release tag to install (default: latest)
  --build-from-source      skip release download and compile locally
EOF
      exit 0 ;;
    *)
      die "unknown argument: $1" ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os" in
    darwin) PLATFORM_OS="Darwin" ;;
    linux) PLATFORM_OS="Linux" ;;
    *) die "unsupported OS: $os (use --build-from-source if you know what you're doing)" ;;
  esac

  case "$arch" in
    x86_64|amd64) PLATFORM_ARCH="x86_64" ;;
    arm64|aarch64) PLATFORM_ARCH="arm64" ;;
    *) die "unsupported architecture: $arch (use --build-from-source if supported by Go)" ;;
  esac
}

resolve_release() {
  local api="https://api.github.com/repos/${OWNER}/${REPO}/releases"
  if [[ "$VERSION" == "latest" ]]; then
    api="${api}/latest"
  else
    api="${api}/tags/${VERSION}"
  fi

  RELEASE_JSON="$(curl --retry 3 --retry-all-errors -fsSL "$api")" || return 1
  RELEASE_TAG="$(printf '%s' "$RELEASE_JSON" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$RELEASE_TAG" ]] || return 1
}

download_release_binary() {
  require_cmd curl
  require_cmd tar
  detect_platform
  resolve_release || return 1

  local version_no_v="${RELEASE_TAG#v}"
  local asset_name="ctrlscan_${version_no_v}_${PLATFORM_OS}_${PLATFORM_ARCH}.tar.gz"
  local asset_url="https://github.com/${OWNER}/${REPO}/releases/download/${RELEASE_TAG}/${asset_name}"
  local work_dir tarball
  work_dir="$(mktemp -d)"
  tarball="${work_dir}/${asset_name}"
  trap 'rm -rf "${work_dir:-}"' RETURN

  log "downloading ${asset_name}"
  curl --retry 3 --retry-all-errors -fsSL -o "$tarball" "$asset_url" || return 1

  mkdir -p "$BIN_DIR"
  tar -xzf "$tarball" -C "$work_dir"

  local extracted=""
  if [[ -x "${work_dir}/ctrlscan" ]]; then
    extracted="${work_dir}/ctrlscan"
  else
    extracted="$(find "$work_dir" -type f -name ctrlscan -perm -u+x | head -n1 || true)"
  fi
  [[ -n "$extracted" ]] || die "release archive did not contain ctrlscan binary"

  install -m 0755 "$extracted" "${BIN_DIR}/ctrlscan"
  log "installed ${BIN_DIR}/ctrlscan (${RELEASE_TAG})"
  return 0
}

build_from_source() {
  require_cmd git
  require_cmd go

  mkdir -p "$BIN_DIR"
  local work_dir
  work_dir="$(mktemp -d)"
  trap 'rm -rf "${work_dir:-}"' RETURN

  log "cloning source (${VERSION})"
  git clone --depth 1 "https://github.com/${OWNER}/${REPO}" "${work_dir}/ctrlscan-agent"
  cd "${work_dir}/ctrlscan-agent"
  if [[ "$VERSION" != "latest" ]]; then
    git fetch --tags --depth 1 origin "refs/tags/${VERSION}:refs/tags/${VERSION}" || true
    git checkout "$VERSION"
  fi

  log "building ctrlscan with local Go toolchain"
  go build -o "${BIN_DIR}/ctrlscan" .
  log "installed ${BIN_DIR}/ctrlscan (source build)"
}

post_install_notes() {
  cat <<EOF

Add ctrlscan to your shell profile if needed:
  export PATH="\$HOME/.ctrlscan/bin:\$PATH"

Next:
  ctrlscan onboard
EOF
}

if [[ "$BUILD_FROM_SOURCE" -eq 1 ]]; then
  build_from_source
  post_install_notes
  exit 0
fi

if download_release_binary; then
  post_install_notes
  exit 0
fi

warn "release download failed; falling back to source build (requires git + go)"
build_from_source
post_install_notes
