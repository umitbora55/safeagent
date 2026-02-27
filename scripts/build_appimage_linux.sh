#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${SAFEAGENT_BUILD_VERSION:-$(cat "${REPO_ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]')}"
if [ -z "${VERSION}" ]; then
  VERSION="0.1.0"
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "build_appimage_linux.sh: Linux-only skeleton; skipping on non-Linux host"
  exit 0
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1"
    return 1
  fi
}

need_cmd cargo
need_cmd rustc

OUT_DIR="${REPO_ROOT}/dist/desktop/linux"
mkdir -p "${OUT_DIR}"

echo "Building app image skeleton artifacts..."
cargo build --release --manifest-path desktop/Cargo.toml

APPIMAGE_PATH="${OUT_DIR}/safeagent-desktop-${VERSION}-x86_64.AppImage"
cp "${REPO_ROOT}/desktop/target/release/safeagent-desktop" "${OUT_DIR}/safeagent-desktop"

if command -v appimagetool >/dev/null 2>&1; then
  echo "appimagetool found: generate real AppDir/AppImage in your CI when ready"
else
  cat > "${APPIMAGE_PATH}" <<'EOF'
placeholder-appimage
This is a skeleton AppImage artifact generated when appimagetool is unavailable.
Replace with real AppImage packaging in release CI when integration is enabled.
EOF
fi

echo "Linux AppImage path: ${APPIMAGE_PATH}"
