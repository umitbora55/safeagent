#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${SAFEAGENT_BUILD_VERSION:-$(cat "${REPO_ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]')}"
if [ -z "${VERSION}" ]; then
  VERSION="0.1.0"
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build_dmg_macos.sh: macOS-only placeholder packager; skipping on non-mac host"
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

OUT_DIR="${REPO_ROOT}/dist/desktop/macos"
mkdir -p "${OUT_DIR}/tmp"

echo "Building signed desktop artifacts..."
cargo build --release --manifest-path desktop/Cargo.toml

cp "${REPO_ROOT}/desktop/target/release/safeagent-desktop" "${OUT_DIR}/SafeAgent-Desktop"
cp "${REPO_ROOT}/platform/control-plane/target/release/safeagent-control-plane" "${OUT_DIR}/" 2>/dev/null || true
cp "${REPO_ROOT}/platform/worker/target/release/safeagent-worker" "${OUT_DIR}/" 2>/dev/null || true

cat > "${OUT_DIR}/SafeAgent-Desktop-${VERSION}.dmg" <<'EOF'
placeholder-dmg
This is a packaging stub generated on macOS hosts.
Replace this file with hdiutil output when codesign/notarization is integrated.
EOF

if command -v hdiutil >/dev/null 2>&1; then
  rm -rf "${OUT_DIR}/SafeAgent-Desktop.app" || true
  mkdir -p "${OUT_DIR}/SafeAgent-Desktop.app/Contents/MacOS"
  cp "${OUT_DIR}/SafeAgent-Desktop" "${OUT_DIR}/SafeAgent-Desktop.app/Contents/MacOS/SafeAgent-Desktop"
  if command -v codesign >/dev/null 2>&1; then
    echo "codesign placeholder: command exists, attach signing in CI with CODE_SIGN_IDENTITY"
  else
    echo "codesign not installed; skipping actual sign"
  fi
else
  echo "hdiutil not installed; keeping placeholder artifact only"
fi

echo "macOS installer output: ${OUT_DIR}/SafeAgent-Desktop-${VERSION}.dmg"
