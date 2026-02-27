#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/dist/updates"
VERSION_FILE="${REPO_ROOT}/VERSION"
UPDATE_VERSION="${SAFEAGENT_UPDATE_VERSION:-$(cat "${VERSION_FILE}" 2>/dev/null || printf '0.1.0')}"
UPDATE_VERSION="$(printf '%s' "${UPDATE_VERSION}" | tr -d '[:space:]')"
if [ -z "${UPDATE_VERSION}" ]; then
  UPDATE_VERSION="0.1.0"
fi

ASSET_PATH="${1:-${REPO_ROOT}/dist/desktop/$(uname -s | tr '[:upper:]' '[:lower:]')/safeagent-desktop}"
if [ ! -f "${ASSET_PATH}" ]; then
  ASSET_PATH="${REPO_ROOT}/target/release/safeagent-desktop"
fi
if [ ! -f "${ASSET_PATH}" ]; then
  echo "Asset not found: ${ASSET_PATH}" >&2
  echo "Build desktop first: cargo build --release --manifest-path desktop/Cargo.toml" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

ASSET_SHA256="$(shasum -a 256 "${ASSET_PATH}" | awk '{print $1}')"
MANIFEST_PATH="${OUTPUT_DIR}/update.json"
SIG_PATH="${OUTPUT_DIR}/update.sig"

cat > "${MANIFEST_PATH}" <<EOF
{
  "version": "${UPDATE_VERSION}",
  "url": "file://${ASSET_PATH}",
  "sha256": "${ASSET_SHA256}",
  "notes": [
    "Signed release payload for SafeAgent Desktop update checks."
  ],
  "published_at": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
}
EOF

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to generate deterministic Ed25519 signature." >&2
  exit 1
fi

SIG_B64="$(cargo run --quiet --manifest-path "${REPO_ROOT}/desktop/Cargo.toml" --bin sign-update-manifest -- "${MANIFEST_PATH}")"
printf '%s\n' "${SIG_B64}" > "${SIG_PATH}"

echo "Published update channel:"
echo "  manifest: ${MANIFEST_PATH}"
echo "  signature: ${SIG_PATH}"
echo "  signature-bytes: $(wc -c < "${SIG_PATH}")"
echo "  asset: ${ASSET_PATH}"
echo "  asset-sha256: ${ASSET_SHA256}"
