#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
DIST_ROOT="${REPO_ROOT}/dist/desktop/${OS_NAME}"
DIST_MANIFEST_DIR="${DIST_ROOT}/manifests"
CHECKSUM_FILE="${DIST_ROOT}/checksums.sha256"
SBOM_FILE="${DIST_ROOT}/sbom.json"
VERSION="${SAFEAGENT_BUILD_VERSION:-$(cat "${REPO_ROOT}/VERSION" 2>/dev/null | tr -d '[:space:]')}"
if [ -z "${VERSION}" ]; then
  VERSION="0.1.0"
fi

echo "SafeAgent Desktop release build"
echo "OS: ${OS_NAME}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1"
    exit 1
  fi
}

need_cmd cargo
need_cmd rustc
need_cmd shasum

mkdir -p "${DIST_ROOT}" "${DIST_MANIFEST_DIR}"

echo "Building desktop + platform binaries..."
cargo build --release --manifest-path platform/control-plane/Cargo.toml --bin safeagent-control-plane
cargo build --release --manifest-path platform/worker/Cargo.toml --bin safeagent-worker
cargo build --release --manifest-path crates/skill-registry/Cargo.toml --bin skill
cargo build --release --manifest-path crates/skill-registry-server/Cargo.toml --bin safeagent-skill-registry-server
cargo build --release --manifest-path desktop/Cargo.toml --bin safeagent-desktop

copy_if_exists() {
  local source="$1"
  local fallback="$2"
  local target="$3"
  if [ -f "$source" ]; then
    cp "$source" "$target"
    return
  fi
  if [ -f "$fallback" ]; then
    cp "$fallback" "$target"
    return
  fi
  echo "Missing artifact: $source or $fallback" >&2
  exit 1
}

copy_if_exists \
  "${REPO_ROOT}/platform/control-plane/target/release/safeagent-control-plane" \
  "${REPO_ROOT}/target/release/safeagent-control-plane" \
  "${DIST_ROOT}/safeagent-control-plane"

copy_if_exists \
  "${REPO_ROOT}/platform/worker/target/release/safeagent-worker" \
  "${REPO_ROOT}/target/release/safeagent-worker" \
  "${DIST_ROOT}/safeagent-worker"

copy_if_exists \
  "${REPO_ROOT}/crates/skill-registry/target/release/skill" \
  "${REPO_ROOT}/target/release/skill" \
  "${DIST_ROOT}/safeagent-skill"

copy_if_exists \
  "${REPO_ROOT}/crates/skill-registry-server/target/release/safeagent-skill-registry-server" \
  "${REPO_ROOT}/target/release/safeagent-skill-registry-server" \
  "${DIST_ROOT}/safeagent-skill-registry-server"

copy_if_exists \
  "${REPO_ROOT}/desktop/target/release/safeagent-desktop" \
  "${REPO_ROOT}/target/release/safeagent-desktop" \
  "${DIST_ROOT}/safeagent-desktop"

mkdir -p "${DIST_ROOT}/config"
cp "${REPO_ROOT}/config/dev.env.example" "${DIST_ROOT}/config/dev.env.example"
cp "${REPO_ROOT}/config/staging.env.example" "${DIST_ROOT}/config/staging.env.example"
cp "${REPO_ROOT}/config/prod.env.example" "${DIST_ROOT}/config/prod.env.example"

cat > "${DIST_ROOT}/README.txt" <<EOF
SafeAgent desktop release package
Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
OS: ${OS_NAME}
EOF

(
  cd "${DIST_ROOT}"
  shasum -a 256 \
    safeagent-control-plane \
    safeagent-worker \
    safeagent-skill \
    safeagent-skill-registry-server \
    safeagent-desktop \
  > "${CHECKSUM_FILE}"
) 

cat > "${SBOM_FILE}" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "safeagent-desktop-release",
      "version": "${VERSION}"
    }
  },
  "components": [
    {"type": "application", "name": "safeagent-desktop"},
    {"type": "application", "name": "safeagent-control-plane"},
    {"type": "application", "name": "safeagent-worker"},
    {"type": "application", "name": "safeagent-skill"},
    {"type": "application", "name": "safeagent-skill-registry-server"}
  ]
}
EOF

mkdir -p "${DIST_MANIFEST_DIR}"
cat > "${DIST_MANIFEST_DIR}/desktop-update.json.example" <<EOF
{
  "version": "${VERSION}",
  "notes": [
    "SafeAgent desktop signed release placeholder",
    "Signature check and canary validation are implemented in update endpoint later."
  ]
}
EOF

cat > "${REPO_ROOT}/dist/desktop/README.txt" <<'EOF'
SafeAgent release output:
- dist/desktop/<os>/ contains desktop binary and companion services.
- Signing placeholders:
  - macOS: run `codesign --force --options runtime --sign ...` in packaging pipeline.
  - Windows: run `signtool sign` in packaging pipeline.
  - Linux: packaging can use .deb/.AppImage with distribution signing at repo level.
EOF

echo "Release assets ready: ${DIST_ROOT}"
