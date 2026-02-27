#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
dist_dir="${repo_root}/dist"

echo "SafeAgent Installer (macOS)"
echo "Repo: ${repo_root}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1"
    exit 1
  fi
}

need_cmd rustc
need_cmd cargo
need_cmd just
need_cmd awk
need_cmd sed

if ! command -v shasum >/dev/null 2>&1; then
  echo "shasum is required for checksums"
  exit 1
fi

mkdir -p "${dist_dir}"

echo "Building release artifacts..."
cargo build --release --manifest-path platform/control-plane/Cargo.toml
cargo build --release --manifest-path platform/worker/Cargo.toml
cargo build --release --manifest-path crates/skill-registry/Cargo.toml
cargo build --release --manifest-path crates/skill-registry-server/Cargo.toml

echo "Copying binaries to ${dist_dir}..."
cp "${repo_root}/platform/control-plane/target/release/safeagent-control-plane" "${dist_dir}/safeagent-control-plane"
cp "${repo_root}/platform/worker/target/release/safeagent-worker" "${dist_dir}/safeagent-worker"
cp "${repo_root}/crates/skill-registry/target/release/skill" "${dist_dir}/safeagent-skill"
cp "${repo_root}/crates/skill-registry-server/target/release/safeagent-skill-registry-server" "${dist_dir}/safeagent-skill-registry-server"

echo "Preparing sample configs..."
mkdir -p "${dist_dir}/config"
cp "${repo_root}/config/dev.env.example" "${dist_dir}/config/dev.env.example"
cp "${repo_root}/config/staging.env.example" "${dist_dir}/config/staging.env.example"
cp "${repo_root}/config/prod.env.example" "${dist_dir}/config/prod.env.example"

cat > "${dist_dir}/README.txt" <<EOF
SafeAgent release bundle
Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
Repository: ${repo_root}
EOF

echo "Generating checksums..."
(
  cd "${dist_dir}"
  shasum -a 256 safeagent-control-plane safeagent-worker safeagent-skill safeagent-skill-registry-server > checksums.sha256
)

cat > "${dist_dir}/sbom.json" <<'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "safeagent",
      "version": "0.1.0"
    }
  },
  "components": [
    {"type":"application","name":"safeagent-control-plane","version":"0.1.0"},
    {"type":"application","name":"safeagent-worker","version":"0.1.0"},
    {"type":"application","name":"safeagent-skill","version":"0.1.0"},
    {"type":"application","name":"safeagent-skill-registry-server","version":"0.1.0"}
  ]
}
EOF

echo "Done."
echo "Artifacts saved in ${dist_dir}"
echo "Next steps:"
echo "  1) Export sample config:"
echo "     source dist/config/dev.env.example"
echo "  2) Start Control Plane and Worker from ./dist"
echo "  3) Run scripts/demo_local.sh"
