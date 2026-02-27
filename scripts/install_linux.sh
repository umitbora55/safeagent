#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
dist_dir="${repo_root}/dist"
checksum_file="${dist_dir}/checksums.sha256"
sbom_file="${dist_dir}/sbom.json"

echo "SafeAgent Installer (Linux)"
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

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required for dist checksums"
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

{
  echo "SafeAgent release bundle"
  echo "Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "Repository: ${repo_root}"
  echo "Artifacts:"
  echo "- safeagent-control-plane"
  echo "- safeagent-worker"
  echo "- safeagent-skill"
  echo "- safeagent-skill-registry-server"
} > "${dist_dir}/README.txt"

echo "Generating checksums..."
(
  cd "${dist_dir}"
  for f in safeagent-control-plane safeagent-worker safeagent-skill safeagent-skill-registry-server; do
    sha256sum "${f}"
  done > "${checksum_file}"
)

echo "Generating minimal SBOM..."
cat > "${sbom_file}" <<'EOF'
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
echo "  1) Export one environment file:"
echo "     source dist/config/dev.env.example"
echo "  2) Start Control Plane:"
echo "     ./dist/safeagent-control-plane > logs/control-plane.log 2>&1 &"
echo "  3) Start Worker:"
echo "     CONTROL_PLANE_URL=https://127.0.0.1:8443 ./dist/safeagent-worker > logs/worker.log 2>&1 &"
echo "  4) Run the demo:"
echo "     ./scripts/demo_local.sh"
