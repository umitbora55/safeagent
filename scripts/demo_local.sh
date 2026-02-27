#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${REPO_ROOT}/logs"
DEMO_DIR="${LOG_DIR}/demo_local"
mkdir -p "${LOG_DIR}" "${DEMO_DIR}"

CONTROL_PLANE_BIN="${REPO_ROOT}/dist/safeagent-control-plane"
WORKER_BIN="${REPO_ROOT}/dist/safeagent-worker"
if [[ ! -x "${CONTROL_PLANE_BIN}" || ! -x "${WORKER_BIN}" ]]; then
  echo "Release binaries not found in dist/. Running build..."
  cargo build --release --manifest-path platform/control-plane/Cargo.toml
  cargo build --release --manifest-path platform/worker/Cargo.toml
  mkdir -p "${REPO_ROOT}/dist"
  cp "${REPO_ROOT}/platform/control-plane/target/release/safeagent-control-plane" "${CONTROL_PLANE_BIN}"
  cp "${REPO_ROOT}/platform/worker/target/release/safeagent-worker" "${WORKER_BIN}"
  # Optional tools used by demo checks.
  cargo build --release --manifest-path crates/skill-registry/Cargo.toml
  cargo build --release --manifest-path crates/skill-registry-server/Cargo.toml
  cp "${REPO_ROOT}/crates/skill-registry/target/release/skill" "${REPO_ROOT}/dist/safeagent-skill" 2>/dev/null || true
  cp "${REPO_ROOT}/crates/skill-registry-server/target/release/safeagent-skill-registry-server" "${REPO_ROOT}/dist/safeagent-skill-registry-server" 2>/dev/null || true
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for demo_local.sh"
  exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
  echo "awk is required for demo_local.sh"
  exit 1
fi

export CONTROL_PLANE_LISTEN_ADDR="${CONTROL_PLANE_LISTEN_ADDR:-127.0.0.1:8443}"
export WORKER_ADDR="${WORKER_ADDR:-127.0.0.1:8280}"
export CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-https://127.0.0.1:8443}"
export CONTROL_PLANE_ADDR="${CONTROL_PLANE_ADDR:-${CONTROL_PLANE_LISTEN_ADDR}}"
export MTLS_CA="${MTLS_CA:-${REPO_ROOT}/platform/pki/ca.crt}"
export MTLS_CERT="${MTLS_CERT:-${REPO_ROOT}/platform/pki/control-plane.crt}"
export MTLS_KEY="${MTLS_KEY:-${REPO_ROOT}/platform/pki/control-plane.key}"
export WORKER_MTLS_CA="${WORKER_MTLS_CA:-${REPO_ROOT}/platform/pki/ca.crt}"
export WORKER_MTLS_CERT="${WORKER_MTLS_CERT:-${REPO_ROOT}/platform/pki/worker.crt}"
export WORKER_MTLS_KEY="${WORKER_MTLS_KEY:-${REPO_ROOT}/platform/pki/worker.key}"
export CONTROL_PLANE_SECRET_BACKEND="${CONTROL_PLANE_SECRET_BACKEND:-file}"
export CONTROL_PLANE_SECRET_DIR="${CONTROL_PLANE_SECRET_DIR:-${REPO_ROOT}/platform/control-plane/.secrets}"
export SAFEAGENT_SECRET_PASSWORD="${SAFEAGENT_SECRET_PASSWORD:-demo-password}"
export APPROVAL_TIMEOUT_SECONDS="${APPROVAL_TIMEOUT_SECONDS:-2}"
export CONTROL_PLANE_LISTEN_ADDR
export WORKER_ADDR
export CONTROL_PLANE_URL
export MTLS_CA MTLS_CERT MTLS_KEY WORKER_MTLS_CA WORKER_MTLS_CERT WORKER_MTLS_KEY
export CONTROL_PLANE_SECRET_BACKEND CONTROL_PLANE_SECRET_DIR SAFEAGENT_SECRET_PASSWORD APPROVAL_TIMEOUT_SECONDS

PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do
    if kill -0 "$p" >/dev/null 2>&1; then
      kill "$p" >/dev/null 2>&1 || true
      wait "$p" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

wait_for_ready() {
  local name="$1"
  local host="$2"
  local port="$3"
  for _ in $(seq 1 30); do
    if (echo > "/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      echo "${name} is ready"
      return 0
    fi
    sleep 0.5
  done
  echo "Timeout waiting for ${name}"
  return 1
}

curl_mtls() {
  curl -sk --cert "${WORKER_MTLS_CERT}" --key "${WORKER_MTLS_KEY}" "$@"
}

echo "[1/6] Starting services"
"${CONTROL_PLANE_BIN}" >"${DEMO_DIR}/control-plane.log" 2>&1 &
PIDS+=($!)

wait_for_ready "control-plane" "${CONTROL_PLANE_LISTEN_ADDR%:*}" "${CONTROL_PLANE_LISTEN_ADDR#*:}"

MTLS_CA="${WORKER_MTLS_CA}" \
MTLS_CERT="${WORKER_MTLS_CERT}" \
MTLS_KEY="${WORKER_MTLS_KEY}" \
CONTROL_PLANE_URL="${CONTROL_PLANE_URL}" \
WORKER_ADDR="${WORKER_ADDR}" \
WORKER_ONESHOT="${WORKER_ONESHOT:-0}" \
APPROVAL_TIMEOUT_SECONDS="${APPROVAL_TIMEOUT_SECONDS}" \
"${WORKER_BIN}" >"${DEMO_DIR}/worker.log" 2>&1 &
PIDS+=($!)

wait_for_ready "worker" "${WORKER_ADDR%:*}" "${WORKER_ADDR#*:}"

echo "[2/6] Safe execute scenario (echo)"
safe_body='{"subject":"demo-user","tenant_id":"demo","skill_id":"echo","input":"hello-safeagent","request_id":"demo-echo-1"}'
safe_status=$(curl_mtls --max-time 10 -o "${DEMO_DIR}/safe_execute.json" -w "%{http_code}" \
  -H "content-type: application/json" \
  -X POST "${CONTROL_PLANE_URL}/execute" \
  -d "${safe_body}")
if [[ "${safe_status}" != "200" ]]; then
  echo "Safe execute failed with HTTP ${safe_status}"
  exit 1
fi
grep -q '"ok":true' "${DEMO_DIR}/safe_execute.json" || {
  echo "Safe execute did not return ok=true"
  exit 1
}

echo "[3/6] Red action + approval flow"
red_body='{"subject":"demo-user","tenant_id":"demo","skill_id":"admin_op","input":"system-maintenance","request_id":"demo-admin-1"}'
(
  curl_mtls --max-time 20 -o "${DEMO_DIR}/red_execute.json" -w "%{http_code}" \
    -H "content-type: application/json" \
    -X POST "${CONTROL_PLANE_URL}/execute" \
    -d "${red_body}" >"${DEMO_DIR}/red_execute_status.txt"
) &
RED_PID=$!
PIDS+=($RED_PID)

approval_id=""
for _ in $(seq 1 25); do
  pending_json=$(curl_mtls "${CONTROL_PLANE_URL}/approval/pending")
  approval_id="$(printf '%s\n' "${pending_json}" | sed -n 's/.*\"approval_id\":\"\([^\"]*\)\".*/\1/p' | head -n 1)"
  if [[ -n "${approval_id}" ]]; then
    break
  fi
  sleep 0.2
done

if [[ -z "${approval_id}" ]]; then
  echo "Approval request was not created in time"
  exit 1
fi

approve_body="{\"approval_id\":\"${approval_id}\",\"decision\":\"approved\",\"decided_by\":\"demo-operator\",\"reason\":\"demo approval\"}"
approval_status=$(curl_mtls --max-time 10 -o "${DEMO_DIR}/approval.json" -w "%{http_code}" \
  -H "content-type: application/json" \
  -X POST "${CONTROL_PLANE_URL}/approval/decide" \
  -d "${approve_body}")
if [[ "${approval_status}" != "200" ]]; then
  echo "Approval decision request failed with HTTP ${approval_status}"
  exit 1
fi

wait "${RED_PID}"
red_status=$(awk 'NR==1 {print}' "${DEMO_DIR}/red_execute_status.txt" 2>/dev/null || true)
if [[ -z "${red_status}" ]]; then
  red_status=$(cat "${DEMO_DIR}/red_execute_status.txt" 2>/dev/null || true)
fi
if [[ "${red_status}" != "200" ]]; then
  echo "Red action did not succeed after approval (HTTP ${red_status})"
  exit 1
fi
grep -q '"ok":true' "${DEMO_DIR}/red_execute.json" || {
  echo "Red action did not return ok=true"
  exit 1
}

echo "[4/6] Audit smoke check"
if cargo run --bin audit_fixture -- data/audit/fixture_audit.jsonl >/dev/null && \
   cargo run --bin audit_verify -- data/audit/fixture_audit.jsonl >/dev/null; then
  echo "audit verify: PASS"
else
  echo "audit verify: FAIL"
  exit 1
fi

echo "[5/6] Security check gates"
set +e
just adversarial-check-v2 | tee "${DEMO_DIR}/adversarial.log"
adversarial_rc=${PIPESTATUS[0]}
just poison-check-v2 | tee "${DEMO_DIR}/poison.log"
poison_rc=${PIPESTATUS[0]}
just diff-check-v2 | tee "${DEMO_DIR}/diff-check.log"
diff_rc=${PIPESTATUS[0]}
set -e
if (( adversarial_rc != 0 || poison_rc != 0 || diff_rc != 0 )); then
  echo "security checks failed (adversarial:${adversarial_rc} poison:${poison_rc} diff:${diff_rc})"
  exit 1
fi

echo "[6/6] Done"
echo "PASS: Safe demo complete"
echo "Logs: ${DEMO_DIR}"
echo "PASS checks: safe execute, approval, audit verify, adversarial, poison, diff"
