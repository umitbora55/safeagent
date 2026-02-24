# PHASE 1.3 REPORT — Capability Tokens v2

## Scope Completed
- Implemented capability token flow in platform-v2 skeleton:
  - `POST /issue-token` in control-plane
  - `POST /execute` in control-plane (issues token and forwards to worker)
  - `POST /execute` in worker (token verify + scope enforcement + replay prevention + mock skills)
- Added shared proto contracts for execute/token request/response payloads.
- Added mTLS + cert identity plumbing from shared identity.
- Added/updated tests to cover invalid signature, expired token, replay, scope, and valid token paths.

## Files Added / Changed
- `platform/shared/shared-proto/src/lib.rs`
- `platform/shared/shared-identity/src/lib.rs`
- `platform/shared/shared-errors/src/lib.rs`
- `platform/control-plane/src/lib.rs`
- `platform/control-plane/src/main.rs`
- `platform/control-plane/tests/mtls.rs`
- `platform/worker/src/lib.rs`
- `platform/worker/src/main.rs`
- `platform/worker/Cargo.toml`
- `platform/control-plane/Cargo.toml`
- `platform/shared/Cargo.toml`
- `Justfile` (`verify-v2`, `mtls-smoke-v2`, `token-e2e-v2`)
- `platform/pki/token_issuer.key`
- `platform/pki/token_issuer.pub`
- `platform/pki/worker.crt`
- `platform/pki/openssl-worker.cnf`

## Verify-v2 Gate
Command run:
```bash
cargo fmt --all --check --manifest-path platform/control-plane/Cargo.toml
cargo fmt --all --check --manifest-path platform/worker/Cargo.toml
cargo fmt --all --check --manifest-path platform/shared/Cargo.toml
cargo clippy --manifest-path platform/control-plane/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/worker/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/shared/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path platform/control-plane/Cargo.toml
cargo test --manifest-path platform/worker/Cargo.toml
cargo test --manifest-path platform/shared/Cargo.toml
just mtls-smoke-v2
just token-e2e-v2
```

PASS excerpt:
```text
cargo clippy --manifest-path platform/control-plane/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/worker/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/shared/Cargo.toml --all-targets -- -D warnings
...
test execute_with_valid_token_succeeds ... ok
...
test execute_via_control_plane_passes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out
```

## Endpoints
- `GET /health` (control-plane): returns `{ "ok": true }`
- `POST /register` (control-plane, mTLS required): registers a worker, returns `WorkerRegisterResponse`
- `POST /issue-token` (control-plane): issues capability token
- `POST /execute` (control-plane): issues token (`skill:<skill_id>`) and forwards execution request
- `GET /health` (worker): returns `{ "ok": true }`
- `POST /execute` (worker): verifies token, scope, replay, then executes mock skill

## Scope Rules
- Worker requires token scope format: `skill:<skill_id>` to execute any skill.
- `scope = "skill:echo"` allows executing only `echo`.
- `scope = "skill:health"` allows only `health`.
- If token has neither requested skill scope nor wildcard `"*"`, execution returns `401` with `"missing required scope"`.

## Token Replay Protection
- Worker stores seen nonces in `used_nonces` with expiry on claim `exp`.
- Reusing the same token/nonce returns `403` with `"token replay detected"`.

## Tests Run
### Worker unit tests (`safeagent-worker`)
- `execute_with_invalid_signature_fails`
- `execute_with_expired_token_fails`
- `execute_with_replay_token_fails`
- `execute_with_missing_scope_fails`
- `execute_with_valid_token_succeeds`

Result: `5 passed`.

### control-plane integration (`mtls.rs`)
- `register_with_valid_cert_passes`
- `register_without_client_cert_fails`
- `register_with_wrong_ca_fails`
- `execute_via_control_plane_passes`

Result: `4 passed`.

### required phase-1.3 e2e test
- `just token-e2e-v2`

Result:
```text
cargo test --manifest-path platform/control-plane/Cargo.toml --test mtls -- execute_via_control_plane_passes --exact
running 1 test
test execute_via_control_plane_passes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out
```

## mTLS smoke proof
`just mtls-smoke-v2` command output (key lines):
```text
[control-plane] listen=127.0.0.1:8443 ...
[worker] control_plane=https://127.0.0.1:8443 ...
[worker] registered node_id=001
```

## Example curl commands

1) Register worker (with worker cert):
```bash
curl --fail --silent --show-error \
  --cert platform/pki/worker.crt --key platform/pki/worker.key \
  --cacert platform/pki/ca.crt \
  -H 'content-type: application/json' \
  -d '{"addr":"127.0.0.1:8280","version":"v1"}' \
  https://127.0.0.1:8443/register
```

2) Issue token directly:
```bash
curl --fail --silent --show-error \
  --cert platform/pki/worker.crt --key platform/pki/worker.key \
  --cacert platform/pki/ca.crt \
  -H 'content-type: application/json' \
  -d '{"subject":"safeagent://node/worker-001","scopes":["skill:echo"],"ttl_secs":60}' \
  https://127.0.0.1:8443/issue-token
```

3) Execute via control-plane:
```bash
curl --fail --silent --show-error \
  --cert platform/pki/worker.crt --key platform/pki/worker.key \
  --cacert platform/pki/ca.crt \
  -H 'content-type: application/json' \
  -d '{"subject":"safeagent://node/worker-001","skill_id":"echo","input":"hello","request_id":"req-1"}' \
  https://127.0.0.1:8443/execute
```

