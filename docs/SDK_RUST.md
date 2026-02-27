# SafeAgent Rust SDK

Package: `safeagent-sdk-rust` (crate: `/crates/sdk-rust`)

## Client API

- `register_worker(request)`
- `issue_token(subject, scopes, ttl_secs)`
- `execute(tenant_id, skill_id, input, request_id)`
- `execute_with_token(token, tenant_id, skill_id, input, request_id)`
- `get_pending_approvals()`
- `approve(approval_id, decided_by, reason)`
- `deny(approval_id, decided_by, reason)`
- `decide_approval(...)`
- `get_approval_status(approval_id)`
- `fetch_jwks()`

## Auth

- Bearer token can be passed in config or per-request.
- mTLS is optional through PEM paths:
  - CA cert
  - client cert
  - private key

## Retry

- Built-in simple retry with exponential backoff for:
  - network errors
  - server errors (`5xx`)

## Offline example

- Compile-time example: `examples/rust_client_execute.rs` (offline-friendly structure, no fixed localhost dependency).
