# SafeAgent Configuration Reference

This document lists environment variables used by packaging and local demo runs.

## Core Endpoints

- `CONTROL_PLANE_ADDR`
  - Alias for `CONTROL_PLANE_LISTEN_ADDR`.
  - Format: `host:port`.
  - Use this in demos and runbooks.
- `CONTROL_PLANE_LISTEN_ADDR`
  - Address where Control Plane listens (mTLS HTTPS).
  - Default currently is `127.0.0.1:8443`.
- `WORKER_ADDR`
  - Address where Worker listens.
  - Default currently is `127.0.0.1:8280`.
- `CONTROL_PLANE_URL`
  - URL used by Worker to contact Control Plane.
  - Example: `https://127.0.0.1:8443`.

## mTLS Settings

- `MTLS_CA`
  - Shared CA path used by both services.
- `MTLS_CERT`
  - Control Plane certificate path.
- `MTLS_KEY`
  - Control Plane private key path.
- `WORKER_MTLS_CA`
  - Worker CA path (used for client trust in worker side config).
- `WORKER_MTLS_CERT`
  - Worker certificate path.
- `WORKER_MTLS_KEY`
  - Worker private key path.

## Secret Backend

- `CONTROL_PLANE_SECRET_BACKEND`
  - `file` (default) or `vault`.
- `CONTROL_PLANE_SECRET_DIR`
  - Directory for local encrypted file-based secret store.
- `SAFEAGENT_SECRET_PASSWORD`
  - Master password for local secret store.
- `CONTROL_PLANE_VAULT_ADDR`
  - Vault server address when backend is `vault`.
- `CONTROL_PLANE_VAULT_TOKEN`
  - Vault token for secret operations.
- `CONTROL_PLANE_VAULT_MOUNT`
  - KV v2 mount path name for Vault backend.

## Rate Limits

- `CONTROL_PLANE_TENANT_CONCURRENT_LIMIT`
  - Max concurrent in-flight requests per tenant.
- `CONTROL_PLANE_TENANT_QUEUE_LIMIT`
  - Queue capacity before returning 503.
- `CONTROL_PLANE_TENANT_TOKEN_BUCKET_CAPACITY`
  - Burst capacity for token bucket rate control.
- `CONTROL_PLANE_TENANT_TOKEN_BUCKET_REFILL_PER_SECOND`
  - Refill speed for token bucket.
- `CONTROL_PLANE_TENANT_COST_BUDGET`
  - Per-tenant cost budget for quota checks.

## Worker and Control Plane Timing

- `APPROVAL_TIMEOUT_SECONDS`
  - Worker red-action polling timeout.
- `WORKER_JWKS_TTL_SECONDS`
  - Worker JWKS cache TTL (reserved for demo docs; worker default is 60s in code).
- `WORKER_ONESHOT`
  - Set to `1` to start worker and exit after registration.

## Logging and Output

- `LOG_LEVEL`
  - Runtime log verbosity convention used in documentation:
    `trace`, `debug`, `info`, `warn`, `error`.

## Compatibility Notes

- `CONTROL_PLANE_ADDR` is kept for developer ergonomics and mapped to `CONTROL_PLANE_LISTEN_ADDR` in scripts.
- Secret values should never be committed to repository.
