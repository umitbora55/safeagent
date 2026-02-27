# SafeAgent TypeScript SDK

Package: `safeagent-ts-sdk` (folder: `sdk/ts`)

## Public surface

- `SafeAgentClient`
  - `registerWorker`
  - `issueToken`
  - `execute`
  - `getPendingApprovals`
  - `approve` / `deny`
  - `fetchJwks`

## Types

Types mirror shared control-plane contracts where practical:
- register/issue token
- execute
- approval
- JWKS

## Offline and security notes

- This SDK is transport-only and uses `fetch`.
- No secrets are logged by default; callers are responsible for safe logger configuration.
- Example uses token placeholder and example host (`examples/ts_client_execute.ts`).

## Build and typecheck

- `npm --prefix sdk/ts install`
- `npm --prefix sdk/ts run build`
- `npm --prefix sdk/ts run typecheck`
