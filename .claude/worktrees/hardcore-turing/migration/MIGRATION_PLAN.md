# V1 → V2 Migration Plan (Control Plane / Worker Split)

## Goals
- Split SafeAgent into Control Plane + Worker + Shared contracts.
- Enforce zero-trust boundaries with mTLS and signed capability tokens.
- Maintain deterministic verification gates.

## Phases

### Phase 1 — Skeleton (this step)
- Create platform workspace structure.
- Define shared contracts and identity types.
- Define mTLS contract (spec only).
- Define token interfaces (issuer/verifier traits).
- Provide minimal binaries for control-plane and worker.
- Add `just verify-v2` gate.

### Phase 2 — Core Capability Ports
- Move policy engine decisions to control-plane.
- Implement token issuance and verification (PASETO).
- Implement worker registration and heartbeat.

### Phase 3 — Data Plane + Auditing
- Route skill execution requests to workers.
- Move audit logging to control-plane with hash-chain verification.
- Add OTEL pipelines across components.

### Phase 4 — Production Readiness
- Certificate rotation and reload.
- Rate-limiting and abuse protection between components.
- Signed artifacts and SBOM for v2.

## Planned Moves
- Gateway runtime → worker
- Policy engine → control-plane
- Audit log service → control-plane
- Skill dispatch → worker
- Shared protocol crate → `platform/shared` (v2 only)

## Breaking Points
- New network boundary (mTLS required)
- Capability token enforcement at worker only
- Control-plane becomes source of truth for authorization
