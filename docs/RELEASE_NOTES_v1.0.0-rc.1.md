# SafeAgent v1.0.0-rc.1 — Release Notes

Date: 2026-02-24

## Highlights
- **Policy-before-tool execution**: the policy engine gates tool use to enforce permission boundaries.
- **Capability tokens (PASETO)**: scoped, revocable permissions for high-risk actions.
- **Hash-chain audit log**: cryptographic integrity checks on audit entries.
- **STRIDE generator + Red-team/Chaos suites**: threat model → automated verification.
- **OpenTelemetry (OTEL) smoke gate**: deterministic collector + connectivity check.

## Evidence (RC Gate)
These claims are backed by the verification gate outputs and audit log hash-chain verification:
- `just verify` PASS (see `docs/ai/STEP_0_2_3_REPORT.md`).
- Red-team + Chaos suites PASS (same report).
- Hash-chain audit verification PASS (same report).
- OTEL smoke test PASS (same report).

## Breaking Changes
- None noted for this RC.

## Upgrade Notes
- No breaking changes. Re-run `just verify` after pulling to validate environment readiness.

## Known Issues
- None tracked in this RC.
