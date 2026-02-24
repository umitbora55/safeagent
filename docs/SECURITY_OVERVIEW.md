# Security Overview

SafeAgent is built for local-first security and provable verification. This document summarizes the threat model, controls, and the release verification gate.

## Threat Model (STRIDE Summary)
SafeAgent uses a STRIDE-based model documented in `threat_model/stride.yaml` and summarized in `docs/THREAT_MODEL.md`.

- **Spoofing:** credential vault with Argon2id + AES-256-GCM; per-provider API keys; Telegram allowlist.
- **Tampering:** hash-chain audit log verification; deterministic audit fixtures for verification.
- **Repudiation:** audit logging with cryptographic linkage and retention.
- **Information Disclosure:** prompt guard, secret redaction, encrypted vault, optional skill allowlists.
- **Denial of Service:** policy-based rate limits; chaos scenarios for fault tolerance.
- **Elevation of Privilege:** capability tokens (PASETO) and policy-before-tool execution.

## Capability Tokens (PASETO)
Capabilities are scoped, time-bounded permissions used to gate sensitive actions. They are designed to be:
- **Least-privilege** by default (deny-all for write skills).
- **Revocable** through policy and token invalidation.
- **Auditable** via the hash-chain audit log.

## Hash-Chain Audit Log
Audit entries are chained with SHA-256 to detect:
- modification
- deletion
- insertion

Verification is part of the release gate (see `just verify`).

## OpenTelemetry Observability
SafeAgent provides OTEL tracing with a local collector used for smoke verification. This ensures telemetry pipelines are viable without external infrastructure.

## Red-Team + Chaos Verification Gate
Every release candidate requires:
- red-team suite PASS
- chaos suite PASS
- audit hash-chain PASS
- OTEL smoke PASS

See `docs/ai/STEP_0_2_3_REPORT.md` for the latest verification evidence.
