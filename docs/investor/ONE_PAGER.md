# SafeAgent — One Pager

## Problem
AI agents are powerful but insecure by default: uncontrolled tool execution, credential leakage, and unbounded costs. Enterprises need provable security and local control. Developers need a short path to production.

## Product
SafeAgent is a local-first AI agent with policy-gated tools, encrypted credentials, and cryptographic auditability. It ships with a deterministic verification gate (red-team + chaos + audit hash-chain + OTEL smoke).

## Why Now
- AI agents are moving from demos to production.
- Security and governance are the blockers.
- Local-first agents reduce compliance burden.

## Differentiation (OpenClaw vs SafeAgent)
- **SafeAgent**: policy-before-tool, cryptographic audit chain, verification gate, local-first
- **OpenClaw**: strong autonomy focus, less emphasis on auditability and deterministic gates

## Moat
- Provable security posture (hash-chain audit + deterministic verify gate)
- Zero-trust direction: capability tokens + deny-by-default policies

## 12-Month Roadmap (Phase 1 split)
- **Months 1–4:** Governance + signed releases + SBOM + SOC2-aligned controls
- **Months 5–8:** Enterprise integrations (KMS/SIEM), role-based policy presets
- **Months 9–12:** Advanced routing, adaptive risk scoring, deployment profiles
