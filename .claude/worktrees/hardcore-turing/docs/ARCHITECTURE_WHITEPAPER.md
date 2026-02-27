# SafeAgent Architecture Whitepaper (v1.0.0-rc.1)

Date: 2026-02-24

## Executive Summary
SafeAgent is a local-first AI agent that prioritizes security, cost control, and auditability. It runs entirely on user hardware, encrypts credentials at rest, gates tools by policy and capabilities, and ships with a verification gate that includes red-team and chaos suites. This paper explains the system design, threat model, and verification posture for the v1.0.0 release candidate.

## Table of Contents
1. Problem Statement
2. Design Principles
3. System Overview
4. Core Components
5. Data & Control Flow
6. Security Model
7. Verification Gate
8. Observability
9. Operational Posture
10. Roadmap (12 Months)

---

## 1. Problem Statement
AI agents offer powerful automation but introduce risk: unmanaged tool execution, credential leakage, and runaway API costs. Most agent frameworks assume cloud-hosted infrastructure and do not provide strong local auditability. Enterprises and developers need a solution that can run locally, enforce policy before tool use, and produce verifiable evidence of integrity.

SafeAgent’s goal is to deliver a local-first agent with:
- policy-gated tool execution
- cryptographic audit trails
- cost-aware routing
- deterministic verification gate

## 2. Design Principles
1. **Policy-before-tool**: every tool execution is gated by policy.
2. **Least privilege**: deny-by-default for write actions.
3. **Cryptographic auditability**: audit entries linked by hash chain.
4. **Deterministic verification**: release gates must be repeatable.
5. **Local-first**: no hosted backend required.
6. **Cost-aware routing**: select the cheapest adequate model.

## 3. System Overview
SafeAgent is composed of a gateway orchestrator and a set of crates providing routing, vault, memory, audit, and security harnesses. The system is built as a Rust workspace with deterministic CI gates.

High-level pipeline:
1. Input (CLI/Telegram) → Gateway
2. Policy evaluation & prompt guard
3. Routing decision (cost-aware LLM router)
4. Model call + cache-aware decision
5. Audit log + memory update
6. Response to user

## 4. Core Components

### 4.1 Gateway
The gateway orchestrates the runtime flow, builds requests, enforces policy gates, and dispatches to LLMs and tools. It also handles:
- command parsing (`safeagent init`, `safeagent run`, etc.)
- memory integration
- audit logging
- cache affinity and routing decisions

### 4.2 Policy Engine
The policy engine defines:
- permission levels (green/yellow/red)
- spend limits (daily/monthly)
- action allowlists/denylists

The policy is evaluated before tool invocation.

### 4.3 Prompt Guard
Prompt guard inspects user input for:
- prompt injection attempts
- token manipulation
- invisible characters
- data exfiltration patterns

Inputs exceeding risk thresholds are blocked or require confirmation.

### 4.4 Credential Vault
The vault stores API keys using:
- AES-256-GCM encryption
- Argon2id key derivation
- zeroization for sensitive memory

### 4.5 Memory Store
Local SQLite storage for:
- conversation history
- user facts

Memory is used for context but remains local.

### 4.6 Audit Log (Hash Chain)
Audit entries are chained with SHA-256 over canonical JSON to detect tampering. Verification is part of the release gate.

### 4.7 LLM Router
The router selects among model tiers (economy/standard/premium) using:
- embedding similarity (Voyage AI)
- rule-based fallback
- cache affinity

### 4.8 Security Harness (Red-Team + Chaos)
SafeAgent ships harnesses that:
- execute red-team scenarios from STRIDE
- inject fault scenarios for chaos testing
- produce deterministic PASS/FAIL outputs

## 5. Data & Control Flow

### 5.1 User → Gateway
- Input received from CLI or Telegram
- Prompt guard runs
- Policy engine gates tool usage

### 5.2 Gateway → Router
- Router selects model based on cost/risk
- Cache affinity may bias routing

### 5.3 Gateway → LLM
- Request built with stable prefix + dynamic tail
- Responses are audited and stored

### 5.4 Gateway → Audit Log
- Each request/response writes an audit entry
- Hash chain links entries

### 5.5 Gateway → Memory
- Messages and user facts stored for context

## 6. Security Model

### 6.1 Threat Model (STRIDE)
STRIDE drives scenario generation. Each threat is mapped to:
- red-team tests
- chaos tests
- mitigation controls

### 6.2 Capability Tokens (PASETO)
Capabilities provide scoped permission to execute sensitive actions. They are designed for:
- least privilege
- time bounds
- revocation workflows

### 6.3 Auditability & Non-Repudiation
The hash-chain audit log provides tamper detection and a verifiable audit trail. Verification is required by the release gate.

### 6.4 Secret Management
All secrets are stored in the encrypted vault. No secrets are persisted in plaintext.

## 7. Verification Gate
The verification gate is the single source of truth for release readiness:

```
just verify
```

The gate includes:
1. Formatting
2. Clippy
3. Tests
4. Policy conformance
5. STRIDE generation
6. Red-team suite
7. Chaos suite
8. Audit verify
9. OTEL smoke

Evidence for v1.0.0-rc.1 is documented in `docs/ai/STEP_0_2_3_REPORT.md`.

## 8. Observability
OpenTelemetry is used for tracing and debugging. The release gate ensures OTEL smoke tests pass with a local collector.

## 9. Operational Posture
- Local-only by default
- Deterministic verification gate
- Clear incident response and key rotation procedures

## 10. Roadmap (12 Months)
Phase 1
- Hardened governance and release automation
- Signed artifacts and SBOM publishing

Phase 2
- Enterprise integrations (KMS, SIEM export)
- Role-based policy presets

Phase 3
- Advanced routing with adaptive risk scoring
- Deployment profiles for regulated environments

---

## Appendix A: Verification Evidence
See `docs/ai/STEP_0_2_3_REPORT.md` for PASS evidence.
