# Enterprise Security FAQ

## How do you prevent prompt injection?

SafeAgent enforces multiple layers before tool execution:
- structured request validation and scope checks
- explicit policy decision engine
- explicit approval flow for red/high-risk actions
- prompt-guard and sanitizer hooks in execution path
- adversarial test gates integrated via CI (`jailbreak-fuzzer`, `context-poison-sim`)

Decision outcomes are explicit and logged, so bypass behavior is observable and auditable.

## How do you prevent supply-chain skill malware?

- All marketplace packages go through deterministic scan rules (signatures and policy checks).
- Execution is blocked unless package is verified, signed, and policy-compliant.
- Verified publisher model and manifest allowlists constrain what is loaded.
- Marketplace checks are repeatable and included in verification flows.

## How is audit integrity protected?

- Audit entries include chain/verification-oriented data and replay-resistant ordering.
- Integrity is validated through existing audit fixture/verification tooling during release validation.
- Logs can be exported and retained according to retention policy.

## How is key rotation handled?

- The keyset model supports active/retired keys with grace period semantics.
- Tokens include key identifiers for verification against current keyset.
- Rotation is test-driven and verification is checked as part of release gates.

## How is rate limiting / backpressure enforced?

- Tenant-level token bucket, queue limits, and concurrent request controls exist at control-plane level.
- Exceeded limits return deterministic responses (429/503-style behavior as designed).
- Cost/quota controls can be set per tenant/plan.

## Incident response readiness?

- Incident playbooks and response process are captured in repository docs.
- Security failures emit structured logs and decision events.
- Recovery and escalation steps are documented in incident SOPs and can be extended for SOC/SRE integration.

## Evidence references

- `docs/ai/LAUNCH_1_REPORT.md` (delivery + verification evidence)
- `logs/verify_launch1.log` / `logs/verify_v2_launch1.log` (verification gates)
- `docs/ai/PHASE_5_3_REPORT.md` onward (lab gate evidence)
