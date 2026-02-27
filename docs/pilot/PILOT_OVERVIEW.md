# SafeAgent Pilot Overview (2–4 Week)

## Pilot Goal

Validate that SafeAgent can secure AI/LLM execution in a real team environment with measurable outcomes:
- policy enforcement reliability
- security posture against adversarial prompts
- deployment and operations fit for production teams

## Pilot Scope

- 1 control-plane + 1–3 workers
- Existing IdP or manual operator model (as configured)
- Team size: up to 3 teams, up to 5 tenants
- Use-case: skill execution, approvals, and audit review

## Success Metrics

### Security
- 0 critical policy bypasses in red-team scenarios
- 100% audit event emission for executed and denied requests
- 0 supply-chain install incidents (marketplace package fail-safe checks pass)

### Operations
- Mean approval latency < 60 seconds
- Skill execution success rate > 99.5% (excluding intentional deny)
- No uncontrolled egress to disallowed targets

### Business
- Team adoption: ≥ 20% of target workflows use tool safely by end of week 4
- Reduction in manual incident triage tasks for AI actions

## 4-Week Plan

### Week 1 — Onboarding & Baseline
- Install via `scripts/install_*`
- Configure certs, worker registration, and secrets
- Run `just verify`, `just verify-v2`, `just demo-check`
- Publish pilot playbook and risk register

### Week 2 — Safety and Policy
- Enable approval + tenant policies
- Apply network policy and marketplace scanning
- Run adversarial/lab checks in CI
- Validate incident response runbook

### Week 3 — Integration & Adoption
- Connect 1–2 production-like clients/skills
- Evaluate workflow approvals and cost guardrails
- Measure false-positive/false-negative decision quality

### Week 4 — Stabilization & Handoff
- Tune limits and retention
- Security review with audit exports
- Close findings and define commercial terms

## Exit Criteria

- All pilot KPIs achieved for 5 consecutive business days
- Security controls accepted by technical stakeholders
- Customer signs procurement decision pack for next phase
