# SafeAgent Pilot-to-Paid Conversion Playbook

## 1) Pilot → Paid Conversion Path

### Phase A: Qualification (Week 0)
- Confirm pain: uncontrolled tool execution, governance gaps, and audit obligations.
- Confirm architecture fit and identity baseline.
- Define target use cases.

### Phase B: Pilot Launch (Weeks 1–4)
- Run safe pilot checklist.
- Enable baseline policies + network policy.
- Capture baseline + gate metrics weekly.

### Phase C: Value Demonstration (Week 3)
- Security metrics review:
  - policy denials
  - blocked egress attempts
  - adversarial gate trend
- Ops metrics review:
  - approval latency
  - execution success ratio

### Phase D: Expansion Proposal (Week 4+)
- Convert usage to production profile.
- Add SLA and support model.
- Define rollout plan and change management.

## 2) Security Objection Handling

### Objection: “Our models are already guarded.”
- Response: Model guard is output-level. SafeAgent is execution-level.

### Objection: “This will slow our dev velocity.”
- Response: Policies are declarative; defaults are safe and progressive rollout.
- Approval-only paths are explicit and observable.

### Objection: “Security overhead is too high.”
- Response: Verification gates run deterministically; once configured, day-to-day operations become policy-driven and repeatable.

### Objection: “No appetite for external tooling.”
- Response: Designed as deployment control plane with local-first operation and optional registry modes.

## 3) Procurement Checklist

- Security dossier (CISO-level)
- Data path and audit retention requirements
- Key rotation and secret backend expectations
- SSO / cert topology
- Vendor assessment artifacts:
  - verify-v2 result
  - sandbox/egress/lab evidence
  - pilot metrics and exception log

## 4) Technical Champion Support Plan

### Week 1
- Architecture call with platform and security teams
- Baseline policy templates + onboarding

### Week 2
- Joint review of first denied actions and workflow tuning

### Week 3
- Security workshop with AppSec: adversarial scenarios and false positive calibration

### Week 4
- Production readiness checklist
- Final proposal and transition path

## 5) Escalation and Expansion Signals

- Positive conversion signal:
  - no critical bypasses in pilot
  - 0 egress policy violations
  - successful adversarial gate completion
- Expansion signal:
  - team adoption rate > 20%
  - repeated manual escalation reduction
  - request volumes stable under limits
