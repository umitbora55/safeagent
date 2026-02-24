# Compliance Readiness (SOC2-Oriented)

This document maps SafeAgent controls to a SOC2-style checklist. It is not a formal audit report.

## Control Areas

### Logging & Monitoring
**What we already have**
- Hash-chain audit log with integrity verification.
- OTEL tracing with collector smoke test.
- Redaction of secrets in audit logs.

**Phase 1 planned**
- Centralized log shipping profiles.
- Alerting playbooks for audit anomalies.

### Change Management
**What we already have**
- `just verify` gate for release candidates.
- STRIDE → red-team/chaos generated tests.

**Phase 1 planned**
- Signed release artifacts + SBOM publishing.
- Formal release checklist with approvals.

### Access Control
**What we already have**
- Capability tokens (PASETO) for scoped actions.
- Policy-before-tool enforcement.
- Deny-all defaults for write skills.

**Phase 1 planned**
- Role-based policy presets with audit trails.
- Key rotation automation.

### Key Management
**What we already have**
- AES-256-GCM encrypted vault.
- Argon2id key derivation.

**Phase 1 planned**
- External KMS integrations (optional).
- Key rotation workflows and automation.

### Data Retention
**What we already have**
- Configurable audit log retention.
- Local-only storage by default.

**Phase 1 planned**
- Data retention policies per tenant.

---

## Evidence Links
- Verification gate: `docs/ai/STEP_0_2_3_REPORT.md`
- Threat model: `docs/THREAT_MODEL.md`
- Release checklist: `docs/RELEASE_CHECKLIST.md`
