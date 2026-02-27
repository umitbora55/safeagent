# SafeAgent Editions

## Edition Overview

SafeAgent is shipped as a single codebase with three commercial editions for different maturity levels.

### Community Edition

- **Target:** Early adopters, PoCs, internal sandboxes
- **Deployment:** Local single-node control-plane + worker
- **Core security posture:** baseline hardening and execution safety
- **Delivery:** open runtime + minimal tooling for local evaluation

#### Included
- Local install flow (`scripts/install_*`, `scripts/demo_local.sh`)
- Basic token-based auth model and prompt/skill safety controls
- Sandbox + egress + approval flow in local mode
- mTLS runtime path and verification artifacts (`verify`, `verify-v2`)
- Demo and packaging docs (`docs/INSTALL.md`, `docs/CONFIG_REFERENCE.md`)

#### Limits
- No Vault/KMS integration dependency
- No SLA/SRE commitments
- No enterprise compliance package

---

### Pro Edition

- **Target:** Teams running production-like pilot
- **Deployment:** distributed control-plane + worker topology
- **Core security posture:** adversarial defense and policy gate coverage
- **Delivery:** production-hardening defaults with operational controls

#### Included
- Distributed control-plane / worker deployment patterns
- Admin approval gating and tenant-aware execution policies
- Enterprise-style rate limiting and backpressure behavior
- Adversarial verification gates:
  - jailbreak-fuzzer
  - context-poison simulation
  - diff-canary check
  - exploit replay regression checks
- JWKS rotation and multi-key token verification
- Secret store abstraction + file backend and vault-oriented architecture
- Signed skill/package verification
- Audit export compatibility for ingestion pipelines

#### Limits
- Optional enterprise policy integrations (SIEM, IdP, CMDB) not bundled by default
- No negotiated SLA unless Enterprise contract selected

---

### Enterprise Edition

- **Target:** Production deployments with procurement/compliance requirements
- **Deployment:** hardened infra, policy controls, governance outputs
- **Core security posture:** security-first with auditability and operator accountability

#### Included
- Vault/KMS-backed key and secret operations
- Tenant-level policy + rate limiting + cost controls
- Full signed marketplace flow with scanning and deny/allow policy
- Audit export formats (JSONL + integrity hash-chain) and retention policy mapping
- Key rotation evidence, incident response playbook integration
- Deployment and operations checklist pack
- Enterprise procurement and security-answer dossier
- SLA options and support model add-on
- Onboarding package for 2–4 week pilot

#### Enterprise-level Guarantees
- Operational guardrails for skill execution and egress
- Deterministic verification with reproducible gate checks
- Security controls documented for buyer due diligence

---

## Edition-to-Use Recommendation

- **Pilot in 1 week:** start with **Pro**.
- **Procurement in 30–60 days:** migrate to **Enterprise** for Vault/KMS, compliance package, and SLA.
- **Community users:** upgrade path to Pro via same installer and config presets.

## Version scope

All editions are documentation-defined and use the same technical control plane built in this repository. Functionality is activated through configuration and deployment profile.
