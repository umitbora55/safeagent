# SafeAgent Website Structure

## 1) Homepage
- Hero: "AI execution should be policy-controlled, not model-driven."
- Subheadline: SafeAgent as AI execution firewall.
- 3 value cards: Policy-first safety, Zero-trust worker isolation, Supply-chain-verified marketplace.
- Trust section: verify-v2 badge + lab checks mention.
- Feature highlights:
  - Tenant-aware execution
  - Approval gating and audit trail
- Red action simulation
- Network lockdown + egress policy
- Security-first defaults section.
- CTA: Book a demo / Start free pilot.
- Proof strip: "Running e2e verify and adversarial gates."

## 2) Product
- Positioning: AI Execution Control Plane.
- Architecture overview:
  - Client
  - Control Plane
  - Worker nodes
  - Registry/tooling and marketplaces
- Execution flow diagram (text): Request → policy → approval → isolated worker → audit.
- Key modules:
  - Policy engine
  - Token verification with key rotation
  - Network egress policy
  - Secret management and key lifecycle
  - Skill packaging/verification tools
- Feature list with modes:
  - Basic
  - Team
  - Enterprise
- Onboarding quickstart (5 commands + config).
- Integration examples (Rust/TypeScript SDK).

## 3) Security
- Security by design principles:
  - Zero trust assumptions
  - Kernel isolation and syscall controls
  - Deny-by-default egress
  - Signed package enforcement
- Threat model summary
- Security controls by layer (control-plane, worker, network, audit).
- Compliance readiness:
  - Audit export
  - Retention and rotation controls
  - Key lifecycle visibility
- Threat-to-control mapping grid.
- FAQ:
  - "What if a model hallucinates instructions?"
  - "How do we prevent supply-chain abuse?"
  - "How are regressions detected?"

## 4) Marketplace
- What is safe marketplace:
  - Signed, scanned, verified publishers only.
- Package flow:
  - skill.toml
  - archive
  - signature + checksum
  - verification results
- User journey:
  - publish
  - scan
  - install
  - execute
- Trust signals:
  - verified publisher
  - signature status
  - scan report
- API/CLI docs links.
- Guardrails:
  - forbidden actions blocklist
  - no unsafe redirects
  - fail-closed policy
- Enterprise add-on: private registry + reputation model.

## 5) Docs
- Getting started section
  - install
  - config presets
  - demo local run
- API quick references
  - control-plane endpoints
  - worker behavior model
  - policy schema
- Security guides:
  - sandbox settings
  - egress policy
  - audit and logs
- Operations:
  - rollout playbook
  - incident response
  - troubleshooting matrix
- Developer docs:
  - skill sdk
  - local testing

## 6) Pricing
- Editions: Community / Pro / Enterprise.
- Side-by-side card layout.
- Included capacity table.
- Overage pricing model.
- SLA matrix.
- Procurement add-ons and pilot terms.
- FAQ:
  - trial policy
  - support model
  - usage visibility

## 7) Contact
- Contact pathways:
  - Technical demo booking
  - Security review request
  - Pilot application
- For prospects:
  - Region + company size + use case form
- What to include in first meeting:
  - topology, tenant count, existing identity model, risk profile
- Security docs bundle download links.
- CTA sections:
  - Schedule architecture review
  - Start pilot readiness checklist
