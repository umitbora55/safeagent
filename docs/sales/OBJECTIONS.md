# Sales Objections — Standard Answers

## “It's too complex to deploy.”
**Answer:** SafeAgent ships install scripts for macOS/Linux/Windows and a one-command local demo script. Enterprise features are enabled through documented presets (`docs/INSTALL.md`, `docs/CONFIG_REFERENCE.md`).

## “Will this slow us down?”
**Answer:** Default path keeps execution overhead small while adding policy-first checks only where action risk requires approval. You get deterministic guardrails, not extra human burden.

## “Can we prove it works?”
**Answer:** Yes. Repository includes executable verification targets and logs: `verify`, `verify-v2`, and `demo-check`. These are the basis for commercial proof artifacts.

## “How do you prevent prompt injection?”
**Answer:** Multi-stage control with sanitizer checks, explicit policy engine, approvals for sensitive operations, and adversarial CI gates.

## “What about vendor lock-in?”
**Answer:** The platform is crate-first and deployable in-container/on-host; core controls are configurable and policy-driven. Skills are package-based with verifiable manifests.

## “Is this safe for regulated environments?”
**Answer:** Enterprise edition includes Vault/KMS, audit mapping, rate limiting, signed marketplace, and procurement/security answer pack.
