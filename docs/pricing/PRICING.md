# SafeAgent Pricing (MRR)

## Pricing Model Summary

All plans are subscription-based and charged monthly in USD.

- **Billing base:** SKU per edition
- **Unit add-ons:** additional tenants, requests/day, workers, and retention
- **SLA add-on:** available only for Enterprise

## Plans

### 1) Community
- **$0 / month**
- Target: internal projects and PoCs
- Includes:
  - Local single-node deployment
  - Basic verification gates (`verify`, `verify-v2`)
  - Installer + docs + demo kit
- Limits:
  - No support SLA
  - No enterprise onboarding

### 2) Pro
- **$299 / month**
- Target: teams piloting production workloads
- Includes:
  - Distributed topology (control-plane + workers)
  - Tenant-aware limiting and queue controls
  - Approval workflows
  - Adversarial QA gates in CI (`adversarial`, `poison`, `diff`, `replay`)
  - Signed marketplace support and skill scanning
  - 1 business day support SLA
- Overages:
  - $0.02 per request above included cap
  - $29 per extra worker/month

### 3) Enterprise
- **$1,499 / month** (starting)
- Target: mission-critical, regulated environments
- Includes:
  - Everything in Pro
  - Vault/KMS-first secret and key workflows
  - Advanced audit export and retention policy integration
  - Signed marketplace + policy-compliance pack
  - Procurement security dossier and incident response package
  - SLA: 24x7, 4-hour critical response window
  - Dedicated onboarding and quarterly review
- Overages:
  - $0.01 per extra request/day block (rounded monthly)
  - $199 per extra worker/month
  - $0.10 per tenant above included cap

## Usage Metrics and Included Capacity

| Metric | Community | Pro | Enterprise |
|---|---:|---:|---:|
| Included tenants | 1 | 5 | 25 |
| Requests/day include | 5,000 | 100,000 | 1,000,000 |
| Workers included | 1 | 3 | 25 |
| Audit retention | 7 days | 30 days | 365 days |

## Overage Rules (Examples)

- Example: Pro plan with 150,000 requests/day and 120,000 included
  - Billed at $299 + 25,000 × $0.02 = **$799/month**

- Example: Enterprise with 30 workers (included 25)
  - Billed at $1,499 + 5 × $199 = **$2,494/month**

- Audit retention extension:
  - Enterprise can extend retention to 365+ days via add-on:
  - 10 TB retention extension: +$899/month

## Annual Billing

- **2 months free (16.67% discount)** for annual prepay.
- Invoice cadence:
  - Monthly: 1 invoice/month
  - Annual: 1 invoice/year (prepaid)

## Non-Functional Entitlement

- All paid plans include secure updates and evidence-backed release cadence.
- Feature usage beyond included capacities is capped with hard-stop or grace controls depending on edition policy.
- Enterprise customers may negotiate custom enterprise MRR for cross-tenant or multi-region scale.
