# SafeAgent Pilot Checklist

## Infra Prerequisites

- [ ] Linux/macOS build host with Rust + just available
- [ ] HTTPS certificate chain for control-plane/worker
- [ ] At least one dedicated control-plane host (VM or container)
- [ ] Storage for logs and package artifacts
- [ ] Network policy allowlist decided

## Security Prerequisites

- [ ] PKI material prepared (CA, cert, key)
- [ ] SECRET_BACKEND configured (`file` or `vault`)
- [ ] Vault/KMS path validated for Enterprise mode (if enabled)
- [ ] Rate limits and queue limits set for expected tenant load
- [ ] Incident response contacts and escalation path documented

## Data Handling

- [ ] Define log retention and redaction policy
- [ ] Decide audit export destination (S3/SIEM/Lake)
- [ ] Confirm no customer secrets are logged in cleartext
- [ ] Enable approval decision snapshots

## Go-live Checklist

- [ ] `just verify` PASS
- [ ] `just verify-v2` PASS
- [ ] `just demo-check` PASS
- [ ] Pilot skills installed via signed workflow
- [ ] Realtime alerts wired for denied actions and approval timeouts
- [ ] Runbook posted and on-call assigned
- [ ] Final security signoff and business acceptance
