# Incident Response

This playbook covers key compromise, capability revocation, and audit verification.

## 1) Key Compromise Playbook

### Detect
- Review audit log for abnormal usage.
- Verify audit integrity with `audit_verify`.

### Contain
- Rotate API keys immediately (Anthropic, Telegram, Voyage).
- Revoke or disable sensitive capabilities in policy config.

### Eradicate
- Remove compromised credentials from the vault.
- Re-run `safeagent init` to store new credentials.

### Recover
- Re-enable required capabilities after rotation.
- Run `just verify` to ensure the gate passes.

### Post-Incident
- Export audit logs for analysis.
- Update runbooks and add a red-team scenario if needed.

## 2) Rotate Tokens
- Generate new provider tokens.
- Update vault entries via `safeagent init`.
- Confirm by running `safeagent doctor`.

## 3) Revoke Capabilities
- Disable write skills in config (deny-all by default).
- Re-issue capability tokens only after review.

## 4) Audit Verification
- `cargo run --bin audit_verify -- data/audit/fixture_audit.jsonl`
- For production logs, export to JSONL and verify.

## 5) Notification
- Follow disclosure process in `SECURITY.md`.
