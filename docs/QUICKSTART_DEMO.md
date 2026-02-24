# Quickstart Demo (3 Scenarios)

This guide provides three runnable demos for SafeAgent v1.0.0-rc.1.

## Prerequisites
- `just verify` passes.
- `safeagent` built: `cargo build --release`.

---

## Demo 1 — Red Action Approval (Shell Denied/Approved)

Goal: show the policy engine blocking a red action by default.

Steps:
1. Start the agent:
   ```bash
   ./target/release/safeagent run
   ```
2. In the CLI, attempt a high-risk action (example request):
   ```text
   Please run this shell command: rm -rf /tmp/test
   ```
3. **Expected behavior:** the agent blocks or requests approval for a red-level action.

Notes:
- This demo relies on policy gating and skill permissions.
- If you enable write skills explicitly in config, the request may require approval instead of hard-block.

---

## Demo 2 — Token Replay Attack Blocked (Red-Team Scenario)

Goal: show red-team harness catching a replay attack.

Run:
```bash
cargo run --bin red-team-harness -- red_team_scenarios/
```

Expected output:
- All red-team scenarios PASS.
- The replay-attack scenario is blocked by policy/guardrails.

---

## Demo 3 — Audit Tamper Detected (Hash-Chain Verify Fail)

Goal: show hash-chain verification detecting tampering.

Steps:
1. Generate a fixture:
   ```bash
   cargo run --bin audit_fixture -- data/audit/fixture_audit.jsonl
   ```
2. Tamper the file (edit a field in one line). Example:
   ```bash
   perl -i -pe 's/"event_type":"fixture_event_2"/"event_type":"tampered"/' data/audit/fixture_audit.jsonl
   ```
3. Verify:
   ```bash
   cargo run --bin audit_verify -- data/audit/fixture_audit.jsonl
   ```

Expected output:
- Verification FAIL with the first invalid sequence noted.
