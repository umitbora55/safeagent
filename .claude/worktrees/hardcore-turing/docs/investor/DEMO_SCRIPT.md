# Investor Demo Script (Terminal, Copy/Paste)

This script is designed for a single terminal session. It assumes prerequisites are installed and Docker is running.

## 0) Verify Gate (Proof of Security)
```bash
just verify
```
Expected: all 9 steps PASS.

## 1) Red-Team + Chaos (Security Harness)
```bash
cargo run --bin red-team-harness -- red_team_scenarios/
cargo run --bin chaos-harness -- chaos_scenarios/
```
Expected: all scenarios PASS.

## 2) Audit Hash-Chain Verification
```bash
cargo run --bin audit_fixture -- data/audit/fixture_audit.jsonl
cargo run --bin audit_verify -- data/audit/fixture_audit.jsonl
```
Expected: PASS and chain integrity verified.

## 3) OTEL Smoke (Observability)
```bash
just otel-up
cargo test --package safeagent-telemetry otel_smoke_test -- --ignored
just otel-down
```
Expected: OTEL smoke test PASS.

## 4) Optional Live Agent Run (Interactive)
```bash
./target/release/safeagent init
./target/release/safeagent run
```
Expected: interactive setup, then CLI chat loop.
