# PHASE 4.2 — Context Poisoning Simulator (Adversarial Lab)

## Scope
- Added a deterministic lab-only simulator under `platform/lab/context-poison-sim`.
- Added a new verify gate target: `poison-check-v2`.
- Integrated `poison-check-v2` into `verify-v2` for CI gating.

## Poisoning modes
- `tool_output`: injects tool_output-shaped payloads such as:
  - `<tool_output>...` JSON/tool marker injection
  - `[SYSTEM]` spoof patterns
  - multilingual and canary (`LEAK_CANARY_123`) variants
- `memory`: injects memory payloads such as:
  - fake admin override records
  - policy override text
  - `token=...` scope spoof snippets
- `hybrid`: both `tool_output` and `memory` combined from deterministic RNG.

## Payload/model and finding criteria
- Run config:
  - `--seed` (u64, default `0xC0FFEE`)
  - `--runs` (default 200)
  - `--mode tool_output|memory|hybrid` (default `hybrid`)
  - `--out` JSONL output path
  - `--max-findings` (default 0)
- Finding definition:
  - Policy/approval/scope chain allows execution path for a red/blocked action.
  - `risk_score` remains below allow threshold (`0.35`) but bypass is still observed.
- Finding schema (JSONL per line):
  - `id, seed, mode, payload_type, payload, risk_score, threats, decision, bypass_type, reproducer`

## Command wiring
- `poison-check-v2` (in `Justfile`):
  - runs:
    `cargo run --manifest-path platform/lab/context-poison-sim/Cargo.toml -- --seed 0xC0FFEE --runs 200 --mode hybrid --out logs/context_poison_findings_v2.jsonl --max-findings 0`
- verify integration:
  - `just verify-v2` now executes `just poison-check-v2`.

## Determinism tests
- `deterministic_findings_match_same_seed`
- `finding_jsonl_schema_is_valid`
- `poison_run_under_ten_seconds_for_200_runs`

## Verification proof
- Run this to capture logs:
  - `just poison-check-v2-log`
  - `just verify-v2`
- Expected pass pattern:
  - `findings=0`
  - `verify-v2` completes successfully

## Proof excerpts

### poison-check-v2 (runs=200, seed=0xC0FFEE)
- `logs/poison_check_v2_local.log`
```text
total_runs=200
findings=0
```
- `logs/poison_check_v2_linux.log`
```text
total_runs=200
findings=0
```
- Findings JSONL output: `logs/context_poison_findings_v2.jsonl`

### verify-v2 pass
- `logs/verify_v2_phase_4_2_linux.log`
```text
just adversarial-check-v2
...
total_runs=200
findings=0
just poison-check-v2
...
total_runs=200
findings=0
```
- `logs/verify_v2_phase_4_2_local.log` includes `verify-v2` gate steps and the same `findings=0` endings for both adversarial and poison checks.
