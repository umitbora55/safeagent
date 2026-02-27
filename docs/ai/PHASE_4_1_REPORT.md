# PHASE 4.1 — Jailbreak Fuzzer

## Proof of Execution (4.1.1)

### Adversarial check (fixed run)
- Command: `just adversarial-check-v2`
- Runtime: `runs=200`, `seed=0xC0FFEE`
- Findings threshold: `--max-findings 0`
- Result proof:
```text
total_runs=200
findings=0
```

### verify-v2 (includes adversarial gate)
- Command: `just verify-v2`
- `adversarial-check-v2` is executed inside verify-v2.
- Result proof (`logs/verify_v2_phase_4_1_local.log` and `logs/verify_v2_phase_4_1_linux.log`):
```text
running tests ...
...
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 1.74s

just adversarial-check-v2
...
total_runs=200
findings=0
```

### Linux proof log excerpts
- `logs/adversarial_check_v2_linux.log` last lines:
```text
mkdir -p logs
cargo run --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml -- --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0
...
total_runs=200
findings=0
```

- `logs/verify_v2_phase_4_1_linux.log` last lines:
```text
just adversarial-check-v2
...
total_runs=200
findings=0
```

### PASS assertion
- `findings = 0` is recorded in both local and Linux adversarial check logs.
- `verify-v2` exits successfully on both local and Linux runs.
