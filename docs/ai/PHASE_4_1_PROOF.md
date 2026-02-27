# PHASE 4.1.1 Proof

## Commands
- `just adversarial-check-v2 > logs/adversarial_check_v2_local.log 2>&1`
- `just verify-v2 > logs/verify_v2_phase_4_1_local.log 2>&1`
- Linux proof container:
  - `docker run --rm --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt seccomp=unconfined -v "$(pwd)":/workspace -w /workspace ubuntu:22.04 bash -c "..."`
- Inside Linux container:
  - `just adversarial-check-v2 > logs/adversarial_check_v2_linux.log 2>&1`
  - `just verify-v2 > logs/verify_v2_phase_4_1_linux.log 2>&1`

## Ortam
- Local:
  - `uname -a`: `Darwin Umit-MacBook-Air.local 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64`
  - `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`
- Linux:
  - `uname -a`: `Linux f60596e36138 6.12.54-linuxkit #1 SMP Tue Nov  4 21:21:47 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux`
  - `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`

## Local PASS excerpts
### `adversarial_check_v2_local.log` (last 40)
```text
mkdir -p logs
cargo run --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml -- --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.99s
     Running `platform/lab/jailbreak-fuzzer/target/debug/jailbreak-fuzzer --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0`
total_runs=200
findings=0
```

### `verify_v2_phase_4_1_local.log` (last 40)
```text
just adversarial-check-v2
mkdir -p logs
cargo run --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml -- --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.18s
     Running `platform/lab/jailbreak-fuzzer/target/debug/jailbreak-fuzzer --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0`
total_runs=200
findings=0
```

## Linux PASS excerpts
### `adversarial_check_v2_linux.log` (last 40)
```text
Compiling safeagent-jailbreak-fuzzer v0.1.0 (/workspace/platform/lab/jailbreak-fuzzer)
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 20.90s
    Running `platform/lab/jailbreak-fuzzer/target/debug/jailbreak-fuzzer --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0`
total_runs=200
findings=0
```

### `verify_v2_phase_4_1_linux.log` (last 40)
```text
running 0 tests
...
running 2 tests
test red_action_waits_for_approval_then_executes ... ok
test red_action_timeout_is_rejected ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 1.74s
just adversarial-check-v2
...
total_runs=200
findings=0
```
