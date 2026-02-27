# PHASE 4.2 — Proof of Execution (Context Poisoning)

## Commands
- Local:
  - `just poison-check-v2 > logs/poison_check_v2_local.log 2>&1`
  - `just verify-v2 > logs/verify_v2_phase_4_2_local.log 2>&1`
- Linux container:
  - `docker run -it --rm --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt seccomp=unconfined -v "$(pwd):/workspace" -w /workspace ubuntu:22.04 bash -c "apt-get update -qq && apt-get install -y curl build-essential pkg-config libssl-dev 2>&1 | tail -1 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>&1 | tail -1 && source \\$HOME/.cargo/env && cargo install just 2>&1 | tail -1 && just poison-check-v2 > logs/poison_check_v2_linux.log 2>&1 && just verify-v2 > logs/verify_v2_phase_4_2_linux.log 2>&1 && tail -60 logs/poison_check_v2_linux.log && tail -60 logs/verify_v2_phase_4_2_linux.log"`

## Environment
- Local:
  - `uname -a`: `Darwin Umit-MacBook-Air.local 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64`
  - `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`
- Linux container:
  - `uname -a`: `Linux 6d2951a96db9 6.12.54-linuxkit #1 SMP Tue Nov  4 21:21:47 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux`
  - `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`

## Log excerpts

### Local
- `logs/poison_check_v2_local.log` (last 40 lines)
```text
warning: `safeagent-context-poison-sim` (lib) generated 4 warnings (run `cargo fix --lib -p safeagent-context-poison-sim` to apply 3 suggestions)
warning: unused import: `ValueEnum`
 --> src/main.rs:1:20
 | use clap::{Parser, ValueEnum};
 |                    ^^^^^^^^^
 | ...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.51s
     Running `platform/lab/context-poison-sim/target/debug/context-poison-sim --seed 0xC0FFEE --runs 200 --mode hybrid --out logs/context_poison_findings_v2.jsonl --max-findings 0`
total_runs=200
findings=0
```

- `logs/verify_v2_phase_4_2_local.log` (selected tail excerpt)
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

### Linux container
- `logs/poison_check_v2_linux.log` (last 40 lines)
```text
warning: `safeagent-context-poison-sim` (lib) generated 4 warnings (run `cargo fix --lib -p safeagent-context-poison-sim` to apply 3 suggestions)
warning: unused import: `ValueEnum`
 --> src/main.rs:1:20
 | use clap::{Parser, ValueEnum};
 |                    ^^^^^^^^^
 | ...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.93s
     Running `platform/lab/context-poison-sim/target/debug/context-poison-sim --seed 0xC0FFEE --runs 200 --mode hybrid --out logs/context_poison_findings_v2.jsonl --max-findings 0`
total_runs=200
findings=0
```

- `logs/verify_v2_phase_4_2_linux.log` (last 40 lines)
```text
just adversarial-check-v2
mkdir -p logs
cargo run --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml -- --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.11s
     Running `platform/lab/jailbreak-fuzzer/target/debug/jailbreak-fuzzer --seed 0xC0FFEE --runs 200 --out logs/adversarial_findings_v2.jsonl --max-findings 0`
total_runs=200
findings=0
just poison-check-v2
mkdir -p logs
cargo run --manifest-path platform/lab/context-poison-sim/Cargo.toml -- --seed 0xC0FFEE --runs 200 --mode hybrid --out logs/context_poison_findings_v2.jsonl --max-findings 0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s
     Running `platform/lab/context-poison-sim/target/debug/context-poison-sim --seed 0xC0FFEE --runs 200 --mode hybrid --out logs/context_poison_findings_v2.jsonl --max-findings 0`
total_runs=200
findings=0
```
