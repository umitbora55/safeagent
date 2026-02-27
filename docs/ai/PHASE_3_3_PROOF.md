# PHASE 3.3 PROOF — Rate Limiting + Backpressure + Quotas

## Komutlar

- Local:
  - `just rate-limit-tests-v2 > logs/rate_limit_tests_v2_local.log 2>&1`
  - `just verify-v2 > logs/verify_v2_phase_3_3_local.log 2>&1`

- Linux container:
  - `docker run -it --rm \
    --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$(pwd):/workspace" -w /workspace ubuntu:22.04 \
    bash -c "apt-get update -qq && apt-get install -y curl build-essential pkg-config libssl-dev 2>&1 | tail -1 && \
             curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>&1 | tail -1 && \
             source \$HOME/.cargo/env && cargo install just 2>&1 | tail -1 && \
             just rate-limit-tests-v2 > logs/rate_limit_tests_v2_linux.log 2>&1 && \
             just verify-v2 > logs/verify_v2_phase_3_3_linux.log 2>&1 && \
             tail -60 logs/rate_limit_tests_v2_linux.log && tail -60 logs/verify_v2_phase_3_3_linux.log"`

## Ortam

- Local:
  - `uname -a`: `Darwin Umit-MacBook-Air.local 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64`
  - `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`

- Linux:
  - `uname -a`: `Linux e0935f30befd 6.12.54-linuxkit #1 SMP Tue Nov  4 21:21:47 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux`
  - `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)` (kanıttan alınan sürüm)

## PASS excerpt (rate-limit-tests-v2)

### Local

```text
running 3 tests
test rate_limit_cost_limit_returns_payment_required ... ok
test rate_limit_parallel_requests_enforce_tenant_concurrency_limit ... ok
test rate_limit_queue_limit_returns_service_unavailable_when_queue_exhausted ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.05s
```

### Linux

```text
running 3 tests
test rate_limit_cost_limit_returns_payment_required ... ok
test rate_limit_parallel_requests_enforce_tenant_concurrency_limit ... ok
test rate_limit_queue_limit_returns_service_unavailable_when_queue_exhausted ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.86s
```

## PASS excerpt (verify-v2)

### Local

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.47s
```

### Linux

```text
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.58s
```
