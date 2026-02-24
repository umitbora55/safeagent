# PHASE 2.1 Proof of Execution (Sandbox)

## Commands
- `cd '/Users/umitboragunaydin/Desktop/Eski Masaüstü/SafeAgent'`
- `just sandbox-tests-v2 > logs/sandbox_tests_v2.log 2>&1`
- `just verify-v2 > logs/verify_v2_phase_2_1.log 2>&1`

## Environment
- `uname -a`: `Darwin Umit-MacBook-Air.local 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64`
- `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`

## Log Excerpts (last 40 lines)

### `logs/sandbox_tests_v2.log`
```text
cargo test --manifest-path platform/worker/Cargo.toml -- test_no_new_privs_set test_capabilities_dropped test_rlimit_enforced test_seccomp_blocks_disallowed_syscall test_skill_exec_under_sandbox
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.09s
     Running unittests src/lib.rs (platform/worker/target/debug/deps/safeagent_worker-eb7e9a5d521bd8b6)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s

     Running unittests src/main.rs (platform/worker/target/debug/deps/safeagent_worker-ca0ce30a2314274b)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests safeagent_worker

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

sandbox-tests-v2 EXIT:0
```

### `logs/verify_v2_phase_2_1.log`
```text
   Doc-tests safeagent_shared_proto

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

just sandbox-tests-v2
cargo test --manifest-path platform/worker/Cargo.toml -- test_no_new_privs_set test_capabilities_dropped test_rlimit_enforced test_seccomp_blocks_disallowed_syscall test_skill_exec_under_sandbox
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.37s
     Running unittests src/lib.rs (platform/worker/target/debug/deps/safeagent_worker-eb7e9a5d521bd8b6)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s

     Running unittests src/main.rs (platform/worker/target/debug/deps/safeagent_worker-ca0ce30a2314274b)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests safeagent_worker

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

just approval-e2e-v2
cargo test --manifest-path platform/control-plane/Cargo.toml --test mtls -- red_action_waits_for_approval_then_executes red_action_timeout_is_rejected --exact
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.28s
     Running tests/mtls.rs (platform/control-plane/target/debug/deps/mtls-005888d24772d4df)

running 2 tests
test red_action_waits_for_approval_then_executes ... ok
test red_action_timeout_is_rejected ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 1.20s

verify-v2 EXIT:0
```
