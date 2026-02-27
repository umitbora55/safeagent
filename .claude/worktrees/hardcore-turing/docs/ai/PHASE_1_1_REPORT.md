# PHASE 1.1 — Control Plane / Worker Split (Skeleton)

Date: 2026-02-24

## New Tree
```
platform/
  control-plane/
    Cargo.toml
    src/
      main.rs
  worker/
    Cargo.toml
    src/
      main.rs
  shared/
    Cargo.toml
    shared-proto/
      Cargo.toml
      src/lib.rs
      docs/MTLS_SPEC.md
    shared-identity/
      Cargo.toml
      src/lib.rs
    shared-errors/
      Cargo.toml
      src/lib.rs
```

## Crate List
- safeagent-control-plane (binary: `safeagent-control-plane`)
- safeagent-worker (binary: `safeagent-worker`)
- safeagent-shared-proto (lib)
- safeagent-shared-identity (lib)
- safeagent-shared-errors (lib)

## verify-v2 PASS
Command:
```
just verify-v2 > logs/verify_v2.log 2>&1
```

Output excerpt:
```
cargo fmt --all --check --manifest-path platform/control-plane/Cargo.toml
cargo fmt --all --check --manifest-path platform/worker/Cargo.toml
cargo fmt --all --check --manifest-path platform/shared/Cargo.toml
cargo clippy --manifest-path platform/control-plane/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/worker/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/shared/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path platform/control-plane/Cargo.toml
cargo test --manifest-path platform/worker/Cargo.toml
cargo test --manifest-path platform/shared/Cargo.toml
```

Full log:
- `logs/verify_v2.log`
