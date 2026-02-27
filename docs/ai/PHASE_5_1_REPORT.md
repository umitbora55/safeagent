# PHASE 5.1 — Public SDK + Skill SDK (Ecosystem Foundation)

## What was added

- Rust control-plane client crate: `crates/sdk-rust`
- TypeScript client package: `sdk/ts`
- Skill authoring crate: `platform/worker/skills-sdk`
- Example assets:
  - `examples/rust_client_execute.rs`
  - `examples/custom_skill.rs`
  - `examples/ts_client_execute.ts`
- Verify integration:
  - new `sdk-check-v2` command
  - wired into `verify-v2`

## Rust SDK surface

- Config: `SafeAgentClientConfig`
  - `base_url`, `timeout`, `retries`, `mtls()`, `token()`, `build()`
- Runtime client: `SafeAgentClient`
  - `register_worker`
  - `issue_token`
  - `execute`
  - `execute_with_token`
  - `get_pending_approvals`
  - `approve` / `deny` / `decide_approval`
  - `get_approval_status`
  - `fetch_jwks`

## Skill SDK surface

- `SkillV2`:
  - `id()`
  - `required_scope()`
  - `execute(input)`
- Helper types:
  - `SkillExecutionOutput`
  - `SkillPolicyMetadata`
  - `SkillDefinition`
  - `SkillError`
- Helpers:
  - `scope_allows`
  - `run_skill_with_policy`
  - `SkillRegistry`

## TypeScript SDK surface

- `SafeAgentClient` methods:
  - `registerWorker`
  - `issueToken`
  - `execute`
  - `getPendingApprovals`
  - `approve` / `deny`
  - `fetchJwks`
- `retry` and `timeout` defaults align with Rust client.

## Gate wiring

- `Justfile`:
  - `sdk-check-v2` target:
    - `cargo test --manifest-path crates/sdk-rust/Cargo.toml`
    - `cargo test --manifest-path platform/worker/skills-sdk/Cargo.toml`
    - `cargo build --manifest-path crates/sdk-rust/Cargo.toml --examples`
    - `npm --prefix sdk/ts run build`
    - `npm --prefix sdk/ts run typecheck`
  - `verify-v2` includes `sdk-check-v2`

## Notes

- Semver baseline set to `0.1.0` in both Rust crates.
- No control-plane/worker runtime logic was changed.
