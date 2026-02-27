# SafeAgent Skill SDK

Package: `safeagent-skills-sdk` (crate: `/platform/worker/skills-sdk`)

## Purpose

- Provides a tiny, stable interface for skill authors.
- Keeps runtime policy/enforcement in worker; authoring SDK only defines:
  - `SkillV2` trait
  - metadata and output shape
  - scope checking helper
  - test harness helper
  - optional registry for local testing

## Core trait

```rust
#[async_trait]
pub trait SkillV2 {
    fn id(&self) -> &str;
    fn required_scope(&self) -> &str;
    async fn execute(&self, input: &str) -> Result<SkillExecutionOutput, SkillError>;
}
```

## Test helpers

- `run_skill_with_policy` enforces scope gate before execution.
- `SkillRegistry` provides deterministic lookup by `id`.
- `Scope` errors are surfaced as `SkillError::ScopeMissing`.

## Example

- `examples/custom_skill.rs`
