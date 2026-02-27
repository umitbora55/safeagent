# Contributing to SafeAgent

Thanks for contributing. We prioritize security, deterministic verification, and minimal regression risk.

## High-Signal Workflow
1. **Open an issue first** for non-trivial changes.
2. **Keep changes scoped**. Avoid refactors when possible.
3. **Add tests** for behavior changes.
4. **Run the gate** before PR:
   ```bash
   just verify
   ```

## Code Style
- Rust: `cargo fmt` + `cargo clippy -- -D warnings`
- Prefer small, readable diffs.

## Security-Sensitive Areas
Extra care is required for:
- credential vault
- policy engine
- prompt guard
- audit log

## Commit Guidelines
- Use clear, descriptive commit messages.
- One logical change per commit.

## Reporting Security Issues
Do **not** open public issues for vulnerabilities. See `SECURITY.md`.
