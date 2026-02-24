# SafeAgent Release Policy

## v1-core Definition

**v1-core** is the stable, production-ready core of SafeAgent. It includes:

- Policy Engine (`crates/policy-engine`)
- Capability Tokens (`crates/capability-tokens`)
- Audit Log with Hash Chain (`crates/audit-log`)
- Shell Executor (`crates/skills/src/shell_executor.rs`)
- Prompt Guard (`crates/prompt-guard`)
- Credential Vault (`crates/credential-vault`)
- LLM Router (`crates/llm-router`)
- Cost Ledger (`crates/cost-ledger`)
- Memory Store (`crates/memory`)
- Telemetry (`crates/telemetry`)

## Change Policy

### v1-core Branch (main)

Only the following changes are permitted:

1. **Security Patches** - Critical vulnerability fixes
2. **Hotfixes** - Production-breaking bug fixes
3. **Documentation** - README, docs/, comments
4. **CI/CD** - Pipeline improvements that don't change behavior
5. **Dependency Updates** - Security-related only

**Prohibited:**
- New features
- Architectural refactors
- Breaking API changes
- Performance optimizations (unless security-related)

### Feature Development (platform-v2)

All new feature work must happen on the `platform-v2` branch:

```bash
git checkout -b platform-v2 main
# ... feature development ...
git push -u origin platform-v2
```

Features are merged to main only after:
1. Full test coverage
2. Security review
3. Performance benchmarks
4. Documentation complete

## Versioning (SemVer)

SafeAgent follows [Semantic Versioning 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH

MAJOR - Breaking API changes
MINOR - New features (backward compatible)
PATCH - Bug fixes, security patches
```

### Current Version

- **v1.0.0** - Initial stable release (pending)

### Version Progression

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| Security patch | PATCH | 1.0.0 → 1.0.1 |
| Bug fix | PATCH | 1.0.1 → 1.0.2 |
| New feature | MINOR | 1.0.2 → 1.1.0 |
| Breaking change | MAJOR | 1.1.0 → 2.0.0 |

## Release Gate

Every release must pass the verify gate:

```bash
just verify
```

This runs 9 verification steps:
1. Format check (`cargo fmt --check`)
2. Clippy lints (`cargo clippy`)
3. Unit/Integration tests (`cargo test`)
4. Policy conformance (30 cases)
5. STRIDE test generation
6. Red team scenarios (17 cases)
7. Chaos fault injection (15 cases)
8. Audit hash chain verification
9. OpenTelemetry smoke test

## Release Checklist

See [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md) for the complete pre-release checklist.

## Security Disclosure

Security vulnerabilities should be reported via:
- Private security advisory (GitHub)
- Direct contact to maintainers

Do NOT open public issues for security vulnerabilities.

## Branching Strategy

```
main (v1-core stable)
  │
  ├── hotfix/CVE-XXXX-YYYY  → merged to main
  │
  └── platform-v2 (feature development)
        │
        ├── feature/auth-improvements
        ├── feature/new-skill-xyz
        └── feature/performance-boost
```

## Approval Requirements

| Change Type | Required Approvals |
|-------------|-------------------|
| Security patch | 1 maintainer |
| Hotfix | 1 maintainer |
| Documentation | 1 reviewer |
| Feature (v2) | 2 maintainers + security review |
| Breaking change | All maintainers |
