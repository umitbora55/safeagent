# SafeAgent Versioning

## Semantic Versioning

SafeAgent follows [SemVer 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

## Version History

| Version | Status | Date | Notes |
|---------|--------|------|-------|
| v1.0.0 | Planned | TBD | Initial stable release |

## v1.0.0 Release Plan

### Prerequisites

1. **Verify Gate**: `just verify` passes
2. **Security Audit**: `cargo audit` clean
3. **Documentation**: Complete
4. **API Stability**: All public APIs finalized

### Tag Creation

```bash
# Ensure on main branch
git checkout main
git pull origin main

# Verify everything passes
just verify

# Create annotated tag
git tag -a v1.0.0 -m "Release v1.0.0: Initial stable release

Features:
- Policy engine with green/yellow/red classification
- PASETO v4 capability tokens with replay prevention
- SHA256 hash-chain audit log
- Shell executor with strict allowlist
- Multi-provider LLM routing (Anthropic/OpenAI/Gemini)
- AES-256-GCM encryption at rest
- OpenTelemetry integration

Security:
- STRIDE threat model coverage
- 17 red team scenarios passing
- 15 chaos fault injection scenarios passing
- 30 policy conformance tests passing
"

# Push tag
git push origin v1.0.0
```

### Release Notes Template

```markdown
# SafeAgent v1.0.0

## Highlights

- Production-ready security framework for AI agents
- Comprehensive policy engine with traffic light classification
- Cryptographic audit trail with tamper detection
- Multi-provider LLM support with fallback chains

## Security

- PASETO v4 capability tokens (Ed25519)
- AES-256-GCM encryption at rest
- Argon2id key derivation
- Nonce-based replay prevention

## Verified Components

| Component | Tests | Status |
|-----------|-------|--------|
| Policy Engine | 30 | PASS |
| Capability Tokens | 25 | PASS |
| Audit Log | 13 | PASS |
| Shell Executor | 32 | PASS |
| Red Team | 17 | PASS |
| Chaos | 15 | PASS |

## Installation

\`\`\`bash
cargo install safeagent
\`\`\`

## Documentation

See [docs/](./docs/) for full documentation.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for detailed changes.
```

## Future Versions

### v1.0.x (Patch Releases)

- Security fixes
- Bug fixes
- No new features

### v1.1.0 (Next Minor)

Planned features (platform-v2 branch):
- TBD based on roadmap

### v2.0.0 (Next Major)

Reserved for breaking changes:
- API redesigns
- Major architectural changes

## Pre-release Versions

For testing and preview:

```
v1.0.0-alpha.1  - Early preview
v1.0.0-beta.1   - Feature complete, testing
v1.0.0-rc.1     - Release candidate
v1.0.0          - Stable release
```

## Build Metadata

For CI builds:

```
v1.0.0+build.123
v1.0.0+20240224.abc123
```

Build metadata is ignored for version precedence.
