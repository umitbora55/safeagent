# SafeAgent Release Checklist

## Pre-Release Verification

### 1. Verify Gate

```bash
just verify
```

**Required:** All 9 steps must pass.

- [ ] Format check passed
- [ ] Clippy lints passed (no warnings with `-D warnings`)
- [ ] All unit tests passed
- [ ] Policy conformance: 30/30
- [ ] STRIDE scenarios generated
- [ ] Red team: 17/17 passed
- [ ] Chaos: 15/15 passed
- [ ] Audit hash chain verified
- [ ] OTEL smoke test passed (or skipped if no collector)

### 2. Security Audit

```bash
cargo audit
```

- [ ] No known vulnerabilities
- [ ] All advisories reviewed
- [ ] Exceptions documented (if any)

### 3. Dependency Check

```bash
cargo outdated
```

- [ ] Security-critical dependencies up to date
- [ ] No yanked crates

### 4. SBOM Generation

```bash
cargo sbom > sbom.json
```

- [ ] SBOM generated
- [ ] SBOM committed to release artifacts

## Documentation

### 5. Changelog

- [ ] `CHANGELOG.md` updated with:
  - Version number
  - Release date
  - Added features
  - Changed behavior
  - Deprecated items
  - Removed items
  - Fixed bugs
  - Security patches

### 6. Version Bump

- [ ] `Cargo.toml` workspace version updated
- [ ] All crate versions consistent

### 7. Documentation Review

- [ ] README.md accurate
- [ ] API documentation current
- [ ] Examples working

## Release Process

### 8. Create Release Tag

```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

- [ ] Tag created
- [ ] Tag pushed

### 9. Release Notes

Create GitHub release with:

- [ ] Version number as title
- [ ] Changelog excerpt as body
- [ ] Binary artifacts attached (if applicable)
- [ ] SBOM attached

### 10. Post-Release

- [ ] Announce release
- [ ] Monitor for issues
- [ ] Update documentation site (if applicable)

## Emergency Hotfix Process

For critical security fixes:

1. [ ] Create `hotfix/CVE-XXXX-YYYY` branch from main
2. [ ] Apply minimal fix
3. [ ] Run `just verify`
4. [ ] Get 1 maintainer approval
5. [ ] Merge to main
6. [ ] Tag as patch version (e.g., v1.0.1)
7. [ ] Publish security advisory

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Release Manager | | | |
| Security Review | | | |
| QA Verification | | | |
