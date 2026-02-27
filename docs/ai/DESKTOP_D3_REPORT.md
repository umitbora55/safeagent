# DESKTOP D3 — Real Signed Update + Support Bundle

## What changed

- Added signed update manifest flow for desktop:
  - `desktop/src/update.rs` now validates Ed25519 signature + asset SHA-256 + version monotonicity.
  - Signature verification uses `verify_signature`, `verify_manifest_signature`, and `verify_asset_sha256`.
  - Support for local `file://` manifests and local signature path auto-detection was hardened.
- Added local support bundle generation:
  - `desktop/src/support.rs::create_support_bundle`
  - ZIP contents include redacted `settings.json`, status, version and log tails.
  - `safeagent-desktop` exposes `create_support_bundle` invoke command.
- Added update publishing helper script:
  - `scripts/publish_update_channel.sh`
  - produces:
    - `dist/updates/update.json`
    - `dist/updates/update.sig`
- Added deterministic Ed25519 helper binary:
  - `desktop/src/bin/sign-update-manifest.rs`
  - emits base64 signature used by publish script.
- Added update gate target:
  - `just desktop-update-check`
  - runs publish helper + signature tests + support bundle redaction test.
- Verify gate updated:
  - `verify-v2` now includes `just desktop-update-check`.

## Update model

- Manifest path (default): `~/.safeagent-desktop/update.json`
- Signature path: sibling `update.sig` (`manifest_signature_path`)
- Valid update criteria:
  - manifest signature valid
  - payload hash valid (`sha256` match)
  - candidate version newer than current version
  - public key verification succeeds (fallback key if none provided)

## Support bundle contract

- Output: ZIP at `~/.safeagent-desktop/support_bundles/support_bundle_<timestamp>.zip`
- Redaction rules:
  - API keys / tokens / secrets are sanitized before write.
- Example archive content list:
  - `support/manifest.json`
  - `support/status_snapshot.json`
  - `support/versions_snapshot.json`
  - `support/settings.json`
  - `support/events.cp.log`
  - `support/events.worker.log`
  - `support/version.txt`
  - `support/README.txt`
- Optional checksum: `support_bundle_*.zip.sha256`

## Tests and verification (D3)

- `desktop-update-check` executes:
  - `scripts/publish_update_channel.sh`
  - `cargo test --manifest-path desktop/Cargo.toml`
  - `verify-v2` includes `desktop-update-check`.

## Log excerpts

### desktop-update-check log
`logs/desktop_update_check.log`
```text
scripts/publish_update_channel.sh
Published update channel:
  manifest: /Users/.../dist/updates/update.json
  signature: /Users/.../dist/updates/update.sig
  asset: .../dist/desktop/<os>/safeagent-desktop
  asset-sha256: <sha256>
running 9 tests
test tests::pki_function_is_idempotent ... ok
test tests::update_manifest_parse ... ok
test tests::read_tail_limits_lines ... ok
test tests::settings_default_and_roundtrip ... ok
test update::tests::verify_valid_signature_passes ... ok
test update::tests::verify_wrong_signature_fails ... ok
test update::tests::verify_tampered_manifest_fails ... ok
test tests::copy_dir_recursive_works_for_nested ... ok
test support::tests::support_bundle_redacts_secrets ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### verify-v2 log
`logs/verify_v2_linux.log`
```text
just desktop-update-check
scripts/publish_update_channel.sh
Published update channel: ...
running 9 tests
test tests::pki_function_is_idempotent ... ok
test support::tests::support_bundle_redacts_secrets ... ok
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
