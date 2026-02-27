# D2 — Ship-Ready Desktop Report

## Scope
- Desktop supervisor, settings persistence, updater skeleton, release packaging, and verify gate were updated on top of D1.
- Focus is usability-first shipping: one-click style operation, fail-closed defaults, and recoverability.

## Crash Recovery Supervisor
- `desktop/src/main.rs` now runs control-plane and worker as managed child services.
- `ManagedService` keeps:
- `restart_count`
- `restart_state.attempts`
- `next_restart_ms`
- `backoff_ms`
- `manual_restart_required`
- On process exit, supervisor computes exponential backoff:
- base 500 ms
- cap 20,000 ms
- max attempts: `MAX_RESTART_ATTEMPTS = 5`
- If 5 attempts are exhausted, service goes to `manual_restart_required` and status becomes red.
- `get_status` reports `safety_state`:
- `green` when both services running
- `yellow` when recovering
- `red` when manual restart needed
- `stopped` when desired state is stopped
- UI status light maps:
- green/sarı/kırmızı via `desktop-ui/index.html`.
- Added restart command `restart_services` and auto-restart logic in `get_status` / polling flow.

## Settings Persistence (4 Toggles Only)
- Added persisted settings model: `DesktopSettings` in `desktop/src/main.rs`.
- File path: `~/.safeagent-desktop/settings.json`.
- Toggles:
- `strict_mode` (default `true`) — safe-by-default mode.
- `verified_publisher_only` (default `true`) — marketplace allowlist gate.
- `allowlist_network_only` (default `true`) — egress lock to allowlist mode.
- `advanced_logs` (default `false`).
- RPC endpoints:
- `get_settings` reads defaults on first run and writes defaults when missing.
- `update_settings` persists user changes immediately.
- UI panel under **Simple Settings** with exactly 4 toggles.

### settings.json sample
```json
{
  "strict_mode": true,
  "verified_publisher_only": true,
  "allowlist_network_only": true,
  "advanced_logs": false
}
```

## Release / Signing / Installer Plan
- Added `scripts/build_desktop_release.sh`.
- Outputs artifacts to: `dist/desktop/<os>/`.
- Copies binaries:
- `safeagent-control-plane`
- `safeagent-worker`
- `safeagent-skill`
- `safeagent-skill-registry-server`
- `safeagent-desktop`
- Copies sample env files:
- `config/dev.env.example`
- `config/staging.env.example`
- `config/prod.env.example`
- Produces:
- `dist/desktop/README.txt`
- `dist/desktop/<os>/README.txt`
- `dist/desktop/<os>/checksums.sha256`
- `dist/desktop/<os>/sbom.json`
- Includes placeholder placeholders for signing:
- macOS `codesign`
- Windows `signtool`
- Linux `.deb/.AppImage` distribution signing note

## Updater Flow
- Added manifest parser in backend:
- `parse_update_manifest`
- `check_for_updates` command.
- Supports manifest path env or override parameter.
- Returns:
- manifest presence
- latest/current version
- notes
- local safe flag (`safe: true` placeholder in MVP)
- `docs/DESKTOP_INSTALL.md` includes upgrade check guidance and placeholder pipeline.

## Verification and Proof
- Added `desktop-release-check` in `Justfile`.
- `desktop-release-check` currently executes:
- `scripts/build_desktop_release.sh`
- `just desktop-check`
- config persistence tests:
- `tests::settings_default_and_roundtrip`
- `tests::update_manifest_parse`

### desktop-release-check log excerpt
`logs/desktop_release_check.log`
```
running 5 tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

running 2 tests
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s
```

## Known limitations
- Updater remains manifest-parse MVP in this phase (no remote signing/rollback yet).
- Crash recovery currently tracks binary child exit; deeper telemetry hooks can be added in next phase.
