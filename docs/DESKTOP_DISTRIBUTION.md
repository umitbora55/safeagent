# SafeAgent Desktop Distribution and Release Automation

This document defines the production distribution chain for SafeAgent Desktop.

## 1) Packaging entry points
- `scripts/build_dmg_macos.sh`
  - macOS installer skeleton (DMG)
  - Produces `dist/desktop/macos/SafeAgent-Desktop-<version>.dmg`
- `scripts/build_installer_windows.ps1`
  - Windows installer skeleton (NSIS/MSI)
  - Produces placeholder MSI/EXE output when NSIS is unavailable
- `scripts/build_appimage_linux.sh`
  - Linux AppImage packaging skeleton
  - Produces `dist/desktop/linux/SafeAgent-Desktop-<version>-x86_64.AppImage`
- `scripts/build_desktop_release.sh`
  - Cross-package builder for release artifacts under `dist/desktop/<os>`
- `scripts/publish_update_channel.sh`
  - Builds `dist/updates/update.json` and `dist/updates/update.sig`

## 2) Versioning source
- Single source: `/VERSION`
- Update scripts and release manifest templates read from this file.
- Existing runtime version reads now resolve from this source via `desktop/src/update.rs` and `desktop/src/main.rs`.

## 3) Artifacts
From `scripts/build_desktop_release.sh`:
- `dist/desktop/<os>/safeagent-desktop`
- `dist/desktop/<os>/safeagent-control-plane`
- `dist/desktop/<os>/safeagent-worker`
- `dist/desktop/<os>/safeagent-skill`
- `dist/desktop/<os>/safeagent-skill-registry-server`
- `dist/desktop/<os>/config/{dev,staging,prod}.env.example`
- `dist/desktop/<os>/checksums.sha256`
- `dist/desktop/<os>/sbom.json`
- `dist/desktop/<os>/README.txt`

From update publishing:
- `dist/updates/update.json`
- `dist/updates/update.sig`

## 4) GitHub release flow
- Workflow: `.github/workflows/desktop-release.yml`
- Trigger: `git push` on tags `v*`
- Steps:
  - build desktop release bundle
  - publish update manifest/signature
  - run `desktop-update-check`
  - run `verify-v2`
  - upload desktop + updates artifacts
  - create GitHub release with signed update channel files

## 5) Update channel semantics
- Manifest: `update.json` (versioned metadata + SHA-256 of payload)
- Signature: `update.sig` (Ed25519 signature)
- Client-side verify remains fail-closed for missing/invalid signature/hash.

## 6) Security notes
- No private signing keys are stored in this repository.
- `SAFEAGENT_UPDATE_SIGNING_KEY_B64` environment variable supports explicit testing/signing override.
- Scripts are deterministic and artifact list is static for release runs.
