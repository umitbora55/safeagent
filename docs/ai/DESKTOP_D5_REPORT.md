# D5 — Real Installers + Release Channel Automation

## Scope
- Added a real release automation workflow for desktop artifacts on tag pushes.
- Added version unification via root `VERSION` file.
- Added release/installer skeleton scripts for macOS DMG, Windows installer, and Linux AppImage.
- Added update-channel publish step and desktop release artifact packaging.

## Release workflow summary

### `.github/workflows/desktop-release.yml`
- Trigger: `push` on tags `v*`
- Steps:
  1. checkout
  2. install Rust toolchain
  3. install `just`
  4. `scripts/build_desktop_release.sh`
  5. `scripts/publish_update_channel.sh dist/desktop/linux/safeagent-desktop`
  6. `just desktop-update-check`
  7. `just verify-v2`
  8. upload `dist/desktop/**` and `dist/updates/**`
  9. publish GitHub release

## Scripts added
- `scripts/build_dmg_macos.sh`
- `scripts/build_appimage_linux.sh`
- `scripts/build_installer_windows.ps1`
- `docs/DESKTOP_DISTRIBUTION.md`

## Version source consolidation
- Created `/VERSION`.
- `desktop/src/update.rs` reads version through `current_version()`.
- `desktop/src/main.rs` version endpoints use `update::current_version()`.
- `scripts/build_desktop_release.sh` and `scripts/publish_update_channel.sh` read `VERSION`.

## Release artifacts
- `dist/desktop/linux/safeagent-desktop`
- `dist/desktop/linux/safeagent-control-plane`
- `dist/desktop/linux/safeagent-worker`
- `dist/desktop/linux/safeagent-skill`
- `dist/desktop/linux/safeagent-skill-registry-server`
- `dist/desktop/linux/config/{dev,staging,prod}.env.example`
- `dist/desktop/linux/checksums.sha256`
- `dist/desktop/linux/sbom.json`
- `dist/desktop/linux/README.txt`
- `dist/updates/update.json`
- `dist/updates/update.sig`

## workflow excerpt (important)
```text
jobs:
  desktop-release:
    runs-on: ubuntu-latest
    steps:
      - name: Build desktop release bundle
        run: scripts/build_desktop_release.sh

      - name: Publish update channel manifest
        run: scripts/publish_update_channel.sh dist/desktop/linux/safeagent-desktop

      - name: Run desktop update checks
        run: just desktop-update-check

      - name: Run verify-v2 gate
        run: just verify-v2
```

## Update channel publish output example
```text
Published update channel:
  manifest: /workspace/dist/updates/update.json
  signature: /workspace/dist/updates/update.sig
  signature-bytes: 172
  asset: /workspace/dist/desktop/linux/safeagent-desktop
  asset-sha256: <sha256>
```

## Known status
- macOS/Windows/Linux installer scripts are production-skeleton ready with explicit signing placeholders.
- Release channel publication is automated in workflow and tied to tag push via `desktop-release.yml`.
