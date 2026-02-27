# SafeAgent Installation

## 1) Prerequisites

- Rust stable toolchain
- `just`
- `curl`
- OpenSSL/CURL dependencies for HTTPS
- `git`

## 2) One-command install

- macOS:
  - `scripts/install_macos.sh`
- Linux:
  - `scripts/install_linux.sh`
- Windows:
  - `scripts/install_windows.ps1`

The install scripts:
- verify toolchain
- build all release binaries
- produce `./dist/` bundle:
  - `safeagent-control-plane`
  - `safeagent-worker`
  - `safeagent-skill`
  - `safeagent-skill-registry-server`
  - `checksums.sha256`
  - `sbom.json`
  - `config/*.env.example`

## 3) Config presets

Use one of:
- `config/dev.env.example`
- `config/staging.env.example`
- `config/prod.env.example`

For variable details see `docs/CONFIG_REFERENCE.md`.

## 4) One-command local demo

Run:
```bash
scripts/demo_local.sh
```

It will:
1. start control-plane + worker
2. run safe execute (`echo`)
3. run red action with approval (`admin_op`)
4. run audit verify
5. run adversarial/poison/diff checks

## 5) Verify gates

- `just verify`
- `just verify-v2`
- `just demo-check` (runs the local demo script)
