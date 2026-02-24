# Install

This guide covers macOS, Linux, and Windows (WSL2 recommended) for SafeAgent.

## Prerequisites
- Rust toolchain (stable)
- `just` task runner
- Docker (for local OTEL collector used by `just verify`)

## macOS
1. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. Install `just`:
   ```bash
   brew install just
   ```
3. Install Docker Desktop:
   - Download from Docker Desktop and start the daemon.

4. Build:
   ```bash
   cargo build --release
   ```

## Linux (Ubuntu/Debian)
1. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. Install `just`:
   ```bash
   sudo apt-get update
   sudo apt-get install -y just
   ```
3. Install Docker:
   ```bash
   sudo apt-get install -y docker.io
   sudo usermod -aG docker $USER
   ```
   Log out/in to apply Docker group changes.

4. Build:
   ```bash
   cargo build --release
   ```

## Windows
Recommended: WSL2 + Ubuntu.

1. Install WSL2 + Ubuntu.
2. Follow the Linux instructions above inside WSL.
3. Install Docker Desktop for Windows and enable WSL2 integration.

## Docker Mode (OTEL Collector)
`just verify` starts a local OTEL collector for the smoke test:

```bash
just otel-up
just otel-smoke
just otel-down
```

If Docker is not running, `otel-up` will fail.

## Post-Install Check
```bash
just verify
```

If verification passes, proceed to `safeagent init` and `safeagent run`.
