# SafeAgent Desktop App Build Guide

## Prerequisites
```bash
# Install Tauri CLI
cargo install tauri-cli

# macOS: Xcode command line tools
xcode-select --install

# Linux: Required packages
# sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev
```

## Development
```bash
cd desktop
cargo tauri dev
```

## Build for Production
```bash
cd desktop
cargo tauri build
```

### Output locations:
- **macOS:** `target/release/bundle/dmg/SafeAgent_0.1.0_aarch64.dmg`
- **Linux:** `target/release/bundle/deb/safeagent_0.1.0_amd64.deb`
- **Windows:** `target/release/bundle/msi/SafeAgent_0.1.0_x64.msi`

## Architecture
```
SafeAgent Desktop
├── desktop/          # Tauri (Rust) backend
│   └── src/main.rs   # IPC commands, system tray
├── desktop-ui/       # Frontend (HTML/CSS/JS)
│   └── index.html    # Single-page app
└── crates/           # Core SafeAgent engine
    ├── gateway/      # Main orchestrator
    ├── web-ui/       # REST API (shared with desktop)
    └── ...           # 14 crates
```

The desktop app embeds the same SafeAgent engine that powers the CLI and Telegram bot.
All processing happens locally — no data leaves your machine unless you configure API keys.
