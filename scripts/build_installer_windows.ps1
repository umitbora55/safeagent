#requires -Version 7
param(
    [string]$Mode = "local"
)

$ErrorActionPreference = "Stop"

function Ensure-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $Name"
    }
}

Ensure-Command cargo
Ensure-Command rustc

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$distRoot = Join-Path $repoRoot "dist/windows"
New-Item -ItemType Directory -Force -Path $distRoot | Out-Null

Write-Host "Building release artifacts for Windows installer skeleton..."
cargo build --release --manifest-path platform/control-plane/Cargo.toml
cargo build --release --manifest-path platform/worker/Cargo.toml
cargo build --release --manifest-path crates/skill-registry/Cargo.toml
cargo build --release --manifest-path crates/skill-registry-server/Cargo.toml
cargo build --release --manifest-path desktop/Cargo.toml

$items = @(
    @{Name = "safeagent-control-plane.exe"; Path = Join-Path $repoRoot "platform/control-plane/target/release/safeagent-control-plane"},
    @{Name = "safeagent-worker.exe"; Path = Join-Path $repoRoot "platform/worker/target/release/safeagent-worker"},
    @{Name = "safeagent-skill.exe"; Path = Join-Path $repoRoot "crates/skill-registry/target/release/skill"},
    @{Name = "safeagent-skill-registry-server.exe"; Path = Join-Path $repoRoot "crates/skill-registry-server/target/release/safeagent-skill-registry-server"},
    @{Name = "safeagent-desktop.exe"; Path = Join-Path $repoRoot "desktop/target/release/safeagent-desktop"}
)

foreach ($item in $items) {
    if (Test-Path $item.Path) {
        Copy-Item $item.Path (Join-Path $distRoot $item.Name)
    } else {
        throw "Missing artifact: $($item.Path)"
    }
}

Copy-Item (Join-Path $repoRoot "config/dev.env.example") (Join-Path $distRoot "dev.env.example")
Copy-Item (Join-Path $repoRoot "config/staging.env.example") (Join-Path $distRoot "staging.env.example")
Copy-Item (Join-Path $repoRoot "config/prod.env.example") (Join-Path $distRoot "prod.env.example")

if (Get-Command iscc -ErrorAction SilentlyContinue) {
    Write-Host "NSIS is available; integrate NSIS script to generate installer package"
} else {
    Write-Host "NSIS not found; creating signed-installer placeholder artifact"
    "placeholder msi" | Out-File (Join-Path $distRoot "safeagent-desktop-installer.msi") -Encoding utf8
    "placeholder exe" | Out-File (Join-Path $distRoot "safeagent-desktop-installer.exe") -Encoding utf8
}

Write-Host "Windows output directory: $distRoot"
