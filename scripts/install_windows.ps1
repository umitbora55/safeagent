#requires -Version 7
Param(
    [string]$Mode = "local"
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Missing required tool: $Name"
    }
}

Require-Command "cargo"
Require-Command "rustc"
Require-Command "just"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$distDir = Join-Path $repoRoot "dist"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

Write-Host "SafeAgent Installer (Windows)"
Write-Host "Repository: $repoRoot"
Write-Host "Mode: $Mode"

Write-Host "Building release artifacts..."
cargo build --release --manifest-path platform/control-plane/Cargo.toml
cargo build --release --manifest-path platform/worker/Cargo.toml
cargo build --release --manifest-path crates/skill-registry/Cargo.toml
cargo build --release --manifest-path crates/skill-registry-server/Cargo.toml

$sources = @(
    @{Name="safeagent-control-plane"; Path=Join-Path $repoRoot "platform/control-plane/target/release/safeagent-control-plane"},
    @{Name="safeagent-worker"; Path=Join-Path $repoRoot "platform/worker/target/release/safeagent-worker"},
    @{Name="safeagent-skill"; Path=Join-Path $repoRoot "crates/skill-registry/target/release/skill"},
    @{Name="safeagent-skill-registry-server"; Path=Join-Path $repoRoot "crates/skill-registry-server/target/release/safeagent-skill-registry-server"}
)

foreach ($item in $sources) {
    if (-not (Test-Path $item.Path)) {
        throw "Expected binary not found: $($item.Path)"
    }
    Copy-Item $item.Path (Join-Path $distDir $item.Name)
}

$configDir = Join-Path $distDir "config"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
Copy-Item (Join-Path $repoRoot "config/dev.env.example") (Join-Path $configDir "dev.env.example")
Copy-Item (Join-Path $repoRoot "config/staging.env.example") (Join-Path $configDir "staging.env.example")
Copy-Item (Join-Path $repoRoot "config/prod.env.example") (Join-Path $configDir "prod.env.example")

Get-ChildItem $distDir | Where-Object { $_.Name -in @("safeagent-control-plane","safeagent-worker","safeagent-skill","safeagent-skill-registry-server") } |
    ForEach-Object {
        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
        "$($hash.Hash.ToLower())  $($_.Name)" | Out-File (Join-Path $distDir "checksums.sha256") -Append -Encoding utf8
    }

[PSCustomObject]@{
    bomFormat = "CycloneDX"
    specVersion = "1.4"
    version = 1
    metadata = @{
        component = @{
            type="application"
            name="safeagent"
            version="0.1.0"
        }
    }
    components = @(
        @{type="application"; name="safeagent-control-plane"; version="0.1.0"},
        @{type="application"; name="safeagent-worker"; version="0.1.0"},
        @{type="application"; name="safeagent-skill"; version="0.1.0"},
        @{type="application"; name="safeagent-skill-registry-server"; version="0.1.0"}
    )
} | ConvertTo-Json -Depth 3 | Out-File (Join-Path $distDir "sbom.json") -Encoding utf8

Write-Host "Done. Artifacts saved in $distDir"
Write-Host "Next steps:"
Write-Host " - Copy dist\\config\\dev.env.example to a local .env"
Write-Host " - Start control plane and worker from dist directory"
Write-Host " - Run scripts\\demo_local.sh (from WSL for full demo automation)"
