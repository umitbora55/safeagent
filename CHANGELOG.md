# Changelog

All notable changes to SafeAgent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Skills framework** with SSRF protection, permission model, and rate limiting
- **Web Search skill** (Brave Search API integration)
- **URL Fetcher skill** with HTML-to-text extraction and content-type filtering
- **Bridge abstraction** with `BridgeCapabilities` and message chunking
- **Audit log** with automatic secret redaction and log rotation (`safeagent audit`)
- **Cost ledger** with SQLite-backed per-request cost tracking (`safeagent stats`)
- **Spending limits** — daily and monthly hard caps with pre-request budget check
- **Model fallback** — automatic retry on 429/500/529 errors with fallback chain
- **Init wizard** — interactive setup with API key validation (`safeagent init`)
- **Doctor diagnostics** — 7-check system health tool (`safeagent doctor`)
- **Example configs** — economy, balanced, performance, telegram presets
- **Troubleshooting guide** — error codes SA-E001 through SA-E006 with fixes
- **Threat model document** — security scope and recommendations
- **CI/CD pipeline** — GitHub Actions for build, test, audit, release
- **Release workflow** — multi-platform binary builds, SHA-256 checksums, SBOM

### Architecture
- 11 crates: bridge-common, bridge-telegram, credential-vault, llm-router, memory, policy-engine, prompt-guard, gateway, cost-ledger, audit-log, skills
- 100+ tests across all crates
- 7 CLI subcommands: init, doctor, stats, audit, run, help, version

---

## [0.1.0] — 2025-02-23

### Added
- Initial release
- AES-256-GCM encrypted credential vault (Argon2id KDF)
- 3-tier LLM routing (Haiku / Sonnet / Opus) with embedding-based smart routing
- Prompt caching with cache affinity system
- Prompt injection detection and content safety
- Conversation memory with user fact extraction
- Policy engine with permission levels (green/yellow/red)
- Telegram bridge
- CLI interface

[Unreleased]: https://github.com/umitbora55/safeagent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/umitbora55/safeagent/releases/tag/v0.1.0
