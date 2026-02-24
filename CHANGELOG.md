# Changelog

All notable changes to SafeAgent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Phase 7: Scale & Enterprise**
  - Docker deployment (Dockerfile + docker-compose.yml)
  - Webhook API (`POST /api/webhook/message`)
  - MCP server (`/mcp` endpoint, JSON-RPC 2.0)
  - Multi-user support with per-user isolation (vault, memory, limits)
  - Team mode with shared skills and individual budgets
  - Cloud hosting configs (Fly.io + Railway)
- **Phase 6: Web UI & Dashboard**
  - Browser-based dashboard with cost cards, model analytics
  - Audit log viewer, conversation browser, settings UI
  - REST API (5 endpoints: health, stats, audit, conversations, settings)
  - HTMX + auto-refresh (15s interval)
- **Phase 5: Streaming & UX**
  - Token-by-token streaming for CLI
  - Voice input (Whisper STT) and output (OpenAI TTS)
  - Conversation export as Markdown and JSON (`safeagent export`)
  - Auto-summarization for long conversations (>20 messages)
- **Phase 4B: Write Skills**
  - File Writer (allowlist dirs, create-only default)
  - Calendar Writer (Google Calendar, daily limit)
  - Email Sender (Gmail, recipient allowlist, daily limit)
  - All write skills deny-all by default
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

## [1.0.0-rc.1] — 2026-02-24

### Highlights
- Policy-before-tool execution (policy engine gates all tool use)
- Capability tokens (PASETO-based) for scoped, revocable permissions
- Hash-chain audit log with verification gate
- STRIDE generator → Red-team + Chaos scenario suites
- OpenTelemetry (OTEL) smoke verification

### Breaking Changes
- None noted for this RC

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

[Unreleased]: https://github.com/umitbora55/safeagent/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/umitbora55/safeagent/releases/tag/v1.0.0-rc.1
[0.1.0]: https://github.com/umitbora55/safeagent/releases/tag/v0.1.0
