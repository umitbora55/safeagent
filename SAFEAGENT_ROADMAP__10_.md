# SafeAgent — Full Product Roadmap v3.0

> **Vision:** The personal AI assistant that OpenClaw should have been.
> Secure by default. Cost-optimized. Just works.

---

## Positioning: OpenClaw's 7 Deadly Sins → SafeAgent's 7 Pillars

| # | OpenClaw Pain | SafeAgent Solution | Status |
|---|---------------|-------------------|--------|
| 1 | **$300-750/mo API costs**, $200/day runaway loops | Embedding-based 3-tier routing + prompt caching (35-40% savings) | ✅ Built |
| 2 | **Plain-text API keys**, widespread security vulnerabilities ([sources](#security-references)) | AES-256 encrypted vault (Argon2id KDF), prompt injection guard, audit logging | ✅ Partial |
| 3 | **3-day setup**, $250 spent before first useful response | `safeagent init` wizard — working bot in under 10 minutes | ⏳ Phase 3A |
| 4 | **Numerous malicious skills** in open marketplace ([sources](#security-references)) | Capability-based permission system, no untrusted marketplace | ⏳ Phase 4 |
| 5 | **3 name changes**, abandoned repos hijacked by scammers | Clean brand, single repo, stable identity from day one | ✅ Done |
| 6 | **Dedicated Mac Mini required**, $500+ hardware | Runs on any machine — laptop, VPS, Raspberry Pi | ✅ Done |
| 7 | **Thousands of open GitHub issues**, frequent gateway crashes | Rust-native architecture — memory safe, zero GC pauses, 71+ tests | ✅ Built |

---

## Completed Phases

### Phase 1 — Core Infrastructure ✅

8 crates, 71+ tests, working Telegram MVP.

| Crate | Purpose | Tests |
|-------|---------|-------|
| `bridge-common` | Shared types & traits | — |
| `policy-engine` | Rate limiting, content filtering | 10 |
| `prompt-guard` | Injection detection, content safety | 14 |
| `llm-router` | Multi-signal model routing | 24 |
| `credential-vault` | AES-256 encrypted credential storage | 14 |
| `memory-store` | User fact persistence | 9 |
| `gateway` | Core orchestrator | — |
| `bridge-telegram` | Telegram platform adapter | — |

### Phase 2 — Intelligent Cost Optimization ✅

| Feature | Detail |
|---------|--------|
| Embedding-based routing | Voyage AI voyage-3-large, reference dataset (3 sources, expanding — see Evaluation Harness) |
| Hybrid routing | Embedding (conf > threshold) → rule-based fallback |
| Dynamic confidence threshold | Configurable presets: `conservative` / `balanced` / `aggressive` (see Threshold Calibration) |
| Prompt caching | Stable prefix architecture, 35-40% cache efficiency |
| Cache bootstrap | Haiku below threshold → auto-upgrade to Sonnet for cache seeding |
| Embedding cache | In-memory HashMap — same query never re-embedded |
| Per-tier parameters | Haiku: 1024 max_tokens / Sonnet: 4096 / Opus: 8192 |

**Threshold Calibration:**
The confidence threshold determines when the embedding router's decision is trusted vs falling back to rule-based routing. Instead of hardcoded magic numbers, thresholds are calibrated against the evaluation dataset and exposed as presets:

| Preset | Behavior | Use Case |
|--------|----------|----------|
| `conservative` | Higher threshold — more fallback to rule-based, less cost savings but fewer quality misses | New users, safety-critical |
| `balanced` | Default — optimized for cost/quality trade-off on validation set | Most users |
| `aggressive` | Lower threshold — trusts embeddings more, maximum cost savings, slightly higher quality miss risk | Cost-sensitive, high volume |

Config: `[router] confidence_preset = "balanced"` or `[router] confidence_threshold = 0.012` for manual override. Threshold selection documented per release with validation set results.

**Confidence Score Definition:**
The embedding router computes cosine similarity between the user's prompt embedding and each tier centroid (economy, standard, premium). The confidence score is the **margin** between the top-1 and top-2 similarities:

```
confidence = cosine_sim(prompt, best_tier_centroid) - cosine_sim(prompt, second_tier_centroid)
```

- Range: 0.0 to ~0.05 in practice (centroids are close in embedding space; margins are small)
- Embeddings: Voyage AI `voyage-3-large`, 1024 dimensions, L2-normalized
- Decision: If confidence > threshold → use embedding winner. Else → fall back to rule-based router.
- Why thresholds are small (~0.01): Centroid vectors represent averaged embeddings of 350 prompts each; averaging compresses inter-centroid distance. A margin of 0.005 is still meaningful in this space.

---

## Phase 3A — Distribution & Trust 🔜 NEXT

> **Goal:** First-run success rate > 90%. A developer goes from zero to working bot in under 10 minutes.
>
> **Definition of Done:** `safeagent init` wizard works on macOS/Linux, 5-command quickstart tested, top 10 common errors documented with solutions, 3 example configs shipped, README reviewed by external dev.
>
> **Windows:** Not in Phase 3A scope. Windows support (via WSL2 or native) tracked as Phase 3A.4 stretch goal. If community demand is high, prioritize after Discord bridge. Decision documented to avoid ambiguity.

### 3A.1 — GitHub Repository & Landing README

- Public GitHub repo with clean structure
- README as landing page:
  - "What is SafeAgent" (30 seconds)
  - "Why not OpenClaw" (pain comparison table)
  - "Quickstart" (copy-paste 5 commands)
  - Architecture diagram (Mermaid)
  - Feature matrix with status badges
- LICENSE (MIT or Apache 2.0)
- CONTRIBUTING.md
- CHANGELOG.md
- **SECURITY.md:** Responsible disclosure policy (email + PGP key), supported versions, GPG fingerprint for release verification, security issue response SLA (critical: 48h acknowledgment, 7-day fix target)

### 3A.2 — Interactive Setup Wizard

```
$ cargo install safeagent
$ safeagent init

🔐 Create vault password: ********
🤖 Anthropic API key: sk-ant-...  ✅ Valid (Sonnet 4.5 accessible)
📱 Platform? [telegram/discord/cli]
   → Telegram bot token: 123456:ABC... ✅ Connected as @MyBot
🧭 Voyage AI key (optional, for smart routing): ...

✅ SafeAgent is ready! Send a message to @MyBot on Telegram.
   Local stats: http://localhost:18789/stats (minimal read-only status page)
```

> **Note:** This is a minimal status endpoint (health, cost summary, model info). The full interactive Web UI with chat, analytics, and settings comes in Phase 6.

- Config validation with clear error messages
- Auto-test API key validity
- Generate default config file
- **Error UX:** Every failure shows error code + one-line cause + fix command or doc link
- **`safeagent doctor`:** Auto-diagnose common issues (env vars, port conflicts, DNS, TLS/proxy, API key format, disk permissions)
- Common errors guide (wrong key format, network issues, permissions)

### 3A.3 — Example Configs & Troubleshooting

- `examples/telegram-basic.toml`
- `examples/discord-basic.toml`
- `examples/multi-platform.toml`
- `docs/troubleshooting.md` — top 10 setup errors with solutions

---

## Phase 3B — Cost & Safety Guardrails 🔜

> **Goal:** No user should ever be surprised by their API bill. No credential should ever be exposed.
>
> **Definition of Done:** Per-message cost visible in terminal, daily hard cap stops requests at limit, model fallback works on 429/500/529 errors, audit log captures all requests with log rotation, `safeagent stats` shows daily/weekly/monthly cost report.

### 3B.1 — Cost Visibility

- Per-message cost breakdown in terminal log:
  ```
  💰 Cost: $0.0034 (Haiku 847 in / 203 out) | Session: $0.12 | Today: $0.89
  ```
- Model-level cost aggregation (daily/weekly/monthly)
- `safeagent stats` CLI command — cost report by model, by day
- Local SQLite cost ledger (no telemetry, everything stays on disk)
- **Pricing source:** Model prices loaded from versioned `pricing.toml` manifest
  - Each ledger entry records which pricing version was used
  - `safeagent pricing update` fetches latest prices from pinned GitHub tag with checksum verification
  - **Trust chain:** Signing key is Ed25519; public key pinned in binary at compile time
  - **Key rotation:** New key announced via GitHub Security Advisory + 30-day overlap period
  - **Offline behavior:** If update unavailable, continues with last known pricing + logs warning
  - Manifest is signed; update rejects tampered or unsigned files
  - Manual override supported for custom/self-hosted models

### 3B.2 — Spending Limits

- Daily hard cap (e.g. $5/day) — bot responds with "Budget limit reached"
- Monthly soft warning (e.g. $50/mo) — bot warns but continues
- Monthly hard cap — full stop
- Per-conversation limit option
- Config: `[limits] daily_usd = 5.0, monthly_usd = 50.0`

### 3B.3 — Model Fallback

- API error (429/500/529) → automatic fallback to next tier
- Timeout → fallback with shorter prompt
- All providers down → graceful offline message
- Fallback chain configurable: `fallback = ["sonnet", "haiku", "offline"]`

### 3B.4 — Audit Log

- Every request logged: timestamp, model, tier, tokens, cost, bridge source
- Every credential access logged: what was accessed, when, by which skill
- **Secret redaction in logs**: API keys, tokens, passwords automatically masked (`sk-ant-...****`)
- `safeagent audit` CLI — browse logs, filter by date/model/cost
- Log rotation: keep 30 days by default **or** max 200 MB, whichever triggers first. Oldest logs pruned automatically. Configurable: `[audit] retention_days = 30, max_size_mb = 200`.
- **File permissions:** Ledger (SQLite) and log files created with `0600`; data directory with `0700`. `safeagent doctor` warns if permissions are too open.
- **At-rest note:** Ledger and logs are not encrypted by default (vault is). For shared/multi-user machines, recommend full-disk encryption or placing SafeAgent data dir on an encrypted volume. Future: optional ledger encryption.

### 3B.5 — Security Hardening

- **KDF:** Vault master password → encryption key via Argon2id (memory-hard, brute-force resistant)
- **Secret redaction:** All log outputs mask sensitive values (keys, tokens, passwords)
- **OS keychain integration (optional):** Store vault password in macOS Keychain / Linux Secret Service
- **Threat model document:** Clear documentation of what SafeAgent protects against and what it doesn't
  - ✅ Protects: credential theft from disk, prompt injection, accidental API key exposure in logs
  - ⚠️ Out of scope: memory-resident attacks, root-level compromise, physical access

### 3B.6 — Release & Distribution Security

- **Signed releases:** Signed git tags (GPG) + signed release artifacts (binary + tarball). Crate publishes to crates.io rely on crates.io's own authentication; additionally, release artifacts on GitHub Releases are signed with project GPG key.
- **Checksums:** SHA-256 checksums published alongside every release artifact
- **SBOM:** Software Bill of Materials generated for each release (SPDX format)
- **Reproducible builds:** CI pipeline produces bit-identical output from same source
- **Dependency audit:** `cargo audit` runs in CI; no known vulnerable dependencies in releases

---

## Phase 3C — Bridge Abstraction + Discord 🔜

> **Goal:** Add Discord as second platform, but build the bridge framework that makes Slack/WhatsApp trivial later.
>
> **Definition of Done:** Discord `/ask` and `/stats` commands work, message chunking handles 2000-char limit, retry on rate limit, typing indicator during generation, bridge trait fully abstracted so adding a new platform requires implementing only 4 methods: 2 async (`start`, `send`) + 2 metadata (`platform`, `capabilities`), Telegram + Discord run simultaneously. Edge cases handled: attachments have size limit + type allowlist (text/JSON/images only), thread/reply context correctly mapped so conversations never cross-contaminate between channels.

### 3C.1 — Bridge Trait Abstraction

```rust
#[async_trait]
pub trait Bridge: Send + Sync {
    async fn start(&self, tx: Sender<IncomingMessage>) -> Result<()>;
    async fn send(&self, msg: OutgoingMessage) -> Result<()>;
    fn platform(&self) -> Platform;
    fn capabilities(&self) -> BridgeCapabilities;
}

pub struct BridgeCapabilities {
    pub max_message_length: usize,
    pub supports_threads: bool,
    pub supports_reactions: bool,
    pub supports_attachments: bool,
    pub supports_typing_indicator: bool,
}
```

- Platform-agnostic message format
- Automatic message chunking per platform limits
- Retry with exponential backoff
- Rate limit handling per platform

### 3C.2 — Discord Bridge

- Slash commands (`/ask`, `/model`, `/stats`, `/budget`)
- Thread-based conversations (context preserved per thread)
- Message chunking (2000 char Discord limit)
- Typing indicator during generation
- Embed formatting for cost/model info
- Per-channel/per-user allowed tools policy

### 3C.3 — Multi-Bridge Runtime

- Run Telegram + Discord simultaneously
- Shared vault, memory, router across bridges
- Per-bridge config in single `safeagent.toml`

---

## Phase 4 — Agentic Skills (Read-Only First)

> **Goal:** SafeAgent can do useful things beyond chat — safely.

### Phase 4A — Read-Only Skills (low risk, deploy early)

| Skill | Capability | Permission Level |
|-------|-----------|-----------------|
| Web Search | Brave/DuckDuckGo API, GET only | `read:web` |
| File Reader | Read files from allowlisted directories | `read:fs` |
| Calendar Reader | Google Calendar read-only | `read:calendar` |
| Email Reader | IMAP read-only, no send | `read:email` |
| URL Fetcher | Fetch and summarize web pages | `read:web` |

**Phase 4A Security Checklist (mandatory before any read-only skill ships):**

| Attack Surface | Mitigation |
|---------------|-----------|
| **SSRF (URL Fetcher/Web Search)** | Block private IPs (10.x, 172.16.x, 192.168.x), localhost, link-local (169.254.x), cloud metadata (169.254.169.254). Allowlist/denylist configurable. |
| **Path traversal (File Reader)** | Resolve realpath before access, reject symlinks outside allowlist, block `..` sequences, allowlisted directories only |
| **Prompt injection via tool output** | All skill outputs pass through prompt-guard before insertion into LLM context. Tool results wrapped in `<tool_output>` markers with injection filters. |
| **Zip bomb / large response** | Max response size per skill (default: 1MB). Timeout per request (default: 30s). Max redirects: 3. |
| **Content-type spoofing** | Content-type allowlist per skill (text/html, application/json, text/plain). Binary content rejected unless explicitly allowed. |
| **DNS rebinding** | Re-resolve DNS after redirect; reject if target IP is private |

### Phase 4B — Write/Action Skills (high risk, needs guardrails)

| Skill | Capability | Permission Level | Guardrail |
|-------|-----------|-----------------|-----------|
| Email Sender | SMTP send | `write:email` | Confirmation prompt + **recipient allowlist** (configurable approved domains/addresses) |
| File Writer | Create/modify files | `write:fs` | Allowlist dirs only + **create-only mode by default** (no overwrite/delete unless explicitly enabled) |
| Calendar Writer | Create/modify events | `write:calendar` | Confirmation prompt + **max events per day limit** |
| Browser Control | Headless browser actions | `execute:browser` | Sandboxed + **domain allowlist** + no form submission by default |

> **Note:** Shell Executor (`execute:shell`) is intentionally deferred to Phase 7. Even with allowlists and sandboxing, shell access in an OSS agent is a high-risk surface that requires mature audit logging, sandboxing infrastructure, and community trust before shipping.

> **Default posture for all write-skills: deny-all.** Recipient allowlists, directory allowlists, and domain allowlists ship empty by default. Nothing is permitted until the user explicitly configures allowed targets. This ensures no write-skill can take action on first install without conscious user opt-in.

### Skill Security Framework

```toml
# safeagent.toml
[skills.web_search]
enabled = true
permissions = ["read:web"]
rate_limit = "10/minute"

[skills.email_send]
enabled = true
permissions = ["write:email"]
require_confirmation = true  # User must approve each send
daily_limit = 20
```

- Capability-based permissions (skill declares what it needs)
- Runtime confirmation for write operations (first N uses)
- Rate limits per skill
- Audit log mandatory for all skill invocations
- No third-party skill marketplace — all skills are built-in or user-reviewed

---

## Phase 5 — Streaming & User Experience

> **Goal:** Real-time responses, voice, rich media.

| Feature | Detail |
|---------|--------|
| Streaming responses | Token-by-token display on Telegram/Discord/Web |
| Voice input | Whisper API for speech-to-text |
| Voice output | TTS for responses (optional) |
| Rich media | Image/file upload and processing |
| Conversation export | Export chat history as Markdown/JSON |
| Context management | Auto-summarization for long conversations |

---

## Phase 6 — Web UI & Dashboard

> **Goal:** Browser-based interface for non-CLI users and monitoring.

| Feature | Detail |
|---------|--------|
| Chat interface | Web-based chat (React/HTMX) |
| Cost dashboard | Real-time cost tracking with charts |
| Model analytics | Which models used, cache hit rates, routing decisions |
| Conversation browser | Search and view past conversations |
| Settings UI | Configure vault, models, limits, bridges |
| Health monitor | Bridge status, API availability, error rates |

---

## Phase 7 — Scale & Enterprise

> **Goal:** Multi-user, teams, advanced deployment.

| Feature | Detail |
|---------|--------|
| Multi-user support | Per-user vault, memory, limits |
| Team mode | Shared skills, individual budgets |
| Docker deployment | One-line `docker run` |
| Cloud hosting | Deploy to Railway/Fly.io with one click |
| Webhook API | External services trigger SafeAgent |
| MCP server | Model Context Protocol for tool integration |

---

## Priority Matrix

| Priority | Feature | Why Now |
|----------|---------|---------|
| 🔴 P0 | GitHub + README | Can't grow without visibility |
| 🔴 P0 | `safeagent init` wizard | First impression = adoption |
| 🔴 P0 | Cost breakdown + spending limits | #1 OpenClaw complaint after security |
| 🟠 P1 | Model fallback | Reliability = trust |
| 🟠 P1 | Audit log | Security differentiator |
| 🟠 P1 | Bridge abstraction + Discord | Second platform = credibility |
| 🟠 P1 | Web search skill (read-only) | First "it does things" moment — ship with Discord |
| 🟡 P2 | Remaining read-only skills | Expand capability gradually |
| 🟡 P2 | Streaming responses | UX quality |
| 🟢 P3 | Web UI | Nice to have, not blocking |
| 🟢 P3 | Voice | Differentiator but complex |
| 🟢 P3 | Multi-user / Enterprise | Growth stage |

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        SafeAgent                             │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Telegram  │  │ Discord  │  │   Slack  │  │  Web UI  │    │
│  │  Bridge   │  │  Bridge  │  │  Bridge  │  │  Bridge  │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       └──────────────┴──────────────┴──────────────┘         │
│                          │                                    │
│                    ┌─────▼─────┐                              │
│                    │  Gateway   │                              │
│                    │ (core hub) │                              │
│                    └─────┬─────┘                              │
│           ┌──────────────┼──────────────┐                    │
│     ┌─────▼─────┐  ┌────▼────┐  ┌──────▼──────┐            │
│     │ LLM Router │  │  Vault  │  │ Prompt Guard │            │
│     │ (hybrid)   │  │ (AES)   │  │ (injection)  │            │
│     └─────┬─────┘  └─────────┘  └─────────────┘            │
│           │                                                   │
│     ┌─────▼─────┐  ┌─────────┐  ┌─────────────┐            │
│     │  Voyage    │  │ Memory  │  │ Cost Ledger  │            │
│     │ Embedding  │  │  Store  │  │  + Limiter   │            │
│     └───────────┘  └─────────┘  └─────────────┘            │
│                                                              │
│     ┌─────────────────────────────────────────┐             │
│     │           Skill Framework               │             │
│     │  ┌────┐ ┌─────┐ ┌──────┐ ┌──────────┐  │             │
│     │  │Web │ │File │ │Email │ │ Calendar │  │             │
│     │  │Srch│ │Read │ │Read  │ │  Read    │  │             │
│     │  └────┘ └─────┘ └──────┘ └──────────┘  │             │
│     └─────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

---

## Success Metrics

| Metric | Target | Measured By |
|--------|--------|-------------|
| Setup time | < 10 minutes | User testing + init wizard timing log |
| First-run success | > 90% | Init wizard exit codes + opt-in local log export + GitHub issue triage |

**Opt-in log export format:**
- Format: JSONL (one event per line), exported via `safeagent export-logs --anonymized`
- **Fields included:** timestamp, event type (init_success/init_failure/error_code), platform, phase duration, SafeAgent version, OS family
- **Fields NEVER included:** API keys, message content, user identity, IP addresses, vault contents, conversation history, file paths, embedding vectors
- Purpose: aggregate first-run success tracking only. No automatic upload; user must explicitly run the export command and choose to share.
- **Redaction CI test:** Test suite injects synthetic secrets (API keys, phone numbers, emails, SSNs) into sample logs, runs export pipeline, asserts zero sensitive values in output. Runs on every CI build.
| Cost savings vs single-model | > 40% | Cost ledger comparison reports |
| Cache hit rate | > 30% | Dashboard / `safeagent stats` |
| Correct tier routing | > 85% | Routing evaluation harness |
| GitHub stars (6 months) | 1,000+ | GitHub |
| Security CVEs | 0 critical | Audit + responsible disclosure program |

### Routing Accuracy Definition

The "correct tier" metric measures whether the router picked the cheapest model that still meets quality requirements:

| Outcome | Definition | Counted As |
|---------|-----------|------------|
| **Economy correct** | Economy model passes quality threshold, router selected economy | ✅ Success |
| **Standard correct** | Economy fails quality threshold, standard passes, router selected standard | ✅ Success |
| **Premium correct** | Only premium passes quality threshold, router selected premium | ✅ Success |
| **Cost-optimal miss** | Router over-provisioned (e.g. premium when standard sufficed) | ⚠️ Safe miss (not failure, but tracked for cost optimization) |
| **Quality miss** | Router under-provisioned (e.g. economy when premium needed) | ❌ Failure |

**Accuracy = (Successes) / (Successes + Failures). Safe misses are excluded from failure count but tracked separately as "over-spend rate".**

### Routing Evaluation Harness (Phase 2.5)

An offline evaluation pipeline that runs on every release to measure routing quality:

**Components:**
- **Anchor dataset (curated, ~3K prompts):** Hand-labeled economy/standard/premium, covering greetings, factual QA, code, reasoning, creative writing, edge cases. Updated manually.
- **Coverage dataset (larger, ~20K+ prompts):** Updated per release. Core sources:

| Dataset | Hugging Face ID | License | Usage |
|---------|----------------|---------|-------|
| RouterArena | `RouteWorks/RouterArena` (split: full) | Apache 2.0 | Difficulty labels → tier mapping |
| HelpSteer2 | `nvidia/HelpSteer2` | CC-BY-4.0 | Complexity scores → tier mapping |
| GPT-4 routing | `routellm/gpt4_dataset` | MIT | Mixtral quality scores → tier mapping |
| SPROUT (future) | `CARROT-LLM-Routing/SPROUT` | TBD | Multi-model correctness scores |

Version pinning: Each release records the exact dataset commit hash in `eval/DATASET_MANIFEST.md`.

**Dataset governance:**
- All source datasets must have permissive licenses (Apache 2.0, MIT, CC-BY, or public domain). License verified and recorded in `datasets/LICENSE_MANIFEST.md`.
- No PII in any dataset. Anchor set is manually reviewed; coverage set is run through PII detection (regex for emails, phone numbers, names) + manual spot-check per release.
- If future datasets are derived from SafeAgent usage logs: opt-in only, anonymized (no user ID, no message content — only routing metadata: tier selected, prompt length, task type label), documented in privacy policy.
- **Quality metric per task type:** LLM-judge score for open-ended, regex/exact-match for factual, unit test pass for code, rubric score for reasoning.

**Default quality thresholds** (configurable in `eval/quality_thresholds.toml`):

| Task Type | Metric | Threshold | Notes |
|-----------|--------|-----------|-------|
| Open-ended chat | LLM-judge score (1-5) | ≥ 3.5 | "Adequate and helpful" |
| Factual QA | Exact/regex match | Pass/Fail | Binary correctness |
| Code generation | Unit test pass rate | ≥ 80% | Tests provided per prompt |
| Reasoning/math | Rubric score (1-5) | ≥ 4.0 | Higher bar for precision |
| Translation | BLEU + judge hybrid | ≥ 3.0 | Fluency + accuracy |

These thresholds are published in each release evaluation report alongside routing accuracy.
- **Ground truth labeling:** For each prompt, run all 3 tiers and record quality scores. The "correct tier" is the cheapest tier that passes the quality threshold.

**Output per release:**
```
Routing Evaluation Report — v0.3.0
─────────────────────────────────
Accuracy:       87.2% (target: >85%)
Over-spend rate: 8.1% (router chose premium when standard sufficed)
Quality miss:    4.7% (router chose economy when premium was needed)
Cost savings:   42% vs always-premium baseline
Dataset:        anchor=3012 prompts, coverage=21440 prompts
Judge model:    claude-sonnet-4-5-20250929 (pinned)
```

**LLM-judge variance control:**
- Judge model pinned to specific version, never `latest`. Canonical format in config:
  ```toml
  [eval.judge]
  provider = "anthropic"
  model = "claude-sonnet-4-5-20250929"
  temperature = 0.0
  ```
- Judge outputs cached per `(prompt_hash, judge_model_id, rubric_version, prompt_template_hash)` — same input always produces same score across runs
- Release evaluation report includes: judge model ID, prompt template hash, rubric version, sampling params, cache hit rate
- Judge model upgrade = full re-evaluation of anchor set + documented in CHANGELOG
- Non-LLM metrics (regex, exact-match, unit test) preferred where applicable to eliminate judge variance entirely

**Integration:** Runs in CI on tagged releases. Results published in CHANGELOG. Regression = release blocker.

---

## Competitive Landscape (as of February 2026)

| Feature | SafeAgent | OpenClaw | Claude Code |
|---------|-----------|----------|-------------|
| Smart cost routing | ✅ 3-tier hybrid | Not built-in | Not built-in |
| Encrypted credentials | ✅ AES-256 + Argon2id vault (default) | Plain text by default; encryption opt-in via community patches | N/A |
| Setup time | ~10 min target | Varies widely; depends on user experience and deployment method | ~5 min |
| Spending limits | ✅ Daily/monthly hard caps (built-in) | Not built-in; achievable via external tooling or manual config | N/A |
| Platform count | 2 (growing) | 15+ ([per GitHub README](https://github.com/openclaw/openclaw)) | CLI only |
| Skill security | ✅ Capability-based, no open marketplace | Open marketplace with VirusTotal scanning | N/A |
| Architecture | Rust (memory safe) | Node.js/TypeScript | N/A |
| Prompt caching | ✅ 35-40% savings | Not built-in | N/A |
| Audit logging | ✅ Designed, shipping in Phase 3B | Partial / varies by config | N/A |
| Open source | ✅ Yes | ✅ Yes | ❌ No |

---

*SafeAgent: The AI assistant you can trust with your keys, your budget, and your time.*

---

## Security References

The following third-party sources document security challenges in the OpenClaw ecosystem. These are provided for context, not as a comprehensive audit. SafeAgent's security approach is designed to address the categories of issues described in these reports.

> **Maintainer note:** Verify all links and titles before each public release. Archive snapshots (Wayback Machine) recommended for link stability. Remove or update any link that becomes inaccurate or misleading.

- [XDA Developers: "Please stop using OpenClaw"](https://www.xda-developers.com/please-stop-using-openclaw/) — CVE details, credential storage concerns
- [Kaspersky: "Key OpenClaw risks"](https://www.kaspersky.com/blog/moltbot-enterprise-risk-management/55317/) — Skill marketplace risks, infostealer targeting
- [Veracode: "Clawing for Scraps"](https://www.veracode.com/blog/clawing-for-scraps-openclaw-clawdbot/) — Supply chain attack analysis
- [Bitsight: "OpenClaw Security"](https://www.bitsight.com/blog/openclaw-ai-security-risks-exposed-instances) — Exposed instance analysis
- [CNBC: "From Clawdbot to OpenClaw"](https://www.cnbc.com/2026/02/02/openclaw-open-source-ai-agent-rise-controversy-clawdbot-moltbot-moltbook.html) — Adoption and controversy overview
