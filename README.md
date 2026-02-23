# SafeAgent

**Secure, cost-optimized AI assistant that runs on your hardware.**

SafeAgent routes every message to the cheapest model that can handle it, encrypts all credentials at rest, and connects to Telegram out of the box. Runs entirely on your machine — no hosted backend, no telemetry, no data leaves your device except LLM API calls (Anthropic, optionally Voyage AI).

---

## Why SafeAgent?

Open-source AI agents are powerful but often ship with real problems: plain-text credentials, runaway API costs, and complex setup that can take days. SafeAgent was built to fix that.

| Problem | SafeAgent's approach |
|---------|---------------------|
| High API costs with single-model usage | 3-tier smart routing + prompt caching ([see benchmarks](#benchmarks)) |
| Plain-text API keys on disk | AES-256-GCM vault with Argon2id key derivation |
| Complex multi-day setup | Build from source now; prebuilt binaries from v0.3.0 |
| Uncontrolled bot behavior | Prompt injection guard with leet-speak normalization |
| Dedicated hardware required | Runs on any machine — laptop, VPS, Raspberry Pi |

---

## How It Works

```
You (Telegram / CLI)
        │
   ┌────▼─────┐
   │  Gateway  │  ← Central orchestrator
   └────┬──────┘
        │
  ┌─────┼──────────────┐
  │     │              │
  ▼     ▼              ▼
Router  Vault     Prompt Guard
  │   (AES-256)   (injection detection)
  │
  ├─ Economy  → Haiku 4.5   (greetings, simple Q&A)
  ├─ Standard → Sonnet 4.5  (code, summaries, analysis)
  └─ Premium  → Opus 4.6    (deep reasoning, architecture)
```

Every message goes through three steps:

1. **Prompt Guard** scans for injection attacks, invisible characters, token manipulation, and data exfiltration patterns. Leet-speak normalization catches bypass attempts like `1gn0r3 pr3v10us 1nstruct10ns`.

2. **Smart Router** decides which model to use. First, it checks embeddings (Voyage AI cosine similarity against tier centroids). If confidence is high enough, the embedding winner is used. Otherwise, a rule-based fallback scores task type, code presence, math, constraints, and conversation depth.

3. **Prompt Caching** structures every request with a stable prefix (system prompt + oldest messages) and dynamic tail (recent messages), so Anthropic's cache can serve repeat context at 90% discount.

---

## Quickstart

### Prerequisites

- Rust toolchain ([rustup.rs](https://rustup.rs))
- An Anthropic API key (`sk-ant-...`)
- Optional: Telegram bot token (from [@BotFather](https://t.me/BotFather))
- Optional: Voyage AI key (for embedding-based routing)

### Option A: Prebuilt Binary (coming in v0.3.0)

Prebuilt binaries for macOS and Linux will be available on [GitHub Releases](https://github.com/umitbora55/safeagent/releases) starting with v0.3.0.

### Option B: Build from Source (current)

Requires Rust toolchain ([rustup.rs](https://rustup.rs)).

```bash
git clone https://github.com/umitbora55/safeagent.git
cd safeagent
cargo build --release
./target/release/safeagent
```

On first run, SafeAgent walks you through setup interactively (a dedicated `safeagent init` wizard is planned for v0.3.0):

1. Ask for a vault password (encrypts all stored credentials)
2. Prompt for your Anthropic API key (stored encrypted, never in plain text)
3. Optionally ask for Telegram bot token and chat ID
4. Optionally ask for Voyage AI key (enables smart embedding routing)

```
  🛡️  SafeAgent v0.1.0
  Secure AI Assistant
  ─────────────────────

  🔐 Vault şifresi: ********
  🤖 Anthropic API key: sk-ant-...  ✅ Stored
  📱 Telegram bot token (Enter to skip): ...
  🧭 Embedding centroids loaded (3x1024)
  ✅ All systems ready

  💬 CLI active — type a message (or /help, /quit)
```

---

## Features

### Smart Cost Routing

The router uses a hybrid approach: embedding similarity (when available) combined with rule-based feature extraction.

**Embedding routing:** Each message is embedded via Voyage AI (`voyage-3-large`, 1024 dimensions) and compared to three tier centroids built from a 1050-prompt reference dataset. The tier with the highest cosine similarity wins — if the margin between top-1 and top-2 exceeds the confidence threshold.

**How centroids were built:** 1050 prompts (350 per tier) were sourced from RouterArena, HelpSteer2, and routellm/gpt4_dataset, labeled by difficulty. Each prompt was embedded via `voyage-3-large`. The centroid for each tier is the element-wise mean of its 350 embeddings, stored in `crates/llm-router/centroids.json` (3x1024 float vectors). Regeneration script will ship in `bench/generate_centroids.py` with v0.3.0.

**Rule-based fallback:** When embeddings are unavailable or confidence is low, the router scores 8 signals: task type, code presence, math/logic, constraint count, word count, conversation depth, system prompt complexity, and vision/tool requirements.

**Cache-aware routing:** The router considers prompt caching opportunity cost. If a cheaper model would fall below the cache token threshold (wasting a previously seeded cache), it may prefer the model with active cache affinity.

```
  ┌───────────────────────────────────────────────────────────────────────────────────────────────┐
  │ SAFEAGENT EXECUTIVE CACHE DASHBOARD                                                           │
  │ LIVE MODEL ROUTING + CACHE OPERATIONS                                                         │
  │ ─────────────────────────────────────────────────────────────────────────────────────────────── │
  │ MODEL PIPELINE      claude-haiku-4-5-20251001 -> claude-sonnet-4-5-20250929                   │
  │ STATUS              [ HIT+WRITE       ] ● serving from cache and refreshing seed              │
  │ ROUTING CODE        CACHE_BOOTSTRAP    detail: upgraded model to seed cache                   │
  │ CACHE READ            1847 tok ( 72%) [██████████████████████········]                        │
  │ CACHE WRITE            512 tok ( 20%) [██████························]                        │
  │ CACHE EFFICIENCY     67% [████████████████████··········]                                     │
  │ CACHE ELIGIBILITY   [PASS]  total_in   2563 | min   1024 | delta +1539                       │
  └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Encrypted Credential Vault

All API keys and tokens are encrypted with AES-256-GCM. The encryption key is derived from your vault password via Argon2id (memory-hard, brute-force resistant). Credentials are stored in a local SQLite database — nothing is ever sent anywhere.

- Sensitive values auto-zeroized in memory after use (`zeroize` crate)
- Credential metadata (key, label, provider, timestamps) queryable without decryption
- Vault locks on shutdown; requires password to unlock

### Prompt Injection Guard

Multi-layer defense against prompt injection:

- **Pattern matching** with normalized input (catches leet-speak variants)
- **Token manipulation detection** (strips `<|im_start|>`, `<|endoftext|>`, etc.)
- **Invisible character detection** (zero-width spaces, direction overrides)
- **Marker spoofing prevention** (nonce-based safety boundaries)
- **Data exfiltration detection** on untrusted content (email forwarding, URL commands)
- **Risk scoring** with per-category caps (injection: 0.6, manipulation: 0.3, exfil: 0.25)

Messages scoring above 0.5 risk are blocked automatically.

### Conversation Memory

SQLite-backed persistent memory with two components:

- **Message history:** Full conversation stored per chat. Gateway retrieves oldest 12 + newest 8 messages (deduped) to maintain context while keeping the stable cache prefix intact.
- **User facts:** Key-value store for persistent facts about the user, injected into every system prompt.

**Managing memory:**

| Action | How |
|--------|-----|
| View stored facts | Facts are shown in debug logs (`RUST_LOG=safeagent=debug`) |
| Clear all history | Delete `memory.db` from the data directory and restart |
| Clear facts only | Delete `memory.db` (facts and history share the same database; granular deletion coming in v0.3.0) |
| Prevent storage | Delete `memory.db` after each session (no-persist mode planned for v0.3.0) |

> **Privacy reminder:** User facts are included in the system prompt and sent to the Anthropic API on every request. See [Data & Privacy](#data--privacy) for details.

### Platform Bridges

Currently supported:

- **Telegram** — Long-polling bridge with typing indicators, Markdown-to-plain fallback, chat ID allowlist
- **CLI** — Interactive terminal with `/help`, `/stats`, `/mode` commands

Both bridges feed into a central message channel and share the same vault, memory, and router.

---

## Architecture

```
safeagent/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── gateway/                  # Core orchestrator + CLI + main binary
│   │   └── src/main.rs           # Entry point, routing loop, cache affinity
│   ├── bridges/
│   │   ├── common/               # Shared types: Platform, MessageId, Bridge trait
│   │   └── telegram/             # Telegram long-polling bridge
│   ├── llm-router/               # Hybrid routing engine + embedding + feature extraction
│   │   ├── src/lib.rs            # Router, centroids, task classification
│   │   ├── centroids.json        # 3x1024 tier centroids (economy/standard/premium)
│   │   └── training_data.json    # 1050 reference prompts (350 per tier)
│   ├── credential-vault/         # AES-256-GCM + Argon2id encrypted storage
│   ├── memory/                   # SQLite message history + user facts
│   ├── policy-engine/            # Rate limiting, content filtering, spend tracking
│   └── prompt-guard/             # Injection detection, risk scoring, nonce markers
```

### Crate Dependency Graph

```
gateway
  ├── bridge-common
  ├── bridge-telegram → bridge-common
  ├── llm-router
  ├── credential-vault → llm-router (SecretResolver trait)
  ├── memory → bridge-common
  ├── policy-engine → bridge-common
  └── prompt-guard
```

### Models (pricing as of February 2026 — verify at [anthropic.com/pricing](https://www.anthropic.com/pricing))

| ID | Model | Tier | Input (per 1K tokens) | Output (per 1K tokens) |
|----|-------|------|-----------------------|------------------------|
| `haiku` | claude-haiku-4-5-20251001 | Economy | $0.0008 | $0.0032 |
| `sonnet` | claude-sonnet-4-5-20250929 | Standard | $0.003 | $0.015 |
| `opus` | claude-opus-4-6 | Premium | $0.015 | $0.075 |

### Routing Modes

| Mode | Behavior | CLI Command |
|------|----------|-------------|
| **Balanced** (default) | Hybrid embedding + rule-based routing | `/mode balanced` |
| **Economy** | Always routes to cheapest model | `/mode economy` |
| **Performance** | Always routes to most capable model | `/mode performance` |

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/stats` | Display request count, token usage, total cost |
| `/mode economy` | Switch to economy routing |
| `/mode balanced` | Switch to balanced routing (default) |
| `/mode performance` | Switch to performance routing |
| `/quit` | Exit SafeAgent |

---

## Configuration

SafeAgent stores data in OS-appropriate directories:

| OS | Location |
|----|----------|
| macOS | `~/Library/Application Support/dev.safeagent.SafeAgent/` |
| Linux | `~/.local/share/SafeAgent/` |
| Fallback | `./.safeagent/` |

Files stored:

| File | Purpose |
|------|---------|
| `vault.db` | Encrypted credentials (AES-256-GCM) |
| `memory.db` | Conversation history + user facts |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `safeagent=info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `SAFEAGENT_THEME` | `dark` | Terminal color theme (`dark`, `light`, `soft`) |
| `NO_COLOR` | — | Disable ANSI colors entirely |

---

## Benchmarks

Cost savings and cache efficiency claims are based on the following methodology. You can reproduce these with your own prompts.

### How we measure

1. **Baseline:** Route all messages to Sonnet 4.5 (single-model, no routing).
2. **SafeAgent:** Same messages through balanced routing (embedding + rule-based) with prompt caching.
3. **Compare:** Total cost, cache hit rate, per-message breakdown.

### Example session (20 mixed messages: greetings, Q&A, code, analysis)

```
Baseline (all-Sonnet):    $0.0842
SafeAgent (balanced):     $0.0491
─────────────────────────
Savings:                  41.7%
Cache hit rate:           34% of input tokens served from cache
Messages routed Economy:  9/20 (greetings, simple Q&A)
Messages routed Standard: 8/20 (code, summaries)
Messages routed Premium:  3/20 (architecture, proofs)
```

**To reproduce:**

```bash
# Quick: run interactively and check /stats after ~20 messages
RUST_LOG=safeagent=debug ./target/release/safeagent

# Scripted: use the benchmark prompt set (coming in v0.3.0)
# cargo run --bin safeagent-bench -- --prompts bench/mixed_20.jsonl --baseline sonnet
```

**Currently included in `bench/`:**
- `mixed_20.jsonl` — 20 prompts (greetings, Q&A, code, analysis) with expected tier labels

**Coming in v0.3.0:**
- `bench.sh` — automated runner: baseline (all-Sonnet) vs SafeAgent (balanced), outputs cost comparison
- `METHODOLOGY.md` — scoring rubric, seed, environment requirements for reproducibility

**Important caveats:**

- Savings depend heavily on your prompt mix. Chat-heavy workloads (lots of greetings, simple questions) save more. All-complex-code workloads save less.
- Cache efficiency improves over a conversation as the stable prefix grows.
- "90% cache discount" refers to Anthropic's prompt caching pricing (cached input tokens cost ~10% of base price). This is Anthropic's pricing, not a SafeAgent claim.
- The 1050-prompt reference dataset (350 per tier) is sourced from RouterArena, HelpSteer2, and routellm/gpt4_dataset. See `crates/llm-router/training_data.json`.

---

## Data & Privacy

SafeAgent stores two local databases. Nothing is sent anywhere except LLM API calls.

| File | Contents | Encrypted? | Notes |
|------|----------|-----------|-------|
| `vault.db` | API keys, bot tokens, credentials | **Yes** — AES-256-GCM, Argon2id KDF | Locked on shutdown, requires password to unlock |
| `memory.db` | Conversation history, user facts | **No** — plaintext SQLite | See privacy notes below |

### Privacy notes for `memory.db`

- **Not encrypted by default.** Your conversation history is stored in plaintext SQLite. For sensitive workloads on shared machines, use full-disk encryption or place SafeAgent's data directory on an encrypted volume.
- **User facts are sent to the LLM.** Facts stored in `memory.db` (key-value pairs like "name: Alice") are injected into the system prompt on every request. This means they are sent to the Anthropic API. Do not store sensitive personal data as user facts.
- **Retention:** Currently no automatic deletion. You can delete `memory.db` at any time to clear all history.
- **No-persist mode:** Not yet available (planned for Phase 3B). For now, deleting the file between sessions achieves the same effect.
- **No telemetry, no analytics, no phone-home.** SafeAgent never sends usage data anywhere. Logs are local only.

### What gets sent to external APIs

| API | What is sent | When |
|-----|-------------|------|
| Anthropic Messages API | System prompt (includes user facts from memory.db) + conversation history + user message | Every message |
| Voyage AI Embeddings API | User message text only (no history) | Every message (if Voyage key configured) |
| Telegram Bot API | Response text + chat ID | When responding to Telegram messages |

---

## Troubleshooting

### Common issues

**"Vault password" — I forgot it**
Delete `vault.db` from the data directory and restart. You'll need to re-enter all API keys.

**Telegram bot not responding**
- Verify your bot token with `curl https://api.telegram.org/bot<TOKEN>/getMe`
- Make sure you entered the correct chat ID (send a message to the bot, check logs for `Ignoring chat: <id>`)
- Only chat IDs in the allowlist receive responses

**"Embedding: unavailable" in logs**
Voyage AI key not configured. Routing falls back to rule-based only. This works fine — embeddings improve accuracy but aren't required.

**Cache status shows "BELOW_THRESHOLD"**
Your conversation is too short for Anthropic's prompt caching to activate. The minimum varies by model (~1024 tokens for most). As the conversation grows, caching kicks in automatically.

**Cache status shows "MISS" repeatedly**
The stable prefix (system prompt + oldest messages) may be changing between requests. Check if facts or system prompt are being modified. Use `RUST_LOG=safeagent=debug` to see prefix fingerprints.

**High cost despite routing**
Check `/stats` to see which models are being used. If most messages go to Premium, your prompt mix may be triggering complex classification. Try `/mode economy` to force cheap routing, or adjust your message style.

---

```bash
# Run all workspace tests
cargo test --workspace

# Run specific crate tests
cargo test -p safeagent-llm-router      # 24 routing tests
cargo test -p safeagent-prompt-guard     # 14 injection detection tests
cargo test -p safeagent-credential-vault # 14 vault encryption tests
cargo test -p safeagent-policy-engine    # 10 policy/rate limit tests
cargo test -p safeagent-memory           # 9 memory store tests
```

Test coverage includes: tier routing accuracy, embedding confidence thresholds, task classification (Turkish + English), code/math detection, constraint counting, circuit breaker behavior, concurrent usage safety, prompt injection patterns (leet-speak, newlines, token manipulation, marker spoofing), vault encrypt/decrypt cycles, and policy rate limiting.

---

## Security Model

### Threat Model

| Attacker | Assumption | Protected? |
|----------|-----------|------------|
| **Someone with disk access** (stolen laptop, shared server) | Can read files but doesn't know vault password | **Yes** — vault.db encrypted, API keys never in plaintext on disk |
| **Malicious prompt content** (injected via external data or crafty user) | Tries to override system prompt or exfiltrate data | **Yes** — prompt guard with pattern matching, risk scoring, nonce boundaries |
| **Network observer** | Can see traffic metadata | **Partial** — all API calls over TLS; but traffic patterns reveal usage |
| **Someone with root/admin access** | Full OS control, can read process memory | **No** — out of scope |
| **Physical access** (cold boot, hardware keylogger) | Direct machine access | **No** — out of scope |
| **Compromised LLM provider** | API returns malicious content | **Partial** — prompt guard scans external content, but cannot detect all semantic attacks |

### What SafeAgent protects against

- **Credential theft from disk:** All API keys encrypted at rest (AES-256-GCM, Argon2id KDF)
- **Prompt injection:** Multi-pattern detection with leet-speak normalization and risk scoring
- **Accidental key exposure:** Credentials never logged, zeroized in memory after use
- **Token manipulation:** Special tokens (`<|im_start|>`, etc.) stripped from all input
- **Boundary spoofing:** Nonce-based safety markers prevent untrusted content from breaking trust boundaries

### What is out of scope

- Memory-resident attacks (attacker with process memory access)
- Root-level compromise (attacker controls OS)
- Physical access to the machine
- Network-level MITM (relies on TLS)

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full product roadmap.

**Current focus (v0.3.0):**

- **Phase 3A:** `safeagent init` setup wizard, example configs, troubleshooting docs
- **Phase 3B:** Per-message cost tracking, spending limits, model fallback, audit logging
- **Phase 3C:** Bridge abstraction framework, Discord bridge

**What's built (v0.1.0):**

- 8 crates, all tests passing (`cargo test --workspace`)
- Hybrid embedding + rule-based routing
- AES-256 vault with Argon2id
- Prompt injection guard (14 tests)
- Telegram bridge with typing indicators
- Prompt caching with cache affinity tracking
- CLI with real-time cache diagnostics dashboard

---

## Contributing

Contributions welcome. Please open an issue before starting work on larger changes.

```bash
# Development setup
git clone https://github.com/umitbora55/safeagent.git
cd safeagent
cargo build --workspace
cargo test --workspace
```

---

## Security

If you discover a security vulnerability, please report it responsibly:

- **Email:** umitbora94@proton.me
- **GitHub:** Use [Security Advisories](https://github.com/umitbora55/safeagent/security/advisories/new) to report privately
- **Response SLA:** Acknowledgment within 48 hours, fix target within 7 days for critical issues
- **Scope:** Vault encryption, prompt injection bypass, credential exposure, dependency vulnerabilities

Please do **not** open public GitHub issues for security vulnerabilities.

A full `SECURITY.md` with GPG fingerprint and supported versions will ship with v0.3.0.

---

## License

MIT OR Apache-2.0 (your choice)
