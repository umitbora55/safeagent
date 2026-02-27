# PROJECT_MAP.md — SafeAgent Crate Listesi

> FAZ 0 Read-Only Analiz | Tarih: 2026-02-24

---

## Workspace Yapısı

**Kaynak:** `Cargo.toml:1-35`

```toml
[workspace]
members = [
    "crates/gateway",
    "crates/bridges/common",
    "crates/bridges/telegram",
    "crates/policy-engine",
    "crates/prompt-guard",
    "crates/llm-router",
    "crates/credential-vault",
    "crates/memory",
    "crates/cost-ledger",
    "crates/audit-log",
    "crates/skills",
    "crates/web-ui",
    "crates/multi-user",
    "crates/desktop",
]
```

---

## Crate Listesi (13 Crate)

| # | Crate | Amaç | Kaynak |
|---|-------|------|--------|
| 1 | **gateway** | Ana CLI binary (safeagent). Tüm crate'leri orkestra eder: vault unlock → memory → policy → guard → LLM routing → audit/cost logging. | `crates/gateway/Cargo.toml:1-8`, `src/main.rs:1-1471` |
| 2 | **bridges/common** | Platform-agnostic veri tipleri: `MessageId`, `ChatId`, `UserId`, `Role`, `Platform`, `MessageEntry`. Tüm bridge'ler bu tipleri kullanır. | `crates/bridges/common/Cargo.toml:1-11`, `src/lib.rs:1-85` |
| 3 | **bridges/telegram** | Telegram Bot API entegrasyonu. Long-polling ile mesaj alır, gateway'e iletir, yanıtı geri gönderir. | `crates/bridges/telegram/Cargo.toml:1-17`, `src/lib.rs:1-282` |
| 4 | **policy-engine** | İzin sistemi (Green/Yellow/Red) + bütçe kontrolü. ActionType → PolicyDecision dönüşümü. Thread-safe DashMap/AtomicU64. | `crates/policy-engine/Cargo.toml:1-14`, `src/lib.rs:1-603` |
| 5 | **prompt-guard** | Prompt injection tespiti + sanitizasyon. ThreatType'lar: InvisibleChars, PromptInjection, DataExfiltration, TokenManipulation, MarkerSpoofing. | `crates/prompt-guard/Cargo.toml:1-13`, `src/lib.rs:1-533` |
| 6 | **llm-router** | 3-tier akıllı yönlendirme (Economy/Standard/Premium). Embedding + rule-based hybrid. Circuit breaker + health tracking. | `crates/llm-router/Cargo.toml:1-18`, `src/lib.rs:1-1128` |
| 7 | **credential-vault** | AES-256-GCM şifreleme + Argon2id KDF. API anahtarlarını güvenli saklar. SensitiveString + Zeroize. | `crates/credential-vault/Cargo.toml:1-17`, `src/lib.rs:1-524` |
| 8 | **memory** | SQLite-backed conversation history + fact storage. r2d2 connection pool (10 concurrent). | `crates/memory/Cargo.toml:1-16`, `src/lib.rs:1-367` |
| 9 | **cost-ledger** | LLM request maliyetlerini microdollar cinsinden izler. Günlük/haftalık/aylık özet + model bazlı breakdown. | `crates/cost-ledger/Cargo.toml:1-15`, `src/lib.rs:1-394` |
| 10 | **audit-log** | Tüm LLM request'lerini loglar. Secret redaction (sk-ant-*, token=*, vb.). Retention-based pruning. | `crates/audit-log/Cargo.toml:1-15`, `src/lib.rs:1-367` |
| 11 | **skills** | Extensible tool framework. Skill trait + Permission newtype. SSRF koruması (private IP blocking). | `crates/skills/Cargo.toml:1-16`, `src/lib.rs:1-217` |
| 12 | **web-ui** | React + TypeScript web arayüzü. Vite build. Chat interface + settings panel. | `crates/web-ui/package.json`, `src/App.tsx:1-178` |
| 13 | **multi-user** | Çoklu kullanıcı yönetimi. UserRole (Admin/Standard/ReadOnly). Skill erişim kontrolü. | `crates/multi-user/Cargo.toml:1-14`, `src/lib.rs:1-267` |
| 14 | **desktop** | Tauri-based masaüstü uygulaması (Windows/macOS/Linux). gateway crate'i wrap eder. | `crates/desktop/Cargo.toml:1-18`, `src/main.rs:1-45` |

---

## Dependency Grafiği (Basitleştirilmiş)

```
                    ┌─────────────┐
                    │   gateway   │ ← Ana orkestratör
                    └──────┬──────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│policy-engine│    │prompt-guard │    │ llm-router  │
└─────────────┘    └─────────────┘    └──────┬──────┘
                                             │
                           ┌─────────────────┼─────────────────┐
                           ▼                 ▼                 ▼
                   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
                   │cost-ledger  │   │  audit-log  │   │   memory    │
                   └─────────────┘   └─────────────┘   └─────────────┘
                                             │
                                             ▼
                                   ┌─────────────────┐
                                   │credential-vault │
                                   └─────────────────┘
                                             │
                                             ▼
                                   ┌─────────────────┐
                                   │ bridges/common  │ ← Shared types
                                   └─────────────────┘
                                             ▲
                                             │
                                   ┌─────────────────┐
                                   │bridges/telegram │
                                   └─────────────────┘
```

---

## Binary'ler

| Binary | Crate | Kaynak |
|--------|-------|--------|
| `safeagent` | gateway | `crates/gateway/Cargo.toml:6-8` |
| `eval_routing` | gateway | `crates/gateway/Cargo.toml:38-40` |
| `safeagent-desktop` | desktop | `crates/desktop/Cargo.toml:6-8` |

---

## Workspace Shared Dependencies

**Kaynak:** `Cargo.toml:17-35`

- `tokio = "1"` (full features) — async runtime
- `serde = "1"` (derive) — serialization
- `serde_json = "1"` — JSON handling
- `anyhow = "1"` — error handling
- `tracing = "0.1"` — structured logging
- `tracing-subscriber = "0.3"` — log output

---

## Verification

```bash
# Tüm crate'lerin derlendiğini doğrula
cargo build --workspace 2>&1 | tail -5

# Crate sayısını doğrula
ls -d crates/*/ crates/bridges/*/ 2>/dev/null | wc -l
# Beklenen: 14 (13 crate + bridges klasörü)
```

---

**Sonraki Doküman:** → `ARCHITECTURE.md`
