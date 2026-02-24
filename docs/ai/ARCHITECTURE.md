# ARCHITECTURE.md — SafeAgent Mimari Dokümanı

> FAZ 0 Read-Only Analiz | Tarih: 2026-02-24

---

## 1. Genel Bakış

SafeAgent, güvenli LLM agent framework'üdür. Temel prensipler:
- **Güvenlik Katmanlı**: prompt-guard → policy-engine → skill execution
- **Maliyet Kontrollü**: cost-ledger + budget enforcement
- **Audit Trail**: Tüm işlemler loglanır, secret'lar redakte edilir
- **Multi-Provider**: Anthropic, OpenAI, Gemini fallback chain

---

## 2. Katmanlı Mimari

```
┌─────────────────────────────────────────────────────────────────────┐
│                          PRESENTATION LAYER                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │     CLI      │  │   Web UI     │  │   Desktop    │               │
│  │ (gateway)    │  │  (web-ui)    │  │  (desktop)   │               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
│         │                 │                 │                        │
│  ┌──────┴─────────────────┴─────────────────┴───────┐               │
│  │              BRIDGE LAYER (bridges/*)             │               │
│  │    ┌─────────────┐        ┌─────────────────┐    │               │
│  │    │   common    │        │    telegram     │    │               │
│  │    │  (types)    │        │   (Bot API)     │    │               │
│  │    └─────────────┘        └─────────────────┘    │               │
│  └──────────────────────────┬───────────────────────┘               │
└─────────────────────────────┼───────────────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────────────┐
│                      SECURITY LAYER                                  │
│  ┌──────────────────────────▼───────────────────────────────────┐   │
│  │                     prompt-guard                              │   │
│  │  Input Sanitization → Threat Detection → Risk Scoring         │   │
│  │  (src/lib.rs:45-180)                                          │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                              │                                       │
│  ┌──────────────────────────▼───────────────────────────────────┐   │
│  │                     policy-engine                             │   │
│  │  Permission Check → Budget Validation → Action Classification │   │
│  │  (src/lib.rs:85-250)                                          │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────────────┐
│                       CORE LAYER                                     │
│  ┌──────────────────────────▼───────────────────────────────────┐   │
│  │                      llm-router                               │   │
│  │  Task Classification → Tier Selection → Provider Routing      │   │
│  │  Circuit Breaker → Health Tracking → Fallback Chain          │   │
│  │  (src/lib.rs:200-600)                                         │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                              │                                       │
│  ┌───────────────┬──────────┴──────────┬───────────────┐           │
│  │    memory     │     cost-ledger     │   audit-log   │           │
│  │  (SQLite)     │    (microdollars)   │  (redaction)  │           │
│  └───────────────┴─────────────────────┴───────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────┼───────────────────────────────────────┐
│                     FOUNDATION LAYER                                 │
│  ┌──────────────────────────▼───────────────────────────────────┐   │
│  │                   credential-vault                            │   │
│  │  AES-256-GCM + Argon2id → Encrypted API Keys                  │   │
│  │  (src/lib.rs:80-200)                                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                       skills                                  │   │
│  │  Skill Trait → Permission System → SSRF Protection           │   │
│  │  (src/lib.rs:20-100, src/shell_executor.rs:1-262)             │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Bileşen Detayları

### 3.1 Gateway (Orkestratör)

**Kaynak:** `crates/gateway/src/main.rs:1-1471`

```rust
// Ana entry point - main.rs:50-80
#[derive(Parser)]
enum Command {
    Init,           // Vault oluştur
    Doctor,         // Sistem kontrolü
    Stats,          // Maliyet istatistikleri
    Audit,          // Audit log görüntüle
    ExportLogs,     // Log export
    Export,         // Veri export
    Pricing,        // Model fiyatları
    Run,            // Agent başlat
}
```

**Orchestration Flow:** `main.rs:800-1100`
1. Vault unlock → API key'leri decrypt et
2. Memory store init → SQLite bağlantısı
3. Policy engine init → Budget/permission kuralları
4. Prompt guard init → Sanitization patterns
5. LLM router init → Provider chain
6. Audit/cost logger init → Logging pipeline
7. Main loop → Input → Process → Output

### 3.2 Policy Engine

**Kaynak:** `crates/policy-engine/src/lib.rs:1-603`

```rust
// İzin seviyeleri - lib.rs:25-60
pub enum ActionType {
    // Green (Otomatik izin)
    ReadCalendar, ReadWeather, SearchWeb, SummarizeContent,

    // Yellow (Bildirimli izin)
    DraftEmail, AddCalendarEvent, CreateReminder, ReadEmail,

    // Red (Onay gerekli)
    SendEmail, SendMessage, DeleteFile, DeleteEmail,
    MakePurchase, RunShellCommand,
}

// Karar tipleri - lib.rs:65-75
pub enum PolicyDecision {
    Allow,
    AllowWithNotification(String),
    RequireApproval(String),
    Deny(String),
}
```

**Budget Tracking:** `lib.rs:150-200`
```rust
pub struct PolicyEngine {
    daily_spend: AtomicU64,          // Thread-safe counter
    monthly_spend: AtomicU64,
    config: PolicyConfig,
    permissions: DashMap<String, ActionType>,
}
```

### 3.3 Prompt Guard

**Kaynak:** `crates/prompt-guard/src/lib.rs:1-533`

```rust
// Threat kategorileri - lib.rs:15-25
pub enum ThreatType {
    InvisibleCharacters,    // U+200B, U+200C, etc.
    PromptInjection,        // "ignore previous instructions"
    DataExfiltration,       // Sensitive data patterns
    TokenManipulation,      // <|im_start|>, [INST]
    MarkerSpoofing,         // [SYSTEM], <tool_output>
}

// Risk scoring - lib.rs:180-220
// Category-capped: injection 0.6, invisible 0.3, exfil 0.4, token 0.5
```

**Normalization:** `lib.rs:300-350`
```rust
fn normalize(text: &str) -> String {
    // Leet-speak defeating: 1gn0r3 → ignore
    // Case normalization
    // Whitespace collapse
}
```

### 3.4 LLM Router

**Kaynak:** `crates/llm-router/src/lib.rs:1-1128`

```rust
// 3-tier model sistemi - lib.rs:30-50
pub enum ModelTier {
    Economy,    // claude-3-haiku, gpt-4o-mini
    Standard,   // claude-3-sonnet, gpt-4o
    Premium,    // claude-3-opus, o1-preview
}

// Task complexity - lib.rs:60-90
pub enum TaskComplexity {
    Simple,     // → Economy tier
    Medium,     // → Standard tier
    Complex,    // → Premium tier
}
```

**Hybrid Routing:** `lib.rs:400-600`
1. Feature extraction (word count, has_code, constraints)
2. Embedding similarity (Voyage AI centroids)
3. Rule-based override (force_model, requires_vision)
4. Health check (circuit breaker state)
5. Tier selection → Provider selection

**Circuit Breaker:** `crates/gateway/src/circuit_breaker.rs:1-155`
```rust
// State machine - circuit_breaker.rs:20-40
enum State { Closed, Open, HalfOpen }

// Thresholds - circuit_breaker.rs:50-60
const FAILURE_THRESHOLD: u32 = 5;   // 5 failures → open
const SUCCESS_THRESHOLD: u32 = 3;   // 3 successes → closed
const TIMEOUT_SECONDS: u64 = 60;    // 60s → half-open
```

### 3.5 Credential Vault

**Kaynak:** `crates/credential-vault/src/lib.rs:1-524`

```rust
// Encryption - lib.rs:80-120
// Algorithm: AES-256-GCM
// KDF: Argon2id (m=65536, t=3, p=4, 32-byte output)
// Nonce: 12-byte random per encryption

pub struct SensitiveString(String);
impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize(); // Memory'den temizle
    }
}
```

### 3.6 Skills Framework

**Kaynak:** `crates/skills/src/lib.rs:1-217`

```rust
// Skill trait - lib.rs:20-40
pub trait Skill: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn permissions(&self) -> Vec<Permission>;
    async fn execute(&self, input: Value) -> Result<Value>;
}

// Permission newtype - lib.rs:45-50
pub struct Permission(pub String);
// Örnekler: "read:web", "read:fs", "write:email"
```

**SSRF Protection:** `lib.rs:100-160`
```rust
fn is_private_ip(ip: &IpAddr) -> bool {
    // Blocked: 10.x, 192.168.x, 172.16-31.x
    // Blocked: 127.0.0.1, 169.254.x, ::1, fc/fd/fe80
}

fn validate_url(url: &str) -> Result<()> {
    // Blocked: file://, localhost
    // Blocked: 169.254.169.254 (cloud metadata)
}
```

### 3.7 Audit Log

**Kaynak:** `crates/audit-log/src/lib.rs:1-367`

```rust
// Secret redaction patterns - lib.rs:50-80
const REDACTION_PATTERNS: &[&str] = &[
    r"sk-ant-[a-zA-Z0-9\-_]+",      // Anthropic keys
    r"pa-[a-zA-Z0-9\-_]+",          // Perplexity keys
    r"\d{9,10}:[A-Za-z0-9_-]{35}",  // Telegram tokens
    r"(password|secret|token|key)=[^\s&]+",
];
```

---

## 4. Data Flow

### 4.1 Request Flow (Simplified)

```
User Input
    │
    ▼
┌─────────────────┐
│  prompt-guard   │──→ Risk Score > 0.5? ──→ BLOCK
│  (sanitize)     │
└────────┬────────┘
         │ clean_text
         ▼
┌─────────────────┐
│  policy-engine  │──→ Budget exceeded? ──→ BLOCK
│  (check)        │──→ Red action? ──→ REQUIRE_APPROVAL
└────────┬────────┘
         │ allowed
         ▼
┌─────────────────┐
│   llm-router    │──→ Circuit open? ──→ FALLBACK
│  (route)        │
└────────┬────────┘
         │ provider selected
         ▼
┌─────────────────┐
│    Provider     │──→ API Error? ──→ next provider
│  (Anthropic/    │
│   OpenAI/etc)   │
└────────┬────────┘
         │ response
         ▼
┌─────────────────┐
│  cost-ledger    │──→ Record cost
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   audit-log     │──→ Record (with redaction)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    memory       │──→ Store conversation
└────────┬────────┘
         │
         ▼
    Response to User
```

### 4.2 Control Flow Diagram

```
                              ┌─────────────┐
                              │   SIGTERM   │
                              │   SIGINT    │
                              └──────┬──────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SHUTDOWN HANDLER                         │
│  crates/gateway/src/shutdown.rs:1-110                           │
│  - Broadcast shutdown signal                                    │
│  - Wait for tasks to complete                                   │
│  - Cleanup (save timestamp, close connections)                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Threading Model

### 5.1 Concurrency Primitives

| Component | Primitive | Location |
|-----------|-----------|----------|
| PolicyEngine | `DashMap`, `AtomicU64` | `policy-engine/src/lib.rs:85-100` |
| MemoryStore | `r2d2::Pool` (10 conn) | `memory/src/lib.rs:50-70` |
| CostLedger | `r2d2::Pool` (10 conn) | `cost-ledger/src/lib.rs:45-60` |
| AuditLog | `r2d2::Pool` (10 conn) | `audit-log/src/lib.rs:40-55` |
| CredentialVault | `RwLock` | `credential-vault/src/lib.rs:70-80` |
| CircuitBreaker | `RwLock` | `circuit_breaker.rs:30-40` |

### 5.2 Async Runtime

**Kaynak:** Root `Cargo.toml:19`
```toml
tokio = { version = "1", features = ["full"] }
```

- Multi-threaded runtime (default)
- Used for: HTTP requests, file I/O, signal handling
- Main loop: `gateway/src/main.rs:900-1100`

---

## 6. Storage Layer

### 6.1 SQLite Databases

| Database | Crate | Tables | Location |
|----------|-------|--------|----------|
| Memory | memory | `messages`, `facts` | `~/.safeagent/memory.db` |
| Cost | cost-ledger | `cost_entries` | `~/.safeagent/costs.db` |
| Audit | audit-log | `audit_entries` | `~/.safeagent/audit.db` |
| Vault | credential-vault | `credentials` | `~/.safeagent/vault.db` |
| MultiUser | multi-user | `users` | `~/.safeagent/users.db` |

### 6.2 Connection Pooling

**Kaynak:** `memory/src/lib.rs:60-75`
```rust
let manager = SqliteConnectionManager::file(&db_path);
let pool = r2d2::Pool::builder()
    .max_size(10)  // 10 concurrent connections
    .build(manager)?;
```

---

## 7. External Dependencies

### 7.1 Cryptography
- `aes-gcm = "0.10"` — AES-256-GCM encryption
- `argon2 = "0.5"` — Password hashing (KDF)

### 7.2 Database
- `rusqlite = "0.31"` — SQLite bindings
- `r2d2_sqlite = "0.24"` — Connection pooling

### 7.3 HTTP
- `reqwest = "0.12"` — HTTP client (rustls-tls)

### 7.4 Serialization
- `serde = "1"` + `serde_json = "1"` — JSON
- `toml = "0.8"` — Config files

---

**Sonraki Doküman:** → `CRITICAL_FLOWS.md`
