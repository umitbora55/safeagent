# GAPS_VS_TARGET.md — Hedef Mimari vs Mevcut Durum Karşılaştırması

> FAZ 0 Read-Only Analiz | Tarih: 2026-02-24

---

## Hedef Mimari

Kullanıcı tarafından belirtilen hedef:

> **Policy-before-tool + capability token + audit+otel + supervisor**

Bu dört temel bileşen açılımı:

| Bileşen | Açıklama |
|---------|----------|
| **Policy-before-tool** | Her tool çağrısından önce policy engine kontrolü |
| **Capability token** | Her işlem için kısa ömürlü, kapsamı dar izin token'ı |
| **Audit + OTel** | Tüm işlemlerin loglanması + OpenTelemetry distributed tracing |
| **Supervisor** | Tehlikeli işlemleri onaylayan insan-in-the-loop mekanizması |

---

## Gap Matrisi

| # | Hedef | Mevcut Durum | Gap Seviyesi | Evidence |
|---|-------|--------------|--------------|----------|
| G1 | Policy-before-tool | Partial | MEDIUM | policy-engine var ama tool call flow'da explicit değil |
| G2 | Capability tokens | Missing | HIGH | Token sistemi yok |
| G3 | Audit logging | Implemented | LOW | audit-log crate çalışıyor |
| G4 | OpenTelemetry | Missing | HIGH | Sadece tracing crate, OTel yok |
| G5 | Supervisor (HITL) | Partial | MEDIUM | Yellow/Red decision var ama UI/approval flow eksik |

---

## Detaylı Gap Analizi

---

### G1: Policy-before-tool

**Hedef:** Her skill/tool çağrısından önce policy engine kontrolü yapılmalı.

**Mevcut Durum:** PARTIAL

#### Evidence

```rust
// policy-engine/src/lib.rs:85-120
pub enum ActionType {
    // Green (auto-allow)
    ReadCalendar, ReadWeather, SearchWeb, SummarizeContent,
    // Yellow (notify)
    DraftEmail, AddCalendarEvent, CreateReminder, ReadEmail,
    // Red (require approval)
    SendEmail, SendMessage, DeleteFile, DeleteEmail,
    MakePurchase, RunShellCommand,
}

pub fn check_action(&self, action: &ActionType) -> PolicyDecision {
    match action.level() {
        PermissionLevel::Green => PolicyDecision::Allow,
        PermissionLevel::Yellow => PolicyDecision::AllowWithNotification(..),
        PermissionLevel::Red => PolicyDecision::RequireApproval(..),
    }
}
```

#### Var Olanlar ✓

- ActionType enum tanımlı (Green/Yellow/Red)
- PolicyDecision enum tanımlı
- `check_action()` fonksiyonu mevcut
- Budget kontrolü (`check_budget()`) mevcut

#### Eksikler ✗

1. **Tool call interception yok**
   - `crates/skills/src/lib.rs` → `execute()` öncesi policy check yok
   - Gateway'de skill çağrısı policy engine'e danışmıyor

   ```rust
   // EKSIK: skills/src/lib.rs'de olması gereken
   pub async fn execute_with_policy(
       &self,
       skill: &dyn Skill,
       input: Value,
       policy: &PolicyEngine,
   ) -> Result<Value> {
       let action = action_for_skill(skill.id());
       match policy.check_action(&action) {
           PolicyDecision::Allow => skill.execute(input).await,
           PolicyDecision::Deny(reason) => Err(PolicyDenied(reason)),
           PolicyDecision::RequireApproval(reason) => {
               // Supervisor flow...
           }
       }
   }
   ```

2. **Skill → ActionType mapping eksik**
   - `action_for_skill()` fonksiyonu yok veya kapsamı dar

3. **Runtime policy updates yok**
   - Policy config startup'ta yükleniyor, runtime değişiklik yok

#### Gap Kapatma Tahmini

| Task | Effort |
|------|--------|
| Skill execute wrapper | 2-3 saat |
| Skill → ActionType mapping | 1-2 saat |
| Integration tests | 2-3 saat |
| **Toplam** | ~1 gün |

---

### G2: Capability Tokens

**Hedef:** Her işlem için kısa ömürlü, dar kapsamlı izin token'ı.

**Mevcut Durum:** MISSING

#### Evidence

```bash
# Token ile ilgili arama
grep -r "capability" crates/
grep -r "CapabilityToken" crates/
grep -r "token.*expir" crates/
# → Sonuç: Yok
```

#### Mevcut Alternatif

```rust
// multi-user/src/lib.rs:80-100
pub fn can_use_skill(&self, user_id: &str, skill_id: &str) -> bool {
    // Static role-based check, token yok
    if let Some(user) = self.get_user(user_id) {
        if !user.active { return false; }
        match user.role {
            UserRole::Admin => true,
            UserRole::Standard => !WRITE_SKILLS.contains(&skill_id),
            UserRole::ReadOnly => READ_SKILLS.contains(&skill_id),
        }
    } else {
        false
    }
}
```

#### Eksikler ✗

1. **Token generation yok**
   - Request başına unique token üretilmiyor
   - Token'da scope/permissions yok

2. **Token expiration yok**
   - TTL yok
   - Revocation mekanizması yok

3. **Token verification yok**
   - Tool çağrısında token kontrolü yok

4. **Audit trail'de token ID yok**
   - Hangi token'la hangi işlem yapıldı izlenemiyor

#### Hedef Mimari Önerisi

```rust
// Önerilen yapı
pub struct CapabilityToken {
    pub id: Uuid,
    pub user_id: String,
    pub session_id: String,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<u32>,
    pub use_count: AtomicU32,
}

impl CapabilityToken {
    pub fn new(user_id: &str, permissions: Vec<Permission>, ttl: Duration) -> Self { }
    pub fn is_valid(&self) -> bool { }
    pub fn has_permission(&self, p: &Permission) -> bool { }
    pub fn consume(&self) -> Result<()> { }
}

// Token service
pub struct TokenService {
    tokens: DashMap<Uuid, CapabilityToken>,
}

impl TokenService {
    pub fn issue(&self, user_id: &str, scope: Vec<Permission>) -> CapabilityToken { }
    pub fn verify(&self, token_id: Uuid, required: &Permission) -> Result<()> { }
    pub fn revoke(&self, token_id: Uuid) { }
    pub fn revoke_user(&self, user_id: &str) { }
}
```

#### Gap Kapatma Tahmini

| Task | Effort |
|------|--------|
| CapabilityToken struct | 2-3 saat |
| TokenService (issue/verify/revoke) | 4-5 saat |
| Integration with skills | 3-4 saat |
| Audit log token tracking | 2-3 saat |
| Tests | 3-4 saat |
| **Toplam** | ~2-3 gün |

---

### G3: Audit + Logging

**Hedef:** Tüm işlemlerin loglanması.

**Mevcut Durum:** IMPLEMENTED

#### Evidence

```rust
// audit-log/src/lib.rs:20-50
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub model_name: String,
    pub tier: String,
    pub platform: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cost_microdollars: u64,
    pub cache_status: String,
    pub latency_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: String,
}

impl AuditLog {
    pub fn record(&self, entry: &AuditEntry) -> Result<()> { }
    pub fn recent_entries(&self, limit: usize) -> Result<Vec<AuditEntry>> { }
    pub fn prune(&self) -> Result<usize> { }
}
```

#### Var Olanlar ✓

- `AuditLog` crate çalışıyor
- SQLite persistence
- Secret redaction
- Retention-based pruning
- Integration test: `integ_audit_record_and_query` ✓

#### Eksikler ✗

1. **Skill/tool execution audit yok**
   - Sadece LLM request'leri loglanıyor
   - Tool çağrıları (web_search, file_read, shell) loglanmıyor

2. **User action audit yok**
   - Login/logout
   - Permission changes
   - Config changes

3. **Structured metadata**
   - `metadata: String` → JSON blob
   - Queryable fields eksik

#### Gap Kapatma Tahmini

| Task | Effort |
|------|--------|
| Tool execution audit | 2-3 saat |
| User action audit | 2-3 saat |
| Structured metadata | 1-2 saat |
| **Toplam** | ~1 gün |

---

### G4: OpenTelemetry

**Hedef:** Distributed tracing via OpenTelemetry.

**Mevcut Durum:** MISSING

#### Evidence

```toml
# Cargo.toml (root):17-25
[workspace.dependencies]
tracing = "0.1"
tracing-subscriber = "0.3"
# opentelemetry = YOK
# opentelemetry-otlp = YOK
# tracing-opentelemetry = YOK
```

```rust
// gateway/src/main.rs:30-40
use tracing::{info, warn, error, debug};
use tracing_subscriber::fmt;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter("safeagent=debug")
        .init();
}
```

#### Var Olanlar ✓

- `tracing` crate kullanılıyor
- Structured logging var (info!, warn!, error!)

#### Eksikler ✗

1. **OpenTelemetry integration yok**
   - No trace context propagation
   - No span exporting
   - No OTLP endpoint config

2. **Distributed tracing yok**
   - Multi-service correlation impossible
   - Request flow tracking limited

3. **Metrics export yok**
   - Prometheus/OTLP metrics yok

#### Hedef Mimari Önerisi

```rust
// Önerilen yapı
use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use tracing_opentelemetry::OpenTelemetryLayer;

fn init_telemetry(otlp_endpoint: &str) -> Result<()> {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint)
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    let telemetry = OpenTelemetryLayer::new(tracer);

    tracing_subscriber::registry()
        .with(telemetry)
        .with(fmt::layer())
        .init();

    Ok(())
}

// Usage in code
#[tracing::instrument(skip(request))]
async fn handle_message(request: &Request) -> Response {
    // Automatic span creation
}
```

#### Gap Kapatma Tahmini

| Task | Effort |
|------|--------|
| OpenTelemetry setup | 3-4 saat |
| Span instrumentation | 4-5 saat |
| Metrics export | 2-3 saat |
| Config (OTLP endpoint) | 1-2 saat |
| Tests | 2-3 saat |
| **Toplam** | ~2 gün |

---

### G5: Supervisor (Human-in-the-Loop)

**Hedef:** Tehlikeli işlemleri onaylayan insan mekanizması.

**Mevcut Durum:** PARTIAL

#### Evidence

```rust
// policy-engine/src/lib.rs:65-75
pub enum PolicyDecision {
    Allow,
    AllowWithNotification(String),
    RequireApproval(String),  // <-- Supervisor trigger
    Deny(String),
}
```

```rust
// gateway/src/main.rs - EKSIK
// RequireApproval sonrası ne olacağı implementasyonu yok
```

#### Var Olanlar ✓

- `PolicyDecision::RequireApproval` enum variant'ı var
- Red actions tanımlı (SendEmail, RunShellCommand, etc.)

#### Eksikler ✗

1. **Approval UI yok**
   - CLI'da approval prompt yok
   - Web UI'da approval modal yok
   - Telegram'da inline keyboard yok

2. **Approval persistence yok**
   - Approved decisions kaydedilmiyor
   - "Always allow for this session" yok

3. **Approval timeout yok**
   - Kullanıcı cevap vermezse ne olacak?

4. **Async approval yok**
   - "Approve via email/SMS" yok
   - Background approval queue yok

5. **Approval audit yok**
   - Kim neyi ne zaman onayladı?

#### Hedef Mimari Önerisi

```rust
// Önerilen yapı
pub struct ApprovalRequest {
    pub id: Uuid,
    pub action: ActionType,
    pub skill_id: String,
    pub input_summary: String,
    pub risk_reason: String,
    pub requested_at: DateTime<Utc>,
    pub timeout: Duration,
}

pub enum ApprovalResponse {
    Approved { by: String, at: DateTime<Utc> },
    Denied { by: String, reason: String },
    Timeout,
}

pub trait Supervisor: Send + Sync {
    async fn request_approval(&self, req: ApprovalRequest) -> ApprovalResponse;
}

// CLI implementation
pub struct CliSupervisor;
impl Supervisor for CliSupervisor {
    async fn request_approval(&self, req: ApprovalRequest) -> ApprovalResponse {
        println!("⚠️  APPROVAL REQUIRED");
        println!("Action: {:?}", req.action);
        println!("Reason: {}", req.risk_reason);
        print!("Approve? [y/N]: ");
        // Read stdin...
    }
}

// Telegram implementation
pub struct TelegramSupervisor { bot: Bot }
impl Supervisor for TelegramSupervisor {
    async fn request_approval(&self, req: ApprovalRequest) -> ApprovalResponse {
        // Send message with inline keyboard
        // Wait for callback query
    }
}
```

#### Gap Kapatma Tahmini

| Task | Effort |
|------|--------|
| Supervisor trait | 1-2 saat |
| CLI supervisor | 2-3 saat |
| Telegram supervisor | 3-4 saat |
| Approval persistence | 2-3 saat |
| Timeout handling | 1-2 saat |
| Tests | 2-3 saat |
| **Toplam** | ~2 gün |

---

## Özet Tablo

| Gap | Seviye | Mevcut | Hedef | Effort |
|-----|--------|--------|-------|--------|
| G1: Policy-before-tool | MEDIUM | Partial | Full interception | ~1 gün |
| G2: Capability tokens | HIGH | Yok | Token service | ~2-3 gün |
| G3: Audit (tool/user) | LOW | LLM only | Full coverage | ~1 gün |
| G4: OpenTelemetry | HIGH | tracing only | Full OTel | ~2 gün |
| G5: Supervisor | MEDIUM | Enum only | Full HITL | ~2 gün |
| **TOPLAM** | | | | **~8-11 gün** |

---

## Sprint 1 Önerisi

En düşük risk, en yüksek değer önceliği:

### Öncelik 1: G1 - Policy-before-tool (1 gün)

**Neden:**
- Mevcut policy-engine kullanılıyor
- Sadece wiring eksik
- Diğer gap'lerin temeli

**Minimum Invasive Adımlar:**
1. `skills/src/lib.rs`'e `execute_with_policy()` wrapper ekle
2. `gateway/src/main.rs`'de skill çağrılarını wrapper'a yönlendir
3. Integration test ekle

### Öncelik 2: G5 - Supervisor (CLI only) (1 gün)

**Neden:**
- `RequireApproval` zaten var
- CLI için basit stdin prompt yeterli
- User-facing güvenlik iyileştirmesi

### Öncelik 3: G3 - Audit genişletme (0.5 gün)

**Neden:**
- Mevcut audit-log crate çalışıyor
- Sadece yeni event types ekleme
- Kolay kazanım

---

## FAZ 0 ÖZETİ

### Tamamlanan Analiz

1. ✅ Tüm 13 crate okundu ve dokümante edildi
2. ✅ 76+ test tespit edildi
3. ✅ 10 risk kategorize edildi
4. ✅ 5 major gap belirlendi
5. ✅ CI/CD pipeline analiz edildi

### Bulgular

**Güçlü Yanlar:**
- Solid Rust codebase
- AES-256-GCM encryption (credential-vault)
- Prompt injection detection
- Multi-provider fallback
- Circuit breaker pattern
- 23 integration test

**Zayıf Yanlar:**
- `encryption.rs` weak KDF (R1)
- Capability token sistemi yok (G2)
- OpenTelemetry yok (G4)
- Supervisor UI yok (G5)
- Shell executor bypass riski (R2)

### Sonraki Adımlar

1. **Sprint 1 Planning:**
   - G1 (Policy-before-tool) implement et
   - R1 (Weak KDF) fix et
   - G5 (CLI Supervisor) implement et

2. **Sprint 2 Planning:**
   - G2 (Capability tokens)
   - G4 (OpenTelemetry)
   - R2 (Shell sandbox)

---

**FAZ 0 TAMAMLANDI**

> Bu dokümanlar read-only analiz sonucudur. Kod değişikliği yapılmamıştır.
> Sprint 1 için kullanıcı onayı beklenmektedir.
