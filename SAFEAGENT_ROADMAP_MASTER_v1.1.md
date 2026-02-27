# SafeAgent — MCP Action Authorization Roadmap (Master)

**Doküman amacı:** SafeAgent MCP Action Authorization ürününün (wedge v0.1 → enterprise wedge) yol haritasını uçtan uca, uygulanabilir şekilde tanımlamak: kapsam, hedefler, fazlar, teslim kriterleri (DoD), demo planı, kalite ölçütleri, riskler, bağımlılıklar ve çıkış kriterleri.

**Hedef kitle:** Platform Engineering, Security Engineering, Compliance/Audit, ürün/engineering liderliği.

**Sürüm:** 1.1 (Revize — Architect Review sonrası)

**Durum:** Draft (iteratif yazım)

**Son güncelleme:** 2026-02-26

---

## İçindekiler

0. Executive Summary (Yönetici Özeti)
1. Ürün Tanımı ve North Star
2. Problem Tanımı ve Neden Şimdi
3. Kapsam ve Kapsam Dışı (Non-goals)
4. Terminoloji ve Spec Uyumu (MCP Transports + Authorization çizgisi)
5. Roadmap İlkeleri (Policy-before-action, Identity-first, Evidence-by-design, Deny-by-default)
6. Roadmap Özeti (W1–W4: amaç, çıktı, demo)
   - 6.1 Moat Upgrades (Ranked)
   - 6.2 Roadmap Revision v1.1 (W1–W5)
7. Faz W1 — MCP Gateway + Minimal Identity Binding + Operasyonel Baseline
   - 7.1–7.6 (mevcut)
   - 7.7 W1 v1.1 Additions (Adoption Gates)
8. Faz W2 — Delegation Token + Replay + Approval Prod + Security Hardening
   - 8.1–8.6 (mevcut)
   - 8.7 W2 v1.1 Additions (Security Hardening)
9. Faz W3 — Policy-as-code + Shadow→Enforce + Drift + Enterprise Tooling
   - 9.1–9.6 (mevcut)
   - 9.7 W3 v1.1 Additions (Enterprise Tooling)
10. Faz W4 — Tool Registry + Signed Manifests + Reputation
    - 10.1–10.6 (mevcut)
    - 10.7 (Opsiyonel) W5 — Advanced Moat Modules
11. Demo Paketi (CISO-kalibre)
    - 11.1–11.7 (mevcut)
    - 11.8 Demo F — Bypass Detection
    - 11.9 Demo G — Policy Simulation CLI
    - 11.10 Demo H — Evidence Verify
12. Pilot Planı (2–4 hafta) ve Exit Criteria
13. Operasyonel Model (Deploy modları, HA, logging, SIEM/OTel)
    - 13.1–13.8 (mevcut)
    - 13.9 Threat Model (Top 10)
14. Riskler, Mitigations, Bağımlılıklar
    - 14.1–14.4 (mevcut)
    - 14.5 Red Team Checklist (Pilot Öncesi)
15. Ekler

---

## 0. Executive Summary (Yönetici Özeti)

### Güçlü Yanlar (korunacak ve satışta öne çıkarılacak)

- **Wedge çok keskin:** "MCP Action Authorization / AI Action Control Plane" mesajı net; "Agent ne dedi?" değil "Agent ne yaptı?".
- **Enforcement-first:** policy-before-action yaklaşımı; observability-first rakiplerden ayrıştırır.
- **Evidence-by-design:** canonical evidence + tamper-evident integrity + **default redacted** ile compliance sorusu baştan kapanır.
- **Spec-aligned transport stratejisi:** stdio vs Streamable HTTP ayrımı doğru; Deprecated HTTP+SSE sadece opsiyonel.
- **Kademeli derinleşme:** W1→W4 sıralaması (Gateway→Token→Policy-as-code→Registry) adoption friction'ı minimize eder.
- **CISO-kalibre demo:** 2 dakikalık akış + 5 mini demo + reason_codes ile kanıtlanabilir değer.

### En büyük riskler (roadmap'e kilitlenecek düzeltmeler)

1) **Bypass (MCP dışı doğrudan API çağrısı) — satış blocker**
   - W1–W2'de "tam kapatma" şart değil, ama **bypass detection telemetry + korelasyon** şart:
     - "Tool credential usage" ve "MCP action stream" korelasyonu
     - Şüpheli doğrudan çağrı sinyalleri → alert (en azından görünürlük)

2) **Multi-tenant isolation belirsiz**
   - Tenant-scoped policy isolation, noisy-neighbor koruması, tenant-scoped keying açıkça tanımlanmalı (özellikle W2 token signing, W4 publisher keys).

3) **IdP entegrasyonu yüzeysel**
   - W1–W2'de minimum "OIDC + group/role claim mapping" netleştirilmeli (Okta/Entra uyumlu).
   - Approval routing (approver_group) için IdP group mapping desteği erken gelir.

4) **Tamper-evidence ölçeklenebilirliği**
   - Tek instance hash-chain yaklaşımı multi-instance'da ordering sorunu yaratır.
   - W2'de "signed batch / Merkle-style batching"e evrim planı eklenmeli (en az tasarım ve DoD).

5) **Latency budget ve rate limiting**
   - Platform ekipleri için **hard latency SLO** (örn p99 hedefi) W1'de yazılı olmalı.
   - W1'de rate limiting / action budget P0 olmalı (abuse pattern'ları).

6) **Incident response / runbook eksik**
   - SafeAgent-down, key compromise, evidence integrity failure senaryoları için runbook ve failover stratejisi eklenmeli.

7) **Moat zamanlaması**
   - Signed manifests/reputation W4'te güçlü ama geç.
   - W2/W3'te "network-effect yaratmayan ama kopyalanması zor" bir primitif eklenmeli:
     - Örn: policy simulation CLI (W3) gibi enterprise adoption moat'u
     - Cross-tenant threat signal ise sadece opsiyonel, strict privacy ile ve W5 olarak planlanmalı.

### Yüksek kaldıraçlı yükseltmeler (fazlara bağlanmış)

- **W1:** rate limiting + bypass detection telemetry + hard latency SLO
- **W1–W2:** OIDC group claims → role mapping + approval routing bağlama
- **W2:** tamper-evidence için signed batch/Merkle batching planı
- **W3:** policy simulation CLI ("deploy etseydik ne olurdu?")
- **W5 (opsiyonel):** cross-tenant anonymized threat signal (network effect)

### Rakiplerden ayrışma (1 cümlelik)

- **Generic AI Gateway:** "Prompt routing değil; **action authorization** (identity-bound + policy-enforced + evidence-backed)."
- **DLP/CASB:** "Veri çıkışını izlemek değil; **eylemi çıkışından önce durdurmak**."
- **Agent frameworks:** "Agent çalıştırmak değil; **agent'ın ne yapabileceğini yönetmek**."
- **Prompt safety:** "Ne söylendiğini filtrelemek değil; **ne yapıldığını kontrol etmek**."

---

## 1. Ürün Tanımı ve North Star

**SafeAgent MCP Action Authorization**, MCP tool çağrılarını araya girerek kontrol eden bir **AI Action Control Plane**'dir.

**North Star (tek cümle):**
SafeAgent, MCP tool çağrılarını **kimlik-temelli yetkilendirme**, **policy enforcement** ve **kanıt (evidence) kaydı** ile kontrol eder.

**Ne yapar (özet):**
- MCP trafiğini **intercept** eder (stdio wrapper veya Streamable HTTP reverse proxy).
- Her tool call'a **actor/tenant identity binding** uygular.
- **Allow / deny / approval_required** kararını action gerçekleşmeden önce verir (policy-before-action).
- (W2+) Tool call'ları **action-bound delegation token** ile doğrular (req_hash + jti/nonce) ve replay'i engeller.
- Her aşamada **tamper-evident evidence** üretir (canonical event schema + hash-chain).
- Sonuç: "Agent ne dedi?" değil, "Agent ne yaptı / neyi denedi?" kontrol edilir.

---

## 2. Problem Tanımı ve Neden Şimdi

### 2.1 Problem

Agent'lar tool kullanmaya başladığında risk prompt'tan **eyleme** taşınır:
- Kim yaptı?
- Hangi yetkiyle yaptı?
- Ne yaptı / neyi denedi?
- Kanıtı nerede?

Birçok çözüm prompt/response filtreler; fakat asıl hasar:
- veri export,
- dosya silme,
- prod değişikliği tetikleme,
- ticket/ödeme/transfer başlatma,
- credential erişimi

gibi **tool/action** tarafında oluşur.

### 2.2 Neden şimdi?

Agent ekosistemi MCP etrafında standardize olurken kurumların ihtiyacı netleşiyor:
- Tool sprawl (shadow tools) kontrol altına alınmalı.
- Approval + IAM + audit beklentileri agent dünyasına taşınmalı.
- "Observability" değil, **enforcement + evidence** birlikte gelmeli.

SafeAgent bu boşluğu "tek kontrol düzlemi" ile kapatır:
**Identity → Policy → Action → Evidence**

### 2.3 SafeAgent'in wedge farkı

SafeAgent "bir gateway daha" değildir; wedge şudur:
- **MCP Action Authorization**: tool çağrısını kimlik ve policy ile yetkilendirir,
- ve bunu **kanıt** ile bağlar.

Bu sayede:
- Agent vendor'larının üst katmanında konumlanır (vendor-agnostic control plane),
- Enterprise pilotlarda düşük sürtünmeyle başlar (W1),
- Sonra security primitive'lere evrilir (W2),
- Rollout ve platformlaşma gelir (W3–W4).

---

## 3. Kapsam ve Kapsam Dışı (Non-goals)

### 3.1 Kapsam (Bu roadmap'in kapsadığı şeyler)

Bu roadmap, SafeAgent'in **wedge (W1–W4)** aşamalarında aşağıdakileri kapsar:

**A) MCP intercept + enforcement (PEP)**
- MCP tool trafiğini araya girerek kontrol etmek:
  - stdio wrapper (subprocess + stdio intercept)
  - Streamable HTTP reverse proxy (tek MCP endpoint)
- Tool allowlist (W1) → tool directory/registry (W4)
- Input/output schema validation (W1)

**B) Identity-first binding ve delegation**
- W1: actor_id + tenant_id binding (minimum)
- W2: action-bound delegation token:
  - req_hash (canonical_input + tool_id + actor + tenant + time_bucket)
  - jti/nonce one-time + replay cache
- Approval akışı (step-up):
  - timeout + default deny
  - break-glass (time-bound + reason mandatory)

**C) Policy sistemi (enforcement + rollout)**
- W1–W2: basit policy evaluation (allow/deny/approval_required)
- W3: policy-as-code + versioning
  - shadow mode ("would-have-happened")
  - canary enforcement
  - exception workflow (TTL)

**D) Evidence / auditability**
- Canonical evidence event schema (sabit)
- Tamper-evident hash-chain
- Default redacted payload (PII minimizasyonu)
- SIEM/OTel export (JSONL/OTLP)

**E) Tool governance & supply-chain (W4)**
- Signed manifests (tool hash + publisher signature + version metadata)
- Verified publisher modeli
- Reputation score (policy sinyali olarak kullanılabilir)

### 3.2 Kapsam Dışı (Bu roadmap'in W1–W4 içinde hedeflemediği şeyler)

Aşağıdakiler bu roadmap'in dışında veya sonraki fazlara bırakılmıştır:

**1) Tam egress confinement / full endpoint enforcement**
- W1–W2'de "kontrol edilen resmi yol + telemetry" yaklaşımı var.
- Tam kapatma (deny-by-default egress + network-level enforce) ve endpoint agent kapsamı bu wedge'in ana hedefi değildir.

**2) Full Privacy Gateway (reversible tokenization + rehydration boundary)**
- W1'de PII_SUSPECTED gibi mini tagging vardır.
- Reversible tokenization/rehydration boundary ayrı "B attach" fazıdır.

**3) Derin sandbox / transactional rollback / attestation**
- Yüksek riskli tool'lar için premium izolasyon katmanı sonraki genişleme yoludur.

**4) AIBOM / AI CMDB platformu**
- W1–W4 evidence temeli atılır.
- Tam AIBOM/CMDB ürünleşmesi 3+ enterprise sonrası moat fazıdır.

**5) Her agent framework'ü için özel SDK'lar**
- SafeAgent vendor-agnostic control plane hedefler.
- Özel framework SDK'ları ancak gerekirse eklenir; wedge'in ilk hedefi değildir.

**6) Full Credential Confinement (W5 opsiyonel)**
- W2'de tasarım RFC, W3'te MVP (1 credential type), tam vault entegrasyonu W5.
- Bu roadmap W1–W4'te "detection + brokering MVP" kapsar; full confinement sonraki faz.

### 3.3 Net çıktı (Wedge başarı tanımı)

W1–W4 tamamlandığında SafeAgent şunu garanti eder:
- MCP tool çağrıları tek kapıdan geçer (PEP).
- Her çağrı kimliğe bağlanır (actor/tenant).
- Policy-before-action karar verilir (allow/deny/approval_required).
- (W2+) Delegation token action-bound + replay-safe çalışır.
- Evidence zinciri tamper-evident ve SIEM uyumludur.
- (W4) Tool governance: approved tools directory + signed manifests + reputation ile "shadow tools" kapanır.

---

## 4. Terminoloji ve Spec Uyumu (MCP Transports + Authorization)

Bu roadmap; MCP'nin transport ve authorization çizgisiyle uyumlu ilerler. Amaç, SafeAgent'in "proxy hack" değil **standartlara oturan** bir kontrol düzlemi olmasıdır.

### 4.1 MCP Transports (terminoloji)

**1) stdio**
- MCP server process'i local/subprocess olarak çalışır.
- İletişim stdin/stdout üzerinden gerçekleşir.
- SafeAgent bu modda **wrapper** olarak araya girer (subprocess başlatır + stdio intercept).

**2) Streamable HTTP (standard remote transport)**
- MCP server remote erişime uygundur.
- SafeAgent bu modda **reverse proxy** olarak araya girer (tek MCP endpoint üzerinden trafik akar).
- Streamable HTTP içinde server gerektiğinde `text/event-stream` ile SSE stream başlatabilir.
- Bu durum, aşağıdaki "Deprecated HTTP+SSE transport" ile aynı şey değildir.

**3) Deprecated HTTP+SSE transport (backwards compatibility)**
- Eski/yerini yeni transport'a bırakmış HTTP+SSE yaklaşımıdır.
- SafeAgent için opsiyonel "backwards compatibility" alanıdır; zorunlu hedef değildir.

### 4.2 Streamable HTTP Security Baseline (W1 DoD'ye giren spec çizgisi)

SafeAgent, Streamable HTTP için spec'in güvenlik uyarılarını ürün policy'si olarak enforce eder:

- **Origin header validation**
  - Origin header **var ve invalid** ise: HTTP **403 Forbidden**
  - (DNS rebinding riskini azaltmak için)
- **Local dev bind**
  - Local dev default bind: **127.0.0.1**
  - 0.0.0.0 default yok
- **Authentication**
  - Spec dili "SHOULD proper authentication" olsa da, SafeAgent bunu **ürün policy'si ile zorunlu kılar**
  - Minimum: mTLS veya OIDC bearer

Bu baseline; "pilot kazalarını" ve "güvenlik tartışmalarını" baştan kapatır.

### 4.3 Authorization çizgisi (stdio vs Streamable HTTP)

SafeAgent kimlik bağlamasını transport'a göre doğru yere oturtur:

**stdio**
- Authorization spec'i HTTP tabanlı transportlar içindir.
- stdio senaryosunda identity/credentials genellikle process context + env üzerinden gelir.
- SafeAgent burada "local session/env identity binding" uygular.

**Streamable HTTP**
- Enterprise IdP, Authorization Server (OAuth2.1/OIDC çizgisi) olarak kullanılır.
- SafeAgent OAuth server yazmaz; **resource server doğrulaması** yapar:
  - token doğrula
  - actor/tenant bağla
  - scope ve policy sinyallerine dönüştür

### 4.4 Spec referansları

- MCP Transports: Streamable HTTP ve güvenlik uyarıları
- MCP Authorization: HTTP transport authorization çizgisi, stdio için uygulanmama notu

(Referans linkleri repo'da ayrıca tutulabilir.)

---

## 5. Roadmap İlkeleri (Engineering Contract)

Bu ilkeler, W1–W4 boyunca "değişmez kurallar"dır. Her deliverable bu ilkelerle uyumlu olmak zorundadır.

### 5.1 Policy-before-action (PEP)

- Policy kararı **action gerçekleşmeden önce** verilir.
- "Sonradan logladık" kabul edilmez: enforcement ilk sınıftır.

### 5.2 Identity-first

- Her tool call; actor_id + tenant_id ile ilişkilendirilir.
- (W2+) Delegation token; action-bound (req_hash) ve one-time (jti/nonce) olacak şekilde tasarlanır.
- "Prompt kim?" yerine "action kimin adına?" deterministik olmalıdır.

### 5.3 Deny-by-default

- Belirsiz durumlar güvenli modda kapanır:
  - tool allowlist dışı → deny
  - schema invalid → deny
  - Streamable HTTP baseline ihlali (Origin/auth) → deny
  - token doğrulama başarısız → deny (W2+)
- İstisnalar yalnızca explicit policy ile açılır.

### 5.4 Evidence-by-design (tamper-evident)

- Her aşama evidence üretir: attempted / blocked / pending / approved / executed.
- Canonical evidence schema sabittir; versiyonlama kontrollüdür.
- Hash-chain zorunludur (tamper-evident).

### 5.5 Privacy-by-default (evidence redaction)

- Evidence payload default redacted.
- Ham içerik gerekiyorsa secure store opsiyoneldir; erişim policy + TTL + audit zorunludur.

### 5.6 Rollout-first (enterprise adoption)

- Enforce'a geçiş kontrollü olmalıdır:
  - Shadow mode ("would-have-happened")
  - Canary enforcement
  - Exception TTL (time-bound allow)
- "Prod'u bozmayız, önce ölçeriz" yaklaşımı W3'ün omurgasıdır.

### 5.7 Observability is mandatory

- Her fazın ölçülebilir KPI/telemetry seti vardır:
  - policy_eval_latency p95
  - blocked actions/week
  - approval rate + timeout + breakglass
  - replay_blocked_count (W2+)
  - SIEM/OTel export success rate

### 5.8 Performance-budgeted (latency gate)

- Inline policy evaluation p99 latency hedefi tanımlıdır (W1: < 50ms, network hariç).
- Her release, latency regresyon testinden geçer; budget aşımı = release block.
- "Sonra optimize ederiz" kabul edilmez; budget W1'den itibaren zorunludur.

---

## 6. Roadmap Özeti (W1–W4)

Aşağıdaki özet, her fazın "neden var", "ne teslim eder", "nasıl kanıtlanır" sorularını tek bakışta cevaplar. Detaylar Bölüm 7–10'da.

### W1 — MCP Gateway + Minimal Identity Binding + Operasyonel Baseline (v0.1)

**Amaç:** İlk pilotta "kim denedi?" sorusunu cevaplamak, MCP tool trafiğini tek kapıdan geçirmek ve operasyonel güveni sağlayan baseline'ları kurmak.

**Teslimatlar (çekirdek + v1.1):**
- MCP intercept: stdio wrapper veya Streamable HTTP reverse proxy
- Tool allowlist (approved tools list)
- Input/output schema validation (+ PII_SUSPECTED tagging mini)
- Policy decision: allow / deny / approval_required
- Minimal identity binding: actor_id + tenant_id
- Canonical evidence schema + hash-chain
- Streamable HTTP security baseline (Origin invalid→403, localhost bind, auth policy-enforced)
- **(v1.1)** Rate limiting + action budget
- **(v1.1)** Bypass detection telemetry
- **(v1.1)** Hard latency SLO (p99 < 50ms release gate)
- **(v1.1)** Formal IdP minimum (OIDC claim extraction)
- **(v1.1)** Tenant-scoped evidence routing
- **(v1.1)** Parameter-level policy guards

**Demo kanıtı:** Demo A (Injection → blocked + evidence) + Demo F (Bypass detection).
**Exit:** 1 gerçek MCP client+server ile E2E + en az 5 reason_code canlı + p95/p99 latency ölçümü + rate limit demo.

### W2 — Delegation Token (action-bound) + Replay + Approval Prod + Security Hardening (v0.2)

**Amaç:** Identity-first delegation'ı gerçek security primitive yapmak, approval'ı prod'a uygun hale getirmek ve güvenlik primitive'lerini sertleştirmek.

**Teslimatlar (çekirdek + v1.1):**
- Delegation token minting: req_hash + jti/nonce + exp + kid
- Verifier enforcement: req_hash match + replay cache
- Replay cache: TTL=exp; local LRU + opsiyonel Redis
- Approval prod-ready: timeout + default deny + break-glass
- Evidence: token_jti ve approval lifecycle eventleri
- **(v1.1)** Replay race ordering guarantee (write-before-forward)
- **(v1.1)** Canonicalization standard: RFC 8785 (JCS) + fuzz gate
- **(v1.1)** Approval callback authentication (HMAC/mTLS)
- **(v1.1)** Approval UX: priority queue + batching
- **(v1.1)** Key storage standard (KMS/HSM-backed)
- **(v1.1)** Evidence anchoring MVP (signed batch / Merkle checkpoint)
- **(v1.1)** IdP group/role → policy input mapping
- **(v1.1)** Credential brokering RFC (design-only)
- **(v1.1)** IR runbook + self-audit trail

**Demo kanıtı:** Demo D (Replay → blocked) + Demo H (Evidence Verify).
**Exit:** replay kapalı + approval timeout/breakglass çalışır + token_jti evidence'da + callback auth + latency SLO karşılanmış.

### W3 — Policy-as-code + Shadow→Enforce + Drift + Enterprise Tooling (v0.3)

**Amaç:** Enterprise rollout: prod'u bozmadan ölçmek, kontrollü enforce'a geçmek ve enterprise operasyonel araçları kurmak.

**Teslimatlar (çekirdek + v1.1):**
- Policy DSL + versioning
- Shadow mode ("would-have-happened" raporu)
- Canary enforcement (tenant subset)
- Exception workflow (TTL)
- Policy drift görünürlüğü (policy_version evidence'da)
- **(v1.1)** Policy Simulation CLI ("what-if" engine)
- **(v1.1)** Credential brokering MVP (1 credential type)
- **(v1.1)** Smart approval routing (policy DSL'de risk_class → approver_group)
- **(v1.1)** Multi-instance evidence consistency (global Merkle root)
- **(v1.1)** Tabletop IR drill + anomaly alerts

**Demo kanıtı:** Demo C (shadow→enforce) + Demo E (policy drift) + Demo G (simulation).
**Exit:** canary + rollback planı + exception TTL + simulation CLI + credential broker MVP.

### W4 — Tool Registry + Signed Manifests + Reputation (v0.4)

**Amaç:** Shadow tools'u kapatmak ve tool supply-chain güvenini kurmak.

**Teslimatlar (çekirdek + v1.1):**
- Approved tools directory (registry UI/CLI)
- Signed manifests: tool hash + publisher signature + version metadata
- Scan rules baseline
- Verified publisher modeli
- Reputation score (policy sinyali)
- **(v1.1)** Mandatory migration deadline (legacy allowlist → signed manifest)

**Demo kanıtı:** Malicious tool manifest → install reject.
**Exit:** signed manifest doğrulama zorunlu + verified publisher akışı + reputation policy'de kullanılabilir + legacy tool count = 0.

---

## 6.1 Moat Upgrades (Ranked) — En Yüksek Kaldıraçlı Yükseltmeler

Bu liste; moat derinliği × adoption etkisi × fizibilite skoruna göre sıralanmıştır. Her öğe, ilgili fazın DoD'sine bağlanır.

1. **Credential Brokering / Vault-gated tool access** (W2 RFC → W3 MVP → opsiyonel W5 full)
2. **Policy Simulation CLI ("what-if engine")** (W3)
3. **Formal IdP integration** (OIDC group claims + approval routing; opsiyonel SCIM/conditional signals) (W1→W3)
4. **Evidence Anchoring** (signed batch + external witness) (W2→W3)
5. **Actor+Tenant rate limiting & action budgets** (W1)
6. **Hard latency SLO + performance budget** (release gate) (W1)
7. **Approval UX: priority queue + batching + smart routing** (W2→W3)
8. **Incident response runbook + self-audit trail** (W2→W3)
9. **Multi-instance evidence consistency** (instance chain + batch merge) (W2→W3)
10. **(Opsiyonel W5) Cross-tenant anonymized threat signal** (network-effect moat)

---

## 6.2 Roadmap Revision v1.1 (W1–W5) — Entegre Plan

Bu revizyon; Executive Summary, Threat Model ve Moat Upgrades bölümlerinden gelen "adoption + security primitive" yükseltmelerini mevcut W1–W4 yapısını bozmadan entegre eder. Yeni işler fazların altına "v1.1 Additions" olarak işlenir.

**Zaman tahmini (revize):**
- W1: 3–4 hafta
- W2: 3–4 hafta
- W3: 4–5 hafta
- W4: 3–4 hafta
- (Opsiyonel) W5: 4–6 hafta (W4 sonrası, modüler)

**Toplam W1–W4:** ~13–17 hafta (3.5–4.5 ay)

**Not:** W5 tek bir "mega faz" değildir; opsiyonel modüllerdir (Credential confinement / Network-effect signals / Regulated evidence). Müşteri segmentine göre seçilebilir.

---

## 7. Faz W1 — MCP Gateway + Minimal Identity Binding + Operasyonel Baseline (v0.1)

### 7.1 Amaç

- MCP tool trafiğini **tek kapıdan** geçirmek (PEP).
- İlk pilotta "**kim denedi?**" sorusuna cevap vermek.
- En temel enforcement + evidence katmanını kurmak.
- **(v1.1)** Operasyonel güveni sağlayan baseline'ları (rate limiting, latency SLO, IdP, bypass telemetry) kurmak.

### 7.2 Deliverables (W1)

**D1) MCP Intercept**
- Seçenek 1: **stdio wrapper** — MCP server process'ini SafeAgent wrapper başlatır, stdio üzerinden request/response intercept eder
- Seçenek 2: **Streamable HTTP reverse proxy** — Tek MCP endpoint üzerinden trafiği proxy'ler

**D2) Tool allowlist (approved tools list)**
- tool_id allowlist'te değilse deny-by-default

**D3) Schema validation**
- Input schema validation (P0)
- Output schema validation (P1)
- Output'ta PII şüphesi → `PII_SUSPECTED` tag (mini)

**D4) Policy decisioning (basit)**
- allow / deny / approval_required
- policy_id + policy_version evidence'a yazılır

**D5) Minimal identity binding**
- actor_id + tenant_id tüm evidence event'lerine bağlanır
- stdio: local session/env identity
- streamable_http: bearer/mTLS ile actor mapping (MVP)

**D6) Evidence stream**
- Canonical evidence schema (sabit)
- Hash-chain (tamper-evident)
- Payload default redacted
- Export: JSONL/OTel (en az birisi)

**D7) Streamable HTTP security baseline (ürün enforce)**
- Origin header validation: invalid → 403
- Local dev default bind: 127.0.0.1
- Auth: spec SHOULD ama ürün policy'si ile zorunlu (mTLS veya OIDC bearer)

### 7.3 Definition of Done (W1 DoD)

**PEP / Intercept**
- [ ] En az bir transport uçtan uca çalışır: stdio wrapper **veya** Streamable HTTP proxy
- [ ] 1 gerçek MCP client + 1 gerçek MCP server ile E2E tool call yapılır
- [ ] Intercept başarısız olursa fail-closed (deny-by-default)

**Allowlist**
- [ ] allowlist dışı tool_id → deny
- [ ] evidence: RC_TOOL_NOT_APPROVED

**Schema validation**
- [ ] input schema invalid → deny + RC_SCHEMA_INVALID
- [ ] output inspection varsa PII şüphesi → data_tags: PII_SUSPECTED (payload redacted kalır)

**Policy**
- [ ] decision seti: allow/deny/approval_required
- [ ] policy_id + policy_version evidence'da görünür
- [ ] default deny-by-default seçeneği vardır

**Identity binding**
- [ ] actor_id + tenant_id evidence event'lerinde zorunlu
- [ ] streamable_http modunda auth yok/invalid → deny (RC_AUTH_MISSING/RC_AUTH_INVALID)

**Evidence**
- [ ] canonical schema tüm event'lerde aynı
- [ ] hash-chain alanları dolu (hash_prev + hash_curr)
- [ ] payload default redacted
- [ ] export pipeline çalışır (JSONL veya OTLP)

**Streamable HTTP baseline**
- [ ] Origin var ve invalid → HTTP 403 + RC_ORIGIN_INVALID
- [ ] Local dev bind: 127.0.0.1 default
- [ ] Auth ürün policy'si ile zorunlu (mTLS/OIDC)

**Rate limiting / DoS (P0)**
- [ ] actor-level ve tenant-level rate limiting aktif (özellikle approval_required spam'e karşı)
- [ ] rate limit ihlali → deny + RC_RATE_LIMIT + evidence event

**Bypass detection telemetry (P0)**
- [ ] bypass_suspected_count metriki üretilir (credential usage ↔ MCP action korelasyonu veya "unmatched outbound tool traffic" sinyali)
- [ ] credential_usage_unmatched_rate dashboard'da izlenir

**Hard latency SLO (P0, release gate)**
- [ ] policy_eval_latency_p99_ms < 50ms (inline karar, network hariç) hedefi tanımlı
- [ ] latency_regression_test_pass = true → breach = release block

**Formal IdP minimum (Streamable HTTP, P0)**
- [ ] OIDC bearer doğrulama + claim extraction: sub + groups/roles
- [ ] idp_claim_extraction_success_rate ölçülür

**Tenant-scoped evidence routing (P1)**
- [ ] evidence export tenant_id'ye göre route edilebilir (en azından konfig ile)
- [ ] tenant_routing_mismatch_alert_count üretilir

**Parameter-level policy guards (P1)**
- [ ] forbidden param patterns (regex/glob) aktif (en az 3 pattern)
- [ ] param_pattern_blocked_count ölçülür

### 7.4 Telemetry / KPI (W1)

Minimum metrikler:
- policy_eval_latency_ms (p50/p95)
- policy_eval_latency_p99_ms
- latency_regression_test_pass (boolean, release gate)
- decision_distribution (allow/deny/approval_required)
- denied_tool_not_approved_count
- schema_invalid_count
- origin_invalid_count (streamable_http)
- auth_missing_count / auth_invalid_count (streamable_http)
- evidence_emit_success_rate
- gateway_uptime
- rate_limit_triggered_count
- action_budget_exhausted_count
- bypass_suspected_count
- credential_usage_unmatched_rate
- idp_claim_extraction_success_rate
- tenant_routing_mismatch_alert_count
- param_pattern_blocked_count

Önerilen dashboard sorguları:
- Top denied tools (tool_id)
- Top reason_codes
- Blocked actions / week
- Bypass suspected events / week
- Rate limit triggers / day

### 7.5 Demo (W1) — Kanıt üretimi

**Demo A: Injection → Block**
1. Malicious content ile agent "crm.export" gibi riskli tool çağrısı üretir
2. SafeAgent intercept eder
3. Policy/allowlist nedeniyle deny veya approval_required (demo için deny tercih)
4. Evidence event göster: actor_id, tenant_id, tool_id, policy_version, reason_codes (RC_EXCESSIVE_SCOPE veya RC_TOOL_NOT_APPROVED)

Demo DoD:
- [ ] attempted + blocked event'leri oluşur
- [ ] reason_codes doğru
- [ ] payload redacted
- [ ] hash-chain tutarlı

### 7.6 W1 Riskler ve Mitigations

- **Interop riski (client/server çeşitliliği):**
  - Mitigation: önce stdio wrapper ile hızlı pilot; sonra Streamable HTTP proxy ile genişleme
- **False positive blokaj:**
  - Mitigation: approval_required opsiyonu + W3 shadow mode planı
- **Auth friction (Streamable HTTP):**
  - Mitigation: policy ile zorunlu ama MVP'de mTLS veya OIDC bearer'dan birini seçip netleştir

### 7.7 W1 v1.1 Additions (Adoption Gates)

Bu ekler, W1'i "satılabilir enterprise wedge" yapmak için gereklidir.

**D8 Rate limiting + action budget (P0)**
- actor-level + tenant-level configurable rate limit (token bucket/sliding window)
- aşıldığında deny + RC_RATE_LIMIT + evidence
- opsiyonel: günlük/saatlik action budget cap

**D9 Bypass detection telemetry (P0)**
- MCP action stream ↔ credential usage/outbound tool traffic korelasyonu (detection-only)
- bypass_suspected_count ve credential_usage_unmatched_rate
- Enforcement değil, detection + alert (W1 scope'u şişirmez)

**D10 Hard latency SLO (P0, release gate)**
- hedef: policy_eval_latency_p99_ms < 50ms (inline karar, network hariç)
- latency_regression_test_pass = true (breach → release block)
- Not: W1 exit'te ölçüm raporu ile hedef revizyonu mümkün, ama "budget + gate" yaklaşımı korunur.

**D11 Formal IdP minimum (P0)**
- Streamable HTTP: OIDC bearer doğrulama + claim extraction (sub + groups/roles)
- idp_claim_extraction_success_rate
- En az Okta veya Entra ID ile test edilmiş

**D12 Tenant-scoped evidence routing (P1)**
- tenant_id → export route mapping (config)
- tenant_routing_mismatch_alert_count

**D13 Parameter-level policy guards (P1)**
- forbidden param patterns (regex/glob) ör: export=true, limit=999999, filter=*
- param_pattern_blocked_count

---

## 8. Faz W2 — Delegation Token + Replay + Approval Prod + Security Hardening (v0.2)

### 8.1 Amaç

- Identity-first delegation'ı "gerçek security primitive" yapmak.
- Token theft/replay gibi pratik saldırıları kapatmak.
- Approval akışını prod'da operasyonel hale getirmek (timeout + break-glass).
- **(v1.1)** Güvenlik primitive'lerini sertleştirmek (key management, evidence anchoring, callback auth, canonicalization standardı).

### 8.2 Deliverables (W2)

**D1) Delegation Token Service (minting)**
- İmzalı token üretimi (kid destekli)
- Claims (minimum): tenant, actor, tool_id, scope, exp, jti, nonce, req_hash
- TTL kısa: 60–120s (konfigüre edilebilir)

**D2) req_hash action-bound binding**
- req_hash = H(tool_id | canonical_input | time_bucket | tenant | actor)
- canonical_input kuralı:
  - **RFC 8785 (JCS)** JSON Canonicalization Scheme (custom canonicalization YAPILMAZ)
  - stable key order (JCS guarantee)
  - whitespace normalize (JCS guarantee)
  - canonicalization_fuzz_test_pass release gate

**D3) Verifier enforcement**
- Token signature/claims doğrulama
- req_hash match (tool call → req_hash yeniden hesaplanır)
- Scope enforcement (token.scope ↔ resource_scope)

**D4) Replay prevention**
- jti/nonce one-time
- replay cache:
  - TTL = token exp
  - local LRU (default)
  - opsiyonel Redis (HA/scale)

**D5) Approval prod-ready**
- approval_required kararı için:
  - timeout (policy ile)
  - default deny (timeout → deny + RC_APPROVAL_TIMEOUT)
- break-glass override:
  - time-bound TTL
  - reason mandatory
  - ayrı event type + RC_BREAKGLASS_USED
- Idempotency: aynı tool call → tek approval_request (idempotency_key)

**D6) Evidence genişletmeleri**
- token_jti (ve opsiyonel token_kid/token_exp) executed/blocked event'lerine yazılır
- replay blocked event'lerinde RC_REPLAY_DETECTED
- approval lifecycle eventleri (pending/approved/executed) zincir halinde görünür

### 8.3 Definition of Done (W2 DoD)

**Token minting**
- [ ] Token imzalıdır; `kid` ile doğru anahtar seçilir
- [ ] exp/iat doğrulanır (expired → deny)
- [ ] Claims minimum set tamamdır (tenant/actor/tool_id/jti/nonce/req_hash)

**Action-bound binding**
- [ ] Verifier canonical_input üretir ve req_hash hesaplar
- [ ] req_hash mismatch → deny (RC_TOKEN_BINDING_MISMATCH)
- [ ] time_bucket drift toleransı tanımlıdır (örn ±1 bucket)

**Replay cache**
- [ ] jti/nonce one-time enforced
- [ ] Aynı token ikinci kullanım → deny + RC_REPLAY_DETECTED
- [ ] Cache TTL = exp-now
- [ ] Backend seçimi telemetry'de görünür (lru|redis)

**Approval prod-ready**
- [ ] approval_required → approval_request oluşturur (idempotency ile)
- [ ] Timeout → deny + RC_APPROVAL_TIMEOUT (default)
- [ ] Break-glass: yalnız yetkili rol, time-bound TTL zorunlu, reason mandatory, evidence: RC_BREAKGLASS_USED
- [ ] Approve/deny callback sadece PENDING state'te kabul edilir (race safety)

**Evidence**
- [ ] executed event'inde token_jti dolu
- [ ] replay blocked event'inde token_jti dolu + RC_REPLAY_DETECTED
- [ ] approval timeline eventleri canonical schema ile uyumlu

**Replay race ordering guarantee (P0, release gate)**
- [ ] write-before-forward: token cache'e yazılmadan action forward edilmez
- [ ] replay_race_condition_test_pass = true (release gate)

**Canonicalization standard (P0, release gate)**
- [ ] RFC 8785 (JCS) sabitlenmiş; custom canonicalization yok
- [ ] canonicalization_fuzz_test_pass = true (release gate)

**Approval callback authentication (P0)**
- [ ] callback endpoint HMAC-signed webhook veya mTLS
- [ ] unsigned/invalid → reject + approval_callback_unsigned_reject_count

**Approval UX (P1)**
- [ ] priority queue: red > amber > green
- [ ] batching: aynı actor + tool_id + time window → tek approval

**Key storage standard (P0)**
- [ ] token signing keys KMS/HSM-backed (raw key file kabul edilmez)
- [ ] emergency rotation runbook mevcut
- [ ] anomalous_mint_alert_count alert kuralı tanımlı

**Evidence anchoring MVP (P1)**
- [ ] signed batch checkpoint (Merkle root + imza) her N event / T dakika
- [ ] batch verification CLI: `safeagent evidence verify --batch <id>`

**IdP group/role → policy mapping (P1)**
- [ ] policy DSL'de actor.role, actor.groups kullanılabilir
- [ ] approval routing: approver_group = IdP group

**Credential brokering RFC (P1, design-only)**
- [ ] RFC dokümanı + threat model + interface tanımı; implementation W3

**Multi-instance evidence ordering design (P2, design-only)**
- [ ] instance_id + sequence_number + batch merge tasarımı

**Incident response runbook (P1)**
- [ ] key compromise / evidence failure / SafeAgent-down runbook
- [ ] self-audit trail: config/policy değişiklikleri evidence'a yazılır

### 8.4 Telemetry / KPI (W2)

Minimum metrikler:
- token_minted_count
- token_mint_latency_ms (p50/p95)
- token_validation_fail_count (by reason)
- replay_cache_hit_rate
- replay_blocked_count
- approval_requests_created_count
- approval_cycle_time_ms (p50/p95)
- approval_timeout_count
- breakglass_usage_count
- decision_distribution (allow/deny/approval_required)
- canonicalization_fuzz_test_pass (release gate)
- replay_race_condition_test_pass (release gate)
- approval_callback_auth_fail_count
- approval_callback_unsigned_reject_count
- approval_batch_count
- approval_queue_depth_p95
- key_storage_compliance (boolean)
- anomalous_mint_alert_count
- chain_anchor_emit_count
- chain_anchor_verification_pass_rate
- approval_routed_via_idp_group_rate
- self_audit_events_count

### 8.5 Demo (W2) — Kanıt üretimi

**Demo D: Token replay → Block**
1. Aynı token ile aynı tool call ikinci kez tetiklenir
2. replay cache hit
3. SafeAgent deny
4. Evidence: blocked event, reason_codes: RC_REPLAY_DETECTED, token_jti görünür

Demo DoD:
- [ ] İlk çağrı executed (veya allow path)
- [ ] İkinci çağrı blocked
- [ ] RC_REPLAY_DETECTED doğru
- [ ] token_jti her iki event'te de görünür
- [ ] payload redacted + hash-chain tutarlı

### 8.6 W2 Riskler ve Mitigations

- **Canonicalization mismatch (false deny):**
  - Mitigation: RFC 8785 (JCS) standardı sabitlendi; canonicalization tek shared modül; gateway+verifier aynı kütüphaneyi kullanır
- **Clock drift / bucket uyuşmazlığı:**
  - Mitigation: ±1 bucket toleransı + kısa TTL
- **Approval operasyonel sürtünme:**
  - Mitigation: timeout default deny + break-glass + priority queue + batching + telemetry (cycle time)
- **Replay cache HA tutarlılığı:**
  - Mitigation: opsiyonel Redis + NX set + TTL=exp + write-before-forward ordering guarantee

### 8.7 W2 v1.1 Additions (Security Hardening)

**D7 Replay race ordering guarantee (P0, release gate)**
- write-before-forward garanti: token "kullanıldı" işaretlenmeden action forward edilmez
- LRU backend'de mutex/CAS garantisi
- replay_race_condition_test_pass release gate

**D8 Approval callback authentication (P0)**
- HMAC-signed webhook veya mTLS callback endpoint
- Approver identity claim cryptographically bound
- approval_callback_unsigned_reject_count, approval_callback_auth_fail_count

**D9 Approval UX (P1)**
- priority queue (red > amber > green) + batching (aynı actor + tool_id + time window → tek approval)
- approval_batch_count, approval_queue_depth_p95

**D10 Key storage standard (P0)**
- token signing keys KMS/HSM-backed (raw key file kabul edilmez)
- emergency rotation runbook + anomalous_mint_alert_count

**D11 Evidence anchoring MVP (P1)**
- signed batch / checkpoint (Merkle root + imza) her N event / T dakika
- chain_anchor_emit_count + chain_anchor_verification_pass_rate
- batch verification CLI: `safeagent evidence verify --batch <id>`

**D12 IdP group/role mapping (P1)**
- policy input: actor.groups/roles kullanılabilir
- approval routing: approver_group = IdP group mapping
- approval_routed_via_idp_group_rate

**D13 Credential brokering RFC (P1, design-only)**
- tasarım + threat model + interface; implementation W3

**D14 Multi-instance evidence ordering design (P2, design-only)**
- instance_id + sequence_number + batch merge tasarımı; implementation W3

**D15 Incident response runbook + self-audit (P1)**
- key compromise / evidence integrity failure / SafeAgent-down senaryoları
- SafeAgent config/policy değişiklikleri evidence'a yazılır (self-audit trail)
- self_audit_events_count

---

## 9. Faz W3 — Policy-as-code + Shadow→Enforce + Drift + Enterprise Tooling (v0.3)

### 9.1 Amaç

- Enterprise rollout: "prod'u bozmadan ölç, sonra enforce".
- Policy'leri versiyonlanabilir, test edilebilir, geri alınabilir hale getirmek.
- Shadow mode ile false positive/negative ölçmek; canary ile kontrollü enforce'a geçmek.
- Policy drift'i evidence üzerinden görünür kılmak (policy_version).
- **(v1.1)** Enterprise operasyonel araçları kurmak: policy simulation, credential broker MVP, smart routing, multi-instance evidence, IR drill.

### 9.2 Deliverables (W3)

**D1) Policy-as-code (DSL + versioning)**
- Policy'ler repo'da versionlanır (policy_id + policy_version).
- Policy evaluation deterministic olmalı (aynı input → aynı output).
- Baseline: allow/deny/approval_required + approval_profile.

**D2) Shadow mode**
- rollout_mode = shadow
- Action gerçekleşebilir; ancak policy decision "would-have-happened" olarak evidence'a yazılır.
- Shadow raporları: decision_distribution (shadow), top reason_codes, false_positive_rate, "most impactful policies"

**D3) Enforce rollout**
- rollout_mode = enforce
- Canary enforcement: tenant subset (örn canary_bucket 0–9), fail-closed + hızlı rollback (shadow'a dönüş)
- Exception workflow (TTL): time-bound allow/approval override, reason mandatory, created_by audit

**D4) Drift görünürlüğü**
- policy_version evidence'da her eventte görünür
- drift demo: v1 shadow → approve_required, v2 enforce → deny

### 9.3 Definition of Done (W3 DoD)

**Policy-as-code**
- [ ] policy_id + policy_version versiyonlanabilir
- [ ] Policy evaluation deterministic (aynı input → aynı output)
- [ ] Policy change rollout planı var (shadow/canary/enforce)

**Shadow mode**
- [ ] Shadow'da kararlar uygulanmaz (enforce etmez) ama evidence'a yazılır
- [ ] "would-have-happened" raporu üretilebilir
- [ ] Shadow ölçümleri: shadow_decision_distribution, shadow_top_denied_tools, shadow_false_positive_rate

**Canary enforcement**
- [ ] Canary tanımı net (tenant subset hashing)
- [ ] Canary'da enforce çalışır; dışındaki tenant'lar shadow'da kalabilir
- [ ] Canary rollback prosedürü dokümante

**Exceptions (TTL)**
- [ ] Exception create/update/revoke akışı var
- [ ] TTL zorunlu (expires_at)
- [ ] reason mandatory
- [ ] Evidence'da exception kullanımı görünür

**Drift**
- [ ] policy_version evidence'da görünür
- [ ] Drift demo çalışır (v1 vs v2 kararı kanıtlı)

**Policy Simulation CLI (P0)**
- [ ] `safeagent simulate --policy <file> --from <date> --to <date>` çalışır
- [ ] çıktı: predicted decision distribution + top blocked tools + export (JSON/CSV)
- [ ] simulation_runs_count ölçülür

**Credential brokering MVP (P1)**
- [ ] en az 1 credential type broker edilir (time-bound/one-time)
- [ ] broker bypass → deny + RC_CREDENTIAL_BROKER_BYPASS

**Smart approval routing (P1)**
- [ ] policy DSL'de risk_class → approver_group mapping
- [ ] approval_routed_via_idp_group_rate ölçülür

**Multi-instance evidence consistency (P1)**
- [ ] instance-local chain + signed batch merge + global Merkle root
- [ ] cross-instance query + external witness export

**Tabletop IR drill (P1)**
- [ ] en az 1 drill tamamlanmış
- [ ] break-glass anomaly alert tanımlı

### 9.4 Telemetry / KPI (W3)

Minimum metrikler:
- policy_update_propagation_time_ms
- shadow_decision_distribution
- shadow_false_positive_rate
- canary_enforcement_success_rate
- exception_active_count (gauge)
- exception_usage_count
- rollback_to_shadow_count
- policy_eval_latency_ms (p95) (versiyonlama sonrası regresyon kontrol)
- simulation_runs_count
- simulation_predicted_block_rate
- credential_broker_requests_count
- credential_direct_usage_detected_count
- broker_bypass_blocked_count
- global_merkle_root_emit_count
- instance_chain_divergence_count
- ir_drill_completed_count
- breakglass_anomaly_alert_count

### 9.5 Demo (W3) — Kanıt üretimi

**Demo C: Shadow → Controlled Enforce**
1. Tenant A shadow modda: allow/deny/approval_required sadece loglanır
2. Canary subset enforce'a alınır
3. Evidence'da rollout_mode ve policy_version görünür

**Demo E: Policy drift**
1. Policy v1 (shadow): approval_required
2. Policy v2 (enforce): deny
3. Evidence, aynı tool call tipinde policy_version farkını gösterir

Demo DoD:
- [ ] Shadow raporu "would-have-happened" çıkar
- [ ] Canary enforce gerçekten davranışı değiştirir
- [ ] policy_version evidence'da doğru

### 9.6 W3 Riskler ve Mitigations

- **Policy değişikliği prod'u bozabilir:**
  - Mitigation: shadow → canary → enforce + hızlı rollback
- **False positives (operasyonel güven kaybı):**
  - Mitigation: shadow haftası + exception TTL + reason mandatory + **policy simulation CLI ile önceden ölç**
- **Policy eval latency artışı:**
  - Mitigation: policy performance budget + p95 takip + caching (policy level) opsiyon

### 9.7 W3 v1.1 Additions (Enterprise Tooling)

**D5 Policy Simulation CLI (P0)**
- `safeagent simulate --policy <file> --from <date> --to <date>`
- çıktı: predicted decision distribution + top blocked tools + predicted FP rate
- export: JSON/CSV
- en az 7 günlük evidence history üzerinde çalışır
- simulation_runs_count, simulation_predicted_block_rate

**D6 Credential brokering MVP (P1)**
- en az 1 credential type (API key) broker edilir (time-bound/one-time)
- tool, credential'ı yalnızca SafeAgent aracılığıyla alır
- broker bypass → deny + RC_CREDENTIAL_BROKER_BYPASS
- credential_broker_requests_count, credential_direct_usage_detected_count

**D7 Smart approval routing (P1)**
- risk_class → approver_group otomatik (red→security team, amber→team lead)
- policy DSL'de approval routing rules tanımlanabilir
- approval_routed_via_idp_group_rate

**D8 Multi-instance evidence consistency (P1)**
- her instance kendi chain'ini yürütür + batch anchor'lar global Merkle root üretir
- cross-instance evidence query: `safeagent evidence query --global --time-range`
- external witness export (SIEM'e signed checkpoint)
- global_merkle_root_emit_count, instance_chain_divergence_count

**D9 Tabletop IR drill + anomaly alerts (P1)**
- en az 1 tabletop incident drill (key compromise veya SafeAgent-down senaryosu)
- break-glass usage anomaly alert (threshold-based)
- ir_drill_completed_count, breakglass_anomaly_alert_count

---

## 10. Faz W4 — Tool Registry + Signed Manifests + Reputation (v0.4)

### 10.1 Amaç

- "Shadow tools" problemini kapatmak: kurum içinde tek doğruluk kaynağı (approved tool directory).
- Tool supply-chain güveni kurmak: signed manifests + verified publisher.
- Policy'nin karar verebileceği ek sinyaller üretmek: reputation score.

### 10.2 Deliverables (W4)

**D1) Approved Tools Directory (Registry)**
- Tool kayıtları: tool_id, tool_version, publisher, publisher_verified, risk_class (green/amber/red), input/output schema references, allowed scopes / scope patterns (opsiyonel)
- Yönetim arayüzü: CLI (P0), UI (P1) veya minimal admin panel

**D2) Signed manifests**
- Manifest alanları (minimum): tool_id, tool_version, tool_hash (sha256), publisher_id, signature (publisher key), created_at
- Doğrulama: signature verify, hash match, revoked publisher/key kontrolü

**D3) Scan rules (baseline)**
- Basit kurallar: forbidden endpoints list (opsiyonel), dependency allowlist (opsiyonel), dangerous permissions flags (opsiyonel)
- Amaç: en azından "bariz kötü" tool'ları bloklamak.

**D4) Verified publisher modeli**
- Publisher kayıtları: publisher_id, public keys (kid set), verification status, revocation status
- Key rotation: current + previous key grace, revoked keys deny-by-default

**D5) Reputation score**
- Reputation sinyalleri (başlangıç): publisher_verified (strong signal), tool_age / version stability (opsiyonel), scan_passed (baseline), usage outcomes (blocked rate, approvals, incidents) (opsiyonel)
- Policy input'a eklenir: publisher_verified, reputation_score (0–100)
- Amaç: risk-based policy (örn düşük reputation → approval_required)

### 10.3 Definition of Done (W4 DoD)

**Registry**
- [ ] CLI ile tool ekle/çıkar/güncelle yapılır
- [ ] Tool kaydında risk_class ve schema referansı vardır
- [ ] allowlist enforcement registry'den beslenir (W1 allowlist → W4 directory)

**Signed manifests**
- [ ] Manifest signature doğrulanır (kid üzerinden)
- [ ] tool_hash doğrulanır
- [ ] verify fail → install/register reject + RC_SIGNATURE_INVALID
- [ ] revoked publisher/key → deny-by-default

**Verified publisher**
- [ ] Publisher verification state yönetilir (verified/unverified/revoked)
- [ ] Key rotation desteklenir (current+previous)
- [ ] Revocation sonrası yeni kayıtlar reject edilir

**Scan rules**
- [ ] Baseline scan çalışır ve sonucu registry'ye yazılır (scan_passed true/false)
- [ ] scan_failed → en azından amber/red tool'larda approval_required veya deny

**Reputation**
- [ ] Reputation score üretilir ve registry'de saklanır
- [ ] Policy evaluation, reputation_score'u input olarak alabilir

**Mandatory migration deadline (P0)**
- [ ] Registry devreye girdikten sonra X hafta (önerilen: 4 hafta) içinde legacy allowlist → signed manifest migration
- [ ] migrate olmayan → amber → deny (grace period)
- [ ] legacy_allowlist_tool_count hedef 0
- [ ] migration_deadline_compliance_rate ölçülür

### 10.4 Telemetry / KPI (W4)

Minimum metrikler:
- registry_tools_count
- registry_publishers_count
- signed_manifest_verify_fail_count
- revoked_key_denials_count
- scan_failed_count
- reputation_distribution (histogram)
- shadow_tool_attempts_count (registry dışı tool denemeleri)
- legacy_allowlist_tool_count (gauge, hedef: 0)
- migration_deadline_compliance_rate
- migration_remaining_days (gauge)

### 10.5 Demo (W4) — Kanıt üretimi

**Demo: Malicious tool manifest → install reject**
1. Signature invalid veya hash mismatch olan manifest ile kayıt/install denemesi
2. SafeAgent reject eder
3. Evidence: blocked, reason_codes: RC_SIGNATURE_INVALID, publisher/key bilgisi (PII yok)

Demo DoD:
- [ ] Reject deterministic
- [ ] Evidence schema uyumlu + hash-chain tutarlı
- [ ] Registry state değişmez (kötü tool eklenmez)

### 10.6 W4 Riskler ve Mitigations

- **Publisher key yönetimi karmaşıklaşabilir:**
  - Mitigation: current+previous + revocation list + basit CLI akışları
- **Scan rules "çok yüzeysel" algısı:**
  - Mitigation: baseline hedefi net; ileri tarama W4.5/W5 genişlemesi olarak planlanır
- **Registry UI gecikirse adoption yavaşlar:**
  - Mitigation: CLI-first + minimal admin panel
- **Grandfather tools (legacy allowlist → registry migration):**
  - Mitigation: mandatory migration deadline + grace period + amber → deny kademesi

### 10.7 (Opsiyonel) W5 — Advanced Moat Modules (W4 sonrası)

W5 tek bir büyük faz değil; müşteri segmentine göre seçilen modüllerdir.
**Tahmini süre:** 4–6 hafta (modüler)

**W5-A Full Credential Confinement**
- Vault entegrasyonu (HashiCorp Vault / AWS Secrets Manager / Azure Key Vault)
- Credential'ların SafeAgent dışında işe yaramaması
- Egress confinement: credential yalnızca SafeAgent broker üzerinden kullanılabilir
- Network-level enforcement (opsiyonel: ZTNA + egress proxy entegrasyonu)
- credential_confinement_bypass_attempt_count (target=0)

**W5-B Cross-tenant anonymized threat signal (opt-in)**
- Strict anonymization: yalnızca tool_hash + block_count + tenant_count (zaman pencereli)
- Tenant_id/actor_id/payload kesinlikle paylaşılmaz
- Opt-in only + legal/compliance review + PIA zorunlu
- Reputation score'a cross-tenant signal input olarak eklenir
- cross_tenant_signal_opt_in_rate, cross_tenant_signal_contribution_count

**W5-C Regulated evidence store (WORM/immutable)**
- S3 Object Lock veya eşdeğer append-only immutable storage
- Regüle sektör compliance requirement (finans, sağlık, kamu)
- worm_store_write_success_rate

**W5 DoD:**
- [ ] W5-A: vault entegrasyonu en az 1 cloud provider ile çalışır
- [ ] W5-B: opt-in + anonymization spec + testler tamamlanmış
- [ ] W5-C: WORM store opsiyonel ama kullanılabilir

---

## 11. Demo Paketi (CISO-kalibre)

Bu bölüm, SafeAgent'in "prompt filter" değil "action governor" olduğunu 2 dakikada ispatlayan demo setini tanımlar.

### 11.1 Demo seti (8 mini demo)

- Demo A: Injection → risky tool call attempt → blocked (W1)
- Demo B: Same action → approval → executed (W1/W2)
- Demo C: Shadow mode → controlled enforce (W3)
- Demo D: Token replay → blocked (W2)
- Demo E: Policy drift (v1 shadow vs v2 enforce) (W3)
- Demo F: Bypass Detection — credential ↔ MCP korelasyonu (W1)
- Demo G: Policy Simulation CLI — "deploy etmeden önce gör" (W3)
- Demo H: Evidence Verify — signed batch + tampering detection (W2)

### 11.2 2 dakikalık CISO demo (iki varyant)

**Varyant-1: Security-first (bypass + proof)**

0:00–0:15 Frame: "Agent'lar konuşur; SafeAgent ne yapabileceklerini yönetir."
0:15–0:40 Demo A (Injection→Block)
0:40–1:00 Demo D (Replay→Block)
1:00–1:25 Demo F (Bypass detection, kısa)
1:25–1:50 Demo H (Evidence verify, kısa)
1:50–2:00 Close: "Identity→Policy→Action→Evidence. Kör nokta yok, kanıt bozulmaz."

**Varyant-2: Ops-first (approval + rollout)**

0:00–0:15 Frame: "Agent'lar konuşur; SafeAgent ne yapabileceklerini yönetir."
0:15–0:40 Demo A (Injection→Block)
0:40–1:10 Demo B (Approval→Execute, kısa)
1:10–1:40 Demo C (Shadow→Enforce, kısa özet)
1:40–2:00 Close: "Rollout safety + audit. Prod'u bozmadan ölç, kontrollü enforce."

Not: Security-first varyant CISO'nun "bypass/audit" itirazını kapatır; Ops-first varyant platform+operasyon güvenini gösterir. Toplantı tipine göre seçilir.

### 11.3 Demo A — Injection → Block (W1)

**Senaryo:**
- Agent, kötü niyetli içerikten etkilenip "crm.export" gibi red tool çağrısı üretir.
- SafeAgent tool allowlist/policy ile engeller.

**Beklenen evidence timeline:**
1. attempted — decision: deny, reason_codes: RC_EXCESSIVE_SCOPE veya RC_TOOL_NOT_APPROVED
2. blocked — decision: deny, reason_codes: yukarıdaki ile tutarlı

**Demo A DoD:**
- [ ] actor_id + tenant_id görünür
- [ ] policy_version görünür
- [ ] payload redacted
- [ ] hash-chain tutarlı

### 11.4 Demo B — Approval → Execute (W1/W2)

**Senaryo:**
- Aynı action bu kez approval_required. Approve edilince execute olur.

**Beklenen evidence timeline:**
1. attempted (decision: approval_required, RC_APPROVAL_REQUIRED)
2. approval_pending (decision: approval_required)
3. approved (actor_id = approver)
4. executed (W2+: token_jti dolu olabilir)

**Demo B DoD:**
- [ ] pending → approved → executed zinciri tam
- [ ] approval timeout olursa RC_APPROVAL_TIMEOUT (opsiyonel alt demo)
- [ ] break-glass varsa RC_BREAKGLASS_USED + reason mandatory (opsiyonel alt demo)

### 11.5 Demo C — Shadow → Controlled Enforce (W3)

**Senaryo:**
- Tenant A shadow mode: "would-have-happened" raporu.
- Canary subset enforce'a alınır.

**Demo C DoD:**
- [ ] shadow raporu üretilir
- [ ] canary subset enforce doğrulanır
- [ ] rollback_to_shadow prosedürü dokümante

### 11.6 Demo D — Token replay → Block (W2)

**Senaryo:**
- Aynı token ile aynı tool call ikinci kez denenir. SafeAgent replay cache ile engeller.

**Beklenen evidence timeline:**
1. executed (ilk çağrı; token_jti dolu)
2. blocked (ikinci çağrı) — reason_codes: RC_REPLAY_DETECTED, token_jti: aynı

**Demo D DoD:**
- [ ] replay blocked deterministic
- [ ] token_jti evidence'da görünür
- [ ] hash-chain tutarlı

### 11.7 Demo E — Policy drift (W3)

**Senaryo:**
- policy v1 shadow: approval_required
- policy v2 enforce: deny
- Aynı tip tool call üzerinde policy_version farkı gösterilir.

**Demo E DoD:**
- [ ] v1/v2 farkı net
- [ ] policy_update_propagation ölçülmüş

### 11.8 Demo F — Bypass Detection (W1)

**İtirazı kapatır:** "Agent MCP'yi bypass ederse kör müsünüz?"

**Senaryo:**
1. Agent, SafeAgent üzerinden normal tool call yapar → allow + evidence (normal akış)
2. Aynı agent/aktör, MCP katmanını atlayıp doğrudan API çağırır
3. SafeAgent bu çağrıyı intercept etMEZ — ama credential usage telemetry, MCP action stream'de karşılığı olmayan outbound API çağrısı tespit eder
4. Dashboard'da bypass_suspected alert yükselir

**Demo F DoD:**
- [ ] bypass_suspected_count artar
- [ ] credential_usage_unmatched_rate > 0 gösterilir
- [ ] "Credential brokering roadmap" slide'ı hazır (detect now, prevent W3+)

**Telemetry:**
- bypass_suspected_count
- credential_usage_unmatched_rate

### 11.9 Demo G — Policy Simulation CLI (W3)

**İtirazı kapatır:** "Bu policy prod'u bozar mı? Deploy etmeden bilemez miyiz?"

**Senaryo:**
1. Son 7 günün evidence'ı üzerinde yeni policy simülasyonu çalıştırılır
2. `safeagent simulate --policy new_export_policy.yaml --from 2026-02-19 --to 2026-02-26`
3. Çıktı: predicted decision distribution, top affected tools, predicted approval queue load
4. Policy daraltılır, simülasyon tekrar çalıştırılır → approval artışı kabul edilebilir seviyeye düşer

**Demo G DoD:**
- [ ] CLI çalıştırılır, simülasyon sonucu üretilir
- [ ] Predicted vs actual decision distribution gösterilir
- [ ] İkinci (daraltılmış) simülasyon çalışır
- [ ] Export: JSON çıktı gösterilir

**Telemetry:**
- simulation_runs_count
- simulation_predicted_block_rate

### 11.10 Demo H — Evidence Verify (W2)

**İtirazı kapatır:** "Log değiştirilebilir, regülatöre kanıt nasıl?"

**Senaryo:**
1. Son 24 saatin evidence event'lerini göster (hash_prev + hash_curr zinciri)
2. CLI: `safeagent evidence verify --from <batch_1> --to <batch_5>` → "5 batch verified. No gaps detected."
3. Tampering simülasyonu: bir event değiştir → verify tekrar çalıştır → "FAIL: hash mismatch. Tampering detected at event #1847."
4. External witness: SIEM'deki signed checkpoint ile SafeAgent root'un eşleştiğini göster

**Demo H DoD:**
- [ ] evidence verify CLI PASS
- [ ] tampering sonrası FAIL + yer tespiti
- [ ] external witness checkpoint karşılaştırması
- [ ] tüm payload'lar redacted (privacy korunur)

**Telemetry:**
- batch_verification_pass_rate
- chain_anchor_verification_pass_rate

---

## 12. Pilot Planı (2–4 hafta) ve Exit Criteria

### 12.1 Pilot ön koşulları (minimum)

- 1 hedef MCP client (agent/IDE/app)
- 1 hedef MCP server (en az 1–2 tool)
- Tenant/actor identity kaynağı:
  - stdio: local session/env mapping veya
  - streamable_http: mTLS veya OIDC bearer
- SIEM/OTel veya JSONL log toplama noktası (en az biri)

### 12.2 Pilot fazları (önerilen zaman çizelgesi)

**Hafta 1 — Visibility + Guardrails (W1 baseline)**
- PEP intercept canlı (stdio wrapper veya Streamable HTTP proxy)
- Allowlist + schema validation + param guards
- Baseline security (Origin invalid→403, auth policy-enforced)
- Rate limiting aktif
- Evidence akışı (attempted/blocked/executed event'leri)
- Bypass detection telemetry canlı
- İlk demo: Demo A (blocked + evidence) + Demo F (bypass detection)

Çıktılar: Top denied tools, top reason_codes, policy_eval_latency p95/p99, bypass_suspected_count

**Hafta 2 — Step-up approval + token primitive (W2 başlangıç)**
- approval_required devreye alınır (timeout + default deny + break-glass)
- delegation token pilot (token_jti evidence'da)
- replay cache pilot (LRU) + callback auth
- Evidence anchoring MVP

Çıktılar: approval_required_rate, approval_cycle_time p95, replay_blocked_count, chain_anchor_verification_pass_rate

**Hafta 3 — Shadow → Canary enforce (W3 pilot)**
- Eğer W3 hazırsa: shadow raporu + canary subset enforce + exception TTL + simulation CLI
- Eğer W3 henüz yoksa: enforce'u sadece "red tools" ile sınırlı canary yap

Çıktılar: shadow_false_positive_rate, policy_update_propagation_time, rollback_to_shadow_count

**Hafta 4 — Stabilizasyon + Sign-off**
- En çok sorun çıkaran kurallar düzeltilir
- Approval sürtünmesi optimize edilir
- Evidence sorguları (audit) test edilir: "who did what when", "what was blocked and why"

### 12.3 Pilot başarı metrikleri (minimum)

**Security:** blocked_actions_per_week, approval_required_rate, replay_blocked_count (W2+), breakglass_usage_count (düşük olmalı), bypass_suspected_count

**Operational:** p95_policy_eval_latency, p99_policy_eval_latency, gateway_uptime, approval_cycle_time_p95, SIEM/OTel ingestion success rate, rate_limit_triggered_count

**Evidence/Compliance:** attempted/blocked/approved/executed coverage, audit query time: "who did what when" < X seconds, chain_anchor_verification_pass_rate

### 12.4 Exit Criteria (pilot çıkış koşulları)

Pilot "başarılı" sayılabilmesi için:

1. **Kontrol edilen resmi yol** — MCP tool çağrıları SafeAgent PEP üzerinden geçiyor (kanıtlı).
2. **Ölçülebilir risk reduction** — Blocked risky actions / week metrikleri anlamlı düzeyde. En az 1 kritik riskli senaryo (export/delete vb.) blocked/approval ile kontrol altında.
3. **W2 security primitive kanıtı** — Replay demo kapalı: RC_REPLAY_DETECTED ile block. executed event'lerinde token_jti görünür.
4. **Operasyonel sürdürülebilirlik** — Approval timeout + default deny çalışıyor. Break-glass time-bound + reason mandatory. p95/p99 latency kabul edilebilir.
5. **Evidence/Audit hazır** — Canonical schema + hash-chain çalışıyor. SIEM/OTel'e taşınıyor. Audit sorguları hızlı cevaplanıyor.
6. **Sign-off** — Platform Engineering sign-off, Security Engineering sign-off, (Gerekirse) Compliance/Audit sign-off.

### 12.5 Pilot sonrası karar

Pilot başarılıysa:
- W3 (policy-as-code + shadow/canary/exception + simulation CLI) tam devreye alınır
- W4 (signed registry + publisher verification + migration deadline) ile "shadow tools" kapatmaya gidilir
- Sonraki genişleme: W5 modülleri (credential confinement, cross-tenant signal, WORM store)

---

## 13. Operasyonel Model (Deploy, HA, Logging, SIEM/OTel)

### 13.1 Deploy modları (MVP'den enterprise'a)

**A) stdio wrapper mode**
- Kullanım: local/subprocess MCP server'lar (IDE/agent side tool hosts)
- Artıları: hızlı pilot, minimum network karmaşası
- Eksileri: dağıtım "host seviyesinde" daha sıkı entegrasyon ister

**B) Streamable HTTP reverse proxy mode**
- Kullanım: remote MCP server'lar / kurum içi tool host'ları
- Artıları: merkezi kontrol, enterprise dağıtım kolaylığı, network policy/SSE/ZTNA ile doğal entegrasyon
- Eksileri: auth/mtls/oidc konfig gerektirir

**Backwards compatibility:** Deprecated HTTP+SSE transport opsiyonel.

### 13.2 Fail-closed davranışlar (deny-by-default operational)

Aşağıdaki durumlarda sistem fail-closed çalışır:
- policy engine unavailable → deny
- tool registry unavailable → deny (veya cached allowlist ile sınırlı allow; kurum politikasına göre)
- schema validation crash/error → deny
- auth invalid/missing (streamable_http) → deny
- token verifier error (W2+) → deny
- approval service unavailable → timeout+deny
- replay cache unavailable → deny (strict mode, default) veya allow + REPLAY_UNVERIFIED tag (degraded mode, policy ile seçilebilir)

### 13.3 HA / ölçeklenme (minimum baseline)

**W1–W2 (baseline):** Tek instance ile pilot mümkün. Evidence export local file (JSONL) veya OTel collector'a.

**W2+ (HA opsiyonu):**
- Replay cache: local LRU (single instance) / Redis (multi-instance)
- Approval adaptor: stateless HTTP callbacks + idempotency_key
- Gateway: çoklu instance + load balancer (streamable_http)

### 13.4 Konfigürasyon yönetimi (config-as-code)

Konfigürasyonlar versionlanabilir olmalı:
- allowlist/registry snapshot
- baseline security (Origin allowlist, auth modes)
- rate limits / budgets
- approval routing (approver_group, timeout)
- token TTL + time_bucket drift
- logging/export endpoints

Öneri: staging/prod ayrı config + canary rollout ile config/policy dağıtımı.

### 13.5 Logging, evidence ve retention

**Evidence log** SafeAgent'in "ürün çıktısıdır".
- Canonical schema + hash-chain
- Default redacted payload

Retention:
- kurum politikasına göre (örn 30/90/180 gün)
- regüle ortamlarda immutable/WORM opsiyonu (W5-C)

### 13.6 SIEM / Observability entegrasyonu

Desteklenen minimum export:
- JSONL (append-only log)
- OTLP (OpenTelemetry)

Önerilen OTel mapping:
- span: `safeagent.mcp.tool_call`
- attributes: tenant_id, actor_id, tool_id, decision, policy_id, policy_version, reason_codes, request_id, transport, token_jti (W2+)
- logs: evidence event JSON (redacted)

### 13.7 Audit sorguları (minimum)

Pilot ve prod'da şu sorular hızlı cevaplanabilmeli:
- Who did what when? (actor_id + time range)
- What was blocked and why? (decision=deny + reason_codes)
- Which tools are most risky? (top denied/approval_required tools)
- Break-glass usage? (RC_BREAKGLASS_USED)
- Bypass suspected? (bypass_suspected_count + credential_usage_unmatched)

### 13.8 Operasyonel SLO'lar (başlangıç hedefleri)

- Gateway uptime: hedef kurumla belirlenir (pilot: ölç, sonra hedef koy)
- policy_eval_latency_ms p99: < 50ms (inline, network hariç) — release gate
- approval_cycle_time p95: operasyonel hedef (örn < 60–120s)
- evidence_emit_success_rate: %99+ hedeflenir (buffer/queue ile)

### 13.9 Threat Model (Top 10) — Pratik Saldırı Yolları ve Kontroller

Bu bölüm; en olası/en yüksek etkili saldırı yollarını ve roadmap'in hangi fazda hangi kontrolü getirdiğini netleştirir.

**ATK-1 MCP Bypass (doğrudan API çağrısı) — KRİTİK**
- Risk: MCP katmanı atlanırsa SafeAgent kör kalır.
- W1 kontrolü (minimum): **bypass detection telemetry** (credential usage ↔ MCP action korelasyonu)
- W2 kontrolü (tasarım): **credential vaulting/brokering** tasarım dokümanı
- W3 kontrolü: credential brokering MVP (1 credential type)
- W5 opsiyonel (enforcement): egress/credential confinement tam kapatma
- Telemetry: bypass_suspected_count, credential_usage_unmatched_rate

**ATK-2 Token theft + replay**
- Kontrol (W2): req_hash action-bound + jti/nonce one-time + replay cache
- Ek DoD: "write-before-forward ordering" + replay race test gate
- Telemetry: replay_blocked_count, replay_race_condition_test_pass (release gate)

**ATK-3 Prompt injection → param escalation**
- Kontrol (W1): allowlist + schema validation + policy
- Ek (W1 P1): **param/pattern guardrails** (forbidden param patterns)
- Telemetry: param_pattern_blocked_count, schema_semantic_violation_count

**ATK-4 Evidence tampering / chain rewrite**
- Kontrol (W1): hash-chain tamper-evident
- Ek (W2): **periodic chain anchor** (signed checkpoint / external witness)
- Telemetry: chain_anchor_emit_count, chain_anchor_verification_pass_rate

**ATK-5 Approval hijack (callback spoofing)**
- Ek (W2): approval callback authentication (HMAC-signed webhook veya mTLS) + approver identity binding
- Telemetry: approval_callback_auth_fail_count, approval_callback_unsigned_reject_count

**ATK-6 Canonicalization ambiguity (oracle)**
- Ek (W2): canonicalization standardı **RFC 8785 (JCS)** + fuzz test gate
- Telemetry: canonicalization_fuzz_test_pass (release gate)

**ATK-7 Cross-tenant isolation breach**
- Ek (W1): tenant-scoped evidence routing (tenant → SIEM/OTel route mapping)
- Ek (W2): policy isolation assertion (tenant mismatch → alert + deny)
- Telemetry: cross_tenant_leak_detected_count (target=0), tenant_routing_mismatch_alert_count

**ATK-8 Approval flooding DoS**
- Ek (W1 P0): actor+tenant rate limiting (özellikle approval_required üretimini sınırla)
- Ek (W2 P1): approval priority + batching (benzer talepleri grupla)
- Telemetry: rate_limit_triggered_count, approval_queue_depth_p95, approval_batch_count

**ATK-9 Key compromise (token/publisher keys)**
- Ek (W2): KMS/HSM-backed key storage requirement + emergency rotation runbook + anomaly alert
- Telemetry: key_rotation_time_to_complete, anomalous_mint_alert_count, key_storage_compliance (boolean)

**ATK-10 Shadow tool persistence (grandfather tools)**
- Ek (W4): migration deadline + grace policy (amber→deny)
- Telemetry: legacy_allowlist_tool_count (target=0), migration_deadline_compliance_rate

---

## 14. Riskler, Mitigations, Bağımlılıklar

### 14.1 Teknik riskler

**R1) MCP interop çeşitliliği (client/server farklılıkları)**
- Risk: farklı MCP client'lar/agent framework'leri farklı davranışlar gösterebilir.
- Mitigation: W1'de stdio wrapper ile hızlı pilot; Streamable HTTP proxy ile enterprise standardizasyon; demo seti ile regresyon (A–H) "release gate" olsun.

**R2) Canonicalization mismatch (W2 req_hash false deny)**
- Risk: gateway/verifier canonical_input farklı üretirse req_hash mismatch olur.
- Mitigation: RFC 8785 (JCS) standardı sabitlendi; canonicalization tek shared modül; time_bucket toleransı (±1 bucket); token TTL kısa (60–120s); fuzz test release gate.

**R3) Replay cache consistency (multi-instance)**
- Risk: çoklu instance'da local LRU replay'i tam kapatmayabilir.
- Mitigation: HA ihtiyacında Redis opsiyonu; Redis SET NX + TTL=exp (atomik); write-before-forward ordering guarantee; replay_blocked_count ve cache backend telemetry ile izleme.

**R4) Approval akışı operasyonel sürtünme**
- Risk: approval gereksiz blokaj, kullanıcı memnuniyetsizliği.
- Mitigation: timeout + default deny; priority queue + batching; approver_group doğru seçimi (IdP group mapping); break-glass; approval_cycle_time_p95 dashboard; W3 shadow + simulation CLI ile approval kuralı kalibre et.

**R5) Policy false positives / trust kaybı**
- Risk: fazla deny/approval_required üretirse platform ekibi sistemi "disable" eder.
- Mitigation: W3 shadow→canary→enforce; exception TTL; reason_codes ile açıklanabilirlik; **policy simulation CLI** ile deploy öncesi etki ölçümü.

**R6) Evidence büyümesi / maliyet**
- Risk: yüksek event hacmi storage ve SIEM maliyetini artırır.
- Mitigation: payload default redacted (boyut küçük); sampling sadece metriklerde; evidence'da değil (audit); retention policy + compaction/archival.

**R7) Key management (W2 token signing, W4 publisher keys)**
- Risk: key rotasyonu, revoke süreçleri karmaşıklaşır.
- Mitigation: kid + current/previous key set + grace period; KMS/HSM-backed storage (raw key KABUL EDİLMEZ); revocation list (deny-by-default); key olayları evidence'a; emergency rotation runbook + tabletop drill.

### 14.2 Ürün/Go-to-market riskleri

**R8) "Gateway daha" olarak etiketlenme**
- Risk: alıcılar ürünü sıradan proxy/gateway sanabilir.
- Mitigation: positioning: "MCP Action Authorization / AI Action Control Plane"; demo D (replay) + Demo H (evidence verify) + evidence chain mutlaka göster; identity-first delegation vurgusu.

**R9) Registry adoption (W4) yavaş kalabilir**
- Risk: tool directory süreçleri ekiplerde sürtünme yaratabilir.
- Mitigation: CLI-first + minimal UI; registry olmadan allowlist ile başla (W1); W4'te mandatory migration deadline + grace period.

**R10) "Bypass" itirazı**
- Risk: "MCP'yi bypass edip direkt API çağırırsa?" sorusu satın alımı yavaşlatır.
- Mitigation: W1 bypass detection telemetry + Demo F; W3 credential brokering MVP; W5 full credential confinement; network/SSE/ZTNA entegrasyonu ile story güçlendirme.

### 14.3 Bağımlılıklar

**D1) Identity kaynağı**
- Streamable HTTP: OIDC bearer veya mTLS mapping (minimum) + group/role claim extraction
- stdio: local session/env mapping (minimum)

**D2) Approval altyapısı**
- Slack/Teams/Jira/Webhook seçeneklerinden en az biri
- Callback endpoint güvenliği (HMAC/mTLS) + idempotency

**D3) Observability altyapısı**
- JSONL log toplama veya OTel collector
- SIEM ingest (opsiyonel ama önerilir)

**D4) Registry datastore (W4)**
- Tool directory ve publisher metadata için DB (örn Postgres)
- Key storage (KMS/HSM-backed)

**D5) KMS/HSM (W2+)**
- Token signing keys için cloud KMS veya HSM backend
- Publisher signing keys (W4) için aynı standart

### 14.4 Risk sahipliği (ownership)

Öneri:
- Interop + transport riskleri → Platform Engineering owner
- Token/replay/key riskleri → Security Engineering owner
- Approval operasyonu → Platform+Security ortak owner
- Evidence/SIEM → Security+Compliance ortak owner
- Bypass detection + credential brokering → Security Engineering owner

### 14.5 Red Team Checklist (Pilot Öncesi)

Pilot'a çıkmadan önce internal red team bu checklist'i çalıştırır. P0 fail = pilot blocker. P1 fail = risk kabul + fix planı.

**Detaylı checklist:** `docs/redteam/REDTEAM_CHECKLIST.md`

**Özet:**
- **Katman 1: Enforcement Integrity** (RT-01..RT-10) — PEP doğruluğu: allowlist deny, schema deny, auth deny, origin deny, rate limit, fail-closed, approval timeout
- **Katman 2: Security Primitives** (RT-11..RT-20) — Token replay, binding mismatch, expired token, parallel replay race, callback auth, break-glass controls, evidence verify, key rotation
- **Katman 3: Operational Resilience** (RT-21..RT-30) — Redis unavailable, approval service unavailable, SIEM export failure, load test, tenant isolation, canary rollout/rollback, registry signing, bypass detection

**Evidence spot-check (EC-01..EC-05):** Her session sonunda — actor_id/tenant_id completeness, reason_code presence, hash-chain consistency, payload redaction, token_jti presence.

**Kurallar:**
- P0 fail = pilot blocker. Düzeltilmeden pilot başlamaz.
- P1 fail = risk kabul gerektirir. Security + Platform Engineering ortak imzası ile pilot başlayabilir ama fix timeline tanımlı.
- RT-01..RT-14 + RT-19 + RT-24/25 otomatize edilmeli (CI/CD release gate).
- Tam checklist: her faz release öncesi + 3 ayda bir regression.

---

## 15. Ekler (Appendix)

### 15.1 Reason Codes Dictionary (minimum)

SafeAgent kararları SIEM/audit için reason_codes ile açıklanır.

**W1 minimum set:**
- RC_TOOL_NOT_APPROVED
- RC_SCHEMA_INVALID
- RC_EXCESSIVE_SCOPE
- RC_APPROVAL_REQUIRED
- RC_APPROVAL_TIMEOUT
- RC_BREAKGLASS_USED
- RC_PII_SUSPECTED
- RC_ORIGIN_INVALID
- RC_AUTH_MISSING
- RC_AUTH_INVALID
- RC_INTERNAL_ERROR
- RC_RATE_LIMIT

**W2 minimum set (ek):**
- RC_REPLAY_DETECTED
- RC_TOKEN_BINDING_MISMATCH
- RC_CREDENTIAL_BROKER_BYPASS

**W4 minimum set (ek):**
- RC_SIGNATURE_INVALID
- RC_KEY_REVOKED

Not:
- reason_codes çoklu olabilir.
- Yeni reason codes gerekirse ilgili fazda eklenir ve bu sözlük güncellenir.

### 15.2 Tool Risk Class Standard (green/amber/red)

- **green:** düşük riskli tool'lar (default allow; policy ile scoped)
- **amber:** belirsiz/orta risk (default shadow ölçüm; sonra enforce kararı)
- **red:** yüksek risk (export/delete/payment/deploy vb.)
  - default approval_required (veya kurum politikasına göre deny)

### 15.3 Evidence Schema (özet)

Canonical evidence event schema şu alanları minimum taşır:
- timestamp, tenant_id, actor_id, agent_id
- transport (stdio|streamable_http)
- tool_id, tool_version, action, resource_scope
- decision, policy_id, policy_version, reason_codes
- request_id, token_jti (W2+)
- hash_prev, hash_curr (tamper-evident chain)
- rollout_mode (shadow|enforce) (W3+)
- payload default redacted

Detaylı şema ve örnekler: `docs/spec/EVIDENCE_EVENT_SCHEMA.md`

### 15.4 Delegation Token (özet)

W2+ token özellikleri:
- action-bound: req_hash (RFC 8785 JCS canonicalization)
- one-time: jti/nonce + replay cache (write-before-forward)
- kısa TTL: 60–120s
- verifier: req_hash match + replay detection
- signing: KMS/HSM-backed keys (raw key kabul edilmez)

Detay: `docs/spec/TOKEN_MODEL.md`

### 15.5 Approval Workflow (özet)

Approval prod-ready kuralları:
- timeout + default deny
- break-glass: time-bound + reason mandatory
- callback authentication: HMAC-signed webhook veya mTLS
- idempotency_key ile duplicate request önleme
- priority queue (red > amber > green) + batching
- smart routing: risk_class → approver_group (IdP group mapping)
- approval lifecycle evidence zinciri: attempted → approval_pending → approved → executed; timeout → blocked (RC_APPROVAL_TIMEOUT)

Detay: `docs/spec/APPROVAL_WORKFLOW.md`

### 15.6 Policy Model (özet)

Policy-as-code (W3) ile:
- shadow mode ("would-have-happened")
- canary enforcement
- exception TTL workflow
- drift görünürlüğü (policy_version)
- **policy simulation CLI** ("what-if" engine)

Detay: `docs/spec/POLICY_MODEL.md`

### 15.7 Credential Brokering Model (özet)

Credential brokering (W2 RFC → W3 MVP → W5 full):
- W2: mimari RFC + interface tanımı + threat model
- W3: 1 credential type (API key) broker MVP — tool credential'ı SafeAgent aracılığıyla alır (time-bound/one-time)
- W5-A: full vault entegrasyonu (HashiCorp Vault / cloud KMS) + egress confinement

Detay: `docs/spec/CREDENTIAL_BROKERING.md`

---

**— Doküman Sonu —**
**Sürüm:** 1.1 | **Son güncelleme:** 2026-02-26 | **Revizyon:** Architect Review (A–G) entegre edildi.
