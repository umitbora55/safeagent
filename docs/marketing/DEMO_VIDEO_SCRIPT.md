# Demo Video Script (5–7 minutes)

## Title
SafeAgent: AI Execution Firewall in 7 Steps

## Audience
- CIO/CISO
- AI Platform & Security leads
- Security engineering teams

## Duration target
Total: 5–7 minutes

---

## Scene 1 — Problem (0:00–0:45)
### Visual
- Screen: blank code diff vs production incident timeline.
- Overlay text: "LLM output is not the endpoint. Execution is the endpoint."

### Narration
"Çoğu AI güvenlik yaklaşımı model davranışını filtreler, ancak eylemi kontrol etmez. SafeAgent bu noktada devreye girer: modelin verdiği talimatı çalıştırmadan önce eylem güvenliğini doğrular."

### On-screen
- 1 cümle: Prompt injection and tool misuse risk.

---

## Scene 2 — Install and run demo_local (0:45–1:45)
### Visual
- Terminal: `scripts/demo_local.sh`
- Show output: control-plane start, worker start, safe execute success.

### Script
- `cd /workspace/safeagent`
- `./scripts/demo_local.sh`

### Narration
"Tek komutla local demo ile güvenli bir kontrol düzlemi ve worker’ın birlikte çalışmasını gösteriyoruz."

### Outcome
- İlk güvenli execute başarılı.

---

## Scene 3 — Red action approval (1:45–2:45)
### Visual
- Bir red action isteği simülasyonu.
- UI/CLI ekranında onay gereksinimi.

### Script
- Safe red action request trigger.
- Show pending state.
- Approve flow.

### Narration
"Kırmızı riskli aksiyonlar otomatik olarak doğrudan çalışmaz; onay zinciri gereklidir."

### Outcome
- Onaysız deneme fail.
- Onay sonrası güvenli çalıştırma.

---

## Scene 4 — Egress block demo (2:45–3:45)
### Visual
- Worker’dan 1.1.1.1 gibi allowlist dışı hedefe çağrı denemesi.
- Log ekranında block event.

### Narration
"SafeAgent’ın varsayılan davranışı deny-by-default’dır. Allowlist yoksa outbound erişim olmaz."

### Outcome
- Network deny mesajı + blocked event.
- İkinci test: allowlisted host ile başarılı erişim.

---

## Scene 5 — Marketplace scan fail demo (3:45–4:45)
### Visual
- `skill verify/scan` komutu.
- Zararlı örnek bir paket (ör. tersine güvenlik komutu) scan fail.

### Script
- Paket yükleme girişimi
- Scan fail output

### Narration
"Supply-chain riskini sadece download sonrası değil, yükleme öncesinde, deterministic kurallarla engelliyoruz."

### Outcome
- Scan failed + install denied.

---

## Scene 6 — Adversarial gate demo (4:45–5:45)
### Visual
- `just adversarial-check-v2`
- `just poison-check-v2`
- `just diff-check-v2`

### Narration
"CI güvenlik kapıları sadece bir test değil; her release’de zero-regression hedefiyle çalışan otomatik saldırı senaryo setidir."

### Outcome
- 0 finding / threshold passed.

---

## Scene 7 — Audit verify (5:45–6:30)
### Visual
- audit event log viewer + verify command.
- show last events timeline.

### Script
- `just verify-v2`
- Security log summary.

### Narration
"Güvenlik bir özellik değil; süreçtir. İzin, red action, egress ve skill paketleri tek doğrulanabilir pipeline’da izlenir."

### Outcome
- Deployment-ready confidence.

---

## Closing (6:30–7:00)
### Visual
- Pricing and contact CTA.

### Narration
"SafeAgent ile modelinizin ne yapabileceğini değil, ne yapamayacağını da güvenle tanımlayın."

### CTA
- Start free pilot
- Request architecture review
