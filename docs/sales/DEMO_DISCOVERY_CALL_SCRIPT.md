# Demo Discovery Call Script (30 Minutes)

## Flow Overview

### 1) Context (0–5 min)
- Kısa tanışma ve toplantı amacını netleştirme.
- Güvenlik pain point özeti:
  - Prompt-to-action güvenlik açığı
  - Tool execution kontrolü
  - Supply-chain riskleri
- Görüşmenin hedefini netleştir:
  - Pilot uygun mu?
  - Teknik sponsor kim?
  - İlk başarı kriteri nedir?

### 2) Risk Surface Mapping (5–15 min)
Amaç: “En kritik risk nerede?” haritasını çıkarmak.

- Mevcut architecture ve risk giriş noktalarını hızlıca çıkar:
  - Tool-calling hangi ürünlerde var?
  - Kimlik/tenant ayrımı nasıl yapılıyor?
  - Onay akışı otomatik mi, manuel mi?
  - Outbound/network politikası var mı?

### 3) Architecture Fit (15–25 min)
- SafeAgent’in potansiyel entegrasyon noktalarını map et:
  - Control-plane entegrasyonu
  - Worker izleme ve izolasyon gereksinimi
  - Skill doğrulama/scan akışı
  - Audit export ve loglama

- Teknik teknik değerlendirme:
  - Mevcut CI/CD ile uyumluluk
  - Kimlik & secret yönetimi
  - Veri izolasyonu / tenant sınırları
  - Ölçeklenebilirlik beklentisi

### 4) Next Step Alignment (25–30 min)
- Decision criteria:
  - Pilot hedefleri
  - Başarı ölçümü
  - Timeline ve owner tanımı
- Net next step:
  - Discovery sonrası doküman gönderimi
  - Pilot kickoff tarihi
  - Tekrar görüşme planı

## 12 Critical Questions

1. Tool usage: agentic workflow’larda hangi model/hizmetler kullanılıyor?
2. Risk profile: geçmişte AI-originated güvenlik olayı yaşandı mı?
3. Approval flow: red/potentially-dangerous aksiyonlar nasıl onaylanıyor?
4. Network egress: outbound trafik için allowlist veya proxy kısıtlaması var mı?
5. Tenant model: tenant ayrımı ve policy map’i nasıl uygulanıyor?
6. Scope enforcement: token ve rol kontrolü gerçek zamanlı mı?
7. Secret management: private key/credentiallar nerede saklanıyor?
8. Audit export: logs hangi formatta ve kaç gün saklanıyor?
9. Incident response: kötü bir event sonrası hangi metrik/kanal ile müdahale ediliyor?
10. CI maturity: test ve doğrulama hangi sıklıkla çalışıyor?
11. Supply-chain: skill/paketler için imza veya scan zorunluluğu var mı?
12. Procurement: güvenlik yatırım bütçesi bu çeyrekte ne ölçekte onaylanabiliyor?

## Call Close Template

- "Bugün netleştirdiğimiz en kritik 3 risk var: [risk1], [risk2], [risk3]."
- "Bu çerçevede 2–4 haftalık SafeAgent pilotunu şu hedeflerle açabiliriz: [KPI1], [KPI2], [KPI3]."
- "Bir sonraki adım: [pilot lead] ve [security lead] ile kısa teknik fit oturumu, ardından pilot teklifini paylaşacağım."
- "Pilotun kapanışında success kriterleri: policy bypasssuz güvenli çalıştırma, deny-by-default egress, audit completeness ve verify gate geçişi olacak."
