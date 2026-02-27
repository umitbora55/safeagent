# Market Positioning

## Problem

Birçok AI entegrasyonu “chat aracı” mantığında kalıyor: LLM’in ürettiği çıktıyı doğrudan çalıştırılıyor.  
Asıl risk burada oluşuyor: **tehdit öncesi filtreleme yoksa**, güvenlik politikanız yalnızca metin seviyesinde kalır ve araç çağrısı doğrudan sistem etkisi yaratır.

## Market Category

SafeAgent **AI Execution Control Plane** kategorisini hedefler; yani:
- prompt güvenliği,
- araç/skill authorization,
- network ve yetki izolasyonu,
- audit ve regresyon güvenlik testlerini tek bir platformda birleştiren kontrol katmanı.

Most AI platforms optimize for generation quality. SafeAgent optimizes for execution safety.

## Competitive Differentiation

### Policy-before-tool enforcement
SafeAgent’da araç çağrısı “izin verildi” demeden önce policy ve token/scope kuralları çalışır.  
Diğer platformlar çoğu zaman çıktı filtreleme odaklıdır; SafeAgent ise eylem öncesi blokaj sağlar.

### Zero-trust multi-node control
Kontrol düzlemi ile worker ayrık çalışır; çoklu tenant, izinsiz egress veya yetki taşması senaryolarını platform seviyesinde sınırlar.

### Signed skill marketplace
Skill dağıtımı “güvenli paket” mantığıyla yapılır: manifest, imza ve statik tarama olmadan yükleme mümkün değildir.

### Adversarial regression lab
Jailbreak, context poisoning ve differential canary testleri gate’lere entegre edilmiştir.  
Yeni bir bulgu otomatik olarak regresyon test mantığına dönüştürülebilir.

### Deterministic verify gates
`verify-v2` yalnızca unit/integration test sonuçları değildir; güvenlik kapanış testleri, ağ izolasyonu ve marketplace doğrulamalarını kapsayan kapatılabilir bir dağıtım kalitesi ölçümüdür.

## Position Statement

SafeAgent, klasik “LLM wrapper”lardan farklıdır; çünkü yalnızca model cevaplarını yönetmez, **modelin sistem üzerinde ne yapabileceğini kontrol eder**.

## Messaging

- OpenClaw/benzeri araçlar: çoğunlukla chat/agent seviyesinde birer orkestratördür.  
- SafeAgent: güvenli eylem platformudur; policy, izolasyon ve supply-chain güvenliği tek çatıdadır.
