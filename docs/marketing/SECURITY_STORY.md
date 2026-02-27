# SafeAgent Güvenlik Hikayesi

## Threat Model

Hedef tehditler:
- prompt injection ve tool-use yanlış yönlendirmesi,
- yetkisiz egress / SSRF benzeri çıkış denemeleri,
- key-compromise ve token replay riskleri,
- supply-chain tarafından kötü amaçlı skill dağıtımı,
- policy bypass ve approval devre dışı bırakma.

SafeAgent assumes that model output is untrusted by default and treats all generated instructions as potentially malicious until proven safe.

Bu nedenle güvenlik “tek bir bileşene” bırakılmaz; aynı istekte birden fazla bariyer zinciri kurulur.

## Isolation Layers

1. **Control-plane karar katmanı**
   - identity doğrulaması, tenant bilgisi ve token claim doğrulaması.
   - işlem mantığı: policy check + scope check + onay.
2. **Worker execution isolation**
   - Linux üzerinde kernel seviyesinde izolasyon ve sistem çağrı filtreleme.
   - sistem kaynak limitleri ve yetki azaltma.
3. **Network policy layer**
   - Varsayılan deny-all.
   - host/port allowlist zorunlu.
   - private network ve metadata IP engelleri.
4. **Runtime telemetry**
   - karar logları ve audit eventleri.

## Egress Lockdown

- Outbound trafik yalnızca policy allowlist ile mümkündür.
- DNS pinning ve re-validate davranışı ile hedef dönüştürme / redirect riskleri azaltılır.
- metadata IP, loopback, link-local ve private bloklar bloklanır.

## Key Rotation + Secret Management

- Key set yaklaşımıyla imza doğrulama yapılır; aktif + geçmiş anahtarlar güvenli geçiş sağlar.
- Secret yönetimi için vault/file abstractions ile private key yaşam döngüsü denetlenir.
- JWKS cache ve kid tabanlı doğrulama ile doğrulama tarafında backward-compatibilite korunur.

## Audit Integrity

- İstemci ve worker işlemlerine dair kararlar tutarlı formatta loglanır.
- Reddedilen ve onaylanan her aksiyonun kanıtı denetlenebilir şekilde saklanır.
- SIEM/export akışları için operasyonel bir formatta export edilebilirlik hedeflenir.

## Supply Chain Protection

- Skill marketplace paketleri imza ve tarama ile doğrulanmadan kabul edilmez.
- Manifest doğrulama, dosya allowlist’i ve statik kötüye kullanım kalıpları engellenir.
- registry flow’da hem server hem istemci seviyesinde yeniden doğrulama yapılır.

## Adversarial Lab Evidence

Genişletilebilir lab kapıları, yalnız geliştirme değil güvenlik kapanış standardı olarak çalışır:
- jailbreak fuzzing,
- context poisoning simulation,
- canary leak detection,
- exploit replay.

Amaç, yeni bulguları tekrar test edilebilir ve kalıcı regresyon halinde izlenebilir hale getirmektir.

Every release must pass deterministic adversarial gates (jailbreak, poisoning, differential, replay) with zero regression findings before deployment.
