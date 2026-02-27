# SafeAgent — AI Execution Firewall

## Hero
**AI tools should not have direct system access.** SafeAgent enforces that boundary.

## 3 Ana Değer Önerisi

- **Policy-first güvenlik:** Her araç çağrısı önce policy, scope, onay ve güvenlik kontrollerinden geçer.  
- **Gerçek izolasyon:** Worker süreçleri kernel seviyesinde izole edilir; egress, sistem kaynakları ve yetkiler kısıtlıdır.  
- **Kanıtlanabilir güven:** Deterministik verify gate, lab tabanlı saldırı simulasyonları ve güvenlik denetimleri ile her sürüm test edilir.

## How It Works (4 adım)

1. **Define:** Güvenlik policy’nizi, tenant limitlerini ve approval kurallarını yapılandırın.  
2. **Execute:** İstemci bir beceri çağrısı yapar; kontrol düzlemi kimlik, kapsam ve token doğrulaması yapar.  
3. **Enforce:** İstek worker’a yalnızca güvenli olduğunda ve egress/policy kuralları uygunsa iletilir.  
4. **Observe:** Tüm kararlar ve güvenlik olayları audit loglarında kalıcı şekilde izlenir ve raporlanır.

## Security by Design

- **Kernel-level isolation:** `no_new_privs`, capability drop, seccomp, RLIMIT ve (Linux’ta) ek izolasyon katmanları.  
- **Network lockdown:** Varsayılan deny-all egress; sadece allowlist hedeflere çıkış.  
- **Supply-chain kontrolü:** Skill paketleri imzalanır, taranır ve doğrulanmadan yüklenmez.  
- **Sürekli test:** Adversarial lab’ler (jailbreak, context poisoning, diff-canary, replay) release akışına bağlı.

## Ecosystem + Marketplace

SafeAgent sadece bir kontrol katmanı değil; dağıtılabilir bir ekosistemi de kurar:
- Control-plane + worker mimarisi
- Skill marketplace araç zinciri (paketleme, imza, tarama)
- Skill SDK’ları (Rust + TypeScript)
- CI’ye bağlı güvenlik kapıları (`verify-v2` + `*-check-v2` hedefleri)

## Call to Action

İhtiyacınız olan tek şey: **güvenli bir AI execution düzlemi**.  
SafeAgent’i kurun, dağıtın ve AI iş akışlarınızı denetlenebilir şekilde açın.
