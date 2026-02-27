# SafeAgent Desktop — Kolay Kurulum Rehberi

Bu doküman, SafeAgent Desktop’ı tek adımda kurup çalıştırmak için hazırlanmıştır.  
Kullanıcıdan terminal komutu istemez; kurulum asistanı dosya bazlıdır.

## 1) Paket Dosyasını İndir

`dist/desktop/<os>/` klasöründeki dosyalar hazırda kurulum paketidir.

Beklenen dosyalar:

- `safeagent-desktop`
- `safeagent-control-plane`
- `safeagent-worker`
- `safeagent-skill`
- `safeagent-skill-registry-server`
- `config/dev.env.example`
- `config/staging.env.example`
- `config/prod.env.example`

## 2) Klasörleri Taşı

1. `dist/desktop/<os>/` içeriğini bir klasöre kopyalayın (ör. `~/Applications/SafeAgent`).
2. `config/*.env.example` dosyalarından birini seçin ve ortamınıza göre kopyalayın.
   - Örn: `cp config/dev.env.example ~/.safeagent-desktop/.env`

## 3) Güvenli Modlarla Başlat

Desktop uygulama içinde:

- Start düğmesi ile PKI otomatik olarak oluşturulur.
- “Güvenli Mod”, “Verified Publisher”, “Allowlist” ve “Advanced Logs” ayarları otomatik olarak kalıcı şekilde `~/.safeagent-desktop/settings.json` içine kaydedilir.
- Her şey çalıştıktan sonra tek ekranda renk durumu görünür:
  - Yeşil: Güvenli çalışıyor
  - Sarı: Yeniden başlatma denemesi var
  - Kırmızı: Maksimum crash recovery’yi geçti, manuel restart gerekli

## 4) Güncelleme (Updater) Notu

Desktop arayüzündeki **Update Check** butonu, lokal manifest’i (`update-manifest.json`) parse eder.
Şu an için bu bir “placeholder” davranışıdır:

- Manifest var ise sürüm kontrolü yapılır.
- İleri adım: imza doğrulaması + yayın manifesti üzerinden gerçek güncelleme indirme.

Örnek manifest:

```json
{
  "version": "0.1.0",
  "notes": ["Signed release checks and staged rollout are planned in packaging step."]
}
```

## 5) İmza (Signing) ve Dağıtım Notu

Paketleme hattında bu adımlar uygulanmalıdır:

- macOS: `codesign` + notarization
- Windows: `signtool`
- Linux: `.deb` / `.AppImage` imzalı dağıtım

Mevcut repo scripti `scripts/build_desktop_release.sh` bu placeholder’ları ve manifest örneklerini üretir.

## 6) Yardım

- Son adım olarak logları kontrol edin:
  - `~/.safeagent-desktop/logs/`
- Ayarları gerektiğinde **Simple Settings** panelinden 4 toggle ile değiştirin.
