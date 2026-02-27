# Ideal Customer Profile (ICP)

## Ideal Customer Profile

### 1) Company Size
- 200–5000 çalışan
- 20+ geliştirici/ML mühendisle AI ürün geliştiren ekip
- En az 3 farklı iş birimi (güvenlik, platform, ürün)

### 2) AI Usage Intensity
- API-first ürünleşmiş AI kullanım
- Agentic workflow veya tool-calling aktif kullanım
- Haftada yüzlerce-yüzbinlerce otomatik çalıştırma
- Kural bazlı policy ve onay süreçlerine geçmişte ihtiyaç doğmuş olması

### 3) Risk Profile
- Müşteri tarafında AI araçlarına yönelik güvenlik olay geçmişi
- Regülasyon baskısı (finans, SAAS, sağlık benzeri alanlar)
- Supply-chain veya bağımlılık yönetimi konusunda geçmişte güvenlik endişesi
- Üretim egress/kötüye kullanım riskinin teknik olarak kritik olduğu ortam

### 4) Tech Stack Maturity
- Containerized deployment (Kubernetes veya VM)
- CI/CD altyapısı düzenli çalışır
- Log ve observability mevcut
- Identity veya mTLS’ye yaklaşımı olan orta-ileri seviye güvenlik disiplini
- Yeni güvenlik katmanını ekleme yetkisine sahip teknik ekip

### 5) Buying Signals
- Governance ve guardrail arayan platform ekipleri
- CISO/AI Platform Lead’in güvenlik yatırım gündemi
- Pilot için zaman ayırma kabiliyeti ve owner atama

## Disqualified Profiles

### 1) Başlangıç aşaması, düşük risk profil
- 20 kişiden az teknik ekip
- AI henüz PoC aşaması ve tool-calling yok
- Güvenlik fonksiyonu operasyonel olarak kurumsallaşmamış

### 2) Kısıtlı erişim ve süreç yetersizliği
- Merkezi güvenlik ownership yok
- Approval workflow kurulumu mümkün değil
- Audit/loglama kültürü zayıf

### 3) Uyum engeli yüksek
- Çalışanların yetki ve kimlik yönetimi düzensiz
- Network egress politikalarını tamamen engellenebilir halde değil
- 3. taraf bağımlılıkların denetlenemeyeceği bir model

## Why this ICP first

ICP odaklı seçim, kısa sürede gerçek değer üretir:
- risk yüzeyi netteyse, politikalar hızlı oturur.
- teknik ekip yeterliyse pilot hızlanır.
- güvenlik metrikleri net bir şekilde ölçülür.
