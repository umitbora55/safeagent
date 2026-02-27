# PHASE 5.3 — Network Registry MVP (Secure Distribution)

## Etki
- `safeagent-skill-registry-server` adında yeni bir registry HTTP sunucusu eklendi.
- Package imza doğrulama + static scan, artık sadece CLI’de değil ağ üzerinden publish/download akışında da zorunlu.
- `marketplace-check-v2` pipeline’dan bağımsız `registry-check-v2` gate’i eklendi.
- CI (`platform-v2`) içinde `registry-check-v2` logu artık ayrı job ile üretiliyor.

## Registry API ve akış

### Sunucu endpointleri
- `POST /publish`
  - Multipart parçaları: `manifest`, `payload`, `signature`, `checksums`.
  - Ekstra alan: `channel` (`stable`|`canary`).
  - Sunucu tarafında:
    - signature doğrulama (`safeagent-skill-registry` ile)
    - static scan
    - kataloğa ekleme.
- `GET /skills`
  - Kayıtlı skill kimliklerini döndürür.
- `GET /skills/{id}/versions`
  - O skill’in katalogdaki sürümlerini listeler.
- `GET /skills/{id}/{version}/download`
  - Paket arşivini `application/gzip` olarak indirir.
- `GET /skills/{id}/reputation`
  - skor hesapları (`verified`, `scan_clean`, `download_count`, `reported_malicious`) üzerinden `score` üretir.

## CLI entegrasyonu (`skill` komutu)
- Yeni komutlar:
  - `publish --server <url> --pkg <path> [--channel stable|canary]`
  - `list --server <url>`
  - `pull --server <url> --id <id> [--version <v>|--channel <stable|canary>] --out <file>`
- `pull` akışı:
  - önce sunucudan indirilir,
  - yerelde paket açılır,
  - `scan_skill` + `verify_skill` tekrar çalışır (defense-in-depth).

## Reputation modeli
- `score = verified_bonus + download_count/100 - malicious_penalty`
  - `verified_bonus`: publisher doğrulama varsa +15 (varsayılan kural).
  - `download_count`: her 100 indirime +1.
  - `reported_malicious`: varsa -50.
- Bu model `GET /skills/{id}/reputation` ile döner.

## Canary/kanal modeli
- Paket kanalı metadata olarak `channel=stable|canary` olarak saklanır.
- `pull` komutu varsayılan olarak `stable` seçer.
- `channel` parametresi ile belirli canary sürümü istenebilir.

## Proof & doğrulama

### Komutlar
- `just registry-check-v2`
- `just verify-v2`

### `registry-check-v2` log excerpt (`logs/registry_check_v2_linux.log`, last 40)
```text
running 1 test
test registry_publish_and_reject_flows ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
```

### `verify-v2` log excerpt (`logs/verify_v2_linux.log`)
```text
just registry-check-v2
cargo test --manifest-path crates/skill-registry-server/Cargo.toml
...
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
```

