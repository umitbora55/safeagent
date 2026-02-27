# PHASE 2.2.1 — Rustls CryptoProvider Fix

## Amaç ve Kapsam
`verify-v2` akışındaki `Could not automatically determine the process-level CryptoProvider` panic’ını ortadan kaldırmak.

## Yapılan Değişiklikler

- `platform/control-plane/Cargo.toml`
  - `rustls` -> `default-features = false`, `features = ["ring", "std", "tls12"]`
  - `tokio-rustls` -> `default-features = false`, `features = ["ring", "tls12", "logging"]`
  - `hyper-rustls` -> `default-features = false`, `features = ["http1", "tls12", "ring", "logging", "native-tokio", "webpki-tokio"]`
  - `dev-dependencies.hyper-rustls` aynı şekilde ring-only profile’a alındı.

- `platform/worker/Cargo.toml`
  - `rustls` -> `default-features = false`, `features = ["ring", "std", "tls12"]`
  - `tokio-rustls` -> `default-features = false`, `features = ["ring", "tls12", "logging"]`
  - `hyper-rustls` -> `default-features = false`, `features = ["http1", "tls12", "ring", "logging", "native-tokio", "webpki-tokio"]`

- Runtime provider install
  - `platform/control-plane/src/lib.rs`: TLS yapılandırıcı fonksiyonlarda `ensure_default_crypto_provider()` eklendi.
  - `platform/control-plane/src/main.rs`: process başlangıcında `ensure_default_crypto_provider()` çağrısı eklendi.
  - `platform/worker/src/lib.rs`: TLS server config üretiminde provider kurulum guard’i eklendi.
  - `platform/worker/src/main.rs`: process başlangıcında ve local `build_client_config` içinde provider kurulum guard’i eklendi.

- Provider seçimi: `ring` provider kullanılarak tek sağlayıcıya zorlanmıştır.

## Test Sonuçları

- `just verify-v2` (log: `logs/verify_v2_phase_2_2_1.log`) PASS.

Sonuç özeti:

```text
running 7 tests
...
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.04s
...
just egress-tests-v2
egress-tests-v2: Not supported on non-Linux platform
just sandbox-tests-v2
sandbox-tests-v2: Not supported on non-Linux platform
...
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Not
- Linux dışında egress/sandbox hedef testleri mevcut olarak atlıyor (`Not supported`), ancak bu fazdaki fix yalnızca `verify-v2` panik kaynağı olan Rustls sağlayıcı seçimi üzerinde odaklandı.
