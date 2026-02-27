# PHASE 2.3 — DNS Pinning + Redirect Revalidation Hardening (Worker egress)

## Ortam
- `uname -a`: `Darwin 192.168.1.142 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64`
- `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`
- Platform: `non-Linux` (Linux runner’da egress testleri `egress-tests-v2` hedefi ile çalışacaktır)

## Threat model
- **DNS rebinding**: ilk allowlist’i geçen host sonradan farklı IP’ye çözülüp bypass sağlama.
- **Redirect abuse**: `Location` ile yeni host/port/scheme’e geçiş.
- **Parser edge**: `http://127.0.0.1@evil.com` gibi kullanıcı bilgisi içerikli URL trick’i.

## Mitigation
- NetworkPolicy tek kaynaktır:
  - `AllowedTarget`
  - `NetworkPolicy`
  - `DnsResolver` trait’i
- `DnsResolver` katmanı eklendi:
  - `pub trait DnsResolver { fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>; }`
  - `SystemDnsResolver` varsayılan sistem çözümleyici olarak kullanılmaya devam eder.
- Resolver injection ile hermetik test:
  - `resolve_and_validate_with_resolver`
  - `enforce_on_request_with_resolver`
- Pinning:
  - `dns_pin=true` ise ilk çözümleme kaydı tutulur, sonraki çağrılar karşılaştırılır (`PinnedResolution` ile context üretilir).
- Redirect revalidation:
  - `validate_redirect_target` base URL + `Location` birleşimi sonrası policy ve DNS kontrolünü yeniden yapar.
- Parsing hardening:
  - `validate_url` kullanıcı bilgisi (`username@`) ve `file://` şemasını reddeder.
  - `localhost` ve metadata IP (`169.254.169.254`) engeli korunur.

## Yapılan değişiklikler
- `platform/worker/src/network_policy.rs`
  - `DnsResolver`, `SystemDnsResolver`
  - `resolve_and_validate`, `resolve_and_validate_with_resolver`
  - `enforce_on_request`, `enforce_on_request_with_resolver`
  - `validate_redirect_target` + private/loopback/link-local/metadata engelleri
  - unit testler:
    - `rejects_userinfo_trick`
    - `redirect_to_allowed_host_is_allowed`
    - `dns_rebinding_is_detected_when_pin_enabled`
    - `rejects_file_scheme`
- `platform/worker/tests/egress_policy_tests.rs`
  - test sayısı: 8
  - yeni Linux entegrasyon testleri:
    - `dns_rebinding_detected_with_pinning`
    - `userinfo_trick_blocked`

## Doğrulama
- `cargo clippy --manifest-path platform/worker/Cargo.toml --all-targets -- -D warnings` ✅
- `cargo fmt --all --check --manifest-path platform/worker/Cargo.toml` (verify-v2 yolu ile) ✅
- `just egress-tests-v2` (Linux target: egress-policy testlerini koşturur; bu ortamda non-Linux)
- `just verify-v2` (tam doğrulama zinciri)

## Log excerpts

`logs/egress_tests_v2_phase_2_3.log`:
```text
egress-tests-v2: Not supported on non-Linux platform
```

`logs/verify_v2_phase_2_3.log` (son satırlar):
```text
just egress-tests-v2
egress-tests-v2: Not supported on non-Linux platform
just sandbox-tests-v2
sandbox-tests-v2: Not supported on non-Linux platform
...
test result: ok. 2 passed; 0 failed; 0 ignored; 5 filtered out; finished in 1.03s
```

## Not
- Bu rapor, Linux runner’da “running 8 tests” ve `test result: ok. 8 passed` doğrulamasını bekler.
- Linux CI’da yeni test sayısı hedefinde (>=8) ve pass olması için bu dosyada ek run logu ile güncelleme yapılacaktır.
