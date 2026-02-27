# PHASE 2.2 — Network Namespace + Egress Policy (Default Deny)

## Ortam
- `uname -a`: `Darwin 192.168.1.142 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64`
- `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`
- Platform: non-Linux (macOS), bu yüzden Linux-only egress/sandbox testleri `Not supported` olarak döndü.

## Yürütülen modüller
- `platform/worker/src/network_policy.rs`
  - `AllowedTarget`
  - `NetworkPolicy`
  - `validate_url`
  - `validate_host_port`
  - `resolve_and_validate`
  - `enforce_on_request`
  - `validate_redirect_target`
- `platform/worker/src/lib.rs`
  - `WorkerState` içine `egress_policy` eklendi
  - `with_control_plane_and_policy` eklendi
  - `url_fetch` skill’i için `execute_network_fetch` entegrasyonu
- `platform/worker/src/main.rs`
  - Başlatmada `NetworkPolicy::from_env()` ile politikayı bağlama
- `platform/worker/src/sandbox.rs`
  - `WORKER_ENFORCE_NETNS` ile opsiyonel `CLONE_NEWNET`
- `platform/worker/tests/egress_policy_tests.rs`
  - Integration testleri (Linux target): 5 test
- `Justfile`
  - `egress-tests-v2` hedefi eklendi
  - `verify-v2` içinde `just egress-tests-v2`
- `.github/workflows/platform-v2.yml`
  - `Run egress-tests-v2` adımı ve logların artifact’a eklenmesi

## Test sonuçları (gerçek loglardan)

### egress-policy unit testleri
- Komut: `cargo test --manifest-path platform/worker/Cargo.toml network_policy -- --nocapture`
- 7 unit test (`platform/worker/src/network_policy.rs::tests`)
- Durum: PASS

### egress integration (Linux-only hedef)
- Komut: `cargo test --manifest-path platform/worker/Cargo.toml --test egress_policy_tests -- --nocapture`
- Bu ortamda Linux dışında çalıştırıldığı için: `0 passed` / `0 failed` / 0 filtered?  
  `platform/worker/tests/egress_policy_tests.rs` testleri `#[cfg(target_os = "linux")]` ile compile edilmiyor.
- `just egress-tests-v2` log excerpt:
  - `egress-tests-v2: Not supported on non-Linux platform`

### sandbox integration (Linux-only hedef)
- Komut: `cargo test --manifest-path platform/worker/Cargo.toml -- --` + ilgili test filtreleri
- `just sandbox-tests-v2` log excerpt:
  - `sandbox-tests-v2: Not supported on non-Linux platform`

### verify-v2
- Komut: `just verify-v2`
- Yerel logda `FAIL`:
  - `Could not automatically determine the process-level CryptoProvider from Rustls crate features.`
  - `error: Recipe verify-v2 failed on line 211`
- Not: Bu hata, Phase 2.2 kapsamı dışındaki kontrol-plane test yürütümünden geliyor.

## Doğrulama çıktıları (isteğinize göre)

### `logs/egress_tests_v2.log` (son 40 satır)
```text
egress-tests-v2: Not supported on non-Linux platform
```

### `logs/sandbox_tests_v2.log` (son 40 satır)
```text
sandbox-tests-v2: Not supported on non-Linux platform
```

### `logs/verify_v2_phase_2_2.log` (son 40 satır)
```text
error: Recipe `verify-v2` failed on line 211 with exit code 101
```

## Notlar
- Linux runner’da bu hedeflerin `5/5` test ve `running 5 tests` çıktısı beklenir.
- Phase 2.2 tesliminde doğrulanmamış bir nokta: bu ortamda Linux doğrulaması koşulamadı; Linux CI loglarıyla `egress-tests-v2`/`sandbox-tests-v2` PASS ve `verify-v2` PASS doğrulaması alınmalı.
