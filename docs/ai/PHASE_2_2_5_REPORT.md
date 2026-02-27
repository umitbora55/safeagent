# PHASE 2.2.5 — Capability Drop: Child-Only (Production Correctness)

## Ortam
- `uname -a`: `Darwin Umit-MacBook-Air.local 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:49:24 PST 2026; root:xnu-12377.81.4~5/RELEASE_ARM64_T8132 arm64`
- `rustc -V`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`
- Platform: `non-Linux` (child-only sandbox testleri yalnızca Linux’ta koşuyor)

## Eski davranış vs Yeni davranış
- Eski:
  - `capset` mantığı, child/parent ayrımı olmadan çalışabilirdi ve çok-thread’li parent’ta sessiz hatalar olabilir.
  - `test_capabilities_dropped`, parent sürecinin durumuna bakarak yanlış pozitif/yanlış negatif üretebilirdi.
- Yeni (2.2.5):
  - `platform/worker/src/sandbox.rs` içinde sandbox kurulum sırası sadece child’da uygulanır:
    `prctl(no_new_privs)` → `capset drop-all` → `rlimits` → `seccomp`.
  - `drop_capabilities()` fonksiyonu yalnızca child-a özel iç fonksiyon adıyla (`drop_capabilities_child_only`) kullanılıyor; parent’ta çağrı kalıntısı kaldırıldı.
  - `run_isolated_child(...)` hata durumunda child’dan hatayı pipe ile parent’a iletir, sessiz başarı döndürmez.
  - Child’da çalışan probe fonksiyonu eklendi: `run_probe_task_without_seccomp(...)`.
  - `test_capabilities_dropped` artık cap durumunu child içinde `/proc/self/status` okuyarak doğruluyor.

## Neden multi-thread parent’da capset yanlış
- Çoklu thread’li process’te capability set yapısı atomik değildir; threadlerin farklı yetki durumu güvenilir davranmayabilir.
- Parent’da drop yapılırsa worker’ın runtime threadleri etkilenebilir; child’da tek thread bağlamı daha doğru bir izolasyon sağlar.
- Bu nedenle sandbox sekansı fork sonrası child’da çalıştırılarak deterministik güvenlik modeli kuruluyor.

## Değişiklikler
- `platform/worker/src/sandbox.rs`
  - `sandbox_setup`: sıra güncellemesi ve parametreyle seccomp kontrolü.
  - `drop_capabilities_child_only` iç fonksiyonuna dönüş ve parent API’lerinden ayrıştırma.
  - `run_sandboxed_skill` child ile çalışır ve sadece child’da sandbox kurar.
  - Linux + non-Linux test probing API’si: `run_probe_task` ve `run_probe_task_without_seccomp`.
- `platform/worker/src/lib.rs` (Linux testleri)
  - `test_no_new_privs_set`: child probe ile doğrulama.
  - `test_capabilities_dropped`: child içinde `CapEff` parse edip sıfır olmasını bekler.
  - `test_rlimit_enforced`: child içinde `getrlimit` ile kontrol.

## Test ve PASS alıntıları
- `cargo clippy --manifest-path platform/worker/Cargo.toml --all-targets -- -D warnings`
  - `Finished 'dev' profile ...` (clean)
- `just sandbox-tests-v2 > logs/sandbox_tests_v2_phase_2_2_5.log 2>&1`
- `just egress-tests-v2 > logs/egress_tests_v2_phase_2_2_5.log 2>&1`
- `just verify-v2 > logs/verify_v2_phase_2_2_5.log 2>&1`

### `logs/sandbox_tests_v2_phase_2_2_5.log` (son satırlar)
```text
sandbox-tests-v2: Not supported on non-Linux platform
```

### `logs/egress_tests_v2_phase_2_2_5.log` (son satırlar)
```text
egress-tests-v2: Not supported on non-Linux platform
```

### `logs/verify_v2_phase_2_2_5.log` (son satırlar)
```text
running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
...
test result: ok. 2 passed; 0 failed; 5 filtered out; finished in 1.03s
```

## `CapEff` child proof
- Linux ortam hedef doğrulaması için hazır davranış:
  - child içinde `/proc/self/status` okunarak `CapEff` alanından alınan hex değerin `0` olduğu doğrulanır.
  - Bu, testin yeni hali ile `test_capabilities_dropped` içinde doğrudan uygulanmıştır.

## Durum
- `cargo clippy` (worker) PASS.
- Bu makinede (non-Linux) Linux-özel sandbox/egress testleri desteklenmiyor; `Not supported` olarak döndürülüyor.
- Linux CI’de child-only cap drop ve `CapEff=0` doğrulaması için tekrar doğrulama gerekecek (pipeline çalışırsa loglarda child assert satırları görünür olacaktır).
