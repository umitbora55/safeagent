# PHASE 4.2.2 — Zero Warnings + Verify-v2 Clippy Coverage

## Önceki uyarılar
- `platform/lab/context-poison-sim` crate’inde derleme/clippy ile tespit edilenlar:
  - `unused import` (`BufRead`, `BufReader`), çünkü testte kullanılmayan lib scope.
  - `dead_code`: `PoisonedContext.clean_prompt` alanı okunmuyordu.
  - `unused import`: `clap::ValueEnum` (main.rs).
  - `if-same-then-else` (`simulate_chain` içinde aynı dalı döndüren if).
  - `bool-comparison` (`== false` kullanımı).
  - `unused mut` (`payload_types`, `mut candidate`).

## Düzeltmeler
- `platform/lab/context-poison-sim/src/main.rs`
  - `ValueEnum` importu kaldırıldı (`clap::ValueEnum` türetilmiyordu).
- `platform/lab/context-poison-sim/src/lib.rs`
  - `PoisonedContext.clean_prompt` alanı kaldırıldı.
  - `BufRead`/`BufReader` test modülü (`#[cfg(test)]`) içine taşındı.
  - `let (tool_output, mut payload_types, ...)` -> `let (tool_output, payload_types, ...)`.
  - `let mut candidate = ...` -> `let candidate = ...`.
  - `if safe_parts.is_empty() { guard.sanitize(...) } else { guard.sanitize(...) }` -> tek satır `guard.sanitize(...)`.
  - `... == false` -> `!...` olarak değiştirildi.
- `Justfile`
  - `verify-v2` içine eklendi:
    - `cargo clippy --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml --all-targets -- -D warnings`
    - `cargo clippy --manifest-path platform/lab/context-poison-sim/Cargo.toml --all-targets -- -D warnings`

## Doğrulama
- Komut:
  - `cargo build --manifest-path platform/lab/context-poison-sim/Cargo.toml`
  - `just verify-v2 > logs/verify_v2_phase_4_2_2.log 2>&1`
- Build sonucu: `Finished` ve warning/cihaz tarafında ek uyarı yok.
- `verify-v2` log excerpt (`logs/verify_v2_phase_4_2_2.log`, ilk clippy satırları):
```text
cargo clippy --manifest-path platform/control-plane/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/worker/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/shared/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path platform/lab/context-poison-sim/Cargo.toml --all-targets -- -D warnings
```
- `verify-v2` tail’da `total_runs=200`, `findings=0` ile `adversarial-check-v2` ve `poison-check-v2` geçti.
