# PHASE 4.4 — Exploit Replay + Adversarial Regression Dataset

## Amaç
- `platform/lab/exploit-replay` altında seed-bağımsız, deterministik bir regresyon yeniden oynatma hattı kuruldu.
- Yeni bir adversarial regresyon dataset’i (`adversarial_regressions.jsonl`) kalıcı şekilde eklendi.
- `verify-v2` sürecine `replay-check-v2` gate’i eklendi.

## Dataset spec
- `platform/lab/regression-dataset/adversarial_regressions.jsonl` (JSONL)
- Her satır:
  - `id`: AR-XXXX
  - `source`: `jailbreak-fuzzer` | `context-poison-sim` | `diff-canary`
  - `mode`: `prompt` | `tool_output` | `memory` | `hybrid`
  - `prompt`: test senaryosu metni
  - `expected`:
    - `must_block` (bool)
    - `max_risk_score` (float)
    - `policy_decision` (`deny` | `allow` | `require_approval` | `allow_with_notification`)
  - `tags`: sınıflandırma etiketleri
  - `created_at`, `seed`
- Toplam vaka sayısı: **10** (komşu saldırı sınıfları dahil)
  - unicode / role spoof
  - tool_output marker
  - memory.fact poisoning
  - canary/metadata/redirect/parsing edge-cases
  - token replay spoof text
  - turkish style injection

## Replay runner
- Crate: `platform/lab/exploit-replay`
- CLI:
  - `--dataset`
  - `--out`
  - `--max-failures`
- Bileşen:
  - `PromptGuard` ile sanitize
  - `PolicyEngine` ile decision
  - scope simulation + approval override değerlendirmesi
  - expected davranış karşılaştırması
  - failed case’leri JSONL olarak yazma
- Çıktı: `ReplayRunResult` (total_cases, executed, failures, failed_ids)

## `Justfile` wiring
- Yeni target eklendi:
  - `replay-check-v2`
- Log target eklendi:
  - `replay-check-v2-log`
- `verify-v2` içeriğine `just replay-check-v2` eklendi.

## Execution command
```bash
just replay-check-v2
just verify-v2
```

## PASS excerpt (replay-check-v2)
From `logs/replay_check_v2_phase_4_4_linux.log`:
```text
total_cases=10
executed=10
failures=0
```

## PASS excerpt (verify-v2)
From `logs/verify_v2_phase_4_4_linux.log`:
```text
running 3 tests
test rate_limit_cost_limit_returns_payment_required ... ok
test rate_limit_parallel_requests_enforce_tenant_concurrency_limit ... ok
test rate_limit_queue_limit_returns_service_unavailable_when_queue_exhausted ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.32s

...

just replay-check-v2
total_cases=10
executed=10
failures=0
```
