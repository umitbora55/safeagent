# PHASE 3.3 — Rate Limiting + Backpressure + Multi-Tenant Control

## Gerçekleştirilen Değişiklikler

- `platform/shared/shared-proto/src/lib.rs`
  - `TenantId` alanını `ExecuteRequest` ve `ControlPlaneExecuteRequest` içine ekledim.
- `platform/control-plane/src/rate_limiter.rs` (yeni)
  - `TenantRateLimitConfig`
  - `TenantRateLimiter` (tenant bazlı token bucket + concurrent + queue + cost ledger)
  - `RateLimitError` ve `RateLimitErrorBody`
  - `TenantLimitPermit` (`Drop` ile otomatik serbest bırakma)
- `platform/control-plane/src/lib.rs`
  - `AppState` içine `rate_limiter` eklendi.
  - `TokenIssuer::issue` imzası tenant taşır şekilde genişletildi (`tenant_id`).
  - `/execute` akışında tenant limiter çağrısı eklendi:
    - `allow_request` → limit hatalarında 429/503/402 benzeri gövde dönümü
    - `charge_cost` sonrası worker isteği
  - Başarısız limit durumlarında `RateLimitErrorBody` JSON olarak dönülüyor (`code`, `message`, `retry_after_seconds`).
- `platform/control-plane/src/main.rs`
  - Tenant limit konfigürasyonları env’den okunur:
    - `CONTROL_PLANE_TENANT_CONCURRENT_LIMIT`
    - `CONTROL_PLANE_TENANT_QUEUE_LIMIT`
    - `CONTROL_PLANE_TENANT_TOKEN_BUCKET_CAPACITY`
    - `CONTROL_PLANE_TENANT_TOKEN_BUCKET_REFILL_PER_SECOND`
    - `CONTROL_PLANE_TENANT_COST_BUDGET`
- `platform/control-plane/tests/mtls.rs`
  - `rate_limit_*` testleri eklendi:
    - `rate_limit_parallel_requests_enforce_tenant_concurrency_limit`
    - `rate_limit_queue_limit_returns_service_unavailable_when_queue_exhausted`
    - `rate_limit_cost_limit_returns_payment_required`
- `Justfile`
  - `rate-limit-tests-v2` hedefi eklendi:
    - `cargo test --manifest-path platform/control-plane/Cargo.toml --test mtls rate_limit --test-threads=1`
  - `verify-v2` içine dahil edildi.

## Varsayılanlar ve Davranış

- Varsayılanlar:
  - `DEFAULT_TENANT_CONCURRENT_LIMIT = 1000`
  - `DEFAULT_TENANT_QUEUE_LIMIT = 1000`
  - `DEFAULT_TENANT_TOKEN_BUCKET_CAPACITY = 10_000`
  - `DEFAULT_TENANT_TOKEN_BUCKET_REFILL_PER_SECOND = 10_000`
  - `DEFAULT_TENANT_COST_BUDGET = 1_000_000`
- `concurrent_limit` taşması `StatusCode::TOO_MANY_REQUESTS` (429) ile dönüyor.
- `queue_limit` taşması `queue_limit_exceeded` hata kodu ile `StatusCode::SERVICE_UNAVAILABLE` (503) dönüyor.
- Cost bütçe taşması `cost_limit_exceeded` hata kodu ile `StatusCode::PAYMENT_REQUIRED` dönüyor.
- Limitler tenant bazında ayrılır (`TenantId`).

## Semantik ve İstenen HTTP Kodları

- `429 Too Many Requests` → `RateLimitErrorBody`
- `503 Service Unavailable` → `RateLimitErrorBody` (backpressure)
- `PAYMENT_REQUIRED` (402-benzeri) → cost quota
- Ortak alanlar:
  - `code`
  - `message`
  - `retry_after_seconds`

## Test ve Verify Göstergeleri

- `verify-v2` artık `rate-limit-tests-v2` çalıştırıyor.
- Gerçek PASS özetleri:
  - `logs/rate_limit_tests_v2_local.log`
  - `logs/verify_v2_phase_3_3_local.log`
  - `logs/rate_limit_tests_v2_linux.log`
  - `logs/verify_v2_phase_3_3_linux.log`

Örnek PASS kesiti (`rate_limit_tests_v2_local.log`):

```
running 3 tests
test rate_limit_cost_limit_returns_payment_required ... ok
test rate_limit_parallel_requests_enforce_tenant_concurrency_limit ... ok
test rate_limit_queue_limit_returns_service_unavailable_when_queue_exhausted ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 1.05s
```

Örnek PASS kesiti (`verify_v2_phase_3_3_local.log`):

```
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.47s
```
