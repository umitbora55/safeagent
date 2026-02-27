# PHASE 3.1 — Key Rotation + JWKS (Enterprise Token Infrastructure)

## Model

- `TokenClaims` içinde `kid` alanı var ve `iat/exp/nbf` alanları standardize edildi.
- Control-plane, signing anahtarlarını dosya tabanlı bir `KeyStore` ile yönetiyor (`platform/control-plane/.keys`).
- İmzalama key seti:
  - `active` anahtar: token üretiminde kullanılır.
  - `retired` anahtarlar: doğrulama için tutulur.
  - `grace window`: `CONTROL_PLANE_KEY_ROTATION_GRACE_SECONDS` ile yönetilir (varsayılan 86400).
- JWKS:
  - Endpoint: `GET /jwks`
  - Token format: `header.payload.signature`
  - Header alanı: `{ "alg": "EdDSA", "kid": "<active_kid>" }`
  - Payload alanlarında `claims.kid` zorunlu.

## Endpointler

- Control Plane:
  - `GET /jwks` → aktif + geçerli `retired` public key seti döner.
  - `POST /admin/rotate-keys` → yeni key üretir, önceki active key’i `retired` yapar.
  - `POST /issue-token` → header/payload/signature formatlı token döndürür.
- Worker:
  - `safeagent_worker::jwks_cache` ile TTL tabanlı JWKS cache.
  - `kid` bazlı doğrulama + bilinmeyen `kid` için bir kez zorunlu refresh.

## Yapılan Değişiklikler

- `platform/shared/shared-proto/src/lib.rs`
  - `TokenHeader`, `Jwk`, `Jwks`, `RotateKeysResponse` eklendi.
- `platform/shared/shared-identity/src/lib.rs`
  - `Claims` içinde `kid` + `iat` alanları eklendi.
- `platform/control-plane/src/keys.rs` (yeni)
  - `KeyRecord`, `KeyStatus`, `KeyStore`
  - dosya tabanlı key materyali (`.keys/<kid>.key`, `.keys/<kid>.pub`, `.keys/keys.json`)
  - rotate/cleanup/retired verify/persistence mantığı
- `platform/control-plane/src/lib.rs`
  - `RotatingTokenIssuer` eklendi.
  - `GET /jwks`, `POST /admin/rotate-keys` rotaları eklendi.
- `platform/control-plane/src/main.rs`
  - `.keys` dizini ve grace env’i ile çalışan rotasyonlu `KeyStore` enjekte edildi.
- `platform/control-plane/tests/mtls.rs`
  - Rotation testleri:
    - `key_rotation_rotate_and_jwks_contains_retired_key`
    - `key_rotation_issue_token_includes_kid`
    - `key_rotation_e2e`
- `platform/worker/src/jwks_cache.rs`
  - `kid` tabanlı JWKS cache doğrulayıcı ve key refresh.
- `Justfile`
  - `rotation-e2e-v2` eklendi.
- `.github/workflows/platform-v2.yml`
  - `rotation-e2e-v2` log yakalama adımı eklendi.

## Test ve doğrulama komutları

- `just rotation-e2e-v2`
- `just verify-v2`

## Gerçek PASS kanıtı

### rotation-e2e-v2

`logs/rotation_e2e_v2_local.log`:
```text
running 1 test
test key_rotation_e2e ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.02s
```

`logs/rotation_e2e_v2_linux.log`:
```text
running 1 test
test key_rotation_e2e ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.03s
```

### verify-v2

`logs/verify_v2_phase_3_1_local.log`:
```text
running 2 tests
test red_action_waits_for_approval_then_executes ... ok
test red_action_timeout_is_rejected ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out
```

`logs/verify_v2_phase_3_1_linux.log`:
```text
running 2 tests
test red_action_waits_for_approval_then_executes ... ok
test red_action_timeout_is_rejected ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 1.06s
```

### JWKS/rotation smoke PASS (mtls.rs)

- `key_rotation_e2e` testi, control-plane `mtls.rs` içinde key rotation + JWKS doğrulama akışını doğruluyor.
- Bu test `running 1 test` ve `test key_rotation_e2e ... ok` ile PASS kaydı üretmiştir.
