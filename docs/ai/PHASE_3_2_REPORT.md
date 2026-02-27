# PHASE 3.2 — Secret Manager / KMS Integration (Vault-Compatible Interface)

## SecretStore API

- Yeni bir shared crate eklendi: `platform/shared/shared-secrets`.
- `SecretStore` trait:
  - `get(name) -> Result<Vec<u8>>`
  - `put(name, bytes) -> Result<()>`
  - `delete(name) -> Result<()>`
  - `list(prefix) -> Result<Vec<String>>`
- `SecretError` tipi: `InvalidName`, `NotFound`, `Io`, `Serialization`, `Crypto`, `Vault`, `Http`.

## File backend (`FileSecretStore`)

- Path: `platform/control-plane/.secrets/`.
- Şifreleme:
  - Anahtar türetme: `Argon2id` (`SAFEAGENT_SECRET_PASSWORD`)
  - Şifreleme: `AES-256-GCM`
  - Depolama formatı: `[16B salt][12B nonce][ciphertext+tag]`
- Davranış:
  - `put(name, bytes)` şifreli yazar.
  - `get(name)` şifreyi doğrular ve çözer.
  - `list(prefix)` prefiks ile filtrelenmiş dosya adlarını döndürür.
- Kontrol-plane private key’ler doğrudan `.key` plaintext dosyasına yazılmıyor; `token-keys/<kid>` adıyla `SecretStore` içinde saklanıyor.

## Vault backend (`VaultSecretStore`)

- HTTP KV v2 tabanlı:
  - `GET /v1/<mount>/data/<path>` → read
  - `PUT /v1/<mount>/data/<path>` → write
  - `DELETE /v1/<mount>/metadata/<path>` → delete
  - `GET /v1/<mount>/metadata/<prefix>?list=true` → list
- Header: `X-Vault-Token` (`VAULT_TOKEN`)
- Ayarları: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_MOUNT`.
- Canlı Vault zorunlu değil; mock HTTP ile test edilir.

## KeyStore refactor (control-plane)

- `platform/control-plane/src/keys.rs`:
  - `KeyStore::new` imzası `Arc<dyn SecretStore>` alacak şekilde güncellendi.
  - Private key persistansı `token-keys/<kid>` olarak SecretStore’e taşındı.
  - `keys.json` metadata dosyası diskte kalıyor, public key ise `.pub` dosyası olarak saklanıyor.
- `platform/control-plane/src/main.rs`:
  - Secret backend seçimi (`file`/`vault`) eklendi.
  - `CONTROL_PLANE_SECRET_DIR`, `SAFEAGENT_SECRET_PASSWORD`, `CONTROL_PLANE_SECRET_BACKEND`.
  - Vault için `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_MOUNT`.

## Test ve kanıt

- `platform/shared/shared-secrets`:
  - File secret roundtrip + wrong password + tamper detection testi.
  - Vault mock ile put/get/delete/list testi.
- `platform/control-plane/src/keys.rs`:
  - rotation + retained key testleri.
- `verify-v2`:
  - `platform/shared` ve `platform/control-plane` test setleri dahil, clippy ve format checkleri ile.

## Gerçek PASS excerptlar

`logs/rotation_e2e_v2_phase_3_2.log`:
```text
running 1 test
test key_rotation_e2e ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.53s
```

`logs/verify_v2_phase_3_2.log`:
```text
running 5 tests
test tests::approval_store_created_to_timeout ... ok
test tests::approval_store_created_to_denied ... ok
test tests::approval_store_double_approve_is_idempotent ... ok
test tests::approval_store_created_to_approved ... ok
test keys::tests::rotate_keeps_retired_keys_for_grace ... ok

running 10 tests
test key_rotation_issue_token_includes_kid ... ok
test key_rotation_rotate_and_jwks_contains_retired_key ... ok
test key_rotation_e2e ... ok
...
test red_action_timeout_is_rejected ... ok

running 2 tests
test red_action_waits_for_approval_then_executes ... ok
test red_action_timeout_is_rejected ... ok
```

`logs/verify_v2_phase_3_2.log` (özet sonucu):
```text
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 2.56s
```

`logs/verify_v2_phase_3_2.log` (shared-secrets PASS):
```text
running 2 tests
test tests::vault_secret_roundtrip_mocked ... ok
test tests::file_secret_roundtrip_and_tamper_detection ... ok
```

`logs/rotation_e2e_v2_linux_phase_3_2.log`:
```text
running 1 test
test key_rotation_e2e ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 1.23s
```

`logs/verify_v2_linux_phase_3_2.log`:
```text
running 10 tests
test key_rotation_issue_token_includes_kid ... ok
...
test red_action_timeout_is_rejected ... ok

running 2 tests
test red_action_waits_for_approval_then_executes ... ok
test red_action_timeout_is_rejected ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 2.56s
```

## Not

Kontrol-plane artık token signing private key’i doğrudan plaintext dosyadan okumuyor; SecretStore üzerinden şifreli olarak saklıyor.
