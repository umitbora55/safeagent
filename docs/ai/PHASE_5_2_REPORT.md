PHASE 5.2 — Signed Marketplace + Static Scanning
===============================================

Scope
-----
- Yeni `safeagent-skill-registry` aracı eklendi: `skill` binary.
- Paket formatı: `skill.toml`, `payload.tar.gz`, `signature.sig`, `checksums.json`.
- `pack`, `sign`, `verify`, `scan` komutları eklendi.
- Publisher allowlist: `registry/publishers/verified.json`.
- `verify-v2` içinde `marketplace-check-v2` hedefi çağrılıyor.

Package formatı
---------------
- `manifest`: `id`, `name`, `version`, `entrypoint`, `required_scopes`, `description`,
  `publisher_id`, `signing_key_id`, `files`.
- `payload.tar.gz`: `manifest.files` içindeki dosyaların gzip+tar arşivi.
- `signature.sig`: Ed25519 imza envelope (JSON).
- `checksums.json`: manifest ve payload SHA256 özetleri.

Signing
-------
- İmza girdisi: canonical JSON manifest + payload sha256.
- Algoritma: Ed25519.
- Varsayılan davranış: imza verisi olmadan doğrulama geçemez.

Static scanning
--------------
- Engellenen içerik örnekleri:
  - `curl|sh`, `wget|sh`, `rm -rf`, `mkfs`, `169.254.169.254`
  - `setuid`, `chmod 777`, `chown`, `chmod +s`
- Path denetimi:
  - Mutlak yol, `..`, `.ssh`, `/etc` içerikli dosyalar engellenir.
- Scope denetimi:
  - Wildcard (`*`) required scope default deny.

Commands
--------
- `skill pack <dir> --out <pkg>`
- `skill sign <pkg> --key <ed25519_private_key_file>`
- `skill verify <pkg> --publishers registry/publishers/verified.json`
- `skill scan <pkg>`
- `skill publisher add --store <file> --publisher-id <id> --key-id <id> --public-key <hex_or_base64>`

Test ve doğrulama
-----------------
- `marketplace-check-v2` hedefi: `cargo test --manifest-path crates/skill-registry/Cargo.toml`
- `verify-v2` içinde `marketplace-check-v2` çağrısı eklendi.

Execution proof
--------------
- `just marketplace-check-v2 > logs/marketplace_check_v2.log 2>&1`
- `just verify-v2 > logs/verify_v2_linux.log 2>&1`

marketplace-check-v2 excerpt
```text
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

verify-v2 excerpt (marketplace section)
```text
just marketplace-check-v2
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```
