# PHASE 1.2 — mTLS + Worker Registration (Real Zero-Trust Link)

Date: 2026-02-24

## PKI Dev Kit
- Present: `platform/pki/ca.key`, `platform/pki/ca.crt`, `platform/pki/control-plane.{key,crt}`, `platform/pki/worker.{key,crt}`
- README: `platform/pki/README.md`

## Handshake Flow Summary
1. Worker connects to control-plane over HTTPS with mTLS.
2. Control-plane validates client cert against CA.
3. Control-plane extracts NodeId from SAN and registers worker.
4. Worker calls `/health` then `/register` and logs registration.

## Tests
- Integration: valid cert registers ✅
- Integration: no client cert fails ✅
- Integration: wrong CA fails ✅
- Unit: cert fingerprint deterministic ✅
- Unit: NodeId parse ✅

## verify-v2 PASS
Command:
```
just verify-v2 > logs/verify_v2.log 2>&1
```

Excerpt:
```
... 
Running tests/mtls.rs (platform/control-plane/target/debug/deps/mtls-...)

running 3 tests
test register_without_client_cert_fails ... ok
test register_with_wrong_ca_fails ... ok
test register_with_valid_cert_passes ... ok

... 
just mtls-smoke-v2
```

Full log:
- `logs/verify_v2.log`

## mTLS Smoke Output (PASS)
From `logs/mtls_worker.log`:
```
[worker] control_plane=https://127.0.0.1:8443 ca=platform/pki/ca.crt cert=platform/pki/worker.crt key=platform/pki/worker.key addr=127.0.0.1:8280 version=v2-skeleton
[worker] registered node_id=001
```
