# SafeAgent Desktop Update Channel Spec

## Versioned manifest

Update metadata is stored at `dist/updates/update.json`.

```json
{
  "version": "0.1.0",
  "url": "/absolute/path/to/safeagent-desktop",
  "sha256": "hex-digest",
  "notes": ["string"],
  "published_at": "2026-01-01T00:00:00Z"
}
```

- `version`: SemVer string.
- `url`: download location for desktop payload (file path or HTTPS URL).
- `sha256`: lower-case hex SHA-256 digest of payload bytes.
- `notes`: ordered changelog-like hints.
- `published_at`: RFC3339 UTC timestamp.

## Signature artifacts

- `dist/updates/update.sig`: Base64-encoded Ed25519 signature.
- Signature covers canonical manifest bytes plus manifest hash:
  - canonical manifest: `serde_json::to_string(manifest)`
  - payload: `canonical_manifest + sha256(canonical_manifest)`

## Verification flow

1. Parse manifest.
2. Fetch manifest signature from sibling `update.sig` (or configured signature URL).
3. Verify signature with embedded/public key fallback.
4. Verify SHA-256 of payload at `url`.
5. Ensure candidate version is strictly newer than current.
6. If any check fails, update is rejected.

## Signing channel script

- `scripts/publish_update_channel.sh`
- Input: release asset path (optional positional arg, defaults to built desktop binary)
- Output: `update.json` + `update.sig` under `dist/updates`

## Security model

- Fail-closed by default.
- Missing/invalid signature/asset hash => `safe=false` and no apply.
- Verify failure is reported to UI as signed update check result.
