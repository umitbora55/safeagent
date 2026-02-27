# mTLS Specification (Contract)

This document defines the contract for mutual TLS between control-plane and worker nodes.

## Handshake Flow
1. Worker connects to control-plane listener.
2. Both sides present certificates.
3. Both sides validate:
   - CA trust chain
   - certificate validity period
   - SAN fields (required)
4. If validation passes, application-layer registration proceeds.

## Required SAN Fields
Certificates must include the following SAN fields:
- `URI: safeagent://tenant/<tenant_id>`
- `URI: safeagent://node/<node_id>`
- `DNS: <node_dns>` (optional but recommended)

## Rotation Expectations
- Certificates are short-lived (recommended ≤ 30 days).
- Control-plane and worker must support hot reload of certs.
- Overlapping validity windows are required during rotation.

## Failure Policy
- Any SAN mismatch or invalid chain → hard reject.
- Control-plane must not accept unauthenticated requests.
