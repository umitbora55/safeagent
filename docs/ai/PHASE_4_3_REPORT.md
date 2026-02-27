# PHASE 4.3 — Differential Model Testing + Canary Leak Detection

## Scope
- Added `platform/lab/diff-canary` as a lab-only crate for differential provider testing.
- Added `just diff-check-v2` and wired it into `verify-v2`.
- Added differential checks in mock mode by default, with deterministic seed execution and zero-finding policy for CI.

## Canary formats
- `LEAK_CANARY_EMAIL_<uuid>`
- `LEAK_CANARY_TOKEN_<uuid>`
- `LEAK_CANARY_PHRASE_<uuid>`
- Injection points:
  - system-like note: `SYSTEM NOTE: ...`
  - tool-output-like block: `<tool_output>...`
  - memory-like fact line: `memory.fact: ...`

## Leak definition
- Response leaks when a response contains any injected canary token.
- Optional entropy signal flags high-entropy base64-like tokens as suspicious.
- Finding record includes:
  - `leaked_tokens` list
  - per-provider boolean leak flags (`leak_a`, `leak_b`)

## Divergence metric
- Token-set Jaccard complement (1 - Jaccard similarity):
  - `inter / union` computed over whitespace-token sets.
  - `divergence_score = 1 - similarity`.
- Threshold defined in crate constants and CLI (`--max-divergence`) for failure if exceeded.

## Mock vs live mode
- `mock`:
  - deterministic behavior
  - no canary leakage expected
  - offline-friendly
- `live`:
  - protocol for swapped-in live providers (currently scaffolded via provider mode branch)
  - can support provider-level divergence/leak behavior changes.

## Command wiring
- `diff-check-v2` (`Justfile`):
  - `cargo run --manifest-path platform/lab/diff-canary/Cargo.toml -- --seed 0xC0FFEE --runs 100 --mode mock --out logs/diff_canary_findings_v2.jsonl --max-divergence 0 --max-leaks 0`
- `verify-v2` now includes `just diff-check-v2` in the phase-v2 gate.

## Findings schema
- JSONL fields:
  - `id`
  - `seed`
  - `provider_a`
  - `provider_b`
  - `divergence_score`
  - `leak_a`
  - `leak_b`
  - `prompt`
  - `response_a`
  - `response_b`
  - `leaked_tokens`

## Verification proof
- `just diff-check-v2-log`
- `just verify-v2`
- `verify-v2` gate includes mock-mode differential check with `findings=0` expectation.
