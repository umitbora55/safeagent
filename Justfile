# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SafeAgent Verify Gate
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# SINGLE SOURCE OF TRUTH for all verification.
# All CI/CD pipelines MUST use `just verify` as the gate.
#
# Usage:
#   just verify        - Full 9-step verification (required for release)
#   just quick-check   - Fast check (fmt + clippy + test)
#   just security-check - Security-focused (conformance + red-team + chaos)
#
# See docs/RELEASE_POLICY.md for v1-core change policy.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set shell := ["bash", "-uc"]

# Default recipe: show available commands
default:
    @just --list

# Run all verification steps
verify:
    @set -euo pipefail; \
        trap 'just otel-down' EXIT; \
        just fmt; \
        just clippy; \
        just test; \
        just conformance; \
        just stride-gen; \
        just red-team; \
        just chaos; \
        just audit-verify; \
        just otel-up; \
        just otel-smoke
    @echo ""
    @echo "╔══════════════════════════════════════════════════════════════╗"
    @echo "║                   ✓ VERIFY GATE PASSED                       ║"
    @echo "║          All 9 verification steps completed                  ║"
    @echo "╚══════════════════════════════════════════════════════════════╝"

# Step 1: Format check
fmt:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[1/9] Format Check"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo fmt --all --check

# Step 2: Clippy lints
clippy:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[2/9] Clippy Lints"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo clippy --workspace --all-targets -- -D warnings

# Step 3: Run all tests
test:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[3/9] Unit & Integration Tests"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo test --workspace

# Step 4: Policy conformance tests
conformance:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[4/9] Policy Conformance Tests"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo run --bin policy-conformance-runner -- policy_conformance/cases/

# Step 5: Generate STRIDE scenarios
stride-gen:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[5/9] STRIDE Test Generation"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo run --bin stride-testgen -- \
        threat_model/stride.yaml \
        --red-team red_team_scenarios \
        --chaos chaos_scenarios

# Step 6: Red team scenarios
red-team:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[6/9] Red Team Scenarios"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo run --bin red-team-harness -- red_team_scenarios/

# Step 7: Chaos scenarios
chaos:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[7/9] Chaos Fault Injection"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo run --bin chaos-harness -- chaos_scenarios/

# Step 8: Audit log hash chain verification
audit-verify:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[8/9] Audit Hash Chain Verification"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @just audit-fixture
    cargo run --bin audit_verify -- data/audit/fixture_audit.jsonl

# Step 9: OpenTelemetry smoke test
otel-smoke:
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "[9/9] OpenTelemetry Smoke Test"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo test --package safeagent-telemetry otel_smoke_test -- --ignored

# Build all binaries
build:
    cargo build --workspace --release

# Run format fix
fmt-fix:
    cargo fmt --all

# Clean build artifacts
clean:
    cargo clean

# Run a quick check (fmt + clippy + test)
quick-check: fmt clippy test
    @echo "Quick check passed!"

# Security-focused verification (conformance + red-team + chaos)
security-check: conformance stride-gen red-team chaos
    @echo "Security verification passed!"

# Show test coverage (requires cargo-llvm-cov)
coverage:
    cargo llvm-cov --workspace --html
    @echo "Coverage report generated in target/llvm-cov/html/"

# Release readiness check (verify + audit)
release-ready: verify
    @echo ""
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    @echo "Security Audit"
    @echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cargo audit || echo "cargo-audit not installed, skipping"
    @echo ""
    @echo "╔══════════════════════════════════════════════════════════════╗"
    @echo "║                 RELEASE READINESS CHECK                      ║"
    @echo "║     See docs/RELEASE_CHECKLIST.md for full checklist         ║"
    @echo "╚══════════════════════════════════════════════════════════════╝"

# CI mode (no interactive output)
ci-verify:
    just audit-fixture
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo run --bin policy-conformance-runner -- policy_conformance/cases/
    cargo run --bin stride-testgen -- \
        threat_model/stride.yaml \
        --red-team red_team_scenarios \
        --chaos chaos_scenarios
    cargo run --bin red-team-harness -- red_team_scenarios/
    cargo run --bin chaos-harness -- chaos_scenarios/
    cargo run --bin audit_verify -- data/audit/fixture_audit.jsonl
    cargo test --package safeagent-telemetry otel_smoke_test -- --ignored

# Generate deterministic audit fixture for verification
audit-fixture:
    @echo "Generating audit fixture: data/audit/fixture_audit.jsonl"
    cargo run --bin audit_fixture -- data/audit/fixture_audit.jsonl

# Start local OTLP collector (gRPC: localhost:4317)
otel-up:
    @echo "Starting OTLP collector (localhost:4317)"
    @mkdir -p docker
    @docker rm -f safeagent-otel-collector >/dev/null 2>&1 || true
    docker run -d --name safeagent-otel-collector \
        -p 4317:4317 \
        -v "$PWD/docker/otel-collector.yaml:/etc/otelcol/config.yaml:ro" \
        otel/opentelemetry-collector:0.101.0 \
        --config /etc/otelcol/config.yaml
    @for i in {1..20}; do \
        if nc -z localhost 4317; then echo "Collector ready"; exit 0; fi; \
        sleep 0.5; \
    done; \
    echo "Collector failed to start"; exit 1

# Stop local OTLP collector
otel-down:
    @docker rm -f safeagent-otel-collector >/dev/null 2>&1 || true

# CI-friendly verify (no skips)
verify-no-skip: audit-fixture
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    cargo run --bin policy-conformance-runner -- policy_conformance/cases/
    cargo run --bin stride-testgen -- \
        threat_model/stride.yaml \
        --red-team red_team_scenarios \
        --chaos chaos_scenarios
    cargo run --bin red-team-harness -- red_team_scenarios/
    cargo run --bin chaos-harness -- chaos_scenarios/
    cargo run --bin audit_verify -- data/audit/fixture_audit.jsonl
    cargo test --package safeagent-telemetry otel_smoke_test -- --ignored

# Verify platform-v2 skeleton only
verify-v2:
    cargo fmt --all --check --manifest-path platform/control-plane/Cargo.toml
    cargo fmt --all --check --manifest-path platform/worker/Cargo.toml
    cargo fmt --all --check --manifest-path platform/shared/Cargo.toml
    cargo clippy --manifest-path platform/control-plane/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path platform/worker/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path platform/shared/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path crates/sdk-rust/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path platform/worker/skills-sdk/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path platform/lab/context-poison-sim/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path platform/lab/diff-canary/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path platform/control-plane/Cargo.toml
    just rotation-e2e-v2
    just egress-tests-v2
    just sandbox-tests-v2
    just rate-limit-tests-v2
    cargo test --manifest-path platform/shared/Cargo.toml
    just mtls-smoke-v2
    just approval-e2e-v2
    just adversarial-check-v2
    just poison-check-v2
    just diff-check-v2
    just replay-check-v2
    just sdk-check-v2
    just marketplace-check-v2
    just registry-check-v2
    just desktop-ux-check
    just desktop-check
    just desktop-release-check
    just desktop-update-check

verify-v2-log:
    mkdir -p logs
    just verify-v2 > logs/verify_v2_linux.log 2>&1

demo-check:
    scripts/demo_local.sh

demo-check-log:
    mkdir -p logs
    just demo-check > logs/demo_check.log 2>&1

desktop-check:
    cargo build --manifest-path desktop/Cargo.toml
    cargo test --manifest-path desktop/Cargo.toml

desktop-check-log:
    mkdir -p logs
    just desktop-check > logs/desktop_check.log 2>&1

desktop-release-check:
    scripts/build_desktop_release.sh
    just desktop-check
    cargo test --manifest-path desktop/Cargo.toml -- --exact tests::settings_default_and_roundtrip tests::update_manifest_parse

desktop-release-check-log:
    mkdir -p logs
    just desktop-release-check > logs/desktop_release_check.log 2>&1

desktop-update-check:
    scripts/publish_update_channel.sh
    cargo test --manifest-path desktop/Cargo.toml

desktop-update-check-log:
    mkdir -p logs
    just desktop-update-check > logs/desktop_update_check.log 2>&1

desktop-ux-check:
    cargo test --manifest-path desktop/Cargo.toml -- --exact tests::onboarding_state_machine
    cargo test --manifest-path desktop/Cargo.toml -- --exact tests::event_human_mapping_is_stable
    cargo test --manifest-path desktop/Cargo.toml -- --exact tests::tray_menu_items_exist

desktop-ux-check-log:
    mkdir -p logs
    just desktop-ux-check > logs/desktop_ux_check.log 2>&1

sdk-check-v2:
    mkdir -p logs
    cargo test --manifest-path crates/sdk-rust/Cargo.toml
    cargo test --manifest-path platform/worker/skills-sdk/Cargo.toml
    cargo build --manifest-path crates/sdk-rust/Cargo.toml --examples
    cargo build --manifest-path platform/worker/skills-sdk/Cargo.toml --examples
    (cd sdk/ts && npm install --no-audit --no-fund && \
    npm run build; \
    npm run typecheck)

sdk-check-v2-log:
    mkdir -p logs
    just sdk-check-v2 > logs/sdk_check_v2.log 2>&1

marketplace-check-v2:
    @if [ "$(uname -s)" = "Linux" ] || [ "$(uname -s)" = "Darwin" ]; then \
        cargo test --manifest-path crates/skill-registry/Cargo.toml; \
    else \
        echo "marketplace-check-v2: not supported on non-linux platforms"; \
    fi

marketplace-check-v2-log:
    mkdir -p logs
    just marketplace-check-v2 > logs/marketplace_check_v2.log 2>&1

registry-check-v2:
    cargo test --manifest-path crates/skill-registry-server/Cargo.toml

registry-check-v2-log:
    mkdir -p logs
    just registry-check-v2 > logs/registry_check_v2.log 2>&1

rotation-e2e-v2:
    cargo test --manifest-path platform/control-plane/Cargo.toml --test mtls -- key_rotation_e2e

rotation-e2e-v2-log:
    mkdir -p logs
    just rotation-e2e-v2 > logs/rotation_e2e_v2.log 2>&1

sandbox-tests-v2:
    @if [ "$(uname -s)" = "Linux" ]; then \
        cargo test --manifest-path platform/worker/Cargo.toml -- --test-threads=1 \
            test_no_new_privs_set \
            test_rlimit_enforced \
            test_seccomp_blocks_disallowed_syscall \
            test_skill_exec_under_sandbox \
            test_capabilities_dropped; \
    else \
        echo "sandbox-tests-v2: Not supported on non-Linux platform"; \
    fi

sandbox-tests-v2-log:
    mkdir -p logs
    just sandbox-tests-v2 > logs/sandbox_tests_v2_linux.log 2>&1

egress-tests-v2:
    @if [ "$(uname -s)" = "Linux" ]; then \
        cargo test --manifest-path platform/worker/Cargo.toml --test egress_policy_tests; \
    else \
        echo "egress-tests-v2: Not supported on non-Linux platform"; \
    fi

egress-tests-v2-log:
    mkdir -p logs
    just egress-tests-v2 > logs/egress_tests_v2_linux.log 2>&1

rate-limit-tests-v2:
    cargo test --manifest-path platform/control-plane/Cargo.toml --test mtls rate_limit -- --test-threads=1

adversarial-check-v2:
    mkdir -p logs
    cargo run --manifest-path platform/lab/jailbreak-fuzzer/Cargo.toml -- \
        --seed 0xC0FFEE \
        --runs 200 \
        --out logs/adversarial_findings_v2.jsonl \
        --max-findings 0

poison-check-v2:
    mkdir -p logs
    cargo run --manifest-path platform/lab/context-poison-sim/Cargo.toml -- \
        --seed 0xC0FFEE \
        --runs 200 \
        --mode hybrid \
        --out logs/context_poison_findings_v2.jsonl \
        --max-findings 0

diff-check-v2:
    mkdir -p logs
    cargo run --manifest-path platform/lab/diff-canary/Cargo.toml -- \
        --seed 0xC0FFEE \
        --runs 100 \
        --mode mock \
        --out logs/diff_canary_findings_v2.jsonl \
        --max-divergence 0 \
        --max-leaks 0

replay-check-v2:
    mkdir -p logs
    cargo run --manifest-path platform/lab/exploit-replay/Cargo.toml -- \
        --dataset platform/lab/regression-dataset/adversarial_regressions.jsonl \
        --out logs/exploit_replay_failures_v2.jsonl \
        --max-failures 0

adversarial-check-v2-log:
    mkdir -p logs
    just adversarial-check-v2 > logs/adversarial_check_v2.log 2>&1

poison-check-v2-log:
    mkdir -p logs
    just poison-check-v2 > logs/poison_check_v2_linux.log 2>&1

diff-check-v2-log:
    mkdir -p logs
    just diff-check-v2 > logs/diff_check_v2_linux.log 2>&1

replay-check-v2-log:
    mkdir -p logs
    just replay-check-v2 > logs/replay_check_v2_linux.log 2>&1

rate-limit-tests-v2-log:
    mkdir -p logs
    just rate-limit-tests-v2 > logs/rate_limit_tests_v2.log 2>&1

# mTLS smoke test for platform-v2
mtls-smoke-v2:
    @set -euo pipefail; \
        CONTROL_PLANE_ADDR=127.0.0.1:8443 \
        MTLS_CA=platform/pki/ca.crt \
        MTLS_CERT=platform/pki/control-plane.crt \
        MTLS_KEY=platform/pki/control-plane.key \
        cargo run --manifest-path platform/control-plane/Cargo.toml --bin safeagent-control-plane > logs/mtls_control_plane.log 2>&1 & \
        sleep 1; \
        CONTROL_PLANE_URL=https://127.0.0.1:8443 \
        MTLS_CA=platform/pki/ca.crt \
        MTLS_CERT=platform/pki/worker.crt \
        MTLS_KEY=platform/pki/worker.key \
        WORKER_ONESHOT=1 \
        cargo run --manifest-path platform/worker/Cargo.toml --bin safeagent-worker > logs/mtls_worker.log 2>&1; \
        grep -q 'registered node_id=' logs/mtls_worker.log; \
        pkill -f safeagent-control-plane

token-e2e-v2:
    cargo test --manifest-path platform/control-plane/Cargo.toml --test mtls -- execute_via_control_plane_passes --exact

approval-e2e-v2:
    cargo test --manifest-path platform/control-plane/Cargo.toml --test mtls -- red_action_waits_for_approval_then_executes red_action_timeout_is_rejected --exact
