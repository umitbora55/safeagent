// safeagent-kill-switch
//
// W5 D5: Kill Switch + Circuit Breakers — Runtime Fence
//
// OWASP February 2026 guidance: kill switches must live *outside* the AI
// reasoning path and protect against misuse as a DoS vector. This crate
// provides five safety primitives:
//
//   1. KillSwitch     — binary on/off flag; activated halts all agent actions
//   2. BudgetCap      — per-session spend ceiling in microdollars
//   3. RateLimit      — calls-per-window ceiling with sliding window
//   4. CircuitBreaker — failure-threshold auto-open with timeout recovery
//   5. RuntimeFence   — composites all four into a single check-before-call API
//
// Design principles:
//   - All state uses std::sync atomics; no async needed for the fence check
//   - Kill switch activation is irreversible within a session
//   - All primitives are individually testable
//   - RuntimeFence::check() returns FenceDecision in < 1µs
//   - No Redis/network dependency; in-process state with optional persistence

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  FenceDecision — result of RuntimeFence::check()
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq)]
pub enum FenceDecision {
    /// All gates pass — proceed with the agent action
    Proceed,
    /// Kill switch is active — session terminated
    KillSwitchActive,
    /// Budget ceiling reached
    BudgetExceeded { spent_microdollars: u64, limit_microdollars: u64 },
    /// Rate limit exceeded
    RateLimited { calls_in_window: u32, limit: u32 },
    /// Circuit breaker open — provider failing
    CircuitOpen { failures: u32 },
}

impl FenceDecision {
    pub fn is_blocked(&self) -> bool {
        !matches!(self, FenceDecision::Proceed)
    }

    pub fn reason(&self) -> String {
        match self {
            FenceDecision::Proceed => "proceed".to_string(),
            FenceDecision::KillSwitchActive => "kill switch active — session terminated".to_string(),
            FenceDecision::BudgetExceeded { spent_microdollars, limit_microdollars } => format!(
                "budget exceeded: ${:.4} / ${:.4}",
                *spent_microdollars as f64 / 1_000_000.0,
                *limit_microdollars as f64 / 1_000_000.0
            ),
            FenceDecision::RateLimited { calls_in_window, limit } => format!(
                "rate limited: {} calls in window (limit {})",
                calls_in_window, limit
            ),
            FenceDecision::CircuitOpen { failures } => format!(
                "circuit breaker open after {} failures",
                failures
            ),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  1. KillSwitch
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Binary on/off kill switch. Once activated, cannot be deactivated
/// without restarting the process (session-scoped safety).
///
/// Lives outside the AI reasoning path — the agent process consults
/// this before every action, and the switch can be toggled via
/// a separate admin channel (SIGTERM, web UI, etc.).
pub struct KillSwitch {
    active: AtomicBool,
    activated_at: Mutex<Option<Instant>>,
    reason: Mutex<Option<String>>,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            activated_at: Mutex::new(None),
            reason: Mutex::new(None),
        }
    }

    /// Activate the kill switch. Idempotent.
    pub fn activate(&self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.active.swap(true, Ordering::SeqCst) {
            *self.activated_at.lock().unwrap() = Some(Instant::now());
            *self.reason.lock().unwrap() = Some(reason.clone());
            error!("KILL SWITCH ACTIVATED: {}", reason);
        }
    }

    /// Check if the kill switch is active. O(1), atomic.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Reason for activation, if any.
    pub fn reason(&self) -> Option<String> {
        self.reason.lock().unwrap().clone()
    }

    /// How long ago the switch was activated.
    pub fn activated_elapsed(&self) -> Option<Duration> {
        self.activated_at.lock().unwrap().map(|t| t.elapsed())
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  2. BudgetCap
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Per-session spending ceiling. Tracks cumulative microdollars
/// and blocks when the ceiling is reached.
pub struct BudgetCap {
    spent_microdollars: AtomicU64,
    limit_microdollars: u64,
}

impl BudgetCap {
    /// Create with a spending ceiling. `None` = unlimited.
    pub fn new(limit_microdollars: Option<u64>) -> Self {
        Self {
            spent_microdollars: AtomicU64::new(0),
            limit_microdollars: limit_microdollars.unwrap_or(u64::MAX),
        }
    }

    /// Record spending. Returns false if the cap is exceeded.
    pub fn record(&self, microdollars: u64) -> bool {
        let new_total = self
            .spent_microdollars
            .fetch_add(microdollars, Ordering::Relaxed)
            + microdollars;
        new_total <= self.limit_microdollars
    }

    /// Check if the cap is already exceeded (without recording).
    pub fn check(&self) -> Option<FenceDecision> {
        let spent = self.spent_microdollars.load(Ordering::Relaxed);
        if spent > self.limit_microdollars {
            Some(FenceDecision::BudgetExceeded {
                spent_microdollars: spent,
                limit_microdollars: self.limit_microdollars,
            })
        } else {
            None
        }
    }

    pub fn spent(&self) -> u64 {
        self.spent_microdollars.load(Ordering::Relaxed)
    }

    pub fn limit(&self) -> u64 {
        self.limit_microdollars
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  3. RateLimit — sliding window counter
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Sliding-window rate limiter. Counts calls within the last `window`.
pub struct RateLimit {
    limit: u32,
    window: Duration,
    /// Timestamps of recent calls (pruned on each check)
    calls: Mutex<Vec<Instant>>,
}

impl RateLimit {
    /// `limit` calls per `window` duration.
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Record a call and check the rate limit.
    /// Returns the blocked FenceDecision if rate exceeded, else None.
    pub fn record_and_check(&self) -> Option<FenceDecision> {
        let now = Instant::now();
        let mut calls = self.calls.lock().unwrap();
        // Prune old calls outside the window
        calls.retain(|&t| now.duration_since(t) < self.window);
        calls.push(now);
        if calls.len() as u32 > self.limit {
            Some(FenceDecision::RateLimited {
                calls_in_window: calls.len() as u32,
                limit: self.limit,
            })
        } else {
            None
        }
    }

    /// Check without recording (peek).
    pub fn check(&self) -> Option<FenceDecision> {
        let now = Instant::now();
        let calls = self.calls.lock().unwrap();
        let count = calls.iter().filter(|&&t| now.duration_since(t) < self.window).count();
        if count as u32 >= self.limit {
            Some(FenceDecision::RateLimited {
                calls_in_window: count as u32,
                limit: self.limit,
            })
        } else {
            None
        }
    }

    pub fn current_count(&self) -> u32 {
        let now = Instant::now();
        let calls = self.calls.lock().unwrap();
        calls.iter().filter(|&&t| now.duration_since(t) < self.window).count() as u32
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  4. FenceCircuitBreaker — used within RuntimeFence
//     (distinct from crates/gateway/src/circuit_breaker.rs
//      which is provider-specific)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FenceCircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct FenceCircuitBreaker {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    last_failure: Mutex<Option<Instant>>,
}

impl FenceCircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout_secs: u64) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            failure_threshold,
            success_threshold,
            timeout: Duration::from_secs(timeout_secs),
            last_failure: Mutex::new(None),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(5, 3, 60)
    }

    pub fn state(&self) -> FenceCircuitState {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.failure_threshold {
            return FenceCircuitState::Closed;
        }
        let last = self.last_failure.lock().unwrap();
        if let Some(t) = *last {
            if t.elapsed() >= self.timeout {
                return FenceCircuitState::HalfOpen;
            }
        }
        FenceCircuitState::Open
    }

    pub fn check(&self) -> Option<FenceDecision> {
        if self.state() == FenceCircuitState::Open {
            Some(FenceDecision::CircuitOpen {
                failures: self.failure_count.load(Ordering::Relaxed),
            })
        } else {
            None
        }
    }

    pub fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.fetch_add(1, Ordering::Relaxed);
        if self.state() == FenceCircuitState::HalfOpen {
            let s = self.success_count.load(Ordering::Relaxed);
            if s >= self.success_threshold {
                info!("Runtime fence circuit breaker: CLOSED (recovered)");
                *self.last_failure.lock().unwrap() = None;
            }
        }
    }

    pub fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        self.success_count.store(0, Ordering::Relaxed);
        *self.last_failure.lock().unwrap() = Some(Instant::now());
        if count == self.failure_threshold {
            warn!(
                "Runtime fence circuit breaker: OPEN (threshold {} reached)",
                self.failure_threshold
            );
        }
    }

    pub fn reset(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        *self.last_failure.lock().unwrap() = None;
    }

    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Relaxed)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  5. RuntimeFence — composite gate
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Composite safety gate. Call `RuntimeFence::check()` before every
/// agent action. Returns `FenceDecision::Proceed` only if all gates pass.
///
/// Priority order (first match wins):
///   1. Kill switch (hardest stop)
///   2. Budget cap
///   3. Rate limit
///   4. Circuit breaker
pub struct RuntimeFence {
    pub kill_switch: Arc<KillSwitch>,
    pub budget: Arc<BudgetCap>,
    pub rate: Arc<RateLimit>,
    pub circuit: Arc<FenceCircuitBreaker>,
}

impl RuntimeFence {
    /// Build with all gates enabled using the given parameters.
    pub fn new(
        budget_limit_microdollars: Option<u64>,
        rate_limit: u32,
        rate_window: Duration,
        circuit_failure_threshold: u32,
        circuit_success_threshold: u32,
        circuit_timeout_secs: u64,
    ) -> Self {
        Self {
            kill_switch: Arc::new(KillSwitch::new()),
            budget: Arc::new(BudgetCap::new(budget_limit_microdollars)),
            rate: Arc::new(RateLimit::new(rate_limit, rate_window)),
            circuit: Arc::new(FenceCircuitBreaker::new(
                circuit_failure_threshold,
                circuit_success_threshold,
                circuit_timeout_secs,
            )),
        }
    }

    /// Default fence: $10 session budget, 60 req/min, circuit at 5 failures.
    pub fn with_defaults() -> Self {
        Self::new(
            Some(10_000_000), // $10.00
            60,               // 60 calls per minute
            Duration::from_secs(60),
            5,  // circuit opens after 5 failures
            3,  // circuit closes after 3 successes
            60, // 60-second circuit timeout
        )
    }

    /// Check all gates. Call before every LLM/tool invocation.
    /// Does NOT record a rate-limit call — use `check_and_record` for that.
    pub fn check(&self) -> FenceDecision {
        if self.kill_switch.is_active() {
            return FenceDecision::KillSwitchActive;
        }
        if let Some(d) = self.budget.check() {
            return d;
        }
        if let Some(d) = self.rate.check() {
            return d;
        }
        if let Some(d) = self.circuit.check() {
            return d;
        }
        FenceDecision::Proceed
    }

    /// Check all gates AND record a rate-limit call (use at action time).
    pub fn check_and_record(&self) -> FenceDecision {
        if self.kill_switch.is_active() {
            return FenceDecision::KillSwitchActive;
        }
        if let Some(d) = self.budget.check() {
            return d;
        }
        if let Some(d) = self.rate.record_and_check() {
            return d;
        }
        if let Some(d) = self.circuit.check() {
            return d;
        }
        FenceDecision::Proceed
    }

    /// Activate the kill switch immediately.
    pub fn kill(&self, reason: impl Into<String>) {
        self.kill_switch.activate(reason);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    // --- KillSwitch ---

    #[test]
    fn kill_switch_starts_inactive() {
        let ks = KillSwitch::new();
        assert!(!ks.is_active());
        assert!(ks.reason().is_none());
    }

    #[test]
    fn kill_switch_activate_sets_state() {
        let ks = KillSwitch::new();
        ks.activate("test reason");
        assert!(ks.is_active());
        assert_eq!(ks.reason().unwrap(), "test reason");
    }

    #[test]
    fn kill_switch_activate_is_idempotent() {
        let ks = KillSwitch::new();
        ks.activate("first");
        ks.activate("second");
        assert_eq!(ks.reason().unwrap(), "first");
    }

    // --- BudgetCap ---

    #[test]
    fn budget_cap_allows_under_limit() {
        let cap = BudgetCap::new(Some(1_000_000));
        assert!(cap.record(500_000));
        assert!(cap.check().is_none());
    }

    #[test]
    fn budget_cap_blocks_over_limit() {
        let cap = BudgetCap::new(Some(1_000_000));
        cap.record(1_500_000);
        assert!(cap.check().is_some());
    }

    #[test]
    fn budget_cap_unlimited() {
        let cap = BudgetCap::new(None);
        cap.record(u64::MAX / 2);
        assert!(cap.check().is_none());
    }

    // --- RateLimit ---

    #[test]
    fn rate_limit_allows_under_limit() {
        let rl = RateLimit::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            assert!(rl.record_and_check().is_none());
        }
    }

    #[test]
    fn rate_limit_blocks_over_limit() {
        let rl = RateLimit::new(3, Duration::from_secs(60));
        rl.record_and_check();
        rl.record_and_check();
        rl.record_and_check();
        let result = rl.record_and_check();
        assert!(result.is_some());
        assert!(matches!(result, Some(FenceDecision::RateLimited { .. })));
    }

    // --- FenceCircuitBreaker ---

    #[test]
    fn circuit_starts_closed() {
        let cb = FenceCircuitBreaker::with_defaults();
        assert_eq!(cb.state(), FenceCircuitState::Closed);
        assert!(cb.check().is_none());
    }

    #[test]
    fn circuit_opens_after_failures() {
        let cb = FenceCircuitBreaker::new(3, 2, 60);
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), FenceCircuitState::Open);
        assert!(matches!(cb.check(), Some(FenceDecision::CircuitOpen { .. })));
    }

    #[test]
    fn circuit_success_resets_failure_count() {
        let cb = FenceCircuitBreaker::new(3, 2, 60);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.state(), FenceCircuitState::Closed);
    }

    #[test]
    fn circuit_half_open_after_timeout() {
        let cb = FenceCircuitBreaker::new(2, 1, 0); // 0-sec timeout
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cb.state(), FenceCircuitState::HalfOpen);
    }

    // --- RuntimeFence ---

    #[test]
    fn fence_proceeds_when_all_clear() {
        let fence = RuntimeFence::with_defaults();
        assert_eq!(fence.check(), FenceDecision::Proceed);
    }

    #[test]
    fn fence_kill_switch_blocks() {
        let fence = RuntimeFence::with_defaults();
        fence.kill("emergency");
        assert_eq!(fence.check(), FenceDecision::KillSwitchActive);
    }

    #[test]
    fn fence_budget_exceeded_blocks() {
        let fence = RuntimeFence::new(
            Some(1_000_000), // $1.00 limit
            1000,
            Duration::from_secs(60),
            5,
            3,
            60,
        );
        fence.budget.record(1_500_000); // overspend
        assert!(matches!(fence.check(), FenceDecision::BudgetExceeded { .. }));
    }

    #[test]
    fn fence_kill_switch_takes_priority_over_budget() {
        let fence = RuntimeFence::new(
            Some(1_000_000),
            1000,
            Duration::from_secs(60),
            5,
            3,
            60,
        );
        fence.budget.record(2_000_000); // budget exceeded
        fence.kill("kill");             // kill switch also active
        // Kill switch should take priority
        assert_eq!(fence.check(), FenceDecision::KillSwitchActive);
    }

    #[test]
    fn fence_circuit_blocked_propagates() {
        let fence = RuntimeFence::new(
            None,
            1000,
            Duration::from_secs(60),
            2, // low threshold for test
            1,
            60,
        );
        fence.circuit.record_failure();
        fence.circuit.record_failure();
        assert!(matches!(fence.check(), FenceDecision::CircuitOpen { .. }));
    }

    #[test]
    fn fence_decision_reason_strings() {
        assert_eq!(FenceDecision::Proceed.reason(), "proceed");
        assert!(FenceDecision::KillSwitchActive.reason().contains("kill switch"));
        assert!(FenceDecision::BudgetExceeded {
            spent_microdollars: 2_000_000,
            limit_microdollars: 1_000_000
        }
        .reason()
        .contains("budget"));
    }
}
