#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal — requests pass through
    Open,     // Failing — requests blocked
    HalfOpen, // Testing — one request allowed
}

/// Circuit breaker for provider resilience.
/// Tracks failures and opens circuit after threshold.
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    last_failure: Mutex<Option<Instant>>,
}

impl CircuitBreaker {
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

    pub fn state(&self) -> CircuitState {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.failure_threshold {
            return CircuitState::Closed;
        }

        let last = self.last_failure.lock().unwrap();
        if let Some(last_time) = *last {
            if last_time.elapsed() >= self.timeout {
                return CircuitState::HalfOpen;
            }
        }

        CircuitState::Open
    }

    /// Check if request should be allowed
    pub fn allow_request(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => true, // Allow one probe
        }
    }

    /// Record a successful call
    pub fn record_success(&self) {
        let prev_state = self.state();
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.fetch_add(1, Ordering::Relaxed);

        if prev_state == CircuitState::HalfOpen {
            let successes = self.success_count.load(Ordering::Relaxed);
            if successes >= self.success_threshold {
                tracing::info!("🔌 Circuit breaker: CLOSED (recovered)");
                *self.last_failure.lock().unwrap() = None;
            }
        }
    }

    /// Record a failed call
    pub fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        self.success_count.store(0, Ordering::Relaxed);
        *self.last_failure.lock().unwrap() = Some(Instant::now());

        if count == self.failure_threshold {
            tracing::warn!(
                "🔌 Circuit breaker: OPEN (threshold {} reached)",
                self.failure_threshold
            );
        }
    }

    /// Reset the breaker
    pub fn reset(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        *self.last_failure.lock().unwrap() = None;
    }

    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starts_closed() {
        let cb = CircuitBreaker::with_defaults();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_opens_after_failures() {
        let cb = CircuitBreaker::new(3, 2, 60);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_success_resets() {
        let cb = CircuitBreaker::new(3, 2, 60);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_half_open_after_timeout() {
        let cb = CircuitBreaker::new(2, 1, 0); // 0 sec timeout
        cb.record_failure();
        cb.record_failure();
        // Timeout is 0, so immediately half-open
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_reset() {
        let cb = CircuitBreaker::new(2, 1, 60);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
    }
}
