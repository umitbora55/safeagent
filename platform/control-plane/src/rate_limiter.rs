use std::{collections::HashMap, sync::Mutex, time::Instant};

use axum::http::StatusCode;
use safeagent_shared_identity::TenantId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct TenantRateLimitConfig {
    pub token_bucket_capacity: u64,
    pub token_bucket_refill_per_second: u64,
    pub concurrent_limit: usize,
    pub queue_limit: usize,
    pub cost_budget: u64,
}

impl Default for TenantRateLimitConfig {
    fn default() -> Self {
        Self {
            token_bucket_capacity: 10_000,
            token_bucket_refill_per_second: 10_000,
            concurrent_limit: 1000,
            queue_limit: 10_000,
            cost_budget: 1_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TenantLimitPermit {
    tenant_id: TenantId,
    limiter: std::sync::Arc<TenantRateLimiter>,
}

impl TenantLimitPermit {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitError {
    pub code: &'static str,
    pub status: StatusCode,
    pub message: String,
    pub retry_after_seconds: Option<u64>,
}

impl RateLimitError {
    pub fn into_body(self) -> RateLimitErrorBody {
        RateLimitErrorBody {
            code: self.code.to_string(),
            message: self.message,
            retry_after_seconds: self.retry_after_seconds,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitErrorBody {
    pub code: String,
    pub message: String,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Default, Debug, Clone)]
struct TenantState {
    tokens: f64,
    last_refill: Option<Instant>,
    in_flight: usize,
    cost_used: u64,
}

impl TenantState {
    fn refill(&mut self, config: &TenantRateLimitConfig, now: Instant) {
        if self.last_refill.is_none() {
            self.tokens = config.token_bucket_capacity as f64;
            self.last_refill = Some(now);
            return;
        }

        let elapsed_ms = now
            .duration_since(self.last_refill.unwrap_or(now))
            .as_millis();
        if elapsed_ms == 0 {
            return;
        }
        let elapsed_seconds =
            (elapsed_ms as f64) / 1000.0 * (config.token_bucket_refill_per_second as f64);
        self.tokens = (self.tokens + elapsed_seconds).min(config.token_bucket_capacity as f64);
        self.last_refill = Some(now);
    }
}

#[derive(Debug, Default)]
struct RateLimiterState {
    tenants: HashMap<TenantId, TenantState>,
}

#[derive(Debug, Clone)]
pub struct TenantRateLimiter {
    config: TenantRateLimitConfig,
    state: std::sync::Arc<Mutex<RateLimiterState>>,
}

impl TenantRateLimiter {
    pub fn new(config: TenantRateLimitConfig) -> Self {
        Self {
            config,
            state: std::sync::Arc::new(Mutex::new(RateLimiterState::default())),
        }
    }

    pub fn config(&self) -> &TenantRateLimitConfig {
        &self.config
    }

    pub fn allow_request(&self, tenant_id: &TenantId) -> Result<TenantLimitPermit, RateLimitError> {
        self.allow_request_at(tenant_id, Instant::now())
    }

    pub(crate) fn allow_request_at(
        &self,
        tenant_id: &TenantId,
        now: Instant,
    ) -> Result<TenantLimitPermit, RateLimitError> {
        let total_limit = self
            .config
            .concurrent_limit
            .saturating_add(self.config.queue_limit);
        let mut state = self.state.lock().map_err(|_| RateLimitError {
            code: "rate_limit_internal",
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "rate limiter lock poisoned".to_string(),
            retry_after_seconds: None,
        })?;

        let tenant_state = state.tenants.entry(tenant_id.clone()).or_default();
        tenant_state.refill(&self.config, now);

        if tenant_state.in_flight >= total_limit {
            return Err(RateLimitError {
                code: "queue_limit_exceeded",
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: "backpressure queue limit exceeded".to_string(),
                retry_after_seconds: Some(1),
            });
        }
        if tenant_state.in_flight >= self.config.concurrent_limit {
            return Err(RateLimitError {
                code: "concurrent_limit_exceeded",
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "concurrent execute limit exceeded".to_string(),
                retry_after_seconds: Some(1),
            });
        }
        if tenant_state.tokens < 1.0 {
            return Err(RateLimitError {
                code: "rate_limit_exceeded",
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "request rate limit exceeded".to_string(),
                retry_after_seconds: Some(1),
            });
        }

        tenant_state.tokens -= 1.0;
        tenant_state.in_flight += 1;
        Ok(TenantLimitPermit {
            tenant_id: tenant_id.clone(),
            limiter: std::sync::Arc::new(self.clone()),
        })
    }

    pub fn release_request(&self, permit: TenantLimitPermit) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(tenant_state) = state.tenants.get_mut(permit.tenant_id()) {
                tenant_state.in_flight = tenant_state.in_flight.saturating_sub(1);
            }
        }
    }

    pub fn charge_cost(&self, tenant_id: &TenantId, amount: u64) -> Result<(), RateLimitError> {
        let mut state = self.state.lock().map_err(|_| RateLimitError {
            code: "rate_limit_internal",
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "rate limiter lock poisoned".to_string(),
            retry_after_seconds: None,
        })?;

        if self.config.cost_budget == 0 {
            return Ok(());
        }

        let tenant_state = state.tenants.entry(tenant_id.clone()).or_default();
        if tenant_state.cost_used.saturating_add(amount) > self.config.cost_budget {
            return Err(RateLimitError {
                code: "cost_limit_exceeded",
                status: StatusCode::PAYMENT_REQUIRED,
                message: "tenant cost budget exceeded".to_string(),
                retry_after_seconds: None,
            });
        }
        tenant_state.cost_used = tenant_state.cost_used.saturating_add(amount);
        Ok(())
    }
}

impl Drop for TenantLimitPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.limiter.state.lock() {
            if let Some(tenant_state) = state.tenants.get_mut(&self.tenant_id) {
                tenant_state.in_flight = tenant_state.in_flight.saturating_sub(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeagent_shared_identity::TenantId;

    #[test]
    fn tenant_rate_limit_token_bucket_refills_without_sleep() {
        let limiter = TenantRateLimiter::new(TenantRateLimitConfig {
            token_bucket_capacity: 2,
            token_bucket_refill_per_second: 4,
            ..TenantRateLimitConfig::default()
        });
        let tenant = TenantId("tenant-a".to_string());

        let now = Instant::now();
        let permit1 = limiter
            .allow_request_at(&tenant, now)
            .expect("first request");
        let permit2 = limiter
            .allow_request_at(&tenant, now)
            .expect("second request");
        drop(permit1);
        drop(permit2);

        assert!(limiter.allow_request_at(&tenant, now).is_err());

        let fast_forward = now
            .checked_add(std::time::Duration::from_millis(300))
            .unwrap_or(now);
        // 0.3s at 4 rps gives enough to refill at least 1 token in deterministic clock math.
        let second = limiter
            .allow_request_at(&tenant, fast_forward)
            .expect("refilled request");
        drop(second);
    }

    #[test]
    fn tenant_rate_limit_concurrent_block() {
        let limiter = TenantRateLimiter::new(TenantRateLimitConfig {
            concurrent_limit: 2,
            token_bucket_capacity: 10,
            token_bucket_refill_per_second: 10,
            queue_limit: 10,
            cost_budget: 10,
        });
        let tenant = TenantId("tenant-b".to_string());
        let now = Instant::now();
        let _p1 = limiter.allow_request_at(&tenant, now).expect("first");
        let _p2 = limiter.allow_request_at(&tenant, now).expect("second");
        let denied = limiter
            .allow_request_at(&tenant, now)
            .expect_err("third denied");
        assert_eq!(denied.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(denied.code, "concurrent_limit_exceeded");
    }

    #[test]
    fn tenant_rate_limit_queue_block() {
        let limiter = TenantRateLimiter::new(TenantRateLimitConfig {
            concurrent_limit: 1,
            queue_limit: 0,
            token_bucket_capacity: 10,
            token_bucket_refill_per_second: 10,
            cost_budget: 10,
        });
        let tenant = TenantId("tenant-c".to_string());
        let p1 = limiter
            .allow_request(&tenant)
            .expect("first request enters");
        let denied = limiter.allow_request(&tenant).expect_err("queue blocked");
        drop(p1);
        assert_eq!(denied.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(denied.code, "queue_limit_exceeded");
    }

    #[test]
    fn tenant_cost_budget_block() {
        let limiter = TenantRateLimiter::new(TenantRateLimitConfig {
            concurrent_limit: 10,
            cost_budget: 1,
            token_bucket_capacity: 10,
            token_bucket_refill_per_second: 10,
            queue_limit: 10,
        });
        let tenant = TenantId("tenant-d".to_string());
        let permit = limiter
            .allow_request(&tenant)
            .expect("request allowed for cost accounting");
        limiter
            .charge_cost(permit.tenant_id(), 1)
            .expect("first cost charge");
        drop(permit);
        let denied = limiter
            .charge_cost(&tenant, 1)
            .expect_err("second cost denied");
        assert_eq!(denied.status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(denied.code, "cost_limit_exceeded");
    }
}
