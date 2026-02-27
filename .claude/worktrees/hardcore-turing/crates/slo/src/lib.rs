// safeagent-slo
//
// W7 D6: SLO governance dashboard
//
// Defines and tracks Service Level Objectives for SafeAgent's
// authorization control plane. Quantifies security posture for CISOs.
//
// Compass W7 D6 SLO targets:
//   authorization_latency_p95  < 50ms
//   evidence_reliability       > 99.9%
//   false_positive_rate        < 2.0%
//   break_glass_usage          < 5 per week
//   kill_switch_response_ms    < 100ms
//
// Architecture:
//   SloMetricsCollector — receives raw events from the gateway
//   SloAggregator       — computes p95, rates, and rolling windows
//   SloReport           — compliance status per objective for CISO review
//   SloAlert            — emitted when an SLO is violated

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tracing::{info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SLO targets
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Configurable SLO targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloTargets {
    /// Authorization latency p95 ceiling (milliseconds).
    pub latency_p95_ms: f64,
    /// Evidence log availability (0.0–1.0). Default: 0.999.
    pub evidence_reliability_min: f64,
    /// False positive rate ceiling (fraction 0.0–1.0). Default: 0.02.
    pub false_positive_rate_max: f64,
    /// Break-glass usage per week ceiling (count). Default: 5.
    pub break_glass_per_week_max: u64,
    /// Kill-switch response time ceiling (milliseconds). Default: 100ms.
    pub kill_switch_response_ms_max: f64,
}

impl Default for SloTargets {
    fn default() -> Self {
        Self {
            latency_p95_ms: 50.0,
            evidence_reliability_min: 0.999,
            false_positive_rate_max: 0.02,
            break_glass_per_week_max: 5,
            kill_switch_response_ms_max: 100.0,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Raw events recorded at the gateway
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A single authorization decision event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub timestamp: DateTime<Utc>,
    /// Wall-clock time for policy evaluation (milliseconds).
    pub latency_ms: f64,
    /// Whether the decision was a false positive (legitimate action blocked).
    pub false_positive: bool,
    /// Whether a break-glass override was used.
    pub break_glass: bool,
    /// Whether this event involved the kill switch.
    pub kill_switch: bool,
    /// Kill-switch response time (ms), if applicable.
    pub kill_switch_response_ms: Option<f64>,
    /// Whether the evidence log entry was successfully written.
    pub evidence_written: bool,
}

impl AuthEvent {
    pub fn new(latency_ms: f64) -> Self {
        Self {
            timestamp: Utc::now(),
            latency_ms,
            false_positive: false,
            break_glass: false,
            kill_switch: false,
            kill_switch_response_ms: None,
            evidence_written: true,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SLO compliance status
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SloStatus {
    /// Within target.
    Compliant,
    /// Within 10% of target — warn.
    AtRisk,
    /// Target breached.
    Violated,
    /// Not enough data to evaluate.
    Insufficient,
}

/// Compliance result for a single SLO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloResult {
    pub name: String,
    pub status: SloStatus,
    pub target: String,
    pub measured: String,
    pub sample_count: usize,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SLO metrics collector and aggregator
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const MIN_SAMPLES_FOR_EVALUATION: usize = 10;

/// Collects auth events in a rolling window and computes SLO compliance.
pub struct SloAggregator {
    targets: SloTargets,
    /// Rolling window of events (most recent first).
    events: VecDeque<AuthEvent>,
    /// Maximum window size.
    window_size: usize,
    /// Window duration for time-bounded metrics (e.g. break-glass per week).
    window_duration: Duration,
}

impl SloAggregator {
    pub fn new(targets: SloTargets) -> Self {
        Self {
            targets,
            events: VecDeque::new(),
            window_size: 10_000,
            window_duration: Duration::weeks(1),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(SloTargets::default())
    }

    /// Record an authorization event.
    pub fn record(&mut self, event: AuthEvent) {
        if self.events.len() >= self.window_size {
            self.events.pop_back();
        }
        self.events.push_front(event);
    }

    /// Total events in the rolling window.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Compute authorization latency at the given percentile (0.0–100.0).
    pub fn latency_percentile(&self, pct: f64) -> Option<f64> {
        if self.events.is_empty() {
            return None;
        }
        let mut latencies: Vec<f64> = self.events.iter().map(|e| e.latency_ms).collect();
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = ((pct / 100.0) * (latencies.len() as f64 - 1.0))
            .round()
            .max(0.0) as usize;
        Some(latencies[idx.min(latencies.len() - 1)])
    }

    /// Events within the configured window duration.
    fn events_in_window(&self) -> impl Iterator<Item = &AuthEvent> {
        let cutoff = Utc::now() - self.window_duration;
        self.events.iter().filter(move |e| e.timestamp >= cutoff)
    }

    /// False positive rate across all recorded events.
    pub fn false_positive_rate(&self) -> Option<f64> {
        let total = self.events.len();
        if total == 0 {
            return None;
        }
        let fp_count = self.events.iter().filter(|e| e.false_positive).count();
        Some(fp_count as f64 / total as f64)
    }

    /// Break-glass events in the current week window.
    pub fn break_glass_count_week(&self) -> u64 {
        self.events_in_window().filter(|e| e.break_glass).count() as u64
    }

    /// Evidence reliability (fraction of events where evidence was written).
    pub fn evidence_reliability(&self) -> Option<f64> {
        let total = self.events.len();
        if total == 0 {
            return None;
        }
        let written = self.events.iter().filter(|e| e.evidence_written).count();
        Some(written as f64 / total as f64)
    }

    /// Kill-switch response p95 (milliseconds).
    pub fn kill_switch_p95_ms(&self) -> Option<f64> {
        let mut ks_latencies: Vec<f64> = self
            .events
            .iter()
            .filter_map(|e| e.kill_switch_response_ms)
            .collect();
        if ks_latencies.is_empty() {
            return None;
        }
        ks_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = (0.95 * (ks_latencies.len() as f64 - 1.0))
            .round()
            .max(0.0) as usize;
        Some(ks_latencies[idx.min(ks_latencies.len() - 1)])
    }

    /// Generate a full SLO compliance report.
    pub fn report(&self) -> SloReport {
        let n = self.events.len();
        let mut results = Vec::new();

        // SLO 1: Authorization latency p95
        {
            let result = if n < MIN_SAMPLES_FOR_EVALUATION {
                SloResult {
                    name: "authorization_latency_p95".to_string(),
                    status: SloStatus::Insufficient,
                    target: format!("< {}ms", self.targets.latency_p95_ms),
                    measured: format!("{} samples", n),
                    sample_count: n,
                }
            } else {
                let p95 = self.latency_percentile(95.0).unwrap();
                let target = self.targets.latency_p95_ms;
                let status = if p95 <= target {
                    SloStatus::Compliant
                } else if p95 <= target * 1.1 {
                    SloStatus::AtRisk
                } else {
                    SloStatus::Violated
                };
                if status == SloStatus::Violated {
                    warn!(p95, target, "SLO violated: authorization_latency_p95");
                }
                SloResult {
                    name: "authorization_latency_p95".to_string(),
                    status,
                    target: format!("< {:.1}ms", target),
                    measured: format!("{:.1}ms", p95),
                    sample_count: n,
                }
            };
            results.push(result);
        }

        // SLO 2: Evidence reliability
        {
            let result = if n < MIN_SAMPLES_FOR_EVALUATION {
                SloResult {
                    name: "evidence_reliability".to_string(),
                    status: SloStatus::Insufficient,
                    target: format!("> {:.1}%", self.targets.evidence_reliability_min * 100.0),
                    measured: format!("{} samples", n),
                    sample_count: n,
                }
            } else {
                let reliability = self.evidence_reliability().unwrap();
                let target = self.targets.evidence_reliability_min;
                let status = if reliability >= target {
                    SloStatus::Compliant
                } else if reliability >= target * 0.99 {
                    SloStatus::AtRisk
                } else {
                    SloStatus::Violated
                };
                SloResult {
                    name: "evidence_reliability".to_string(),
                    status,
                    target: format!("> {:.1}%", target * 100.0),
                    measured: format!("{:.2}%", reliability * 100.0),
                    sample_count: n,
                }
            };
            results.push(result);
        }

        // SLO 3: False positive rate
        {
            let result = if n < MIN_SAMPLES_FOR_EVALUATION {
                SloResult {
                    name: "false_positive_rate".to_string(),
                    status: SloStatus::Insufficient,
                    target: format!("< {:.1}%", self.targets.false_positive_rate_max * 100.0),
                    measured: format!("{} samples", n),
                    sample_count: n,
                }
            } else {
                let fpr = self.false_positive_rate().unwrap();
                let target = self.targets.false_positive_rate_max;
                let status = if fpr <= target {
                    SloStatus::Compliant
                } else if fpr <= target * 1.1 {
                    SloStatus::AtRisk
                } else {
                    SloStatus::Violated
                };
                SloResult {
                    name: "false_positive_rate".to_string(),
                    status,
                    target: format!("< {:.1}%", target * 100.0),
                    measured: format!("{:.2}%", fpr * 100.0),
                    sample_count: n,
                }
            };
            results.push(result);
        }

        // SLO 4: Break-glass usage per week
        {
            let bg = self.break_glass_count_week();
            let target = self.targets.break_glass_per_week_max;
            let status = if bg <= target {
                SloStatus::Compliant
            } else {
                SloStatus::Violated
            };
            results.push(SloResult {
                name: "break_glass_usage_week".to_string(),
                status,
                target: format!("< {} per week", target),
                measured: format!("{} uses", bg),
                sample_count: n,
            });
        }

        // SLO 5: Kill-switch response
        {
            let result = match self.kill_switch_p95_ms() {
                None => SloResult {
                    name: "kill_switch_response_p95".to_string(),
                    status: SloStatus::Insufficient,
                    target: format!("< {}ms", self.targets.kill_switch_response_ms_max),
                    measured: "no kill-switch events".to_string(),
                    sample_count: 0,
                },
                Some(p95) => {
                    let target = self.targets.kill_switch_response_ms_max;
                    let status = if p95 <= target {
                        SloStatus::Compliant
                    } else {
                        SloStatus::Violated
                    };
                    SloResult {
                        name: "kill_switch_response_p95".to_string(),
                        status,
                        target: format!("< {}ms", target),
                        measured: format!("{:.1}ms", p95),
                        sample_count: n,
                    }
                }
            };
            results.push(result);
        }

        let all_compliant = results
            .iter()
            .all(|r| matches!(r.status, SloStatus::Compliant | SloStatus::Insufficient));

        if all_compliant {
            info!(events = n, "SLO report: all objectives compliant");
        } else {
            let violations: Vec<_> = results
                .iter()
                .filter(|r| r.status == SloStatus::Violated)
                .map(|r| r.name.as_str())
                .collect();
            warn!(?violations, "SLO report: violations detected");
        }

        SloReport {
            generated_at: Utc::now(),
            total_events: n,
            objectives: results,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SLO compliance report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Full SLO compliance report, suitable for CISO dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloReport {
    pub generated_at: DateTime<Utc>,
    pub total_events: usize,
    pub objectives: Vec<SloResult>,
}

impl SloReport {
    /// Overall compliance: true if no SLO is violated.
    pub fn fully_compliant(&self) -> bool {
        self.objectives
            .iter()
            .all(|o| o.status != SloStatus::Violated)
    }

    /// Number of violated objectives.
    pub fn violation_count(&self) -> usize {
        self.objectives
            .iter()
            .filter(|o| o.status == SloStatus::Violated)
            .count()
    }

    /// Number of at-risk objectives.
    pub fn at_risk_count(&self) -> usize {
        self.objectives
            .iter()
            .filter(|o| o.status == SloStatus::AtRisk)
            .count()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn fill_events(agg: &mut SloAggregator, count: usize, latency_ms: f64) {
        for _ in 0..count {
            agg.record(AuthEvent::new(latency_ms));
        }
    }

    #[test]
    fn insufficient_data_before_min_samples() {
        let agg = SloAggregator::with_defaults();
        let report = agg.report();
        // All data-dependent SLOs should be Insufficient
        let latency_result = report
            .objectives
            .iter()
            .find(|o| o.name == "authorization_latency_p95")
            .unwrap();
        assert_eq!(latency_result.status, SloStatus::Insufficient);
    }

    #[test]
    fn latency_compliant_under_target() {
        let mut agg = SloAggregator::with_defaults();
        fill_events(&mut agg, 20, 30.0); // 30ms < 50ms target
        let report = agg.report();
        let lat = report
            .objectives
            .iter()
            .find(|o| o.name == "authorization_latency_p95")
            .unwrap();
        assert_eq!(lat.status, SloStatus::Compliant);
    }

    #[test]
    fn latency_violated_over_target() {
        let mut agg = SloAggregator::with_defaults();
        fill_events(&mut agg, 20, 100.0); // 100ms > 50ms target
        let report = agg.report();
        let lat = report
            .objectives
            .iter()
            .find(|o| o.name == "authorization_latency_p95")
            .unwrap();
        assert_eq!(lat.status, SloStatus::Violated);
    }

    #[test]
    fn evidence_reliability_compliant() {
        let mut agg = SloAggregator::with_defaults();
        // 20 events, all written
        fill_events(&mut agg, 20, 10.0);
        let report = agg.report();
        let ev = report
            .objectives
            .iter()
            .find(|o| o.name == "evidence_reliability")
            .unwrap();
        assert_eq!(ev.status, SloStatus::Compliant);
    }

    #[test]
    fn evidence_reliability_violated() {
        let mut agg = SloAggregator::with_defaults();
        for _ in 0..20 {
            let mut evt = AuthEvent::new(10.0);
            evt.evidence_written = false;
            agg.record(evt);
        }
        let report = agg.report();
        let ev = report
            .objectives
            .iter()
            .find(|o| o.name == "evidence_reliability")
            .unwrap();
        assert_eq!(ev.status, SloStatus::Violated);
    }

    #[test]
    fn false_positive_rate_compliant() {
        let mut agg = SloAggregator::with_defaults();
        // 1 FP out of 100 = 1% < 2% target
        for i in 0..100 {
            let mut evt = AuthEvent::new(10.0);
            evt.false_positive = i == 0;
            agg.record(evt);
        }
        let report = agg.report();
        let fp = report
            .objectives
            .iter()
            .find(|o| o.name == "false_positive_rate")
            .unwrap();
        assert_eq!(fp.status, SloStatus::Compliant);
    }

    #[test]
    fn false_positive_rate_violated() {
        let mut agg = SloAggregator::with_defaults();
        // 10 FP out of 20 = 50% >> 2% target
        for i in 0..20 {
            let mut evt = AuthEvent::new(10.0);
            evt.false_positive = i < 10;
            agg.record(evt);
        }
        let report = agg.report();
        let fp = report
            .objectives
            .iter()
            .find(|o| o.name == "false_positive_rate")
            .unwrap();
        assert_eq!(fp.status, SloStatus::Violated);
    }

    #[test]
    fn break_glass_compliant() {
        let mut agg = SloAggregator::with_defaults();
        for i in 0..20 {
            let mut evt = AuthEvent::new(10.0);
            evt.break_glass = i < 3; // 3 < 5 target
            agg.record(evt);
        }
        let report = agg.report();
        let bg = report
            .objectives
            .iter()
            .find(|o| o.name == "break_glass_usage_week")
            .unwrap();
        assert_eq!(bg.status, SloStatus::Compliant);
    }

    #[test]
    fn break_glass_violated() {
        let mut agg = SloAggregator::with_defaults();
        for i in 0..20 {
            let mut evt = AuthEvent::new(10.0);
            evt.break_glass = i < 10; // 10 > 5 target
            agg.record(evt);
        }
        let report = agg.report();
        let bg = report
            .objectives
            .iter()
            .find(|o| o.name == "break_glass_usage_week")
            .unwrap();
        assert_eq!(bg.status, SloStatus::Violated);
    }

    #[test]
    fn kill_switch_response_compliant() {
        let mut agg = SloAggregator::with_defaults();
        for _ in 0..10 {
            let mut evt = AuthEvent::new(10.0);
            evt.kill_switch = true;
            evt.kill_switch_response_ms = Some(50.0); // < 100ms target
            agg.record(evt);
        }
        let report = agg.report();
        let ks = report
            .objectives
            .iter()
            .find(|o| o.name == "kill_switch_response_p95")
            .unwrap();
        assert_eq!(ks.status, SloStatus::Compliant);
    }

    #[test]
    fn kill_switch_no_events_is_insufficient() {
        let agg = SloAggregator::with_defaults();
        let report = agg.report();
        let ks = report
            .objectives
            .iter()
            .find(|o| o.name == "kill_switch_response_p95")
            .unwrap();
        assert_eq!(ks.status, SloStatus::Insufficient);
    }

    #[test]
    fn fully_compliant_when_all_pass() {
        let mut agg = SloAggregator::with_defaults();
        fill_events(&mut agg, 20, 20.0); // fast, all evidence written, no FP
        let report = agg.report();
        assert!(report.fully_compliant());
        assert_eq!(report.violation_count(), 0);
    }

    #[test]
    fn latency_percentile_calculation() {
        let mut agg = SloAggregator::with_defaults();
        for i in 1..=100 {
            agg.record(AuthEvent::new(i as f64));
        }
        // p50 should be ~50
        let p50 = agg.latency_percentile(50.0).unwrap();
        assert!(p50 >= 49.0 && p50 <= 51.0, "p50={}", p50);
        // p95 should be ~95
        let p95 = agg.latency_percentile(95.0).unwrap();
        assert!(p95 >= 94.0 && p95 <= 96.0, "p95={}", p95);
    }

    #[test]
    fn event_count_increments() {
        let mut agg = SloAggregator::with_defaults();
        assert_eq!(agg.event_count(), 0);
        agg.record(AuthEvent::new(10.0));
        assert_eq!(agg.event_count(), 1);
    }
}
