//! W13: Advanced Observability — LLM Cost Intelligence & Token Analytics
//!
//! Tracks per-agent, per-model token usage and computes cost attribution,
//! detects behavioral drift, and provides explainability audit trails.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::info;

// ── Token Usage Record ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageRecord {
    pub record_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
    pub latency_ms: u64,
    pub recorded_at: DateTime<Utc>,
}

impl TokenUsageRecord {
    pub fn new(
        agent_id: impl Into<String>,
        task_id: impl Into<String>,
        model: impl Into<String>,
        prompt_tokens: u64,
        completion_tokens: u64,
        latency_ms: u64,
        price_per_1k_tokens: f64,
    ) -> Self {
        let total = prompt_tokens + completion_tokens;
        let cost = (total as f64 / 1000.0) * price_per_1k_tokens;
        Self {
            record_id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            task_id: task_id.into(),
            model: model.into(),
            prompt_tokens,
            completion_tokens,
            total_tokens: total,
            cost_usd: cost,
            latency_ms,
            recorded_at: Utc::now(),
        }
    }
}

// ── Cost Aggregation ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CostSummary {
    pub total_cost_usd: f64,
    pub total_tokens: u64,
    pub total_calls: u64,
    pub avg_tokens_per_call: f64,
    pub avg_cost_per_call: f64,
    pub cost_by_model: HashMap<String, f64>,
    pub cost_by_agent: HashMap<String, f64>,
}

impl CostSummary {
    pub fn compute(records: &[TokenUsageRecord]) -> Self {
        let mut s = CostSummary::default();
        s.total_calls = records.len() as u64;
        for r in records {
            s.total_cost_usd += r.cost_usd;
            s.total_tokens += r.total_tokens;
            *s.cost_by_model.entry(r.model.clone()).or_default() += r.cost_usd;
            *s.cost_by_agent.entry(r.agent_id.clone()).or_default() += r.cost_usd;
        }
        if s.total_calls > 0 {
            s.avg_tokens_per_call = s.total_tokens as f64 / s.total_calls as f64;
            s.avg_cost_per_call = s.total_cost_usd / s.total_calls as f64;
        }
        s
    }
}

// ── Cost Intelligence Tracker ─────────────────────────────────────────────────

pub struct CostIntelligenceTracker {
    records: Mutex<Vec<TokenUsageRecord>>,
    model_prices: HashMap<String, f64>, // model -> $/1k tokens
}

impl CostIntelligenceTracker {
    pub fn new() -> Self {
        let mut prices = HashMap::new();
        prices.insert("gpt-4".into(), 0.03);
        prices.insert("gpt-4-turbo".into(), 0.01);
        prices.insert("gpt-3.5-turbo".into(), 0.002);
        prices.insert("claude-3-opus".into(), 0.015);
        prices.insert("claude-3-sonnet".into(), 0.003);
        prices.insert("claude-3-haiku".into(), 0.00025);
        prices.insert("llama-3-70b".into(), 0.001);
        prices.insert("default".into(), 0.002);
        Self {
            records: Mutex::new(Vec::new()),
            model_prices: prices,
        }
    }

    pub fn record(
        &self,
        agent_id: &str,
        task_id: &str,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        latency_ms: u64,
    ) {
        let price = self
            .model_prices
            .get(model)
            .copied()
            .unwrap_or_else(|| self.model_prices["default"]);
        let record =
            TokenUsageRecord::new(agent_id, task_id, model, prompt_tokens, completion_tokens, latency_ms, price);
        info!(
            "CostIntel: agent={} model={} tokens={} cost=${:.6}",
            agent_id, model, record.total_tokens, record.cost_usd
        );
        if let Ok(mut v) = self.records.lock() {
            v.push(record);
        }
    }

    pub fn summary(&self) -> CostSummary {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        CostSummary::compute(&records)
    }

    pub fn agent_cost(&self, agent_id: &str) -> f64 {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records.iter().filter(|r| r.agent_id == agent_id).map(|r| r.cost_usd).sum()
    }

    pub fn model_usage(&self, model: &str) -> u64 {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records.iter().filter(|r| r.model == model).map(|r| r.total_tokens).sum()
    }
}

impl Default for CostIntelligenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Behavioral Drift Detector ─────────────────────────────────────────────────

/// A statistical fingerprint of an agent's behavior over a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    pub agent_id: String,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub avg_tokens_per_call: f64,
    pub avg_latency_ms: f64,
    pub call_frequency_per_minute: f64,
    pub model_distribution: HashMap<String, f64>, // model -> fraction of calls
    pub sample_count: u64,
}

impl BehavioralFingerprint {
    pub fn compute(agent_id: &str, records: &[TokenUsageRecord]) -> Option<Self> {
        let agent_records: Vec<_> = records.iter().filter(|r| r.agent_id == agent_id).collect();
        if agent_records.is_empty() {
            return None;
        }

        let n = agent_records.len() as f64;
        let avg_tokens = agent_records.iter().map(|r| r.total_tokens as f64).sum::<f64>() / n;
        let avg_latency = agent_records.iter().map(|r| r.latency_ms as f64).sum::<f64>() / n;

        let mut model_counts: HashMap<String, u64> = HashMap::new();
        for r in &agent_records {
            *model_counts.entry(r.model.clone()).or_default() += 1;
        }
        let model_distribution = model_counts
            .into_iter()
            .map(|(m, c)| (m, c as f64 / n))
            .collect();

        let duration_minutes = {
            let first = agent_records.iter().map(|r| r.recorded_at).min()?;
            let last = agent_records.iter().map(|r| r.recorded_at).max()?;
            let secs = (last - first).num_seconds().max(1);
            secs as f64 / 60.0
        };

        Some(BehavioralFingerprint {
            agent_id: agent_id.to_string(),
            window_start: agent_records.iter().map(|r| r.recorded_at).min().unwrap(),
            window_end: agent_records.iter().map(|r| r.recorded_at).max().unwrap(),
            avg_tokens_per_call: avg_tokens,
            avg_latency_ms: avg_latency,
            call_frequency_per_minute: n / duration_minutes,
            model_distribution,
            sample_count: agent_records.len() as u64,
        })
    }
}

/// Measures drift between two behavioral fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub agent_id: String,
    pub token_drift_pct: f64,
    pub latency_drift_pct: f64,
    pub frequency_drift_pct: f64,
    pub model_drift_score: f64, // 0 = same distribution, 1 = completely different
    pub overall_drift_score: f64,
    pub is_anomalous: bool,
    pub generated_at: DateTime<Utc>,
}

impl DriftReport {
    pub fn compute(baseline: &BehavioralFingerprint, current: &BehavioralFingerprint) -> Self {
        let token_drift = pct_change(baseline.avg_tokens_per_call, current.avg_tokens_per_call).abs();
        let latency_drift = pct_change(baseline.avg_latency_ms, current.avg_latency_ms).abs();
        let freq_drift = pct_change(baseline.call_frequency_per_minute, current.call_frequency_per_minute).abs();

        // Jensen-Shannon divergence approximation for model distribution
        let model_drift = model_distribution_drift(&baseline.model_distribution, &current.model_distribution);

        let overall = (token_drift + latency_drift + freq_drift + model_drift * 100.0) / 4.0;
        let is_anomalous = overall > 50.0 || token_drift > 200.0 || freq_drift > 300.0;

        DriftReport {
            agent_id: baseline.agent_id.clone(),
            token_drift_pct: token_drift,
            latency_drift_pct: latency_drift,
            frequency_drift_pct: freq_drift,
            model_drift_score: model_drift,
            overall_drift_score: overall,
            is_anomalous,
            generated_at: Utc::now(),
        }
    }
}

fn pct_change(baseline: f64, current: f64) -> f64 {
    if baseline == 0.0 {
        return 0.0;
    }
    (current - baseline) / baseline * 100.0
}

fn model_distribution_drift(
    a: &HashMap<String, f64>,
    b: &HashMap<String, f64>,
) -> f64 {
    let all_keys: std::collections::HashSet<_> = a.keys().chain(b.keys()).collect();
    let mut divergence = 0.0;
    for key in all_keys {
        let pa = a.get(key).copied().unwrap_or(0.0);
        let pb = b.get(key).copied().unwrap_or(0.0);
        divergence += (pa - pb).abs();
    }
    (divergence / 2.0).min(1.0)
}

// ── Explainability Audit ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainabilityRecord {
    pub record_id: String,
    pub task_id: String,
    pub agent_id: String,
    pub policy_decision: String,
    pub decision_factors: Vec<DecisionFactor>,
    pub cedar_policy_evaluated: Option<String>,
    pub final_verdict: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFactor {
    pub factor_name: String,
    pub value: serde_json::Value,
    pub contribution: ContributionDirection,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContributionDirection {
    Allow,
    Deny,
    Neutral,
}

impl ExplainabilityRecord {
    pub fn new(
        task_id: impl Into<String>,
        agent_id: impl Into<String>,
        policy_decision: impl Into<String>,
        final_verdict: impl Into<String>,
    ) -> Self {
        Self {
            record_id: uuid::Uuid::new_v4().to_string(),
            task_id: task_id.into(),
            agent_id: agent_id.into(),
            policy_decision: policy_decision.into(),
            decision_factors: vec![],
            cedar_policy_evaluated: None,
            final_verdict: final_verdict.into(),
            recorded_at: Utc::now(),
        }
    }

    pub fn with_factor(mut self, factor: DecisionFactor) -> Self {
        self.decision_factors.push(factor);
        self
    }

    pub fn with_cedar(mut self, policy: impl Into<String>) -> Self {
        self.cedar_policy_evaluated = Some(policy.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(agent: &str, model: &str, tokens: u64) -> TokenUsageRecord {
        TokenUsageRecord::new(agent, "task-1", model, tokens / 2, tokens / 2, 100, 0.01)
    }

    #[test]
    fn cost_summary_totals_correct() {
        let records = vec![
            sample_record("a1", "gpt-4", 1000),
            sample_record("a1", "gpt-4", 2000),
            sample_record("a2", "gpt-3.5-turbo", 500),
        ];
        let summary = CostSummary::compute(&records);
        assert_eq!(summary.total_calls, 3);
        assert!(summary.total_tokens > 0);
        assert!(summary.cost_by_agent.contains_key("a1"));
        assert!(summary.cost_by_agent.contains_key("a2"));
    }

    #[test]
    fn cost_tracker_records_and_queries() {
        let tracker = CostIntelligenceTracker::new();
        tracker.record("bot-1", "t1", "gpt-4", 500, 200, 120);
        tracker.record("bot-1", "t2", "gpt-4", 300, 100, 90);
        tracker.record("bot-2", "t3", "gpt-3.5-turbo", 1000, 500, 200);

        let cost = tracker.agent_cost("bot-1");
        assert!(cost > 0.0);

        let tokens = tracker.model_usage("gpt-4");
        assert!(tokens > 0);

        let summary = tracker.summary();
        assert_eq!(summary.total_calls, 3);
    }

    #[test]
    fn behavioral_fingerprint_computed() {
        let tracker = CostIntelligenceTracker::new();
        for i in 0..5 {
            tracker.record("agent-x", &format!("t{}", i), "gpt-4", 1000, 200, 100);
        }
        let records = tracker.records.lock().unwrap().clone();
        let fp = BehavioralFingerprint::compute("agent-x", &records);
        assert!(fp.is_some());
        let fp = fp.unwrap();
        assert_eq!(fp.sample_count, 5);
    }

    #[test]
    fn drift_report_no_drift_when_identical() {
        let tracker = CostIntelligenceTracker::new();
        for i in 0..5 {
            tracker.record("agent-x", &format!("t{}", i), "gpt-4", 1000, 200, 100);
        }
        let records = tracker.records.lock().unwrap().clone();
        let fp = BehavioralFingerprint::compute("agent-x", &records).unwrap();
        let report = DriftReport::compute(&fp, &fp);
        assert_eq!(report.token_drift_pct, 0.0);
        assert!(!report.is_anomalous);
    }

    #[test]
    fn explainability_record_created() {
        let record = ExplainabilityRecord::new("task-1", "bot-1", "Cedar:permit", "allowed")
            .with_factor(DecisionFactor {
                factor_name: "user_role".into(),
                value: serde_json::json!("admin"),
                contribution: ContributionDirection::Allow,
                weight: 0.9,
            })
            .with_cedar(r#"permit(principal is User, action == Action::"invoke", resource);"#);
        assert_eq!(record.decision_factors.len(), 1);
        assert!(record.cedar_policy_evaluated.is_some());
    }
}
