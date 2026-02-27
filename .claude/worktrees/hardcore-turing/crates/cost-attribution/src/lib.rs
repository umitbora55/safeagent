//! W43: Cost Attribution Engine
//! Per-agent, per-policy OTel cost tracking, budget management,
//! alert generation, cost attribution reporting.
#![allow(dead_code)]

use std::collections::HashMap;
use dashmap::DashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcBudgetExceeded,
    RcCostAnomaly,
}

#[derive(Debug, Clone)]
pub struct CostEntry {
    pub entry_id: String,
    pub agent_id: String,
    pub policy_id: String,
    pub operation: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct CostBudget {
    pub agent_id: String,
    pub daily_limit_usd: f64,
    pub monthly_limit_usd: f64,
    pub alert_threshold: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CostAlertType {
    DailyThresholdWarning,
    DailyLimitExceeded,
    MonthlyThresholdWarning,
    MonthlyLimitExceeded,
}

#[derive(Debug, Clone)]
pub struct CostAlert {
    pub alert_id: String,
    pub agent_id: String,
    pub alert_type: CostAlertType,
    pub current_spend: f64,
    pub limit: f64,
    pub percentage: f64,
}

#[derive(Debug, Clone)]
pub struct CostAttributionReport {
    pub agent_id: String,
    pub total_cost_usd: f64,
    pub total_tokens: u64,
    pub by_policy: HashMap<String, f64>,
    pub most_expensive_operation: Option<String>,
    pub entry_count: usize,
}

#[derive(Debug, Clone)]
pub struct OtelMetric {
    pub metric_name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub timestamp: String,
}

pub struct AgentCostAttributionEngine {
    entries: DashMap<String, Vec<CostEntry>>, // agent_id → entries
    budgets: DashMap<String, CostBudget>,
}

impl AgentCostAttributionEngine {
    pub fn new() -> Self {
        Self { entries: DashMap::new(), budgets: DashMap::new() }
    }

    pub fn record_cost(&self, entry: CostEntry) {
        self.entries.entry(entry.agent_id.clone()).or_default().push(entry);
    }

    pub fn set_budget(&self, budget: CostBudget) {
        self.budgets.insert(budget.agent_id.clone(), budget);
    }

    pub fn get_agent_daily_cost(&self, agent_id: &str, date: &str) -> f64 {
        self.entries.get(agent_id)
            .map(|entries| entries.iter().filter(|e| e.timestamp.starts_with(date)).map(|e| e.cost_usd).sum())
            .unwrap_or(0.0)
    }

    pub fn get_agent_monthly_cost(&self, agent_id: &str, month: &str) -> f64 {
        self.entries.get(agent_id)
            .map(|entries| entries.iter().filter(|e| e.timestamp.starts_with(month)).map(|e| e.cost_usd).sum())
            .unwrap_or(0.0)
    }

    pub fn get_cost_by_policy(&self, agent_id: &str) -> HashMap<String, f64> {
        let mut by_policy: HashMap<String, f64> = HashMap::new();
        if let Some(entries) = self.entries.get(agent_id) {
            for entry in entries.iter() {
                *by_policy.entry(entry.policy_id.clone()).or_insert(0.0) += entry.cost_usd;
            }
        }
        by_policy
    }

    pub fn get_top_n_policies(&self, agent_id: &str, n: usize) -> Vec<(String, f64)> {
        let mut by_policy: Vec<(String, f64)> = self.get_cost_by_policy(agent_id).into_iter().collect();
        by_policy.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        by_policy.truncate(n);
        by_policy
    }

    pub fn check_budget_alerts(&self, agent_id: &str, date: &str, month: &str) -> Vec<CostAlert> {
        let mut alerts = Vec::new();
        if let Some(budget) = self.budgets.get(agent_id) {
            let daily = self.get_agent_daily_cost(agent_id, date);
            let monthly = self.get_agent_monthly_cost(agent_id, month);

            if daily > budget.daily_limit_usd {
                alerts.push(CostAlert { alert_id: Uuid::new_v4().to_string(), agent_id: agent_id.to_string(), alert_type: CostAlertType::DailyLimitExceeded, current_spend: daily, limit: budget.daily_limit_usd, percentage: daily / budget.daily_limit_usd });
            } else if daily > budget.daily_limit_usd * budget.alert_threshold {
                alerts.push(CostAlert { alert_id: Uuid::new_v4().to_string(), agent_id: agent_id.to_string(), alert_type: CostAlertType::DailyThresholdWarning, current_spend: daily, limit: budget.daily_limit_usd, percentage: daily / budget.daily_limit_usd });
            }

            if monthly > budget.monthly_limit_usd {
                alerts.push(CostAlert { alert_id: Uuid::new_v4().to_string(), agent_id: agent_id.to_string(), alert_type: CostAlertType::MonthlyLimitExceeded, current_spend: monthly, limit: budget.monthly_limit_usd, percentage: monthly / budget.monthly_limit_usd });
            } else if monthly > budget.monthly_limit_usd * budget.alert_threshold {
                alerts.push(CostAlert { alert_id: Uuid::new_v4().to_string(), agent_id: agent_id.to_string(), alert_type: CostAlertType::MonthlyThresholdWarning, current_spend: monthly, limit: budget.monthly_limit_usd, percentage: monthly / budget.monthly_limit_usd });
            }
        }
        alerts
    }

    pub fn get_cost_attribution_report(&self, agent_id: &str) -> CostAttributionReport {
        let entries = self.entries.get(agent_id).map(|e| e.clone()).unwrap_or_default();
        let total_cost: f64 = entries.iter().map(|e| e.cost_usd).sum();
        let total_tokens: u64 = entries.iter().map(|e| e.input_tokens + e.output_tokens).sum();
        let by_policy = self.get_cost_by_policy(agent_id);
        let most_expensive = entries.iter().max_by(|a, b| a.cost_usd.partial_cmp(&b.cost_usd).unwrap_or(std::cmp::Ordering::Equal)).map(|e| e.operation.clone());
        CostAttributionReport { agent_id: agent_id.to_string(), total_cost_usd: total_cost, total_tokens, by_policy, most_expensive_operation: most_expensive, entry_count: entries.len() }
    }
}

impl Default for AgentCostAttributionEngine {
    fn default() -> Self { Self::new() }
}

pub struct OtelCostExporter;

impl OtelCostExporter {
    pub fn new() -> Self { Self }

    pub fn export_cost_metric(&self, agent_id: &str, cost: f64, labels: HashMap<String, String>) -> OtelMetric {
        let mut all_labels = labels;
        all_labels.insert("agent_id".to_string(), agent_id.to_string());
        OtelMetric { metric_name: "safeagent.cost.usd".to_string(), value: cost, labels: all_labels, timestamp: chrono::Utc::now().to_rfc3339() }
    }

    pub fn export_token_metric(&self, agent_id: &str, tokens: u64, labels: HashMap<String, String>) -> OtelMetric {
        let mut all_labels = labels;
        all_labels.insert("agent_id".to_string(), agent_id.to_string());
        OtelMetric { metric_name: "safeagent.tokens.total".to_string(), value: tokens as f64, labels: all_labels, timestamp: chrono::Utc::now().to_rfc3339() }
    }
}

impl Default for OtelCostExporter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(agent: &str, policy: &str, op: &str, cost: f64, tokens: u64, ts: &str) -> CostEntry {
        CostEntry { entry_id: Uuid::new_v4().to_string(), agent_id: agent.to_string(), policy_id: policy.to_string(), operation: op.to_string(), input_tokens: tokens / 2, output_tokens: tokens / 2, cost_usd: cost, timestamp: ts.to_string() }
    }

    #[test]
    fn test_record_and_report() {
        let engine = AgentCostAttributionEngine::new();
        engine.record_cost(make_entry("a1", "p1", "chat", 0.05, 500, "2026-02-27T10:00:00Z"));
        let report = engine.get_cost_attribution_report("a1");
        assert!((report.total_cost_usd - 0.05).abs() < 0.0001);
        assert_eq!(report.entry_count, 1);
    }

    #[test]
    fn test_daily_cost() {
        let engine = AgentCostAttributionEngine::new();
        engine.record_cost(make_entry("a1", "p1", "chat", 0.05, 500, "2026-02-27T10:00:00Z"));
        engine.record_cost(make_entry("a1", "p1", "chat", 0.03, 300, "2026-02-27T15:00:00Z"));
        engine.record_cost(make_entry("a1", "p1", "chat", 0.10, 1000, "2026-02-28T10:00:00Z"));
        let daily = engine.get_agent_daily_cost("a1", "2026-02-27");
        assert!((daily - 0.08).abs() < 0.0001);
    }

    #[test]
    fn test_monthly_cost() {
        let engine = AgentCostAttributionEngine::new();
        engine.record_cost(make_entry("a1", "p1", "chat", 0.05, 500, "2026-02-27T10:00:00Z"));
        engine.record_cost(make_entry("a1", "p1", "chat", 0.10, 1000, "2026-02-28T10:00:00Z"));
        let monthly = engine.get_agent_monthly_cost("a1", "2026-02");
        assert!((monthly - 0.15).abs() < 0.0001);
    }

    #[test]
    fn test_cost_by_policy() {
        let engine = AgentCostAttributionEngine::new();
        engine.record_cost(make_entry("a1", "policy-a", "op1", 0.05, 100, "2026-02-27T00:00:00Z"));
        engine.record_cost(make_entry("a1", "policy-b", "op2", 0.10, 200, "2026-02-27T00:00:00Z"));
        engine.record_cost(make_entry("a1", "policy-a", "op3", 0.03, 50, "2026-02-27T00:00:00Z"));
        let by_policy = engine.get_cost_by_policy("a1");
        assert!((by_policy["policy-a"] - 0.08).abs() < 0.0001);
        assert!((by_policy["policy-b"] - 0.10).abs() < 0.0001);
    }

    #[test]
    fn test_top_n_policies() {
        let engine = AgentCostAttributionEngine::new();
        engine.record_cost(make_entry("a1", "p1", "op", 0.01, 100, "2026-01-01T00:00:00Z"));
        engine.record_cost(make_entry("a1", "p2", "op", 0.05, 500, "2026-01-01T00:00:00Z"));
        engine.record_cost(make_entry("a1", "p3", "op", 0.10, 1000, "2026-01-01T00:00:00Z"));
        let top = engine.get_top_n_policies("a1", 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "p3");
    }

    #[test]
    fn test_budget_alert_daily_exceeded() {
        let engine = AgentCostAttributionEngine::new();
        engine.set_budget(CostBudget { agent_id: "a1".to_string(), daily_limit_usd: 0.10, monthly_limit_usd: 10.0, alert_threshold: 0.8 });
        engine.record_cost(make_entry("a1", "p1", "op", 0.15, 100, "2026-02-27T00:00:00Z"));
        let alerts = engine.check_budget_alerts("a1", "2026-02-27", "2026-02");
        assert!(alerts.iter().any(|a| a.alert_type == CostAlertType::DailyLimitExceeded));
    }

    #[test]
    fn test_budget_alert_daily_warning() {
        let engine = AgentCostAttributionEngine::new();
        engine.set_budget(CostBudget { agent_id: "a1".to_string(), daily_limit_usd: 0.10, monthly_limit_usd: 10.0, alert_threshold: 0.8 });
        engine.record_cost(make_entry("a1", "p1", "op", 0.09, 100, "2026-02-27T00:00:00Z"));
        let alerts = engine.check_budget_alerts("a1", "2026-02-27", "2026-02");
        assert!(alerts.iter().any(|a| a.alert_type == CostAlertType::DailyThresholdWarning));
    }

    #[test]
    fn test_no_alerts_within_budget() {
        let engine = AgentCostAttributionEngine::new();
        engine.set_budget(CostBudget { agent_id: "a1".to_string(), daily_limit_usd: 1.0, monthly_limit_usd: 30.0, alert_threshold: 0.8 });
        engine.record_cost(make_entry("a1", "p1", "op", 0.01, 100, "2026-02-27T00:00:00Z"));
        let alerts = engine.check_budget_alerts("a1", "2026-02-27", "2026-02");
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_otel_cost_metric() {
        let exporter = OtelCostExporter::new();
        let metric = exporter.export_cost_metric("a1", 0.05, HashMap::new());
        assert_eq!(metric.metric_name, "safeagent.cost.usd");
        assert!((metric.value - 0.05).abs() < 0.0001);
    }

    #[test]
    fn test_otel_token_metric() {
        let exporter = OtelCostExporter::new();
        let metric = exporter.export_token_metric("a1", 1000, HashMap::new());
        assert_eq!(metric.metric_name, "safeagent.tokens.total");
        assert_eq!(metric.value, 1000.0);
    }

    #[test]
    fn test_report_most_expensive_op() {
        let engine = AgentCostAttributionEngine::new();
        engine.record_cost(make_entry("a1", "p1", "cheap_op", 0.01, 100, "2026-01-01T00:00:00Z"));
        engine.record_cost(make_entry("a1", "p1", "expensive_op", 0.99, 9900, "2026-01-01T00:00:00Z"));
        let report = engine.get_cost_attribution_report("a1");
        assert_eq!(report.most_expensive_operation, Some("expensive_op".to_string()));
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcBudgetExceeded;
        let _ = ReasonCode::RcCostAnomaly;
    }
}
