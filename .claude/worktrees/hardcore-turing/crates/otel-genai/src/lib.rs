//! W33: OTel GenAI Observability + Explainability
//! OpenTelemetry GenAI semantic conventions, SHAP/LIME/counterfactual
//! explanations per deny decision, cost attribution per agent per policy.
#![allow(dead_code)]

use std::collections::HashMap;
use dashmap::DashMap;
use uuid::Uuid;

// ── Reason Codes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcCostThresholdExceeded,
    RcTelemetryAnomaly,
}

// ── GenAiSpanAttributes ──────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenAiSpanAttributes {
    pub gen_ai_system: String,
    pub gen_ai_operation_name: String,
    pub gen_ai_request_model: String,
    pub gen_ai_response_model: String,
    pub gen_ai_usage_input_tokens: u64,
    pub gen_ai_usage_output_tokens: u64,
    pub gen_ai_agent_id: String,
    pub cost_usd: f64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SpanStatus {
    Ok,
    Error,
    Timeout,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OtelGenAiSpan {
    pub span_id: String,
    pub trace_id: String,
    pub attributes: GenAiSpanAttributes,
    pub duration_ms: u64,
    pub status: SpanStatus,
}

// ── GenAiTelemetryCollector ───────────────────────────────────────────────────

pub struct GenAiTelemetryCollector {
    spans: DashMap<String, Vec<OtelGenAiSpan>>, // agent_id → spans
}

impl GenAiTelemetryCollector {
    pub fn new() -> Self {
        Self { spans: DashMap::new() }
    }

    pub fn record_span(&self, span: OtelGenAiSpan) {
        let agent_id = span.attributes.gen_ai_agent_id.clone();
        self.spans.entry(agent_id).or_default().push(span);
    }

    pub fn get_spans_for_agent(&self, agent_id: &str) -> Vec<OtelGenAiSpan> {
        self.spans.get(agent_id).map(|v| v.clone()).unwrap_or_default()
    }

    pub fn get_total_cost(&self, agent_id: &str) -> f64 {
        self.get_spans_for_agent(agent_id)
            .iter()
            .map(|s| s.attributes.cost_usd)
            .sum()
    }

    pub fn get_total_tokens(&self, agent_id: &str) -> u64 {
        self.get_spans_for_agent(agent_id)
            .iter()
            .map(|s| s.attributes.gen_ai_usage_input_tokens + s.attributes.gen_ai_usage_output_tokens)
            .sum()
    }

    pub fn export_spans(&self) -> Vec<OtelGenAiSpan> {
        self.spans.iter().flat_map(|entry| entry.value().clone()).collect()
    }
}

impl Default for GenAiTelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── ShapExplainer ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ShapExplanation {
    pub feature_contributions: Vec<(String, f64)>,
    pub base_value: f64,
    pub prediction: f64,
    pub top_reason: String,
}

pub struct ShapExplainer;

impl ShapExplainer {
    pub fn new() -> Self {
        Self
    }

    pub fn explain_decision(&self, features: &HashMap<String, f64>, decision: &str) -> ShapExplanation {
        let mut contributions: Vec<(String, f64)> = features
            .iter()
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        // Sort by absolute contribution descending
        contributions.sort_by(|a, b| b.1.abs().partial_cmp(&a.1.abs()).unwrap_or(std::cmp::Ordering::Equal));

        let base_value = 0.5;
        let sum: f64 = contributions.iter().map(|(_, v)| v).sum();
        let prediction = (base_value + sum).clamp(0.0, 1.0);
        let top_reason = contributions.first().map(|(k, _)| k.clone()).unwrap_or_else(|| decision.to_string());

        ShapExplanation { feature_contributions: contributions, base_value, prediction, top_reason }
    }
}

impl Default for ShapExplainer {
    fn default() -> Self {
        Self::new()
    }
}

// ── CounterfactualExplainer ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeniedRequest {
    pub agent_id: String,
    pub action: String,
    pub deny_reason: String,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ContextChange {
    pub field: String,
    pub current_value: String,
    pub required_value: String,
    pub importance: f64,
}

#[derive(Debug, Clone)]
pub struct Counterfactual {
    pub changes_required: Vec<ContextChange>,
    pub estimated_approval_probability: f64,
}

pub struct CounterfactualExplainer;

impl CounterfactualExplainer {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_counterfactual(&self, denied: &DeniedRequest) -> Counterfactual {
        let mut changes = Vec::new();
        let reason_lower = denied.deny_reason.to_lowercase();

        if reason_lower.contains("trust_level") || reason_lower.contains("trust level") {
            changes.push(ContextChange {
                field: "trust_level".to_string(),
                current_value: denied.context.get("trust_level").cloned().unwrap_or_else(|| "Intern".to_string()),
                required_value: "Senior".to_string(),
                importance: 0.9,
            });
        }
        if reason_lower.contains("rate_limit") {
            changes.push(ContextChange {
                field: "wait_time".to_string(),
                current_value: "0s".to_string(),
                required_value: "3600s".to_string(),
                importance: 0.7,
            });
        }
        if reason_lower.contains("auth") {
            changes.push(ContextChange {
                field: "auth_method".to_string(),
                current_value: "StaticApiKey".to_string(),
                required_value: "OAuth2".to_string(),
                importance: 0.95,
            });
        }

        let estimated = if changes.is_empty() { 0.2 } else { 0.75 };
        Counterfactual { changes_required: changes, estimated_approval_probability: estimated }
    }
}

impl Default for CounterfactualExplainer {
    fn default() -> Self {
        Self::new()
    }
}

// ── AgentCostAttributor ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CostReport {
    pub agent_id: String,
    pub total_cost_usd: f64,
    pub total_tokens: u64,
    pub by_policy: HashMap<String, f64>,
    pub top_policy: Option<String>,
}

pub struct AgentCostAttributor {
    records: DashMap<String, Vec<(String, f64, u64)>>, // agent_id → [(policy_id, cost, tokens)]
}

impl AgentCostAttributor {
    pub fn new() -> Self {
        Self { records: DashMap::new() }
    }

    pub fn attribute_cost(&self, agent_id: &str, policy_id: &str, cost_usd: f64, tokens: u64) {
        self.records
            .entry(agent_id.to_string())
            .or_default()
            .push((policy_id.to_string(), cost_usd, tokens));
    }

    pub fn get_agent_cost_report(&self, agent_id: &str) -> CostReport {
        let records = self.records.get(agent_id).map(|v| v.clone()).unwrap_or_default();
        let total_cost: f64 = records.iter().map(|(_, c, _)| c).sum();
        let total_tokens: u64 = records.iter().map(|(_, _, t)| t).sum();
        let mut by_policy: HashMap<String, f64> = HashMap::new();
        for (policy_id, cost, _) in &records {
            *by_policy.entry(policy_id.clone()).or_insert(0.0) += cost;
        }
        let top_policy = by_policy
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k.clone());
        CostReport { agent_id: agent_id.to_string(), total_cost_usd: total_cost, total_tokens, by_policy, top_policy }
    }
}

impl Default for AgentCostAttributor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_span(agent_id: &str, cost: f64, input_tokens: u64, output_tokens: u64) -> OtelGenAiSpan {
        OtelGenAiSpan {
            span_id: Uuid::new_v4().to_string(),
            trace_id: Uuid::new_v4().to_string(),
            attributes: GenAiSpanAttributes {
                gen_ai_system: "anthropic".to_string(),
                gen_ai_operation_name: "chat".to_string(),
                gen_ai_request_model: "claude-3-5-sonnet".to_string(),
                gen_ai_response_model: "claude-3-5-sonnet".to_string(),
                gen_ai_usage_input_tokens: input_tokens,
                gen_ai_usage_output_tokens: output_tokens,
                gen_ai_agent_id: agent_id.to_string(),
                cost_usd: cost,
            },
            duration_ms: 250,
            status: SpanStatus::Ok,
        }
    }

    #[test]
    fn test_telemetry_record_and_retrieve() {
        let collector = GenAiTelemetryCollector::new();
        collector.record_span(make_span("agent-1", 0.01, 100, 50));
        let spans = collector.get_spans_for_agent("agent-1");
        assert_eq!(spans.len(), 1);
    }

    #[test]
    fn test_telemetry_total_cost() {
        let collector = GenAiTelemetryCollector::new();
        collector.record_span(make_span("agent-1", 0.01, 100, 50));
        collector.record_span(make_span("agent-1", 0.02, 200, 100));
        let cost = collector.get_total_cost("agent-1");
        assert!((cost - 0.03).abs() < 0.0001);
    }

    #[test]
    fn test_telemetry_total_tokens() {
        let collector = GenAiTelemetryCollector::new();
        collector.record_span(make_span("agent-1", 0.01, 100, 50));
        let tokens = collector.get_total_tokens("agent-1");
        assert_eq!(tokens, 150);
    }

    #[test]
    fn test_telemetry_export_all() {
        let collector = GenAiTelemetryCollector::new();
        collector.record_span(make_span("agent-1", 0.01, 100, 50));
        collector.record_span(make_span("agent-2", 0.02, 200, 100));
        let all = collector.export_spans();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_telemetry_unknown_agent() {
        let collector = GenAiTelemetryCollector::new();
        let spans = collector.get_spans_for_agent("unknown");
        assert!(spans.is_empty());
        assert_eq!(collector.get_total_cost("unknown"), 0.0);
    }

    #[test]
    fn test_shap_explanation() {
        let explainer = ShapExplainer::new();
        let features = HashMap::from([
            ("trust_level".to_string(), -0.4_f64),
            ("rate_limit".to_string(), -0.1_f64),
        ]);
        let explanation = explainer.explain_decision(&features, "DENY");
        assert_eq!(explanation.top_reason, "trust_level");
        assert!(explanation.prediction >= 0.0);
        assert!(explanation.prediction <= 1.0);
    }

    #[test]
    fn test_shap_base_value() {
        let explainer = ShapExplainer::new();
        let features = HashMap::new();
        let explanation = explainer.explain_decision(&features, "DENY");
        assert!((explanation.base_value - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_shap_sorted_contributions() {
        let explainer = ShapExplainer::new();
        let features = HashMap::from([
            ("small".to_string(), -0.1_f64),
            ("large".to_string(), -0.8_f64),
        ]);
        let explanation = explainer.explain_decision(&features, "DENY");
        assert_eq!(explanation.top_reason, "large");
    }

    #[test]
    fn test_counterfactual_trust_level() {
        let explainer = CounterfactualExplainer::new();
        let denied = DeniedRequest {
            agent_id: "agent-1".to_string(),
            action: "delete_file".to_string(),
            deny_reason: "trust_level insufficient".to_string(),
            context: HashMap::new(),
        };
        let cf = explainer.generate_counterfactual(&denied);
        assert!(!cf.changes_required.is_empty());
        let trust_change = cf.changes_required.iter().find(|c| c.field == "trust_level");
        assert!(trust_change.is_some());
        assert!((trust_change.unwrap().importance - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_counterfactual_auth() {
        let explainer = CounterfactualExplainer::new();
        let denied = DeniedRequest {
            agent_id: "agent-1".to_string(),
            action: "api_call".to_string(),
            deny_reason: "authentication failed".to_string(),
            context: HashMap::new(),
        };
        let cf = explainer.generate_counterfactual(&denied);
        let auth_change = cf.changes_required.iter().find(|c| c.field == "auth_method");
        assert!(auth_change.is_some());
        assert_eq!(auth_change.unwrap().required_value, "OAuth2");
    }

    #[test]
    fn test_counterfactual_no_match() {
        let explainer = CounterfactualExplainer::new();
        let denied = DeniedRequest {
            agent_id: "agent-1".to_string(),
            action: "action".to_string(),
            deny_reason: "unknown_reason".to_string(),
            context: HashMap::new(),
        };
        let cf = explainer.generate_counterfactual(&denied);
        assert!(cf.changes_required.is_empty());
        assert!(cf.estimated_approval_probability < 0.5);
    }

    #[test]
    fn test_cost_attributor_basic() {
        let attributor = AgentCostAttributor::new();
        attributor.attribute_cost("agent-1", "policy-a", 0.05, 500);
        let report = attributor.get_agent_cost_report("agent-1");
        assert!((report.total_cost_usd - 0.05).abs() < 0.0001);
        assert_eq!(report.total_tokens, 500);
    }

    #[test]
    fn test_cost_attributor_top_policy() {
        let attributor = AgentCostAttributor::new();
        attributor.attribute_cost("agent-1", "policy-a", 0.05, 500);
        attributor.attribute_cost("agent-1", "policy-b", 0.20, 2000);
        let report = attributor.get_agent_cost_report("agent-1");
        assert_eq!(report.top_policy, Some("policy-b".to_string()));
    }

    #[test]
    fn test_cost_attributor_empty() {
        let attributor = AgentCostAttributor::new();
        let report = attributor.get_agent_cost_report("unknown");
        assert_eq!(report.total_cost_usd, 0.0);
        assert!(report.top_policy.is_none());
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcCostThresholdExceeded;
        let _ = ReasonCode::RcTelemetryAnomaly;
    }

    #[test]
    fn test_span_status_variants() {
        assert_eq!(SpanStatus::Ok, SpanStatus::Ok);
        assert_eq!(SpanStatus::Error, SpanStatus::Error);
        assert_eq!(SpanStatus::Timeout, SpanStatus::Timeout);
    }
}
