//! W31: Agentic Trust Framework (ATF)
//! Intern/Junior/Senior/Principal 4-level progressive trust,
//! CBRA 243 controls / 18 domains, OWASP MAESTRO 7-layer assessment.
#![allow(dead_code)]

use std::collections::HashMap;
use dashmap::DashMap;

// ── Reason Codes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcTrustLevelInsufficient,
    RcAtfDemotion,
    RcMaestroCritical,
}

// ── TrustLevel ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub enum TrustLevel {
    Intern,
    Junior,
    Senior,
    Principal,
}

impl TrustLevel {
    pub fn max_tool_calls_per_hour(&self) -> u32 {
        match self {
            TrustLevel::Intern => 10,
            TrustLevel::Junior => 50,
            TrustLevel::Senior => 200,
            TrustLevel::Principal => u32::MAX,
        }
    }

    pub fn can_access_external_systems(&self) -> bool {
        matches!(self, TrustLevel::Senior | TrustLevel::Principal)
    }

    pub fn requires_human_approval(&self) -> bool {
        matches!(self, TrustLevel::Intern | TrustLevel::Junior)
    }

    pub fn score_threshold(&self) -> f64 {
        match self {
            TrustLevel::Intern => 0.0,
            TrustLevel::Junior => 0.4,
            TrustLevel::Senior => 0.7,
            TrustLevel::Principal => 0.9,
        }
    }

    fn next_level(&self) -> Option<TrustLevel> {
        match self {
            TrustLevel::Intern => Some(TrustLevel::Junior),
            TrustLevel::Junior => Some(TrustLevel::Senior),
            TrustLevel::Senior => Some(TrustLevel::Principal),
            TrustLevel::Principal => None,
        }
    }

    fn prev_level(&self) -> Option<TrustLevel> {
        match self {
            TrustLevel::Intern => None,
            TrustLevel::Junior => Some(TrustLevel::Intern),
            TrustLevel::Senior => Some(TrustLevel::Junior),
            TrustLevel::Principal => Some(TrustLevel::Senior),
        }
    }
}

// ── CbraControl ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CbraControl {
    pub control_id: String,
    pub domain: String,
    pub description: String,
    pub weight: f64,
}

// ── CbraFramework ─────────────────────────────────────────────────────────────

pub struct CbraFramework {
    controls: Vec<CbraControl>,
}

impl CbraFramework {
    pub fn new() -> Self {
        let domains = [
            "identity", "access", "data", "network", "endpoint", "application",
            "cloud", "supply_chain", "incident", "governance", "risk", "compliance",
            "privacy", "resilience", "monitoring", "threat", "change", "vendor",
        ];
        let mut controls = Vec::new();
        let descriptions = [
            "Multi-factor authentication enforcement",
            "Least privilege access control",
            "Data classification and labeling",
            "Network segmentation policy",
            "Endpoint detection and response",
            "Secure coding standards",
            "Cloud configuration hardening",
            "Software bill of materials",
            "Incident response plan",
            "Security governance framework",
            "Risk assessment process",
            "Regulatory compliance tracking",
            "Privacy impact assessment",
            "Business continuity planning",
            "Security monitoring and alerting",
            "Threat intelligence integration",
            "Change management process",
            "Vendor security assessment",
        ];
        for (i, domain) in domains.iter().enumerate() {
            // ~13-14 controls per domain to reach 243 total
            let count = if i < 9 { 14 } else { 13 };
            for j in 0..count {
                controls.push(CbraControl {
                    control_id: format!("CBRA-{}-{:03}", domain.to_uppercase().chars().take(3).collect::<String>(), j + 1),
                    domain: domain.to_string(),
                    description: format!("{} - control {}", descriptions[i], j + 1),
                    weight: 0.5 + (j as f64 * 0.03).min(0.5),
                });
            }
        }
        Self { controls }
    }

    pub fn get_controls_for_domain(&self, domain: &str) -> Vec<CbraControl> {
        self.controls.iter().filter(|c| c.domain == domain).cloned().collect()
    }

    pub fn compute_compliance_score(&self, passed_control_ids: &[String]) -> f64 {
        let total = 243.0_f64;
        let passed = passed_control_ids.len() as f64;
        (passed / total).min(1.0)
    }

    pub fn total_controls(&self) -> usize {
        self.controls.len()
    }
}

impl Default for CbraFramework {
    fn default() -> Self {
        Self::new()
    }
}

// ── BehaviorEvent ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum BehaviorEventType {
    PolicyCompliance,
    PolicyViolation,
    HumanApprovalRequired,
    SuccessfulTask,
    SuspiciousAction,
}

#[derive(Debug, Clone)]
pub struct BehaviorEvent {
    pub event_type: BehaviorEventType,
    pub severity: f64,
    pub timestamp: String,
}

// ── TrustEvaluation ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustEvaluation {
    pub current_level: TrustLevel,
    pub recommended_level: TrustLevel,
    pub compliance_score: f64,
    pub reason: String,
}

// ── AtfTrustManager ──────────────────────────────────────────────────────────

pub struct AtfTrustManager {
    trust_levels: DashMap<String, TrustLevel>,
    events: DashMap<String, Vec<BehaviorEvent>>,
}

impl AtfTrustManager {
    pub fn new() -> Self {
        Self {
            trust_levels: DashMap::new(),
            events: DashMap::new(),
        }
    }

    pub fn register_agent(&mut self, agent_id: &str, initial_level: TrustLevel) {
        self.trust_levels.insert(agent_id.to_string(), initial_level);
        self.events.insert(agent_id.to_string(), Vec::new());
    }

    pub fn get_trust_level(&self, agent_id: &str) -> Option<TrustLevel> {
        self.trust_levels.get(agent_id).map(|v| v.clone())
    }

    pub fn record_behavior(&mut self, agent_id: &str, event: BehaviorEvent) {
        // Auto-demote on suspicious action
        if event.event_type == BehaviorEventType::SuspiciousAction {
            if let Some(level) = self.trust_levels.get(agent_id) {
                if let Some(prev) = level.prev_level() {
                    drop(level);
                    self.trust_levels.insert(agent_id.to_string(), prev);
                }
            }
        }
        self.events.entry(agent_id.to_string()).or_default().push(event);
    }

    pub fn evaluate_promotion(&self, agent_id: &str) -> TrustEvaluation {
        let current = self
            .trust_levels
            .get(agent_id)
            .map(|v| v.clone())
            .unwrap_or(TrustLevel::Intern);

        let events = self.events.get(agent_id).map(|v| v.clone()).unwrap_or_default();
        let total = events.len().max(1);
        let compliant = events.iter().filter(|e| e.event_type == BehaviorEventType::PolicyCompliance || e.event_type == BehaviorEventType::SuccessfulTask).count();
        let has_violation = events.iter().any(|e| e.event_type == BehaviorEventType::PolicyViolation);
        let compliance_score = compliant as f64 / total as f64;

        let recommended = if let Some(next) = current.next_level() {
            if compliance_score >= next.score_threshold() && !has_violation {
                next
            } else {
                current.clone()
            }
        } else {
            current.clone()
        };

        let reason = if recommended != current {
            format!("Score {:.2} meets threshold for {:?}", compliance_score, recommended)
        } else if has_violation {
            "Recent policy violation prevents promotion".to_string()
        } else {
            format!("Score {:.2} below threshold for next level", compliance_score)
        };

        TrustEvaluation { current_level: current, recommended_level: recommended, compliance_score, reason }
    }
}

impl Default for AtfTrustManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── OWaspMaestroChecker ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LayerAssessment {
    pub layer: String,
    pub risk_score: f64,
    pub critical_findings: Vec<String>,
    pub remediation_required: bool,
}

pub struct OWaspMaestroChecker {
    layers: Vec<String>,
}

impl OWaspMaestroChecker {
    pub fn new() -> Self {
        Self {
            layers: vec![
                "model_layer".to_string(),
                "app_layer".to_string(),
                "agent_framework".to_string(),
                "data_layer".to_string(),
                "infrastructure".to_string(),
                "governance".to_string(),
                "human_interface".to_string(),
            ],
        }
    }

    pub fn assess_layer(&self, layer: &str, findings: &[String]) -> LayerAssessment {
        let risk_score = (findings.len() as f64 * 0.15_f64).min(1.0);
        let remediation_required = !findings.is_empty();
        LayerAssessment {
            layer: layer.to_string(),
            risk_score,
            critical_findings: findings.to_vec(),
            remediation_required,
        }
    }

    pub fn get_overall_risk(&self, assessments: &[LayerAssessment]) -> f64 {
        if assessments.is_empty() {
            return 0.0;
        }
        let sum: f64 = assessments.iter().map(|a| a.risk_score).sum();
        sum / assessments.len() as f64
    }

    pub fn layers(&self) -> &[String] {
        &self.layers
    }
}

impl Default for OWaspMaestroChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_tool_calls() {
        assert_eq!(TrustLevel::Intern.max_tool_calls_per_hour(), 10);
        assert_eq!(TrustLevel::Junior.max_tool_calls_per_hour(), 50);
        assert_eq!(TrustLevel::Senior.max_tool_calls_per_hour(), 200);
        assert_eq!(TrustLevel::Principal.max_tool_calls_per_hour(), u32::MAX);
    }

    #[test]
    fn test_trust_level_external_access() {
        assert!(!TrustLevel::Intern.can_access_external_systems());
        assert!(!TrustLevel::Junior.can_access_external_systems());
        assert!(TrustLevel::Senior.can_access_external_systems());
        assert!(TrustLevel::Principal.can_access_external_systems());
    }

    #[test]
    fn test_trust_level_human_approval() {
        assert!(TrustLevel::Intern.requires_human_approval());
        assert!(TrustLevel::Junior.requires_human_approval());
        assert!(!TrustLevel::Senior.requires_human_approval());
        assert!(!TrustLevel::Principal.requires_human_approval());
    }

    #[test]
    fn test_trust_level_thresholds() {
        assert!((TrustLevel::Intern.score_threshold() - 0.0).abs() < 0.001);
        assert!((TrustLevel::Junior.score_threshold() - 0.4).abs() < 0.001);
        assert!((TrustLevel::Senior.score_threshold() - 0.7).abs() < 0.001);
        assert!((TrustLevel::Principal.score_threshold() - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_cbra_framework_total_controls() {
        let framework = CbraFramework::new();
        assert_eq!(framework.total_controls(), 243);
    }

    #[test]
    fn test_cbra_framework_domain_controls() {
        let framework = CbraFramework::new();
        let controls = framework.get_controls_for_domain("identity");
        assert!(!controls.is_empty());
        assert!(controls.iter().all(|c| c.domain == "identity"));
    }

    #[test]
    fn test_cbra_compliance_score() {
        let framework = CbraFramework::new();
        let passed: Vec<String> = (0..100).map(|i| format!("ctrl-{}", i)).collect();
        let score = framework.compute_compliance_score(&passed);
        assert!((score - 100.0 / 243.0).abs() < 0.001);
    }

    #[test]
    fn test_cbra_compliance_score_capped() {
        let framework = CbraFramework::new();
        let passed: Vec<String> = (0..300).map(|i| format!("ctrl-{}", i)).collect();
        let score = framework.compute_compliance_score(&passed);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_atf_register_and_get() {
        let mut mgr = AtfTrustManager::new();
        mgr.register_agent("agent-1", TrustLevel::Intern);
        assert_eq!(mgr.get_trust_level("agent-1"), Some(TrustLevel::Intern));
    }

    #[test]
    fn test_atf_demotion_on_suspicious() {
        let mut mgr = AtfTrustManager::new();
        mgr.register_agent("agent-1", TrustLevel::Senior);
        mgr.record_behavior("agent-1", BehaviorEvent {
            event_type: BehaviorEventType::SuspiciousAction,
            severity: 0.9,
            timestamp: "2026-01-01".to_string(),
        });
        assert_eq!(mgr.get_trust_level("agent-1"), Some(TrustLevel::Junior));
    }

    #[test]
    fn test_atf_no_demotion_below_intern() {
        let mut mgr = AtfTrustManager::new();
        mgr.register_agent("agent-1", TrustLevel::Intern);
        mgr.record_behavior("agent-1", BehaviorEvent {
            event_type: BehaviorEventType::SuspiciousAction,
            severity: 1.0,
            timestamp: "2026-01-01".to_string(),
        });
        // Already at lowest - stays Intern
        assert_eq!(mgr.get_trust_level("agent-1"), Some(TrustLevel::Intern));
    }

    #[test]
    fn test_atf_promotion_logic() {
        let mut mgr = AtfTrustManager::new();
        mgr.register_agent("agent-1", TrustLevel::Intern);
        // Record many compliant events
        for _ in 0..10 {
            mgr.record_behavior("agent-1", BehaviorEvent {
                event_type: BehaviorEventType::PolicyCompliance,
                severity: 0.0,
                timestamp: "2026-01-01".to_string(),
            });
        }
        let eval = mgr.evaluate_promotion("agent-1");
        // 10/10 = 1.0 score >= 0.4 (Junior threshold) → promote to Junior
        assert_eq!(eval.recommended_level, TrustLevel::Junior);
    }

    #[test]
    fn test_atf_no_promotion_with_violation() {
        let mut mgr = AtfTrustManager::new();
        mgr.register_agent("agent-1", TrustLevel::Intern);
        for _ in 0..10 {
            mgr.record_behavior("agent-1", BehaviorEvent {
                event_type: BehaviorEventType::PolicyCompliance,
                severity: 0.0,
                timestamp: "2026-01-01".to_string(),
            });
        }
        mgr.record_behavior("agent-1", BehaviorEvent {
            event_type: BehaviorEventType::PolicyViolation,
            severity: 0.8,
            timestamp: "2026-01-01".to_string(),
        });
        let eval = mgr.evaluate_promotion("agent-1");
        assert_eq!(eval.current_level, eval.recommended_level);
    }

    #[test]
    fn test_maestro_seven_layers() {
        let checker = OWaspMaestroChecker::new();
        assert_eq!(checker.layers().len(), 7);
    }

    #[test]
    fn test_maestro_assess_layer_no_findings() {
        let checker = OWaspMaestroChecker::new();
        let assessment = checker.assess_layer("model_layer", &[]);
        assert_eq!(assessment.risk_score, 0.0);
        assert!(!assessment.remediation_required);
    }

    #[test]
    fn test_maestro_assess_layer_with_findings() {
        let checker = OWaspMaestroChecker::new();
        let findings = vec!["unsafe_output".to_string(), "missing_sanitization".to_string()];
        let assessment = checker.assess_layer("app_layer", &findings);
        assert!(assessment.risk_score > 0.0);
        assert!(assessment.remediation_required);
    }

    #[test]
    fn test_maestro_overall_risk() {
        let checker = OWaspMaestroChecker::new();
        let assessments = vec![
            checker.assess_layer("model_layer", &["finding1".to_string()]),
            checker.assess_layer("app_layer", &[]),
        ];
        let overall = checker.get_overall_risk(&assessments);
        assert!(overall > 0.0);
    }

    #[test]
    fn test_maestro_risk_capped_at_1() {
        let checker = OWaspMaestroChecker::new();
        let findings: Vec<String> = (0..20).map(|i| format!("f{}", i)).collect();
        let assessment = checker.assess_layer("data_layer", &findings);
        assert!(assessment.risk_score <= 1.0);
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcTrustLevelInsufficient;
        let _ = ReasonCode::RcAtfDemotion;
        let _ = ReasonCode::RcMaestroCritical;
    }

    #[test]
    fn test_cbra_all_domains_have_controls() {
        let framework = CbraFramework::new();
        let domains = ["identity", "access", "data", "network", "endpoint", "application",
            "cloud", "supply_chain", "incident", "governance", "risk", "compliance",
            "privacy", "resilience", "monitoring", "threat", "change", "vendor"];
        for domain in &domains {
            let controls = framework.get_controls_for_domain(domain);
            assert!(!controls.is_empty(), "Domain {} should have controls", domain);
        }
    }
}
