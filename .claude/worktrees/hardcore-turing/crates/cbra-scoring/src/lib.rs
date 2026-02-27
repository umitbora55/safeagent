//! W39: CBRA Composite Risk Scoring
//! 243 controls across 18 domains, weighted composite risk scoring,
//! tier classification, critical gap detection, remediation planning.
#![allow(dead_code)]

use std::collections::HashMap;
use dashmap::DashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcCbraCriticalGap,
    RcCbraTier1Risk,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ControlDomain {
    Identity, Access, Data, Network, Endpoint, Application,
    Cloud, SupplyChain, Incident, Governance, Risk, Compliance,
    Privacy, Resilience, Monitoring, Threat, Change, Vendor,
}

impl ControlDomain {
    pub fn name(&self) -> &'static str {
        match self {
            ControlDomain::Identity => "identity",
            ControlDomain::Access => "access",
            ControlDomain::Data => "data",
            ControlDomain::Network => "network",
            ControlDomain::Endpoint => "endpoint",
            ControlDomain::Application => "application",
            ControlDomain::Cloud => "cloud",
            ControlDomain::SupplyChain => "supply_chain",
            ControlDomain::Incident => "incident",
            ControlDomain::Governance => "governance",
            ControlDomain::Risk => "risk",
            ControlDomain::Compliance => "compliance",
            ControlDomain::Privacy => "privacy",
            ControlDomain::Resilience => "resilience",
            ControlDomain::Monitoring => "monitoring",
            ControlDomain::Threat => "threat",
            ControlDomain::Change => "change",
            ControlDomain::Vendor => "vendor",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlStatus {
    Passed,
    Failed,
    NotApplicable,
    InProgress,
}

#[derive(Debug, Clone)]
pub struct CbraControl {
    pub id: String,
    pub domain: ControlDomain,
    pub title: String,
    pub weight: f64,
    pub status: ControlStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskTier {
    Tier1Critical,
    Tier2High,
    Tier3Medium,
    Tier4Low,
}

impl RiskTier {
    pub fn from_score(score: f64) -> Self {
        if score < 0.4 { RiskTier::Tier1Critical }
        else if score < 0.6 { RiskTier::Tier2High }
        else if score < 0.8 { RiskTier::Tier3Medium }
        else { RiskTier::Tier4Low }
    }
}

#[derive(Debug, Clone)]
pub struct CompositeRiskScore {
    pub overall_score: f64,
    pub domain_scores: HashMap<String, f64>,
    pub risk_level: RiskTier,
    pub total_controls: u32,
    pub passed_controls: u32,
}

pub struct CbraRiskScoringEngine {
    controls: DashMap<String, CbraControl>,
}

impl CbraRiskScoringEngine {
    pub fn new() -> Self {
        let engine = Self { controls: DashMap::new() };
        engine.load_243_controls();
        engine
    }

    fn load_243_controls(&self) {
        let domains = [
            (ControlDomain::Identity, 14), (ControlDomain::Access, 14),
            (ControlDomain::Data, 14), (ControlDomain::Network, 14),
            (ControlDomain::Endpoint, 14), (ControlDomain::Application, 14),
            (ControlDomain::Cloud, 14), (ControlDomain::SupplyChain, 14),
            (ControlDomain::Incident, 14), (ControlDomain::Governance, 13),
            (ControlDomain::Risk, 13), (ControlDomain::Compliance, 13),
            (ControlDomain::Privacy, 13), (ControlDomain::Resilience, 13),
            (ControlDomain::Monitoring, 13), (ControlDomain::Threat, 13),
            (ControlDomain::Change, 13), (ControlDomain::Vendor, 13),
        ];
        for (domain, count) in &domains {
            for j in 1..=*count {
                let id = format!("CBRA-{}-{:03}", domain.name().to_uppercase().chars().take(3).collect::<String>(), j);
                self.controls.insert(id.clone(), CbraControl {
                    id,
                    domain: domain.clone(),
                    title: format!("{} control {}", domain.name(), j),
                    weight: 0.5 + ((j as f64 - 1.0) * 0.035).min(0.5),
                    status: ControlStatus::Failed, // default to failed
                });
            }
        }
    }

    pub fn update_control_status(&self, control_id: &str, status: ControlStatus) {
        if let Some(mut ctrl) = self.controls.get_mut(control_id) {
            ctrl.status = status;
        }
    }

    pub fn compute_composite_score(&self) -> CompositeRiskScore {
        let mut domain_totals: HashMap<String, (f64, f64)> = HashMap::new(); // name → (weighted_pass, total_weight)
        let mut total_controls = 0u32;
        let mut passed_controls = 0u32;

        for entry in self.controls.iter() {
            let ctrl = entry.value();
            let domain_name = ctrl.domain.name().to_string();
            let (wp, tw) = domain_totals.entry(domain_name).or_insert((0.0, 0.0));
            *tw += ctrl.weight;
            if ctrl.status == ControlStatus::Passed {
                *wp += ctrl.weight;
                passed_controls += 1;
            }
            if ctrl.status != ControlStatus::NotApplicable {
                total_controls += 1;
            }
        }

        let mut domain_scores: HashMap<String, f64> = HashMap::new();
        for (domain, (wp, tw)) in &domain_totals {
            domain_scores.insert(domain.clone(), if *tw > 0.0 { wp / tw } else { 0.0 });
        }

        let overall = if domain_scores.is_empty() {
            0.0
        } else {
            domain_scores.values().sum::<f64>() / domain_scores.len() as f64
        };

        CompositeRiskScore {
            overall_score: overall,
            domain_scores,
            risk_level: RiskTier::from_score(overall),
            total_controls,
            passed_controls,
        }
    }

    pub fn get_critical_gaps(&self) -> Vec<CbraControl> {
        self.controls
            .iter()
            .filter(|entry| {
                let ctrl = entry.value();
                ctrl.status == ControlStatus::Failed && ctrl.weight >= 0.8
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn generate_remediation_plan(&self, top_n: usize) -> Vec<String> {
        let mut failed: Vec<CbraControl> = self.controls
            .iter()
            .filter(|e| e.value().status == ControlStatus::Failed)
            .map(|e| e.value().clone())
            .collect();
        failed.sort_by(|a, b| b.weight.partial_cmp(&a.weight).unwrap_or(std::cmp::Ordering::Equal));
        failed.into_iter().take(top_n).map(|c| format!("Remediate: {} (weight={:.2})", c.id, c.weight)).collect()
    }

    pub fn total_controls_loaded(&self) -> usize {
        self.controls.len()
    }
}

impl Default for CbraRiskScoringEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_243_controls_loaded() {
        let engine = CbraRiskScoringEngine::new();
        assert_eq!(engine.total_controls_loaded(), 243);
    }

    #[test]
    fn test_risk_tier_from_score() {
        assert_eq!(RiskTier::from_score(0.3), RiskTier::Tier1Critical);
        assert_eq!(RiskTier::from_score(0.5), RiskTier::Tier2High);
        assert_eq!(RiskTier::from_score(0.7), RiskTier::Tier3Medium);
        assert_eq!(RiskTier::from_score(0.9), RiskTier::Tier4Low);
    }

    #[test]
    fn test_all_failed_is_tier1() {
        let engine = CbraRiskScoringEngine::new();
        let score = engine.compute_composite_score();
        assert_eq!(score.risk_level, RiskTier::Tier1Critical);
        assert_eq!(score.overall_score, 0.0);
    }

    #[test]
    fn test_update_control_status() {
        let engine = CbraRiskScoringEngine::new();
        engine.update_control_status("CBRA-IDE-001", ControlStatus::Passed);
        let ctrl = engine.controls.get("CBRA-IDE-001").map(|c| c.status.clone());
        assert_eq!(ctrl, Some(ControlStatus::Passed));
    }

    #[test]
    fn test_critical_gaps() {
        let engine = CbraRiskScoringEngine::new();
        // All controls are failed by default with varying weights
        let gaps = engine.get_critical_gaps();
        // Controls with weight >= 0.8 exist
        assert!(!gaps.is_empty());
    }

    #[test]
    fn test_remediation_plan() {
        let engine = CbraRiskScoringEngine::new();
        let plan = engine.generate_remediation_plan(5);
        assert_eq!(plan.len(), 5);
        assert!(plan[0].starts_with("Remediate:"));
    }

    #[test]
    fn test_domain_scores_present() {
        let engine = CbraRiskScoringEngine::new();
        let score = engine.compute_composite_score();
        assert_eq!(score.domain_scores.len(), 18);
    }

    #[test]
    fn test_passed_controls_count() {
        let engine = CbraRiskScoringEngine::new();
        engine.update_control_status("CBRA-IDE-001", ControlStatus::Passed);
        engine.update_control_status("CBRA-ACC-001", ControlStatus::Passed);
        let score = engine.compute_composite_score();
        assert_eq!(score.passed_controls, 2);
    }

    #[test]
    fn test_score_increases_when_controls_pass() {
        let engine = CbraRiskScoringEngine::new();
        let initial = engine.compute_composite_score().overall_score;
        // Collect all keys first to avoid DashMap read/write guard conflict
        let all_ids: Vec<String> = engine.controls.iter().map(|e| e.key().clone()).collect();
        for id in all_ids {
            engine.update_control_status(&id, ControlStatus::Passed);
        }
        let final_score = engine.compute_composite_score().overall_score;
        assert!(final_score > initial);
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcCbraCriticalGap;
        let _ = ReasonCode::RcCbraTier1Risk;
    }
}
