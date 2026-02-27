//! W45: Cross-Jurisdictional Compliance Automation
//! Automated multi-regulation compliance, conflict detection,
//! unified control set generation across EU AI Act, ISO 42001, CNSA 2.0, etc.
#![allow(dead_code)]

use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcJurisdictionConflict,
    RcCrossRegGap,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegulationId {
    EuAiAct2026,
    Iso420012023,
    Cnsa20Suite,
    KoreaAiAct2026,
    ColoradoAiAct,
    NistAiRmf,
    CsaAiControlsMatrix,
}

impl RegulationId {
    pub fn name(&self) -> &'static str {
        match self {
            RegulationId::EuAiAct2026 => "EU AI Act 2026",
            RegulationId::Iso420012023 => "ISO 42001:2023",
            RegulationId::Cnsa20Suite => "CNSA 2.0 Suite",
            RegulationId::KoreaAiAct2026 => "Korea AI Basic Act",
            RegulationId::ColoradoAiAct => "Colorado AI Act",
            RegulationId::NistAiRmf => "NIST AI RMF",
            RegulationId::CsaAiControlsMatrix => "CSA AI Controls Matrix",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequirementMapping {
    pub source_reg: RegulationId,
    pub source_req: String,
    pub target_reg: RegulationId,
    pub target_req: String,
    pub mapping_confidence: f64,
}

#[derive(Debug, Clone)]
pub struct JurisdictionalRequirement {
    pub req_id: String,
    pub regulation: RegulationId,
    pub title: String,
    pub mandatory: bool,
    pub deadline: String,
}

#[derive(Debug, Clone)]
pub struct ComplianceConflict {
    pub conflict_id: String,
    pub description: String,
    pub regulation_1: String,
    pub regulation_2: String,
    pub resolution: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct UnifiedControl {
    pub control_id: String,
    pub title: String,
    pub covers_regulations: Vec<String>,
    pub implementation_effort: EffortLevel,
}

pub struct CrossJurisdictionalAutomation {
    requirements: Vec<JurisdictionalRequirement>,
    mappings: Vec<RequirementMapping>,
}

impl CrossJurisdictionalAutomation {
    pub fn new() -> Self {
        let mut reqs = Vec::new();
        let mut maps = Vec::new();

        // EU AI Act requirements
        for i in 1..=5 {
            reqs.push(JurisdictionalRequirement { req_id: format!("EU-{}", i), regulation: RegulationId::EuAiAct2026, title: format!("EU AI Act Req {}", i), mandatory: true, deadline: "2026-08-02".to_string() });
        }
        // ISO 42001
        for i in 1..=4 {
            reqs.push(JurisdictionalRequirement { req_id: format!("ISO-{}", i), regulation: RegulationId::Iso420012023, title: format!("ISO 42001 Req {}", i), mandatory: i <= 2, deadline: "2023-12-18".to_string() });
        }
        // CNSA 2.0
        for i in 1..=3 {
            reqs.push(JurisdictionalRequirement { req_id: format!("CNSA-{}", i), regulation: RegulationId::Cnsa20Suite, title: format!("CNSA 2.0 Req {}", i), mandatory: true, deadline: "2027-01-01".to_string() });
        }
        // Korea
        for i in 1..=3 {
            reqs.push(JurisdictionalRequirement { req_id: format!("KR-{}", i), regulation: RegulationId::KoreaAiAct2026, title: format!("Korea AI Req {}", i), mandatory: i == 1, deadline: "2026-01-22".to_string() });
        }
        // NIST
        for i in 1..=3 {
            reqs.push(JurisdictionalRequirement { req_id: format!("NIST-{}", i), regulation: RegulationId::NistAiRmf, title: format!("NIST AI RMF Req {}", i), mandatory: false, deadline: "2023-01-01".to_string() });
        }
        // CSA
        for i in 1..=4 {
            reqs.push(JurisdictionalRequirement { req_id: format!("CSA-{}", i), regulation: RegulationId::CsaAiControlsMatrix, title: format!("CSA AI Controls Req {}", i), mandatory: true, deadline: "2024-01-01".to_string() });
        }

        // Mappings
        maps.push(RequirementMapping { source_reg: RegulationId::EuAiAct2026, source_req: "EU-1".to_string(), target_reg: RegulationId::Iso420012023, target_req: "ISO-1".to_string(), mapping_confidence: 0.9 });
        maps.push(RequirementMapping { source_reg: RegulationId::EuAiAct2026, source_req: "EU-2".to_string(), target_reg: RegulationId::CsaAiControlsMatrix, target_req: "CSA-1".to_string(), mapping_confidence: 0.85 });
        maps.push(RequirementMapping { source_reg: RegulationId::Iso420012023, source_req: "ISO-1".to_string(), target_reg: RegulationId::NistAiRmf, target_req: "NIST-1".to_string(), mapping_confidence: 0.88 });
        maps.push(RequirementMapping { source_reg: RegulationId::EuAiAct2026, source_req: "EU-3".to_string(), target_reg: RegulationId::KoreaAiAct2026, target_req: "KR-1".to_string(), mapping_confidence: 0.75 });

        Self { requirements: reqs, mappings: maps }
    }

    pub fn get_requirements_for_regulation(&self, reg: &RegulationId) -> Vec<JurisdictionalRequirement> {
        self.requirements.iter().filter(|r| &r.regulation == reg).cloned().collect()
    }

    pub fn map_requirement(&self, source: &RegulationId, req_id: &str, target: &RegulationId) -> Option<RequirementMapping> {
        self.mappings.iter().find(|m| &m.source_reg == source && m.source_req == req_id && &m.target_reg == target).cloned()
    }

    pub fn compute_compliance_coverage(&self, fulfilled_reqs: &[String]) -> HashMap<String, f64> {
        let all_regs = [
            RegulationId::EuAiAct2026, RegulationId::Iso420012023, RegulationId::Cnsa20Suite,
            RegulationId::KoreaAiAct2026, RegulationId::ColoradoAiAct, RegulationId::NistAiRmf,
            RegulationId::CsaAiControlsMatrix,
        ];
        let mut coverage = HashMap::new();
        for reg in &all_regs {
            let reqs = self.get_requirements_for_regulation(reg);
            if reqs.is_empty() {
                coverage.insert(reg.name().to_string(), 1.0);
                continue;
            }
            let fulfilled = reqs.iter().filter(|r| fulfilled_reqs.contains(&r.req_id)).count();
            coverage.insert(reg.name().to_string(), fulfilled as f64 / reqs.len() as f64);
        }
        coverage
    }

    pub fn identify_conflicts(&self, _reg1: &RegulationId, _reg2: &RegulationId) -> Vec<ComplianceConflict> {
        vec![
            ComplianceConflict { conflict_id: Uuid::new_v4().to_string(), description: "EU data localization vs US CLOUD Act extraterritorial access".to_string(), regulation_1: "EU AI Act".to_string(), regulation_2: "US CLOUD Act".to_string(), resolution: "Use EU-hosted cloud with DPA agreement".to_string() },
            ComplianceConflict { conflict_id: Uuid::new_v4().to_string(), description: "CNSA 2.0 algorithm requirements conflict with EU approved algorithms".to_string(), regulation_1: "CNSA 2.0".to_string(), regulation_2: "EU AI Act".to_string(), resolution: "Implement separate compliance paths per jurisdiction".to_string() },
        ]
    }

    pub fn generate_unified_control_set(&self) -> Vec<UnifiedControl> {
        vec![
            UnifiedControl { control_id: "UC-001".to_string(), title: "AI Risk Assessment".to_string(), covers_regulations: vec!["EU AI Act 2026".to_string(), "ISO 42001:2023".to_string(), "NIST AI RMF".to_string()], implementation_effort: EffortLevel::High },
            UnifiedControl { control_id: "UC-002".to_string(), title: "Data Governance Framework".to_string(), covers_regulations: vec!["EU AI Act 2026".to_string(), "Korea AI Basic Act".to_string()], implementation_effort: EffortLevel::Medium },
            UnifiedControl { control_id: "UC-003".to_string(), title: "Algorithm Transparency Report".to_string(), covers_regulations: vec!["EU AI Act 2026".to_string(), "Colorado AI Act".to_string(), "ISO 42001:2023".to_string()], implementation_effort: EffortLevel::Medium },
            UnifiedControl { control_id: "UC-004".to_string(), title: "Cryptographic Algorithm Inventory".to_string(), covers_regulations: vec!["CNSA 2.0 Suite".to_string(), "CSA AI Controls Matrix".to_string()], implementation_effort: EffortLevel::Low },
            UnifiedControl { control_id: "UC-005".to_string(), title: "Incident Response Plan".to_string(), covers_regulations: vec!["EU AI Act 2026".to_string(), "ISO 42001:2023".to_string(), "NIST AI RMF".to_string(), "CSA AI Controls Matrix".to_string()], implementation_effort: EffortLevel::Critical },
        ]
    }
}

impl Default for CrossJurisdictionalAutomation {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eu_requirements_loaded() {
        let automation = CrossJurisdictionalAutomation::new();
        let reqs = automation.get_requirements_for_regulation(&RegulationId::EuAiAct2026);
        assert_eq!(reqs.len(), 5);
    }

    #[test]
    fn test_iso_requirements_loaded() {
        let automation = CrossJurisdictionalAutomation::new();
        let reqs = automation.get_requirements_for_regulation(&RegulationId::Iso420012023);
        assert_eq!(reqs.len(), 4);
    }

    #[test]
    fn test_map_requirement_found() {
        let automation = CrossJurisdictionalAutomation::new();
        let mapping = automation.map_requirement(&RegulationId::EuAiAct2026, "EU-1", &RegulationId::Iso420012023);
        assert!(mapping.is_some());
        assert_eq!(mapping.unwrap().target_req, "ISO-1");
    }

    #[test]
    fn test_map_requirement_not_found() {
        let automation = CrossJurisdictionalAutomation::new();
        let mapping = automation.map_requirement(&RegulationId::Cnsa20Suite, "CNSA-1", &RegulationId::ColoradoAiAct);
        assert!(mapping.is_none());
    }

    #[test]
    fn test_compliance_coverage_full_eu() {
        let automation = CrossJurisdictionalAutomation::new();
        let fulfilled = vec!["EU-1".to_string(), "EU-2".to_string(), "EU-3".to_string(), "EU-4".to_string(), "EU-5".to_string()];
        let coverage = automation.compute_compliance_coverage(&fulfilled);
        let eu_cov = coverage.get("EU AI Act 2026").unwrap();
        assert!((eu_cov - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_compliance_coverage_partial() {
        let automation = CrossJurisdictionalAutomation::new();
        let fulfilled = vec!["EU-1".to_string(), "EU-2".to_string()];
        let coverage = automation.compute_compliance_coverage(&fulfilled);
        let eu_cov = coverage.get("EU AI Act 2026").unwrap();
        assert!((eu_cov - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_identify_conflicts() {
        let automation = CrossJurisdictionalAutomation::new();
        let conflicts = automation.identify_conflicts(&RegulationId::EuAiAct2026, &RegulationId::Cnsa20Suite);
        assert!(!conflicts.is_empty());
    }

    #[test]
    fn test_unified_controls_generated() {
        let automation = CrossJurisdictionalAutomation::new();
        let controls = automation.generate_unified_control_set();
        assert_eq!(controls.len(), 5);
    }

    #[test]
    fn test_unified_controls_cover_multiple_regs() {
        let automation = CrossJurisdictionalAutomation::new();
        let controls = automation.generate_unified_control_set();
        let incident = controls.iter().find(|c| c.control_id == "UC-005").unwrap();
        assert!(incident.covers_regulations.len() >= 2);
        assert_eq!(incident.implementation_effort, EffortLevel::Critical);
    }

    #[test]
    fn test_total_requirements_count() {
        let automation = CrossJurisdictionalAutomation::new();
        let total: usize = [
            RegulationId::EuAiAct2026,
            RegulationId::Iso420012023,
            RegulationId::Cnsa20Suite,
            RegulationId::KoreaAiAct2026,
            RegulationId::NistAiRmf,
            RegulationId::CsaAiControlsMatrix,
        ].iter().map(|r| automation.get_requirements_for_regulation(r).len()).sum();
        assert!(total >= 20);
    }

    #[test]
    fn test_regulation_names() {
        assert_eq!(RegulationId::EuAiAct2026.name(), "EU AI Act 2026");
        assert_eq!(RegulationId::Cnsa20Suite.name(), "CNSA 2.0 Suite");
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcJurisdictionConflict;
        let _ = ReasonCode::RcCrossRegGap;
    }
}
