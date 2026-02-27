//! W32: Compliance Intelligence Engine
//! EU AI Act (Aug 2026), ISO 42001, CNSA 2.0, South Korea AI Basic Act,
//! Colorado AI Act, CSA AICM 243 controls, cross-jurisdictional mapping,
//! audit evidence packages.
#![allow(dead_code)]

use std::collections::HashMap;
use uuid::Uuid;

// ── Reason Codes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcComplianceGap,
    RcProhibitedUseCase,
    RcAuditRequired,
}

// ── Jurisdiction ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Jurisdiction {
    EuAiAct,
    Iso42001,
    Cnsa20,
    SouthKoreaAiAct,
    ColoradoAiAct,
    CsaAicm,
}

impl Jurisdiction {
    pub fn enforcement_date(&self) -> &'static str {
        match self {
            Jurisdiction::EuAiAct => "2026-08-02",
            Jurisdiction::Iso42001 => "2023-12-18",
            Jurisdiction::Cnsa20 => "2027-01-01",
            Jurisdiction::SouthKoreaAiAct => "2026-01-22",
            Jurisdiction::ColoradoAiAct => "2026-02-01",
            Jurisdiction::CsaAicm => "2024-01-01",
        }
    }

    pub fn is_active(&self, current_date: &str) -> bool {
        self.enforcement_date() <= current_date
    }

    pub fn name(&self) -> &'static str {
        match self {
            Jurisdiction::EuAiAct => "EU AI Act",
            Jurisdiction::Iso42001 => "ISO 42001",
            Jurisdiction::Cnsa20 => "CNSA 2.0",
            Jurisdiction::SouthKoreaAiAct => "South Korea AI Basic Act",
            Jurisdiction::ColoradoAiAct => "Colorado AI Act",
            Jurisdiction::CsaAicm => "CSA AI Controls Matrix",
        }
    }
}

// ── ComplianceControl ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceControl {
    pub id: String,
    pub jurisdiction: Jurisdiction,
    pub title: String,
    pub mandatory: bool,
    pub weight: f64,
}

// ── ComplianceAssessment ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ComplianceAssessment {
    pub jurisdiction: Jurisdiction,
    pub total_controls: usize,
    pub passed: usize,
    pub score: f64,
    pub compliant: bool,
    pub gaps: Vec<String>,
}

// ── ComplianceIntelligenceEngine ─────────────────────────────────────────────

pub struct ComplianceIntelligenceEngine {
    controls: Vec<ComplianceControl>,
}

impl ComplianceIntelligenceEngine {
    pub fn new() -> Self {
        let mut controls = Vec::new();
        // EU AI Act controls
        for i in 1..=5 {
            controls.push(ComplianceControl {
                id: format!("EU-{}", i),
                jurisdiction: Jurisdiction::EuAiAct,
                title: format!("EU AI Act Control {}", i),
                mandatory: true,
                weight: 1.0,
            });
        }
        // ISO 42001 controls
        for i in 1..=4 {
            controls.push(ComplianceControl {
                id: format!("ISO-{}", i),
                jurisdiction: Jurisdiction::Iso42001,
                title: format!("ISO 42001 Control {}", i),
                mandatory: true,
                weight: 1.0,
            });
        }
        // CNSA 2.0 controls
        for i in 1..=3 {
            controls.push(ComplianceControl {
                id: format!("CNSA-{}", i),
                jurisdiction: Jurisdiction::Cnsa20,
                title: format!("CNSA 2.0 Control {}", i),
                mandatory: true,
                weight: 1.0,
            });
        }
        // South Korea
        for i in 1..=3 {
            controls.push(ComplianceControl {
                id: format!("KR-{}", i),
                jurisdiction: Jurisdiction::SouthKoreaAiAct,
                title: format!("Korea AI Act Control {}", i),
                mandatory: i == 1,
                weight: 0.8,
            });
        }
        // CSA AICM
        for i in 1..=5 {
            controls.push(ComplianceControl {
                id: format!("CSA-AI-{}", i),
                jurisdiction: Jurisdiction::CsaAicm,
                title: format!("CSA AI Controls Matrix {}", i),
                mandatory: true,
                weight: 0.9,
            });
        }
        Self { controls }
    }

    pub fn get_applicable_regulations(&self, current_date: &str) -> Vec<Jurisdiction> {
        let all = [
            Jurisdiction::EuAiAct,
            Jurisdiction::Iso42001,
            Jurisdiction::Cnsa20,
            Jurisdiction::SouthKoreaAiAct,
            Jurisdiction::ColoradoAiAct,
            Jurisdiction::CsaAicm,
        ];
        all.iter().filter(|j| j.is_active(current_date)).cloned().collect()
    }

    pub fn assess_compliance(
        &self,
        jurisdiction: &Jurisdiction,
        passed_control_ids: &[String],
    ) -> ComplianceAssessment {
        let jur_controls: Vec<&ComplianceControl> = self
            .controls
            .iter()
            .filter(|c| &c.jurisdiction == jurisdiction)
            .collect();
        let total = jur_controls.len();
        let passed_count = jur_controls
            .iter()
            .filter(|c| passed_control_ids.contains(&c.id))
            .count();
        let score = if total == 0 { 1.0 } else { passed_count as f64 / total as f64 };
        let gaps: Vec<String> = jur_controls
            .iter()
            .filter(|c| !passed_control_ids.contains(&c.id))
            .map(|c| c.id.clone())
            .collect();
        ComplianceAssessment {
            jurisdiction: jurisdiction.clone(),
            total_controls: total,
            passed: passed_count,
            score,
            compliant: score >= 0.85,
            gaps,
        }
    }
}

impl Default for ComplianceIntelligenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── EuAiActRiskClassifier ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AiRiskLevel {
    Minimal,
    Limited,
    High,
    Prohibited,
}

#[derive(Debug, Clone)]
pub struct SystemDescription {
    pub use_case: String,
    pub affects_fundamental_rights: bool,
    pub critical_infrastructure: bool,
    pub biometric_data: bool,
}

pub struct EuAiActRiskClassifier;

impl EuAiActRiskClassifier {
    pub fn new() -> Self {
        Self
    }

    pub fn classify_system(&self, system: &SystemDescription) -> AiRiskLevel {
        if system.use_case.to_lowercase().contains("facial recognition in public") {
            return AiRiskLevel::Prohibited;
        }
        if system.biometric_data || system.critical_infrastructure || system.affects_fundamental_rights {
            return AiRiskLevel::High;
        }
        AiRiskLevel::Limited
    }
}

impl Default for EuAiActRiskClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── CrossJurisdictionalMapper ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuditPackage {
    pub package_id: String,
    pub jurisdiction: Jurisdiction,
    pub evidence_items: Vec<String>,
    pub generated_at: String,
}

pub struct CrossJurisdictionalMapper {
    mappings: HashMap<(String, String, String), String>,
}

impl CrossJurisdictionalMapper {
    pub fn new() -> Self {
        let mut mappings = HashMap::new();
        mappings.insert(
            ("EuAiAct".to_string(), "EU-4".to_string(), "Iso42001".to_string()),
            "ISO-4".to_string(),
        );
        mappings.insert(
            ("EuAiAct".to_string(), "EU-1".to_string(), "CsaAicm".to_string()),
            "CSA-AI-1".to_string(),
        );
        mappings.insert(
            ("Iso42001".to_string(), "ISO-1".to_string(), "EuAiAct".to_string()),
            "EU-1".to_string(),
        );
        Self { mappings }
    }

    pub fn map_control(
        &self,
        source_jurisdiction: &Jurisdiction,
        control_id: &str,
        target_jurisdiction: &Jurisdiction,
    ) -> Option<String> {
        let key = (
            format!("{:?}", source_jurisdiction),
            control_id.to_string(),
            format!("{:?}", target_jurisdiction),
        );
        self.mappings.get(&key).cloned()
    }

    pub fn generate_audit_package(
        &self,
        jurisdiction: &Jurisdiction,
        assessment: &ComplianceAssessment,
    ) -> AuditPackage {
        let mut evidence_items = Vec::new();
        evidence_items.push(format!("compliance_score: {:.2}", assessment.score));
        evidence_items.push(format!("passed_controls: {}/{}", assessment.passed, assessment.total_controls));
        if !assessment.gaps.is_empty() {
            evidence_items.push(format!("gaps: {}", assessment.gaps.join(", ")));
        }
        AuditPackage {
            package_id: Uuid::new_v4().to_string(),
            jurisdiction: jurisdiction.clone(),
            evidence_items,
            generated_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for CrossJurisdictionalMapper {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jurisdiction_enforcement_dates() {
        assert_eq!(Jurisdiction::EuAiAct.enforcement_date(), "2026-08-02");
        assert_eq!(Jurisdiction::SouthKoreaAiAct.enforcement_date(), "2026-01-22");
        assert_eq!(Jurisdiction::Cnsa20.enforcement_date(), "2027-01-01");
        assert_eq!(Jurisdiction::Iso42001.enforcement_date(), "2023-12-18");
    }

    #[test]
    fn test_jurisdiction_is_active() {
        // ISO 42001 active since 2023 → active in 2026
        assert!(Jurisdiction::Iso42001.is_active("2026-02-01"));
        // CNSA 2.0 active 2027 → not active in 2026
        assert!(!Jurisdiction::Cnsa20.is_active("2026-02-01"));
        // EU AI Act active Aug 2026 → not active Feb 2026
        assert!(!Jurisdiction::EuAiAct.is_active("2026-02-01"));
        assert!(Jurisdiction::EuAiAct.is_active("2026-09-01"));
    }

    #[test]
    fn test_applicable_regulations_early_2026() {
        let engine = ComplianceIntelligenceEngine::new();
        let active = engine.get_applicable_regulations("2026-02-27");
        // Iso42001 (2023), CsaAicm (2024), SouthKoreaAiAct (2026-01-22), ColoradoAiAct (2026-02-01) are active
        assert!(active.contains(&Jurisdiction::Iso42001));
        assert!(active.contains(&Jurisdiction::CsaAicm));
        // EU AI Act and CNSA 2.0 are not yet active
        assert!(!active.contains(&Jurisdiction::EuAiAct));
        assert!(!active.contains(&Jurisdiction::Cnsa20));
    }

    #[test]
    fn test_compliance_assessment_full_pass() {
        let engine = ComplianceIntelligenceEngine::new();
        let passed = vec!["EU-1".to_string(), "EU-2".to_string(), "EU-3".to_string(), "EU-4".to_string(), "EU-5".to_string()];
        let assessment = engine.assess_compliance(&Jurisdiction::EuAiAct, &passed);
        assert_eq!(assessment.passed, 5);
        assert!(assessment.score >= 0.99);
        assert!(assessment.compliant);
        assert!(assessment.gaps.is_empty());
    }

    #[test]
    fn test_compliance_assessment_partial() {
        let engine = ComplianceIntelligenceEngine::new();
        let passed = vec!["EU-1".to_string(), "EU-2".to_string()];
        let assessment = engine.assess_compliance(&Jurisdiction::EuAiAct, &passed);
        assert_eq!(assessment.passed, 2);
        assert!(!assessment.compliant);
        assert!(!assessment.gaps.is_empty());
    }

    #[test]
    fn test_eu_ai_act_prohibited_use_case() {
        let classifier = EuAiActRiskClassifier::new();
        let system = SystemDescription {
            use_case: "Facial recognition in public spaces".to_string(),
            affects_fundamental_rights: false,
            critical_infrastructure: false,
            biometric_data: false,
        };
        assert_eq!(classifier.classify_system(&system), AiRiskLevel::Prohibited);
    }

    #[test]
    fn test_eu_ai_act_high_risk_biometric() {
        let classifier = EuAiActRiskClassifier::new();
        let system = SystemDescription {
            use_case: "HR screening".to_string(),
            affects_fundamental_rights: false,
            critical_infrastructure: false,
            biometric_data: true,
        };
        assert_eq!(classifier.classify_system(&system), AiRiskLevel::High);
    }

    #[test]
    fn test_eu_ai_act_high_risk_critical_infra() {
        let classifier = EuAiActRiskClassifier::new();
        let system = SystemDescription {
            use_case: "Power grid management".to_string(),
            affects_fundamental_rights: false,
            critical_infrastructure: true,
            biometric_data: false,
        };
        assert_eq!(classifier.classify_system(&system), AiRiskLevel::High);
    }

    #[test]
    fn test_eu_ai_act_limited_risk() {
        let classifier = EuAiActRiskClassifier::new();
        let system = SystemDescription {
            use_case: "Customer service chatbot".to_string(),
            affects_fundamental_rights: false,
            critical_infrastructure: false,
            biometric_data: false,
        };
        assert_eq!(classifier.classify_system(&system), AiRiskLevel::Limited);
    }

    #[test]
    fn test_cross_jurisdictional_mapping() {
        let mapper = CrossJurisdictionalMapper::new();
        let result = mapper.map_control(&Jurisdiction::EuAiAct, "EU-4", &Jurisdiction::Iso42001);
        assert_eq!(result, Some("ISO-4".to_string()));
    }

    #[test]
    fn test_cross_jurisdictional_no_mapping() {
        let mapper = CrossJurisdictionalMapper::new();
        let result = mapper.map_control(&Jurisdiction::Cnsa20, "CNSA-1", &Jurisdiction::ColoradoAiAct);
        assert!(result.is_none());
    }

    #[test]
    fn test_audit_package_generation() {
        let engine = ComplianceIntelligenceEngine::new();
        let mapper = CrossJurisdictionalMapper::new();
        let passed = vec!["EU-1".to_string(), "EU-2".to_string()];
        let assessment = engine.assess_compliance(&Jurisdiction::EuAiAct, &passed);
        let package = mapper.generate_audit_package(&Jurisdiction::EuAiAct, &assessment);
        assert!(!package.package_id.is_empty());
        assert!(!package.evidence_items.is_empty());
    }

    #[test]
    fn test_compliance_score_threshold() {
        let engine = ComplianceIntelligenceEngine::new();
        // Pass 4 out of 5 EU controls = 80% < 85% → not compliant
        let passed = vec!["EU-1".to_string(), "EU-2".to_string(), "EU-3".to_string(), "EU-4".to_string()];
        let assessment = engine.assess_compliance(&Jurisdiction::EuAiAct, &passed);
        assert!(!assessment.compliant);
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcComplianceGap;
        let _ = ReasonCode::RcProhibitedUseCase;
        let _ = ReasonCode::RcAuditRequired;
    }

    #[test]
    fn test_jurisdiction_names() {
        assert!(!Jurisdiction::EuAiAct.name().is_empty());
        assert!(!Jurisdiction::SouthKoreaAiAct.name().is_empty());
    }

    #[test]
    fn test_compliance_high_risk_flag() {
        let classifier = EuAiActRiskClassifier::new();
        let system = SystemDescription {
            use_case: "Benefits allocation".to_string(),
            affects_fundamental_rights: true,
            critical_infrastructure: false,
            biometric_data: false,
        };
        assert_eq!(classifier.classify_system(&system), AiRiskLevel::High);
    }
}
