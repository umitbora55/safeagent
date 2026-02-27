//! W47: CSA STAR AI Certification Toolkit
//! CSA CCM controls assessment, CAIQ response generation,
//! STAR level scoring (Level 1/2/3), certification readiness.
#![allow(dead_code)]

use std::collections::HashMap;
use dashmap::DashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcCsaNonCompliant,
    RcCsaAuditRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CcmDomain {
    AuditAssurance,
    ChangeControl,
    DataSecurity,
    DataCenterSecurity,
    EncryptionKeyMgmt,
    GovernanceRisk,
    HumanResources,
    IdentityAccess,
    InfraVirtualization,
    InteropPortability,
    MobileSecure,
    SecurityIncident,
    SupplyChainMgmt,
}

impl CcmDomain {
    pub fn name(&self) -> &'static str {
        match self {
            CcmDomain::AuditAssurance => "audit_assurance",
            CcmDomain::ChangeControl => "change_control",
            CcmDomain::DataSecurity => "data_security",
            CcmDomain::DataCenterSecurity => "data_center_security",
            CcmDomain::EncryptionKeyMgmt => "encryption_key_mgmt",
            CcmDomain::GovernanceRisk => "governance_risk",
            CcmDomain::HumanResources => "human_resources",
            CcmDomain::IdentityAccess => "identity_access",
            CcmDomain::InfraVirtualization => "infra_virtualization",
            CcmDomain::InteropPortability => "interop_portability",
            CcmDomain::MobileSecure => "mobile_secure",
            CcmDomain::SecurityIncident => "security_incident",
            CcmDomain::SupplyChainMgmt => "supply_chain_mgmt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CcmControl {
    pub control_id: String,
    pub domain: CcmDomain,
    pub title: String,
    pub requirement: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AssessmentStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotApplicable,
}

#[derive(Debug, Clone)]
pub struct StarAssessmentResult {
    pub control_id: String,
    pub status: AssessmentStatus,
    pub evidence: Vec<String>,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StarCertLevel {
    NotCertified,
    Level1SelfAssessment,
    Level2ThirdParty,
    Level3Continuous,
}

#[derive(Debug, Clone)]
pub struct StarScore {
    pub overall_score: f64,
    pub domain_scores: HashMap<String, f64>,
    pub level: StarCertLevel,
    pub ready_for_audit: bool,
}

#[derive(Debug, Clone)]
pub struct CaiqResponse {
    pub control_id: String,
    pub answer: String,
    pub supplemental_guidance: String,
    pub implementation_status: String,
}

pub struct CsaStarCertificationEngine {
    controls: DashMap<String, CcmControl>,
}

impl CsaStarCertificationEngine {
    pub fn new() -> Self {
        let engine = Self { controls: DashMap::new() };
        engine.load_controls();
        engine
    }

    fn load_controls(&self) {
        let domain_controls = [
            (CcmDomain::AuditAssurance, vec!["AA-01", "AA-02"]),
            (CcmDomain::ChangeControl, vec!["CC-01", "CC-02"]),
            (CcmDomain::DataSecurity, vec!["DS-01", "DS-02", "DS-03"]),
            (CcmDomain::DataCenterSecurity, vec!["DCS-01", "DCS-02"]),
            (CcmDomain::EncryptionKeyMgmt, vec!["EKM-01", "EKM-02"]),
            (CcmDomain::GovernanceRisk, vec!["GRM-01", "GRM-02"]),
            (CcmDomain::HumanResources, vec!["HRS-01"]),
            (CcmDomain::IdentityAccess, vec!["IAM-01", "IAM-02", "IAM-03"]),
            (CcmDomain::InfraVirtualization, vec!["IVS-01", "IVS-02"]),
            (CcmDomain::InteropPortability, vec!["IPY-01"]),
            (CcmDomain::MobileSecure, vec!["MOS-01"]),
            (CcmDomain::SecurityIncident, vec!["SEF-01", "SEF-02"]),
            (CcmDomain::SupplyChainMgmt, vec!["STA-01", "STA-02"]),
        ];
        for (domain, ids) in &domain_controls {
            for id in ids {
                self.controls.insert(id.to_string(), CcmControl {
                    control_id: id.to_string(),
                    domain: domain.clone(),
                    title: format!("{} - {}", domain.name(), id),
                    requirement: format!("Requirement for {}", id),
                });
            }
        }
    }

    pub fn assess_control(&self, control_id: &str, evidence: Vec<String>) -> StarAssessmentResult {
        let (status, score) = if evidence.len() >= 3 {
            (AssessmentStatus::Compliant, 1.0)
        } else if !evidence.is_empty() {
            (AssessmentStatus::PartiallyCompliant, 0.5)
        } else {
            (AssessmentStatus::NonCompliant, 0.0)
        };
        StarAssessmentResult { control_id: control_id.to_string(), status, evidence, score }
    }

    pub fn compute_star_score(&self, results: &[StarAssessmentResult]) -> StarScore {
        let mut domain_totals: HashMap<String, (f64, usize)> = HashMap::new();
        let overall_sum: f64 = results.iter().map(|r| r.score).sum();
        let overall = if results.is_empty() { 0.0 } else { overall_sum / results.len() as f64 };

        for result in results {
            if let Some(ctrl) = self.controls.get(&result.control_id) {
                let domain = ctrl.domain.name().to_string();
                let (sum, count) = domain_totals.entry(domain).or_insert((0.0, 0));
                *sum += result.score;
                *count += 1;
            }
        }
        let domain_scores: HashMap<String, f64> = domain_totals.iter()
            .map(|(d, (sum, count))| (d.clone(), if *count > 0 { sum / *count as f64 } else { 0.0 }))
            .collect();

        let level = if overall >= 0.9 { StarCertLevel::Level3Continuous }
            else if overall >= 0.75 { StarCertLevel::Level2ThirdParty }
            else if overall >= 0.5 { StarCertLevel::Level1SelfAssessment }
            else { StarCertLevel::NotCertified };

        StarScore { overall_score: overall, domain_scores, level, ready_for_audit: overall >= 0.6 }
    }

    pub fn generate_caiq_response(&self, control_id: &str, assessment: &StarAssessmentResult) -> CaiqResponse {
        let answer = match &assessment.status {
            AssessmentStatus::Compliant => "Yes",
            AssessmentStatus::PartiallyCompliant => "Partial",
            AssessmentStatus::NonCompliant => "No",
            AssessmentStatus::NotApplicable => "N/A",
        }.to_string();
        CaiqResponse {
            control_id: control_id.to_string(),
            answer: answer.clone(),
            supplemental_guidance: format!("Evidence count: {}. Status: {}", assessment.evidence.len(), answer),
            implementation_status: format!("{:?}", assessment.status),
        }
    }

    pub fn total_controls(&self) -> usize {
        self.controls.len()
    }
}

impl Default for CsaStarCertificationEngine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_controls_loaded() {
        let engine = CsaStarCertificationEngine::new();
        assert!(engine.total_controls() >= 20);
    }

    #[test]
    fn test_assess_compliant() {
        let engine = CsaStarCertificationEngine::new();
        let result = engine.assess_control("DS-01", vec!["ev1".to_string(), "ev2".to_string(), "ev3".to_string()]);
        assert_eq!(result.status, AssessmentStatus::Compliant);
        assert_eq!(result.score, 1.0);
    }

    #[test]
    fn test_assess_partially_compliant() {
        let engine = CsaStarCertificationEngine::new();
        let result = engine.assess_control("DS-01", vec!["ev1".to_string()]);
        assert_eq!(result.status, AssessmentStatus::PartiallyCompliant);
        assert_eq!(result.score, 0.5);
    }

    #[test]
    fn test_assess_non_compliant() {
        let engine = CsaStarCertificationEngine::new();
        let result = engine.assess_control("DS-01", vec![]);
        assert_eq!(result.status, AssessmentStatus::NonCompliant);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_star_score_level3() {
        let engine = CsaStarCertificationEngine::new();
        let results: Vec<StarAssessmentResult> = ["DS-01", "IAM-01", "EKM-01"].iter().map(|id| {
            engine.assess_control(id, vec!["ev1".to_string(), "ev2".to_string(), "ev3".to_string()])
        }).collect();
        let score = engine.compute_star_score(&results);
        assert_eq!(score.level, StarCertLevel::Level3Continuous);
        assert!(score.ready_for_audit);
    }

    #[test]
    fn test_star_score_level1() {
        let engine = CsaStarCertificationEngine::new();
        let results = vec![
            engine.assess_control("DS-01", vec!["ev1".to_string()]),
            engine.assess_control("IAM-01", vec!["ev1".to_string()]),
        ];
        let score = engine.compute_star_score(&results);
        assert_eq!(score.level, StarCertLevel::Level1SelfAssessment);
    }

    #[test]
    fn test_star_score_not_certified() {
        let engine = CsaStarCertificationEngine::new();
        let results = vec![engine.assess_control("DS-01", vec![])];
        let score = engine.compute_star_score(&results);
        assert_eq!(score.level, StarCertLevel::NotCertified);
    }

    #[test]
    fn test_caiq_response_yes() {
        let engine = CsaStarCertificationEngine::new();
        let assessment = engine.assess_control("DS-01", vec!["ev1".to_string(), "ev2".to_string(), "ev3".to_string()]);
        let caiq = engine.generate_caiq_response("DS-01", &assessment);
        assert_eq!(caiq.answer, "Yes");
    }

    #[test]
    fn test_caiq_response_no() {
        let engine = CsaStarCertificationEngine::new();
        let assessment = engine.assess_control("DS-01", vec![]);
        let caiq = engine.generate_caiq_response("DS-01", &assessment);
        assert_eq!(caiq.answer, "No");
    }

    #[test]
    fn test_caiq_response_partial() {
        let engine = CsaStarCertificationEngine::new();
        let assessment = engine.assess_control("DS-01", vec!["ev1".to_string()]);
        let caiq = engine.generate_caiq_response("DS-01", &assessment);
        assert_eq!(caiq.answer, "Partial");
    }

    #[test]
    fn test_ready_for_audit_threshold() {
        let engine = CsaStarCertificationEngine::new();
        // Score below 0.6 → not ready
        let results = vec![engine.assess_control("DS-01", vec![])];
        let score = engine.compute_star_score(&results);
        assert!(!score.ready_for_audit);
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcCsaNonCompliant;
        let _ = ReasonCode::RcCsaAuditRequired;
    }
}
