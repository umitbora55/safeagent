//! W15: Enterprise Compliance Suite
//!
//! EU AI Act (Articles 9, 12, 13, 14, 15) compliance checks,
//! NIST AI RMF alignment, ISO 42001 controls, continuous compliance
//! monitoring, and one-click audit package generation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

// ── Compliance Frameworks ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    EuAiAct,
    NistAiRmf,
    Iso42001,
    SocType2,
    Gdpr,
}

impl ComplianceFramework {
    pub fn label(&self) -> &'static str {
        match self {
            ComplianceFramework::EuAiAct => "EU AI Act",
            ComplianceFramework::NistAiRmf => "NIST AI RMF",
            ComplianceFramework::Iso42001 => "ISO/IEC 42001",
            ComplianceFramework::SocType2 => "SOC 2 Type II",
            ComplianceFramework::Gdpr => "GDPR",
        }
    }
}

// ── Control ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    Compliant,
    NonCompliant { finding: String },
    PartiallyCompliant { gaps: Vec<String> },
    NotApplicable,
    NotEvaluated,
}

impl ControlStatus {
    pub fn is_fully_compliant(&self) -> bool {
        matches!(self, ControlStatus::Compliant | ControlStatus::NotApplicable)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub control_id: String,
    pub framework: ComplianceFramework,
    pub article_or_section: String,
    pub title: String,
    pub description: String,
    pub status: ControlStatus,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
    pub last_evaluated: DateTime<Utc>,
}

impl ComplianceControl {
    pub fn new(
        framework: ComplianceFramework,
        control_id: impl Into<String>,
        article: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            control_id: control_id.into(),
            framework,
            article_or_section: article.into(),
            title: title.into(),
            description: description.into(),
            status: ControlStatus::NotEvaluated,
            evidence: vec![],
            remediation: None,
            last_evaluated: Utc::now(),
        }
    }

    pub fn evaluate(&mut self, status: ControlStatus, evidence: Vec<String>) {
        self.status = status;
        self.evidence = evidence;
        self.last_evaluated = Utc::now();
    }
}

// ── EU AI Act Compliance ──────────────────────────────────────────────────────

/// Evaluates compliance against EU AI Act Articles 9, 12, 13, 14, 15.
pub struct EuAiActEvaluator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuAiActInputs {
    /// Art. 9: Risk management system is documented
    pub has_risk_management_system: bool,
    /// Art. 9: Risk assessments are conducted and logged
    pub risk_assessments_logged: bool,
    /// Art. 12: System logs all actions with Merkle-chained audit trail
    pub has_immutable_audit_log: bool,
    /// Art. 12: Logs retained for at least 6 months
    pub log_retention_days: u32,
    /// Art. 13: System provides transparency documentation
    pub has_transparency_docs: bool,
    /// Art. 13: Users are informed when interacting with AI
    pub user_ai_disclosure: bool,
    /// Art. 14: Human oversight mechanisms exist
    pub has_human_oversight: bool,
    /// Art. 14: Kill switch / emergency stop implemented
    pub has_kill_switch: bool,
    /// Art. 15: System accuracy metrics tracked
    pub accuracy_metrics_tracked: bool,
    /// Art. 15: Robustness testing performed
    pub robustness_testing_done: bool,
}

impl EuAiActEvaluator {
    pub fn evaluate(inputs: &EuAiActInputs) -> Vec<ComplianceControl> {
        vec![
            Self::eval_art9_risk_management(inputs),
            Self::eval_art12_logging(inputs),
            Self::eval_art13_transparency(inputs),
            Self::eval_art14_human_oversight(inputs),
            Self::eval_art15_accuracy(inputs),
        ]
    }

    fn eval_art9_risk_management(inputs: &EuAiActInputs) -> ComplianceControl {
        let mut ctrl = ComplianceControl::new(
            ComplianceFramework::EuAiAct,
            "EU-AI-9",
            "Article 9",
            "Risk Management System",
            "High-risk AI systems shall implement a risk management system throughout the system lifecycle",
        );
        let mut gaps = vec![];
        let mut evidence = vec![];

        if inputs.has_risk_management_system {
            evidence.push("Risk management system documented".into());
        } else {
            gaps.push("No risk management system documented".into());
        }
        if inputs.risk_assessments_logged {
            evidence.push("Risk assessments are logged".into());
        } else {
            gaps.push("Risk assessment logs missing".into());
        }

        let status = if gaps.is_empty() {
            ControlStatus::Compliant
        } else if !evidence.is_empty() {
            ControlStatus::PartiallyCompliant { gaps }
        } else {
            ControlStatus::NonCompliant {
                finding: "Risk management system absent".into(),
            }
        };
        ctrl.evaluate(status, evidence);
        ctrl
    }

    fn eval_art12_logging(inputs: &EuAiActInputs) -> ComplianceControl {
        let mut ctrl = ComplianceControl::new(
            ComplianceFramework::EuAiAct,
            "EU-AI-12",
            "Article 12",
            "Record-Keeping",
            "High-risk AI systems shall be designed to enable automatic logging of events throughout lifecycle",
        );
        let mut gaps = vec![];
        let mut evidence = vec![];

        if inputs.has_immutable_audit_log {
            evidence.push("Immutable Merkle-chained audit log implemented".into());
        } else {
            gaps.push("Immutable audit log not implemented".into());
        }
        if inputs.log_retention_days >= 180 {
            evidence.push(format!("Log retention: {} days (≥180 required)", inputs.log_retention_days));
        } else {
            gaps.push(format!(
                "Log retention {} days below 180 day minimum",
                inputs.log_retention_days
            ));
        }

        let status = if gaps.is_empty() {
            ControlStatus::Compliant
        } else if !evidence.is_empty() {
            ControlStatus::PartiallyCompliant { gaps }
        } else {
            ControlStatus::NonCompliant {
                finding: "Record-keeping requirements not met".into(),
            }
        };
        ctrl.evaluate(status, evidence);
        ctrl
    }

    fn eval_art13_transparency(inputs: &EuAiActInputs) -> ComplianceControl {
        let mut ctrl = ComplianceControl::new(
            ComplianceFramework::EuAiAct,
            "EU-AI-13",
            "Article 13",
            "Transparency and Provision of Information to Users",
            "High-risk AI systems shall be designed to ensure transparency and information to deployers",
        );
        let mut gaps = vec![];
        let mut evidence = vec![];

        if inputs.has_transparency_docs {
            evidence.push("Transparency documentation available".into());
        } else {
            gaps.push("No transparency documentation".into());
        }
        if inputs.user_ai_disclosure {
            evidence.push("Users informed they are interacting with AI".into());
        } else {
            gaps.push("Users not informed about AI interaction".into());
        }

        let status = if gaps.is_empty() {
            ControlStatus::Compliant
        } else if !evidence.is_empty() {
            ControlStatus::PartiallyCompliant { gaps }
        } else {
            ControlStatus::NonCompliant {
                finding: "Transparency requirements not met".into(),
            }
        };
        ctrl.evaluate(status, evidence);
        ctrl
    }

    fn eval_art14_human_oversight(inputs: &EuAiActInputs) -> ComplianceControl {
        let mut ctrl = ComplianceControl::new(
            ComplianceFramework::EuAiAct,
            "EU-AI-14",
            "Article 14",
            "Human Oversight",
            "High-risk AI systems shall be designed to be effectively overseen by natural persons",
        );
        let mut gaps = vec![];
        let mut evidence = vec![];

        if inputs.has_human_oversight {
            evidence.push("Human oversight mechanisms implemented".into());
        } else {
            gaps.push("No human oversight mechanisms".into());
        }
        if inputs.has_kill_switch {
            evidence.push("Kill switch / emergency stop implemented".into());
        } else {
            gaps.push("Kill switch not implemented".into());
        }

        let status = if gaps.is_empty() {
            ControlStatus::Compliant
        } else if !evidence.is_empty() {
            ControlStatus::PartiallyCompliant { gaps }
        } else {
            ControlStatus::NonCompliant {
                finding: "Human oversight not implemented".into(),
            }
        };
        ctrl.evaluate(status, evidence);
        ctrl
    }

    fn eval_art15_accuracy(inputs: &EuAiActInputs) -> ComplianceControl {
        let mut ctrl = ComplianceControl::new(
            ComplianceFramework::EuAiAct,
            "EU-AI-15",
            "Article 15",
            "Accuracy, Robustness and Cybersecurity",
            "High-risk AI systems shall be designed to achieve appropriate levels of accuracy, robustness and cybersecurity",
        );
        let mut gaps = vec![];
        let mut evidence = vec![];

        if inputs.accuracy_metrics_tracked {
            evidence.push("Accuracy metrics tracked and reported".into());
        } else {
            gaps.push("Accuracy metrics not tracked".into());
        }
        if inputs.robustness_testing_done {
            evidence.push("Robustness testing completed".into());
        } else {
            gaps.push("Robustness testing not performed".into());
        }

        let status = if gaps.is_empty() {
            ControlStatus::Compliant
        } else if !evidence.is_empty() {
            ControlStatus::PartiallyCompliant { gaps }
        } else {
            ControlStatus::NonCompliant {
                finding: "Accuracy and robustness requirements not met".into(),
            }
        };
        ctrl.evaluate(status, evidence);
        ctrl
    }
}

// ── NIST AI RMF ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistAiRmfInputs {
    pub govern_policies_documented: bool,
    pub map_risk_taxonomy_defined: bool,
    pub measure_metrics_collected: bool,
    pub manage_incidents_tracked: bool,
}

pub struct NistAiRmfEvaluator;

impl NistAiRmfEvaluator {
    pub fn evaluate(inputs: &NistAiRmfInputs) -> Vec<ComplianceControl> {
        let functions = vec![
            ("NIST-GOVERN", "GOVERN", "AI governance policies and structures established", inputs.govern_policies_documented),
            ("NIST-MAP", "MAP", "AI risk context established and categorized", inputs.map_risk_taxonomy_defined),
            ("NIST-MEASURE", "MEASURE", "AI risk analysed, assessed and prioritized", inputs.measure_metrics_collected),
            ("NIST-MANAGE", "MANAGE", "AI risk treatments implemented and tracked", inputs.manage_incidents_tracked),
        ];

        functions.into_iter().map(|(id, section, desc, compliant)| {
            let mut ctrl = ComplianceControl::new(
                ComplianceFramework::NistAiRmf,
                id,
                section,
                section,
                desc,
            );
            if compliant {
                ctrl.evaluate(ControlStatus::Compliant, vec![format!("{} function implemented", section)]);
            } else {
                warn!("NIST AI RMF: {} function not implemented", section);
                ctrl.evaluate(
                    ControlStatus::NonCompliant {
                        finding: format!("{} function not implemented", section),
                    },
                    vec![],
                );
            }
            ctrl
        }).collect()
    }
}

// ── ISO 42001 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso42001Inputs {
    pub context_documented: bool,
    pub leadership_commitment: bool,
    pub risk_treatment_plan: bool,
    pub ai_policy_established: bool,
    pub monitoring_implemented: bool,
    pub continual_improvement: bool,
}

pub struct Iso42001Evaluator;

impl Iso42001Evaluator {
    pub fn evaluate(inputs: &Iso42001Inputs) -> Vec<ComplianceControl> {
        let clauses = vec![
            ("ISO-42001-4", "4", "Context of the organization", inputs.context_documented),
            ("ISO-42001-5", "5", "Leadership and commitment", inputs.leadership_commitment),
            ("ISO-42001-6", "6", "Risk treatment planning for AI", inputs.risk_treatment_plan),
            ("ISO-42001-8", "8", "AI policy and operational planning", inputs.ai_policy_established),
            ("ISO-42001-9", "9", "Performance evaluation and monitoring", inputs.monitoring_implemented),
            ("ISO-42001-10", "10", "Continual improvement of AI MS", inputs.continual_improvement),
        ];

        clauses.into_iter().map(|(id, clause, desc, compliant)| {
            let mut ctrl = ComplianceControl::new(
                ComplianceFramework::Iso42001,
                id,
                format!("Clause {}", clause),
                desc,
                desc,
            );
            if compliant {
                ctrl.evaluate(ControlStatus::Compliant, vec![format!("ISO 42001 Clause {} satisfied", clause)]);
            } else {
                ctrl.evaluate(
                    ControlStatus::NonCompliant {
                        finding: format!("Clause {} requirement not met", clause),
                    },
                    vec![],
                );
            }
            ctrl
        }).collect()
    }
}

// ── Compliance Report ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub controls: Vec<ComplianceControl>,
    pub summary_by_framework: HashMap<String, FrameworkSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSummary {
    pub framework: String,
    pub total_controls: u32,
    pub compliant: u32,
    pub non_compliant: u32,
    pub partial: u32,
    pub not_evaluated: u32,
    pub compliance_pct: f64,
}

impl ComplianceReport {
    pub fn new(controls: Vec<ComplianceControl>) -> Self {
        let mut summary: HashMap<String, FrameworkSummary> = HashMap::new();

        for ctrl in &controls {
            let fw = ctrl.framework.label().to_string();
            let entry = summary.entry(fw.clone()).or_insert_with(|| FrameworkSummary {
                framework: fw,
                total_controls: 0,
                compliant: 0,
                non_compliant: 0,
                partial: 0,
                not_evaluated: 0,
                compliance_pct: 0.0,
            });
            entry.total_controls += 1;
            match &ctrl.status {
                ControlStatus::Compliant | ControlStatus::NotApplicable => entry.compliant += 1,
                ControlStatus::NonCompliant { .. } => entry.non_compliant += 1,
                ControlStatus::PartiallyCompliant { .. } => entry.partial += 1,
                ControlStatus::NotEvaluated => entry.not_evaluated += 1,
            }
        }

        for entry in summary.values_mut() {
            if entry.total_controls > 0 {
                entry.compliance_pct =
                    entry.compliant as f64 / entry.total_controls as f64 * 100.0;
            }
        }

        Self {
            report_id: uuid::Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            controls,
            summary_by_framework: summary,
        }
    }

    /// Generate a one-click audit package (serialized JSON summary).
    pub fn audit_package(&self) -> serde_json::Value {
        serde_json::json!({
            "reportId": self.report_id,
            "generatedAt": self.generated_at.to_rfc3339(),
            "totalControls": self.controls.len(),
            "summaryByFramework": self.summary_by_framework,
        })
    }

    pub fn fully_compliant_count(&self) -> usize {
        self.controls.iter().filter(|c| c.status.is_fully_compliant()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_inputs() -> EuAiActInputs {
        EuAiActInputs {
            has_risk_management_system: true,
            risk_assessments_logged: true,
            has_immutable_audit_log: true,
            log_retention_days: 365,
            has_transparency_docs: true,
            user_ai_disclosure: true,
            has_human_oversight: true,
            has_kill_switch: true,
            accuracy_metrics_tracked: true,
            robustness_testing_done: true,
        }
    }

    fn partial_inputs() -> EuAiActInputs {
        EuAiActInputs {
            has_risk_management_system: true,
            risk_assessments_logged: false,
            has_immutable_audit_log: true,
            log_retention_days: 90, // below 180 minimum
            has_transparency_docs: false,
            user_ai_disclosure: true,
            has_human_oversight: true,
            has_kill_switch: false,
            accuracy_metrics_tracked: false,
            robustness_testing_done: false,
        }
    }

    // ── EU AI Act ─────────────────────────────────────────────────────────────

    #[test]
    fn eu_ai_act_full_compliance() {
        let controls = EuAiActEvaluator::evaluate(&full_inputs());
        assert_eq!(controls.len(), 5);
        assert!(controls.iter().all(|c| c.status.is_fully_compliant()));
    }

    #[test]
    fn eu_ai_act_partial_compliance() {
        let controls = EuAiActEvaluator::evaluate(&partial_inputs());
        let non_compliant = controls
            .iter()
            .filter(|c| !c.status.is_fully_compliant())
            .count();
        assert!(non_compliant > 0);
    }

    #[test]
    fn art12_retention_below_minimum_fails() {
        let mut inputs = full_inputs();
        inputs.log_retention_days = 30;
        let controls = EuAiActEvaluator::evaluate(&inputs);
        let art12 = controls.iter().find(|c| c.control_id == "EU-AI-12").unwrap();
        assert!(!art12.status.is_fully_compliant());
    }

    #[test]
    fn art14_no_kill_switch_fails() {
        let mut inputs = full_inputs();
        inputs.has_kill_switch = false;
        let controls = EuAiActEvaluator::evaluate(&inputs);
        let art14 = controls.iter().find(|c| c.control_id == "EU-AI-14").unwrap();
        assert!(!art14.status.is_fully_compliant());
    }

    // ── NIST AI RMF ──────────────────────────────────────────────────────────

    #[test]
    fn nist_full_compliance() {
        let inputs = NistAiRmfInputs {
            govern_policies_documented: true,
            map_risk_taxonomy_defined: true,
            measure_metrics_collected: true,
            manage_incidents_tracked: true,
        };
        let controls = NistAiRmfEvaluator::evaluate(&inputs);
        assert_eq!(controls.len(), 4);
        assert!(controls.iter().all(|c| c.status.is_fully_compliant()));
    }

    #[test]
    fn nist_partial_compliance() {
        let inputs = NistAiRmfInputs {
            govern_policies_documented: true,
            map_risk_taxonomy_defined: false,
            measure_metrics_collected: true,
            manage_incidents_tracked: false,
        };
        let controls = NistAiRmfEvaluator::evaluate(&inputs);
        let compliant = controls.iter().filter(|c| c.status.is_fully_compliant()).count();
        assert_eq!(compliant, 2);
    }

    // ── ISO 42001 ─────────────────────────────────────────────────────────────

    #[test]
    fn iso42001_full_compliance() {
        let inputs = Iso42001Inputs {
            context_documented: true,
            leadership_commitment: true,
            risk_treatment_plan: true,
            ai_policy_established: true,
            monitoring_implemented: true,
            continual_improvement: true,
        };
        let controls = Iso42001Evaluator::evaluate(&inputs);
        assert_eq!(controls.len(), 6);
        assert!(controls.iter().all(|c| c.status.is_fully_compliant()));
    }

    // ── Compliance Report ─────────────────────────────────────────────────────

    #[test]
    fn compliance_report_counts_correctly() {
        let controls = EuAiActEvaluator::evaluate(&full_inputs());
        let report = ComplianceReport::new(controls);
        assert_eq!(report.fully_compliant_count(), 5);
    }

    #[test]
    fn audit_package_json_valid() {
        let controls = EuAiActEvaluator::evaluate(&full_inputs());
        let report = ComplianceReport::new(controls);
        let pkg = report.audit_package();
        assert!(pkg["reportId"].is_string());
        assert!(pkg["totalControls"].as_u64().unwrap() == 5);
    }

    #[test]
    fn compliance_pct_computed() {
        let inputs = full_inputs();
        let controls = EuAiActEvaluator::evaluate(&inputs);
        let report = ComplianceReport::new(controls);
        let fw_summary = report.summary_by_framework.get("EU AI Act").unwrap();
        assert!((fw_summary.compliance_pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn multi_framework_report() {
        let eu_controls = EuAiActEvaluator::evaluate(&full_inputs());
        let nist_controls = NistAiRmfEvaluator::evaluate(&NistAiRmfInputs {
            govern_policies_documented: true,
            map_risk_taxonomy_defined: true,
            measure_metrics_collected: true,
            manage_incidents_tracked: true,
        });
        let all: Vec<_> = eu_controls.into_iter().chain(nist_controls).collect();
        let report = ComplianceReport::new(all);
        assert!(report.summary_by_framework.contains_key("EU AI Act"));
        assert!(report.summary_by_framework.contains_key("NIST AI RMF"));
    }
}
