// eu_ai_act.rs — W7 D5: EU AI Act Compliance Module
//
// EU AI Act high-risk system requirements take effect August 2, 2026.
// This module implements the two most directly applicable articles:
//
// Article 12 — Automatic logging:
//   "High-risk AI systems shall automatically log events throughout their
//    entire lifetime to the extent such logging is necessary to enable the
//    assessment of conformity [...] with EU AI Act requirements."
//   Implementation: structured EuAiActLogEntry capturing action context,
//   authorization decision, risk level, human oversight status.
//
// Article 14 — Human oversight:
//   "High-risk AI systems shall be designed and developed in such a way
//    that they can be effectively overseen by natural persons. [...] persons
//    to whom human oversight is assigned shall be able to [...] intervene
//    on the functioning of the high-risk AI system, or interrupt it."
//   Implementation: HumanOversightRecord tracking intervention capabilities,
//   break-glass usage, and kill-switch activations.
//
// Article 15 — Accuracy, robustness, cybersecurity (partial):
//   Implementation: AccuracyMetrics tracking policy decision accuracy,
//   false positive/negative rates against expected behavior.
//
// The module generates structured compliance reports in JSON suitable
// for regulatory submission.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tracing::info;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Article 12: Automatic Logging
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Risk classification per EU AI Act Annex III categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EuRiskClass {
    /// Minimal risk — no special requirements
    Minimal,
    /// Limited risk — transparency obligations
    Limited,
    /// High risk — Articles 12/14/15 apply
    High,
    /// Unacceptable risk — prohibited
    Unacceptable,
}

/// Authorization decision outcome for compliance logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceOutcome {
    Allowed,
    AllowedWithNotification,
    RequiredHumanApproval,
    Denied,
    BlockedByKillSwitch,
    BlockedByBudget,
    BlockedByRateLimit,
    BlockedByCircuit,
}

/// Article 12 log entry. Every high-risk AI action must be logged
/// with sufficient detail to assess conformity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuAiActLogEntry {
    /// Unique entry ID (UUID)
    pub entry_id: String,
    /// ISO 8601 timestamp
    pub timestamp: DateTime<Utc>,
    /// Agent identifier
    pub agent_id: String,
    /// Action/tool requested
    pub action: String,
    /// Risk class of this action
    pub risk_class: EuRiskClass,
    /// Authorization decision
    pub outcome: ComplianceOutcome,
    /// Was human oversight available at decision time?
    pub human_oversight_available: bool,
    /// Was human approval sought/obtained?
    pub human_approval_obtained: bool,
    /// Risk score at time of decision (0.0–1.0)
    pub risk_score: Option<f64>,
    /// Policy version that made the decision
    pub policy_version: String,
    /// Was the decision overridden by a human?
    pub human_override: bool,
    /// Traceability: evidence log reference
    pub evidence_reference: Option<String>,
}

impl EuAiActLogEntry {
    pub fn new(
        agent_id: impl Into<String>,
        action: impl Into<String>,
        risk_class: EuRiskClass,
        outcome: ComplianceOutcome,
    ) -> Self {
        Self {
            entry_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            agent_id: agent_id.into(),
            action: action.into(),
            risk_class,
            outcome,
            human_oversight_available: true,
            human_approval_obtained: false,
            risk_score: None,
            policy_version: "1.0.0".to_string(),
            human_override: false,
            evidence_reference: None,
        }
    }

    pub fn with_risk_score(mut self, score: f64) -> Self {
        self.risk_score = Some(score);
        self
    }

    pub fn with_human_approval(mut self, obtained: bool) -> Self {
        self.human_approval_obtained = obtained;
        if obtained {
            self.human_oversight_available = true;
        }
        self
    }

    pub fn with_evidence(mut self, ref_id: impl Into<String>) -> Self {
        self.evidence_reference = Some(ref_id.into());
        self
    }

    pub fn with_policy_version(mut self, version: impl Into<String>) -> Self {
        self.policy_version = version.into();
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Article 14: Human Oversight Records
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Types of human intervention on the AI system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionType {
    /// Human approved a pending action
    Approval,
    /// Human rejected a pending action
    Rejection,
    /// Human activated the kill switch
    KillSwitch,
    /// Human overrode an automatic decision
    Override,
    /// Human modified policy configuration
    PolicyUpdate,
    /// Human initiated break-glass access
    BreakGlass,
}

/// Article 14 human oversight record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanOversightRecord {
    pub record_id: String,
    pub timestamp: DateTime<Utc>,
    /// Human who performed the intervention
    pub human_identifier: String,
    /// Type of intervention
    pub intervention: InterventionType,
    /// Action/agent affected
    pub affected_entity: String,
    /// Free-text justification (required for regulatory audit)
    pub justification: Option<String>,
}

impl HumanOversightRecord {
    pub fn new(
        human_id: impl Into<String>,
        intervention: InterventionType,
        affected_entity: impl Into<String>,
    ) -> Self {
        Self {
            record_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            human_identifier: human_id.into(),
            intervention,
            affected_entity: affected_entity.into(),
            justification: None,
        }
    }

    pub fn with_justification(mut self, j: impl Into<String>) -> Self {
        self.justification = Some(j.into());
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Article 15: Accuracy Metrics
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Accumulated accuracy metrics for Article 15 compliance reporting.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub total_decisions: u64,
    pub correct_allows: u64,
    pub correct_denials: u64,
    /// Human-confirmed false positives (should have allowed but denied)
    pub false_positives: u64,
    /// Human-confirmed false negatives (should have denied but allowed)
    pub false_negatives: u64,
    pub human_overrides: u64,
}

impl AccuracyMetrics {
    pub fn precision(&self) -> f64 {
        let tp = self.correct_denials as f64;
        let fp = self.false_positives as f64;
        if tp + fp == 0.0 { 1.0 } else { tp / (tp + fp) }
    }

    pub fn recall(&self) -> f64 {
        let tp = self.correct_denials as f64;
        let fn_ = self.false_negatives as f64;
        if tp + fn_ == 0.0 { 1.0 } else { tp / (tp + fn_) }
    }

    pub fn false_positive_rate(&self) -> f64 {
        if self.total_decisions == 0 { 0.0 } else {
            self.false_positives as f64 / self.total_decisions as f64
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Compliance Report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// EU AI Act compliance report — suitable for regulatory submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuAiActComplianceReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub reporting_period_start: DateTime<Utc>,
    pub reporting_period_end: DateTime<Utc>,
    pub system_version: String,
    pub risk_classification: EuRiskClass,

    // Article 12 stats
    pub total_logged_actions: u64,
    pub actions_by_outcome: std::collections::HashMap<String, u64>,
    pub actions_requiring_human_approval: u64,
    pub human_approvals_obtained: u64,

    // Article 14 stats
    pub human_interventions: u64,
    pub kill_switch_activations: u64,
    pub break_glass_uses: u64,
    pub policy_updates: u64,

    // Article 15 metrics
    pub accuracy: AccuracyMetrics,

    /// Compliance attestation
    pub articles_addressed: Vec<String>,
    pub compliance_notes: Vec<String>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  EU AI Act Compliance Logger
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Central compliance logging service. Thread-safe.
///
/// Collects Article 12 log entries and Article 14 oversight records,
/// and generates compliance reports on demand.
pub struct EuAiActLogger {
    action_log: Mutex<Vec<EuAiActLogEntry>>,
    oversight_log: Mutex<Vec<HumanOversightRecord>>,
    accuracy: Mutex<AccuracyMetrics>,
    system_version: String,
}

impl EuAiActLogger {
    pub fn new(system_version: impl Into<String>) -> Self {
        Self {
            action_log: Mutex::new(Vec::new()),
            oversight_log: Mutex::new(Vec::new()),
            accuracy: Mutex::new(AccuracyMetrics::default()),
            system_version: system_version.into(),
        }
    }

    /// Article 12: Log an action and its authorization decision.
    pub fn log_action(&self, entry: EuAiActLogEntry) {
        info!(
            target: "eu_ai_act",
            entry_id = %entry.entry_id,
            agent = %entry.agent_id,
            action = %entry.action,
            outcome = ?entry.outcome,
            risk_class = ?entry.risk_class,
            "EU AI Act Article 12: action logged"
        );
        self.action_log.lock().unwrap().push(entry);
    }

    /// Article 14: Record a human oversight intervention.
    pub fn log_oversight(&self, record: HumanOversightRecord) {
        info!(
            target: "eu_ai_act",
            record_id = %record.record_id,
            human = %record.human_identifier,
            intervention = ?record.intervention,
            entity = %record.affected_entity,
            "EU AI Act Article 14: human oversight recorded"
        );
        self.oversight_log.lock().unwrap().push(record);
    }

    /// Article 15: Record a confirmed false positive.
    pub fn record_false_positive(&self) {
        let mut acc = self.accuracy.lock().unwrap();
        acc.false_positives += 1;
        acc.total_decisions += 1;
        acc.human_overrides += 1;
    }

    /// Article 15: Record a confirmed false negative.
    pub fn record_false_negative(&self) {
        let mut acc = self.accuracy.lock().unwrap();
        acc.false_negatives += 1;
        acc.total_decisions += 1;
        acc.human_overrides += 1;
    }

    /// Article 15: Record a correct decision.
    pub fn record_correct_decision(&self, was_allow: bool) {
        let mut acc = self.accuracy.lock().unwrap();
        acc.total_decisions += 1;
        if was_allow {
            acc.correct_allows += 1;
        } else {
            acc.correct_denials += 1;
        }
    }

    /// Generate a compliance report for the given reporting period.
    pub fn generate_report(
        &self,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> EuAiActComplianceReport {
        let log = self.action_log.lock().unwrap();
        let oversight = self.oversight_log.lock().unwrap();
        let accuracy = self.accuracy.lock().unwrap().clone();

        // Filter to period
        let period_entries: Vec<&EuAiActLogEntry> = log
            .iter()
            .filter(|e| e.timestamp >= period_start && e.timestamp <= period_end)
            .collect();

        let period_oversight: Vec<&HumanOversightRecord> = oversight
            .iter()
            .filter(|r| r.timestamp >= period_start && r.timestamp <= period_end)
            .collect();

        // Aggregate
        let mut actions_by_outcome = std::collections::HashMap::new();
        let mut requiring_approval = 0u64;
        let mut approvals_obtained = 0u64;

        for entry in &period_entries {
            let key = format!("{:?}", entry.outcome).to_lowercase();
            *actions_by_outcome.entry(key).or_insert(0u64) += 1;
            if matches!(entry.outcome, ComplianceOutcome::RequiredHumanApproval) {
                requiring_approval += 1;
            }
            if entry.human_approval_obtained {
                approvals_obtained += 1;
            }
        }

        let kill_switches = period_oversight
            .iter()
            .filter(|r| r.intervention == InterventionType::KillSwitch)
            .count() as u64;
        let break_glass = period_oversight
            .iter()
            .filter(|r| r.intervention == InterventionType::BreakGlass)
            .count() as u64;
        let policy_updates = period_oversight
            .iter()
            .filter(|r| r.intervention == InterventionType::PolicyUpdate)
            .count() as u64;

        EuAiActComplianceReport {
            report_id: uuid::Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            reporting_period_start: period_start,
            reporting_period_end: period_end,
            system_version: self.system_version.clone(),
            risk_classification: EuRiskClass::High,
            total_logged_actions: period_entries.len() as u64,
            actions_by_outcome,
            actions_requiring_human_approval: requiring_approval,
            human_approvals_obtained: approvals_obtained,
            human_interventions: period_oversight.len() as u64,
            kill_switch_activations: kill_switches,
            break_glass_uses: break_glass,
            policy_updates,
            accuracy,
            articles_addressed: vec![
                "Article 12 (Automatic Logging)".to_string(),
                "Article 14 (Human Oversight)".to_string(),
                "Article 15 (Accuracy Metrics)".to_string(),
            ],
            compliance_notes: vec![
                "Actions are logged with full authorization context".to_string(),
                "Human oversight available via kill switch and approval workflow".to_string(),
                "Policy decisions are formally verified via Cedar policy engine".to_string(),
                "Evidence chain provides tamper-evident audit trail".to_string(),
            ],
        }
    }

    /// Total logged actions (all time).
    pub fn total_actions(&self) -> usize {
        self.action_log.lock().unwrap().len()
    }

    /// Total oversight records (all time).
    pub fn total_oversight_records(&self) -> usize {
        self.oversight_log.lock().unwrap().len()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn logger() -> EuAiActLogger {
        EuAiActLogger::new("0.1.0")
    }

    #[test]
    fn article12_log_action_records_entry() {
        let l = logger();
        l.log_action(EuAiActLogEntry::new(
            "agent1",
            "send_email",
            EuRiskClass::High,
            ComplianceOutcome::RequiredHumanApproval,
        ));
        assert_eq!(l.total_actions(), 1);
    }

    #[test]
    fn article14_log_oversight_records_record() {
        let l = logger();
        l.log_oversight(HumanOversightRecord::new(
            "alice",
            InterventionType::Approval,
            "agent1/send_email",
        ));
        assert_eq!(l.total_oversight_records(), 1);
    }

    #[test]
    fn article15_accuracy_metrics_accumulate() {
        let l = logger();
        l.record_correct_decision(true);
        l.record_correct_decision(false);
        l.record_false_positive();
        let acc = l.accuracy.lock().unwrap().clone();
        assert_eq!(acc.total_decisions, 3);
        assert_eq!(acc.correct_allows, 1);
        assert_eq!(acc.correct_denials, 1);
        assert_eq!(acc.false_positives, 1);
    }

    #[test]
    fn accuracy_metrics_precision_and_recall() {
        let mut m = AccuracyMetrics {
            total_decisions: 100,
            correct_allows: 70,
            correct_denials: 20,
            false_positives: 5,
            false_negatives: 5,
            human_overrides: 10,
        };
        // precision = TP/(TP+FP) = 20/(20+5) = 0.8
        let p = m.precision();
        assert!((p - 0.8).abs() < 0.001);
        // recall = TP/(TP+FN) = 20/(20+5) = 0.8
        let r = m.recall();
        assert!((r - 0.8).abs() < 0.001);
        // FPR = 5/100 = 0.05
        assert!((m.false_positive_rate() - 0.05).abs() < 0.001);
    }

    #[test]
    fn compliance_report_covers_period() {
        let l = logger();
        let now = Utc::now();
        let start = now - chrono::Duration::hours(1);

        l.log_action(
            EuAiActLogEntry::new("a1", "send_email", EuRiskClass::High, ComplianceOutcome::RequiredHumanApproval)
                .with_human_approval(true),
        );
        l.log_action(EuAiActLogEntry::new("a2", "search_web", EuRiskClass::Minimal, ComplianceOutcome::Allowed));
        l.log_oversight(HumanOversightRecord::new("alice", InterventionType::Approval, "a1/send_email"));

        let report = l.generate_report(start, now + chrono::Duration::hours(1));
        assert_eq!(report.total_logged_actions, 2);
        assert_eq!(report.human_interventions, 1);
        assert_eq!(report.human_approvals_obtained, 1);
        assert!(report.articles_addressed.contains(&"Article 12 (Automatic Logging)".to_string()));
    }

    #[test]
    fn log_entry_builder_chain() {
        let entry = EuAiActLogEntry::new("agent1", "run_shell", EuRiskClass::High, ComplianceOutcome::Denied)
            .with_risk_score(0.95)
            .with_human_approval(false)
            .with_evidence("merkle:abc123")
            .with_policy_version("1.2.0");

        assert_eq!(entry.risk_score, Some(0.95));
        assert!(!entry.human_approval_obtained);
        assert_eq!(entry.evidence_reference.unwrap(), "merkle:abc123");
        assert_eq!(entry.policy_version, "1.2.0");
    }

    #[test]
    fn oversight_record_with_justification() {
        let r = HumanOversightRecord::new("bob", InterventionType::KillSwitch, "all_agents")
            .with_justification("Suspected prompt injection attack detected");
        assert!(r.justification.is_some());
        assert_eq!(r.intervention, InterventionType::KillSwitch);
    }

    #[test]
    fn empty_log_produces_valid_report() {
        let l = logger();
        let now = Utc::now();
        let report = l.generate_report(now - chrono::Duration::hours(1), now);
        assert_eq!(report.total_logged_actions, 0);
        assert_eq!(report.human_interventions, 0);
        assert!(!report.articles_addressed.is_empty());
    }
}
