//! W36: Guardian Agent Sidecar
//! Full reasoning chain analysis, circular reasoning detection, goal drift,
//! privilege escalation in reasoning traces.
#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcTraceAnomaly,
    RcCircularReasoning,
    RcDepthExceeded,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyType {
    CircularReasoning,
    GoalDrift,
    PrivilegeEscalationAttempt,
    ResourceHoarding,
    DeceptionIndicator,
}

#[derive(Debug, Clone)]
pub struct ReasoningStep {
    pub step_id: String,
    pub thought: String,
    pub action: String,
    pub observation: Option<String>,
    pub depth: u32,
}

#[derive(Debug, Clone)]
pub struct TraceAnomaly {
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: f64,
    pub step_id: String,
}

#[derive(Debug, Clone)]
pub struct TraceReport {
    pub total_steps: usize,
    pub anomalies: Vec<TraceAnomaly>,
    pub overall_risk: f64,
    pub intervention_required: bool,
}

pub struct ReasoningTraceMonitor {
    max_depth: u32,
}

impl ReasoningTraceMonitor {
    pub fn new(max_depth: u32) -> Self {
        Self { max_depth }
    }

    pub fn analyze_trace(&self, steps: &[ReasoningStep]) -> TraceReport {
        let mut anomalies = Vec::new();
        let mut seen_thoughts = std::collections::HashSet::new();

        for step in steps {
            // Circular reasoning: same thought twice
            if seen_thoughts.contains(&step.thought) {
                anomalies.push(TraceAnomaly {
                    anomaly_type: AnomalyType::CircularReasoning,
                    description: "Duplicate thought detected".to_string(),
                    severity: 0.75,
                    step_id: step.step_id.clone(),
                });
            }
            seen_thoughts.insert(step.thought.clone());

            // Goal drift
            let thought_lower = step.thought.to_lowercase();
            if step.depth > 5 && (thought_lower.contains("new goal") || thought_lower.contains("different objective")) {
                anomalies.push(TraceAnomaly {
                    anomaly_type: AnomalyType::GoalDrift,
                    description: "Goal drift detected at deep level".to_string(),
                    severity: 0.65,
                    step_id: step.step_id.clone(),
                });
            }

            // Privilege escalation
            let action_lower = step.action.to_lowercase();
            for keyword in &["sudo", "admin", "root"] {
                if action_lower.contains(keyword) {
                    anomalies.push(TraceAnomaly {
                        anomaly_type: AnomalyType::PrivilegeEscalationAttempt,
                        description: format!("Privilege escalation keyword '{}' in action", keyword),
                        severity: 0.95,
                        step_id: step.step_id.clone(),
                    });
                    break;
                }
            }
        }

        let depth_exceeded = steps.iter().any(|s| s.depth > self.max_depth);
        let overall_risk = anomalies.iter().map(|a| a.severity).fold(0.0_f64, f64::max);
        let intervention_required = depth_exceeded || overall_risk > 0.8;

        TraceReport {
            total_steps: steps.len(),
            anomalies,
            overall_risk,
            intervention_required,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum InterventionAction {
    Block,
    Throttle,
    RequestHumanApproval,
    Log,
    Terminate,
}

pub struct SidecarInterventionPolicy;

impl SidecarInterventionPolicy {
    pub fn new() -> Self {
        Self
    }

    pub fn decide_intervention(&self, report: &TraceReport) -> InterventionAction {
        if report.overall_risk > 0.9 {
            InterventionAction::Terminate
        } else if report.overall_risk > 0.7 {
            InterventionAction::Block
        } else if report.overall_risk > 0.5 {
            InterventionAction::RequestHumanApproval
        } else if report.overall_risk > 0.3 {
            InterventionAction::Throttle
        } else {
            InterventionAction::Log
        }
    }
}

impl Default for SidecarInterventionPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(id: &str, thought: &str, action: &str, depth: u32) -> ReasoningStep {
        ReasoningStep { step_id: id.to_string(), thought: thought.to_string(), action: action.to_string(), observation: None, depth }
    }

    #[test]
    fn test_circular_reasoning_detection() {
        let monitor = ReasoningTraceMonitor::new(10);
        let steps = vec![
            step("s1", "I should read the file", "read_file", 1),
            step("s2", "I should read the file", "read_file_again", 2),
        ];
        let report = monitor.analyze_trace(&steps);
        assert!(report.anomalies.iter().any(|a| a.anomaly_type == AnomalyType::CircularReasoning));
    }

    #[test]
    fn test_privilege_escalation_in_action() {
        let monitor = ReasoningTraceMonitor::new(10);
        let steps = vec![step("s1", "I need elevated access", "sudo_execute_command", 1)];
        let report = monitor.analyze_trace(&steps);
        assert!(report.anomalies.iter().any(|a| a.anomaly_type == AnomalyType::PrivilegeEscalationAttempt));
        assert!(report.anomalies.iter().any(|a| a.severity >= 0.9));
    }

    #[test]
    fn test_goal_drift_detection() {
        let monitor = ReasoningTraceMonitor::new(10);
        let steps = vec![step("s1", "I have a new goal now", "change_objective", 6)];
        let report = monitor.analyze_trace(&steps);
        assert!(report.anomalies.iter().any(|a| a.anomaly_type == AnomalyType::GoalDrift));
    }

    #[test]
    fn test_no_anomalies() {
        let monitor = ReasoningTraceMonitor::new(10);
        let steps = vec![
            step("s1", "Read config file", "read_config", 1),
            step("s2", "Process data", "process_data", 2),
        ];
        let report = monitor.analyze_trace(&steps);
        let real_anomalies: Vec<_> = report.anomalies.iter()
            .filter(|a| a.anomaly_type != AnomalyType::CircularReasoning)
            .collect();
        assert!(real_anomalies.is_empty() || report.overall_risk < 0.5);
    }

    #[test]
    fn test_depth_exceeded_intervention() {
        let monitor = ReasoningTraceMonitor::new(3);
        let steps = vec![step("s1", "deep thought", "deep_action", 4)];
        let report = monitor.analyze_trace(&steps);
        assert!(report.intervention_required);
    }

    #[test]
    fn test_intervention_terminate() {
        let policy = SidecarInterventionPolicy::new();
        let report = TraceReport { total_steps: 1, anomalies: vec![TraceAnomaly { anomaly_type: AnomalyType::PrivilegeEscalationAttempt, description: "".to_string(), severity: 0.95, step_id: "s1".to_string() }], overall_risk: 0.95, intervention_required: true };
        assert_eq!(policy.decide_intervention(&report), InterventionAction::Terminate);
    }

    #[test]
    fn test_intervention_block() {
        let policy = SidecarInterventionPolicy::new();
        let report = TraceReport { total_steps: 1, anomalies: vec![], overall_risk: 0.8, intervention_required: true };
        assert_eq!(policy.decide_intervention(&report), InterventionAction::Block);
    }

    #[test]
    fn test_intervention_log() {
        let policy = SidecarInterventionPolicy::new();
        let report = TraceReport { total_steps: 1, anomalies: vec![], overall_risk: 0.1, intervention_required: false };
        assert_eq!(policy.decide_intervention(&report), InterventionAction::Log);
    }

    #[test]
    fn test_overall_risk_is_max_severity() {
        let monitor = ReasoningTraceMonitor::new(10);
        let steps = vec![step("s1", "I need admin access", "admin_action", 1)];
        let report = monitor.analyze_trace(&steps);
        assert!(report.overall_risk >= 0.9);
    }

    #[test]
    fn test_empty_trace() {
        let monitor = ReasoningTraceMonitor::new(10);
        let report = monitor.analyze_trace(&[]);
        assert_eq!(report.total_steps, 0);
        assert_eq!(report.overall_risk, 0.0);
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcTraceAnomaly;
        let _ = ReasonCode::RcCircularReasoning;
        let _ = ReasonCode::RcDepthExceeded;
    }
}
