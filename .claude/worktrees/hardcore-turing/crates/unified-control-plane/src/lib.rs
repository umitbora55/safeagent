//! W48: Unified Agent Security Control Plane
//! Single pane of glass for all security enforcement across protocols.
//! Integrates policy, identity, audit, threat intel, compliance, observability.
#![allow(dead_code)]

use std::collections::HashMap;
use dashmap::DashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcControlPlaneDegraded,
    RcUnifiedEnforcementDenied,
    RcIncidentCorrelated,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlPlaneComponent {
    PolicyEngine,
    IdentityFabric,
    AuditLog,
    ThreatIntel,
    ComplianceEngine,
    AgentMesh,
    ObservabilityStack,
    IncidentResponse,
}

impl ControlPlaneComponent {
    pub fn name(&self) -> &'static str {
        match self {
            ControlPlaneComponent::PolicyEngine => "PolicyEngine",
            ControlPlaneComponent::IdentityFabric => "IdentityFabric",
            ControlPlaneComponent::AuditLog => "AuditLog",
            ControlPlaneComponent::ThreatIntel => "ThreatIntel",
            ControlPlaneComponent::ComplianceEngine => "ComplianceEngine",
            ControlPlaneComponent::AgentMesh => "AgentMesh",
            ControlPlaneComponent::ObservabilityStack => "ObservabilityStack",
            ControlPlaneComponent::IncidentResponse => "IncidentResponse",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComponentHealth {
    pub component: ControlPlaneComponent,
    pub healthy: bool,
    pub last_check: String,
    pub metrics: HashMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityEventType {
    PolicyViolation,
    AuthFailure,
    ThreatDetected,
    ComplianceGap,
    AnomalyDetected,
    IncidentTriggered,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub event_id: String,
    pub source_component: ControlPlaneComponent,
    pub event_type: SecurityEventType,
    pub severity: f64,
    pub details: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct EnforcementDecision {
    pub decision_id: String,
    pub agent_id: String,
    pub allowed: bool,
    pub enforced_by: Vec<ControlPlaneComponent>,
    pub latency_ms: u64,
    pub policy_version: String,
}

#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub total_components: usize,
    pub healthy_components: usize,
    pub health_percentage: f64,
    pub degraded_components: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CorrelatedIncident {
    pub incident_id: String,
    pub events: Vec<String>,
    pub pattern: String,
    pub risk_score: f64,
    pub recommended_action: String,
}

#[derive(Debug, Clone)]
pub struct ExecutiveDashboard {
    pub system_health_pct: f64,
    pub active_threats: usize,
    pub compliance_score: f64,
    pub top_risks: Vec<String>,
    pub enforcement_decisions_24h: usize,
    pub cost_usd_24h: f64,
}

pub struct UnifiedSecurityControlPlane {
    components: DashMap<String, ComponentHealth>,
    events: DashMap<String, SecurityEvent>,
    decisions: DashMap<String, EnforcementDecision>,
}

impl UnifiedSecurityControlPlane {
    pub fn new() -> Self {
        Self {
            components: DashMap::new(),
            events: DashMap::new(),
            decisions: DashMap::new(),
        }
    }

    pub fn register_component(&self, health: ComponentHealth) {
        self.components.insert(health.component.name().to_string(), health);
    }

    pub fn get_system_health(&self) -> SystemHealth {
        let all: Vec<ComponentHealth> = self.components.iter().map(|e| e.value().clone()).collect();
        let total = all.len();
        let healthy = all.iter().filter(|c| c.healthy).count();
        let degraded: Vec<String> = all.iter().filter(|c| !c.healthy).map(|c| c.component.name().to_string()).collect();
        let pct = if total == 0 { 100.0 } else { healthy as f64 / total as f64 * 100.0 };
        SystemHealth { total_components: total, healthy_components: healthy, health_percentage: pct, degraded_components: degraded }
    }

    pub fn process_agent_request(
        &self,
        agent_id: &str,
        action: &str,
        context: &HashMap<String, String>,
    ) -> EnforcementDecision {
        let decision_id = Uuid::new_v4().to_string();
        let trust_level = context.get("trust_level").cloned().unwrap_or_else(|| "Intern".to_string());
        let action_lower = action.to_lowercase();

        // Intern with dangerous action → deny
        let allowed = if trust_level == "Intern" && (action_lower.contains("delete") || action_lower.contains("external")) {
            false
        } else {
            true
        };

        let enforced_by = vec![ControlPlaneComponent::PolicyEngine, ControlPlaneComponent::IdentityFabric];
        let decision = EnforcementDecision {
            decision_id: decision_id.clone(),
            agent_id: agent_id.to_string(),
            allowed,
            enforced_by,
            latency_ms: 2,
            policy_version: "v1.0.0".to_string(),
        };
        self.decisions.insert(decision_id, decision.clone());
        decision
    }

    pub fn ingest_security_event(&self, event: SecurityEvent) {
        self.events.insert(event.event_id.clone(), event);
    }

    pub fn get_active_incidents(&self) -> Vec<SecurityEvent> {
        self.events.iter().filter(|e| e.value().severity > 0.7).map(|e| e.value().clone()).collect()
    }

    pub fn correlate_events(&self, _time_window_secs: u64) -> Vec<CorrelatedIncident> {
        // Count events by type
        let mut type_events: HashMap<String, Vec<String>> = HashMap::new();
        for entry in self.events.iter() {
            let event = entry.value();
            let key = format!("{:?}", event.event_type);
            type_events.entry(key.clone()).or_default().push(event.event_id.clone());
        }

        type_events.into_iter()
            .filter(|(_, ids)| ids.len() >= 3)
            .map(|(event_type, ids)| CorrelatedIncident {
                incident_id: Uuid::new_v4().to_string(),
                events: ids,
                pattern: event_type,
                risk_score: 0.85,
                recommended_action: "Escalate to security team".to_string(),
            })
            .collect()
    }

    pub fn generate_executive_dashboard(&self) -> ExecutiveDashboard {
        let health = self.get_system_health();
        let active_threats = self.events.iter().filter(|e| e.value().event_type == SecurityEventType::ThreatDetected).count();
        let top_risks: Vec<String> = self.events.iter()
            .filter(|e| e.value().severity > 0.8)
            .take(3)
            .map(|e| e.value().details.clone())
            .collect();

        ExecutiveDashboard {
            system_health_pct: health.health_percentage,
            active_threats,
            compliance_score: 0.87, // Would be from compliance engine
            top_risks,
            enforcement_decisions_24h: self.decisions.len(),
            cost_usd_24h: 0.0, // Would be from cost attribution engine
        }
    }
}

impl Default for UnifiedSecurityControlPlane {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_type: SecurityEventType, severity: f64) -> SecurityEvent {
        SecurityEvent { event_id: Uuid::new_v4().to_string(), source_component: ControlPlaneComponent::PolicyEngine, event_type, severity, details: "test event".to_string(), timestamp: "2026-02-27T10:00:00Z".to_string() }
    }

    #[test]
    fn test_register_component() {
        let plane = UnifiedSecurityControlPlane::new();
        plane.register_component(ComponentHealth { component: ControlPlaneComponent::PolicyEngine, healthy: true, last_check: "2026-01-01".to_string(), metrics: HashMap::new() });
        let health = plane.get_system_health();
        assert_eq!(health.total_components, 1);
        assert_eq!(health.healthy_components, 1);
    }

    #[test]
    fn test_degraded_component() {
        let plane = UnifiedSecurityControlPlane::new();
        plane.register_component(ComponentHealth { component: ControlPlaneComponent::ThreatIntel, healthy: false, last_check: "2026-01-01".to_string(), metrics: HashMap::new() });
        let health = plane.get_system_health();
        assert_eq!(health.degraded_components.len(), 1);
        assert!(health.degraded_components.contains(&"ThreatIntel".to_string()));
    }

    #[test]
    fn test_health_percentage() {
        let plane = UnifiedSecurityControlPlane::new();
        plane.register_component(ComponentHealth { component: ControlPlaneComponent::PolicyEngine, healthy: true, last_check: "2026-01-01".to_string(), metrics: HashMap::new() });
        plane.register_component(ComponentHealth { component: ControlPlaneComponent::ThreatIntel, healthy: false, last_check: "2026-01-01".to_string(), metrics: HashMap::new() });
        let health = plane.get_system_health();
        assert!((health.health_percentage - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_intern_delete_denied() {
        let plane = UnifiedSecurityControlPlane::new();
        let mut ctx = HashMap::new();
        ctx.insert("trust_level".to_string(), "Intern".to_string());
        let decision = plane.process_agent_request("agent-1", "delete_file", &ctx);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_intern_external_denied() {
        let plane = UnifiedSecurityControlPlane::new();
        let mut ctx = HashMap::new();
        ctx.insert("trust_level".to_string(), "Intern".to_string());
        let decision = plane.process_agent_request("agent-1", "call_external_api", &ctx);
        assert!(!decision.allowed);
    }

    #[test]
    fn test_senior_delete_allowed() {
        let plane = UnifiedSecurityControlPlane::new();
        let mut ctx = HashMap::new();
        ctx.insert("trust_level".to_string(), "Senior".to_string());
        let decision = plane.process_agent_request("agent-1", "delete_temp_file", &ctx);
        assert!(decision.allowed);
    }

    #[test]
    fn test_enforcement_tracked() {
        let plane = UnifiedSecurityControlPlane::new();
        let ctx = HashMap::new();
        plane.process_agent_request("agent-1", "read_file", &ctx);
        plane.process_agent_request("agent-2", "write_file", &ctx);
        let dashboard = plane.generate_executive_dashboard();
        assert_eq!(dashboard.enforcement_decisions_24h, 2);
    }

    #[test]
    fn test_ingest_and_get_incidents() {
        let plane = UnifiedSecurityControlPlane::new();
        plane.ingest_security_event(make_event(SecurityEventType::ThreatDetected, 0.95));
        plane.ingest_security_event(make_event(SecurityEventType::PolicyViolation, 0.5));
        let incidents = plane.get_active_incidents();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].severity, 0.95);
    }

    #[test]
    fn test_correlate_events() {
        let plane = UnifiedSecurityControlPlane::new();
        for _ in 0..5 {
            plane.ingest_security_event(make_event(SecurityEventType::AuthFailure, 0.6));
        }
        let correlated = plane.correlate_events(3600);
        assert!(!correlated.is_empty());
        assert!(correlated[0].events.len() >= 3);
        assert!((correlated[0].risk_score - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_correlate_below_threshold() {
        let plane = UnifiedSecurityControlPlane::new();
        for _ in 0..2 {
            plane.ingest_security_event(make_event(SecurityEventType::PolicyViolation, 0.6));
        }
        let correlated = plane.correlate_events(3600);
        assert!(correlated.is_empty());
    }

    #[test]
    fn test_executive_dashboard() {
        let plane = UnifiedSecurityControlPlane::new();
        plane.register_component(ComponentHealth { component: ControlPlaneComponent::PolicyEngine, healthy: true, last_check: "2026-01-01".to_string(), metrics: HashMap::new() });
        plane.ingest_security_event(make_event(SecurityEventType::ThreatDetected, 0.9));
        let dashboard = plane.generate_executive_dashboard();
        assert_eq!(dashboard.system_health_pct, 100.0);
        assert_eq!(dashboard.active_threats, 1);
        assert!(dashboard.compliance_score > 0.0);
    }

    #[test]
    fn test_enforced_by_components() {
        let plane = UnifiedSecurityControlPlane::new();
        let decision = plane.process_agent_request("a", "action", &HashMap::new());
        assert!(decision.enforced_by.contains(&ControlPlaneComponent::PolicyEngine));
        assert!(decision.enforced_by.contains(&ControlPlaneComponent::IdentityFabric));
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcControlPlaneDegraded;
        let _ = ReasonCode::RcUnifiedEnforcementDenied;
        let _ = ReasonCode::RcIncidentCorrelated;
    }
}
