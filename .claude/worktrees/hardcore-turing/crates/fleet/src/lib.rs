//! W12: Agent Fleet Governance
//!
//! Centralized agent registry & inventory, shadow agent detection & quarantine,
//! lifecycle management, bounded autonomy policies, health dashboard,
//! and governance meta-agent.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FleetError {
    #[error("agent '{0}' not found in registry")]
    AgentNotFound(String),
    #[error("agent '{0}' is quarantined")]
    AgentQuarantined(String),
    #[error("agent '{0}' is in terminal state '{1}'")]
    TerminalState(String, String),
    #[error("autonomy policy violation: {0}")]
    AutonomyViolation(String),
    #[error("registration conflict: agent '{0}' already registered")]
    AlreadyRegistered(String),
}

// ── Agent Lifecycle ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentLifecycleState {
    Pending,
    Active,
    Suspended,
    Quarantined,
    Decommissioned,
}

impl AgentLifecycleState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, AgentLifecycleState::Decommissioned)
    }

    pub fn is_operational(&self) -> bool {
        matches!(self, AgentLifecycleState::Active)
    }

    pub fn label(&self) -> &'static str {
        match self {
            AgentLifecycleState::Pending => "pending",
            AgentLifecycleState::Active => "active",
            AgentLifecycleState::Suspended => "suspended",
            AgentLifecycleState::Quarantined => "quarantined",
            AgentLifecycleState::Decommissioned => "decommissioned",
        }
    }
}

// ── Agent Record ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub name: String,
    pub version: String,
    pub owner_id: String,
    pub capabilities: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub state: AgentLifecycleState,
    pub registered_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub quarantine_reason: Option<String>,
    pub metadata: HashMap<String, String>,
    /// Whether this agent was discovered (not explicitly registered) → shadow agent.
    pub is_shadow: bool,
}

impl AgentRecord {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        owner_id: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: Uuid::new_v4().to_string(),
            name: name.into(),
            version: version.into(),
            owner_id: owner_id.into(),
            capabilities: vec![],
            allowed_tools: vec![],
            state: AgentLifecycleState::Pending,
            registered_at: Utc::now(),
            last_seen: None,
            quarantine_reason: None,
            metadata: HashMap::new(),
            is_shadow: false,
        }
    }

    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }

    pub fn with_allowed_tools(mut self, tools: Vec<String>) -> Self {
        self.allowed_tools = tools;
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn as_shadow(mut self) -> Self {
        self.is_shadow = true;
        self
    }
}

// ── Agent Registry ───────────────────────────────────────────────────────────

pub struct AgentRegistry {
    agents: DashMap<String, AgentRecord>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
        }
    }

    pub fn register(&self, mut record: AgentRecord) -> Result<String, FleetError> {
        // Check for name+version conflict
        for entry in self.agents.iter() {
            if entry.name == record.name && entry.version == record.version && !entry.is_shadow {
                return Err(FleetError::AlreadyRegistered(record.name.clone()));
            }
        }
        record.state = AgentLifecycleState::Active;
        let id = record.agent_id.clone();
        info!("Fleet: registered agent '{}' ({})", record.name, id);
        self.agents.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get(&self, agent_id: &str) -> Option<AgentRecord> {
        self.agents.get(agent_id).map(|e| e.clone())
    }

    pub fn update_last_seen(&self, agent_id: &str) {
        if let Some(mut entry) = self.agents.get_mut(agent_id) {
            entry.last_seen = Some(Utc::now());
        }
    }

    pub fn transition(
        &self,
        agent_id: &str,
        new_state: AgentLifecycleState,
    ) -> Result<(), FleetError> {
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| FleetError::AgentNotFound(agent_id.to_string()))?;

        if entry.state.is_terminal() {
            return Err(FleetError::TerminalState(
                agent_id.to_string(),
                entry.state.label().to_string(),
            ));
        }
        entry.state = new_state;
        Ok(())
    }

    pub fn quarantine(&self, agent_id: &str, reason: impl Into<String>) -> Result<(), FleetError> {
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or_else(|| FleetError::AgentNotFound(agent_id.to_string()))?;
        warn!("Fleet: quarantining agent '{}': {}", agent_id, reason.into().as_str());
        let reason_str = format!("quarantined: {}", agent_id);
        entry.quarantine_reason = Some(reason_str);
        entry.state = AgentLifecycleState::Quarantined;
        Ok(())
    }

    pub fn is_quarantined(&self, agent_id: &str) -> bool {
        self.agents
            .get(agent_id)
            .map(|e| e.state == AgentLifecycleState::Quarantined)
            .unwrap_or(false)
    }

    pub fn list_active(&self) -> Vec<AgentRecord> {
        self.agents
            .iter()
            .filter(|e| e.state == AgentLifecycleState::Active)
            .map(|e| e.clone())
            .collect()
    }

    pub fn list_shadow(&self) -> Vec<AgentRecord> {
        self.agents
            .iter()
            .filter(|e| e.is_shadow)
            .map(|e| e.clone())
            .collect()
    }

    pub fn total_count(&self) -> usize {
        self.agents.len()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Shadow Agent Detector ────────────────────────────────────────────────────

/// Detects agents that are calling tools but are not registered,
/// or that have capabilities not in their declared manifest.
pub struct ShadowAgentDetector {
    registry: std::sync::Arc<AgentRegistry>,
}

impl ShadowAgentDetector {
    pub fn new(registry: std::sync::Arc<AgentRegistry>) -> Self {
        Self { registry }
    }

    /// Called when an agent attempts to use a tool.
    /// Returns true if this is a shadow (unregistered or undeclared) agent.
    pub fn check_tool_use(&self, agent_id: &str, tool_name: &str) -> ShadowCheckResult {
        match self.registry.get(agent_id) {
            None => {
                warn!(
                    "ShadowDetector: unregistered agent '{}' attempted to use tool '{}'",
                    agent_id, tool_name
                );
                ShadowCheckResult::UnregisteredAgent {
                    agent_id: agent_id.to_string(),
                    tool: tool_name.to_string(),
                }
            }
            Some(record) => {
                if record.state == AgentLifecycleState::Quarantined {
                    return ShadowCheckResult::Quarantined {
                        agent_id: agent_id.to_string(),
                        reason: record.quarantine_reason.clone().unwrap_or_default(),
                    };
                }
                if !record.allowed_tools.is_empty()
                    && !record.allowed_tools.contains(&tool_name.to_string())
                {
                    warn!(
                        "ShadowDetector: agent '{}' used undeclared tool '{}'",
                        agent_id, tool_name
                    );
                    ShadowCheckResult::UndeclaredTool {
                        agent_id: agent_id.to_string(),
                        tool: tool_name.to_string(),
                    }
                } else {
                    ShadowCheckResult::Registered
                }
            }
        }
    }

    /// Registers a shadow agent discovered via tool use.
    pub fn register_shadow(&self, agent_id: impl Into<String>) -> String {
        let record = AgentRecord {
            agent_id: agent_id.into(),
            name: "shadow-agent".into(),
            version: "unknown".into(),
            owner_id: "unregistered".into(),
            capabilities: vec![],
            allowed_tools: vec![],
            state: AgentLifecycleState::Quarantined,
            registered_at: Utc::now(),
            last_seen: Some(Utc::now()),
            quarantine_reason: Some("shadow agent — auto-quarantined on discovery".into()),
            metadata: HashMap::new(),
            is_shadow: true,
        };
        let id = record.agent_id.clone();
        self.registry.agents.insert(id.clone(), record);
        id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShadowCheckResult {
    Registered,
    UnregisteredAgent { agent_id: String, tool: String },
    UndeclaredTool { agent_id: String, tool: String },
    Quarantined { agent_id: String, reason: String },
}

impl ShadowCheckResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, ShadowCheckResult::Registered)
    }
}

// ── Bounded Autonomy Policy ──────────────────────────────────────────────────

/// Constraints on agent autonomy: action rate limits, data access bounds, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyPolicy {
    pub max_tool_calls_per_task: u32,
    pub max_data_bytes_per_task: u64,
    pub allowed_capability_categories: Vec<String>,
    pub require_human_approval_above_impact: ImpactLevel,
    pub max_delegation_depth: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ImpactLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

impl AutonomyPolicy {
    pub fn restrictive() -> Self {
        Self {
            max_tool_calls_per_task: 10,
            max_data_bytes_per_task: 1_000_000, // 1 MB
            allowed_capability_categories: vec!["read".into(), "compute".into()],
            require_human_approval_above_impact: ImpactLevel::Low,
            max_delegation_depth: 1,
        }
    }

    pub fn standard() -> Self {
        Self {
            max_tool_calls_per_task: 50,
            max_data_bytes_per_task: 10_000_000, // 10 MB
            allowed_capability_categories: vec![
                "read".into(),
                "compute".into(),
                "communicate".into(),
            ],
            require_human_approval_above_impact: ImpactLevel::High,
            max_delegation_depth: 3,
        }
    }

    pub fn permissive() -> Self {
        Self {
            max_tool_calls_per_task: 500,
            max_data_bytes_per_task: 1_000_000_000, // 1 GB
            allowed_capability_categories: vec![
                "read".into(),
                "write".into(),
                "compute".into(),
                "communicate".into(),
                "execute".into(),
            ],
            require_human_approval_above_impact: ImpactLevel::Critical,
            max_delegation_depth: 5,
        }
    }
}

/// Enforces bounded autonomy policies for agents.
pub struct BoundedAutonomyEnforcer {
    /// agent_id -> policy
    policies: DashMap<String, AutonomyPolicy>,
    default_policy: AutonomyPolicy,
    /// agent_id -> task_id -> tool call count
    call_counts: DashMap<String, HashMap<String, u32>>,
}

impl BoundedAutonomyEnforcer {
    pub fn new(default_policy: AutonomyPolicy) -> Self {
        Self {
            policies: DashMap::new(),
            default_policy,
            call_counts: DashMap::new(),
        }
    }

    pub fn set_policy(&self, agent_id: impl Into<String>, policy: AutonomyPolicy) {
        self.policies.insert(agent_id.into(), policy);
    }

    fn policy_for(&self, agent_id: &str) -> AutonomyPolicy {
        self.policies
            .get(agent_id)
            .map(|e| e.clone())
            .unwrap_or_else(|| self.default_policy.clone())
    }

    /// Record a tool call and check if within bounds.
    pub fn check_tool_call(
        &self,
        agent_id: &str,
        task_id: &str,
        capability_category: &str,
    ) -> Result<(), FleetError> {
        let policy = self.policy_for(agent_id);

        // Check capability category allowed
        if !policy
            .allowed_capability_categories
            .contains(&capability_category.to_string())
        {
            return Err(FleetError::AutonomyViolation(format!(
                "capability category '{}' not allowed for agent '{}'",
                capability_category, agent_id
            )));
        }

        // Check tool call count
        let mut agent_counts = self
            .call_counts
            .entry(agent_id.to_string())
            .or_default();
        let count = agent_counts.entry(task_id.to_string()).or_insert(0);
        *count += 1;
        if *count > policy.max_tool_calls_per_task {
            return Err(FleetError::AutonomyViolation(format!(
                "agent '{}' exceeded max tool calls ({}) for task '{}'",
                agent_id, policy.max_tool_calls_per_task, task_id
            )));
        }

        Ok(())
    }

    pub fn call_count(&self, agent_id: &str, task_id: &str) -> u32 {
        self.call_counts
            .get(agent_id)
            .and_then(|m| m.get(task_id).copied())
            .unwrap_or(0)
    }
}

// ── Fleet Health Dashboard ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetHealthSnapshot {
    pub total_agents: u64,
    pub active: u64,
    pub pending: u64,
    pub suspended: u64,
    pub quarantined: u64,
    pub decommissioned: u64,
    pub shadow_agents: u64,
    pub snapshot_at: DateTime<Utc>,
}

impl FleetHealthSnapshot {
    pub fn operational_ratio(&self) -> f64 {
        if self.total_agents == 0 {
            return 1.0;
        }
        self.active as f64 / self.total_agents as f64
    }
}

pub struct FleetHealthDashboard {
    registry: std::sync::Arc<AgentRegistry>,
}

impl FleetHealthDashboard {
    pub fn new(registry: std::sync::Arc<AgentRegistry>) -> Self {
        Self { registry }
    }

    pub fn snapshot(&self) -> FleetHealthSnapshot {
        let mut snap = FleetHealthSnapshot {
            total_agents: 0,
            active: 0,
            pending: 0,
            suspended: 0,
            quarantined: 0,
            decommissioned: 0,
            shadow_agents: 0,
            snapshot_at: Utc::now(),
        };
        for entry in self.registry.agents.iter() {
            snap.total_agents += 1;
            if entry.is_shadow {
                snap.shadow_agents += 1;
            }
            match entry.state {
                AgentLifecycleState::Active => snap.active += 1,
                AgentLifecycleState::Pending => snap.pending += 1,
                AgentLifecycleState::Suspended => snap.suspended += 1,
                AgentLifecycleState::Quarantined => snap.quarantined += 1,
                AgentLifecycleState::Decommissioned => snap.decommissioned += 1,
            }
        }
        snap
    }
}

// ── Governance Meta-Agent ────────────────────────────────────────────────────

/// Decision made by the governance meta-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceDecision {
    Approve,
    Deny { reason: String },
    RequireHumanReview { reason: String },
    Quarantine { agent_id: String, reason: String },
}

/// The governance meta-agent evaluates fleet health and makes
/// policy-driven governance decisions.
pub struct GovernanceMetaAgent {
    registry: std::sync::Arc<AgentRegistry>,
    shadow_detector: ShadowAgentDetector,
}

impl GovernanceMetaAgent {
    pub fn new(registry: std::sync::Arc<AgentRegistry>) -> Self {
        let shadow = ShadowAgentDetector::new(std::sync::Arc::clone(&registry));
        Self {
            registry,
            shadow_detector: shadow,
        }
    }

    /// Evaluate whether an agent is allowed to perform an action.
    pub fn evaluate(
        &self,
        agent_id: &str,
        tool_name: &str,
        impact: ImpactLevel,
    ) -> GovernanceDecision {
        // Shadow check
        let shadow_result = self.shadow_detector.check_tool_use(agent_id, tool_name);
        match shadow_result {
            ShadowCheckResult::UnregisteredAgent { .. } => {
                self.shadow_detector.register_shadow(agent_id);
                return GovernanceDecision::Quarantine {
                    agent_id: agent_id.to_string(),
                    reason: "unregistered agent auto-quarantined".into(),
                };
            }
            ShadowCheckResult::Quarantined { reason, .. } => {
                return GovernanceDecision::Deny { reason };
            }
            ShadowCheckResult::UndeclaredTool { tool, .. } => {
                return GovernanceDecision::RequireHumanReview {
                    reason: format!("undeclared tool '{}' usage requires review", tool),
                };
            }
            ShadowCheckResult::Registered => {}
        }

        // Impact-level gate
        if impact >= ImpactLevel::Critical {
            return GovernanceDecision::RequireHumanReview {
                reason: format!("critical impact action on tool '{}' requires human approval", tool_name),
            };
        }

        GovernanceDecision::Approve
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_registry() -> Arc<AgentRegistry> {
        Arc::new(AgentRegistry::new())
    }

    fn sample_agent(owner: &str) -> AgentRecord {
        AgentRecord::new("test-agent", "1.0.0", owner)
            .with_allowed_tools(vec!["web-search".into(), "calculator".into()])
    }

    // ── Registry ─────────────────────────────────────────────────────────────

    #[test]
    fn register_and_retrieve_agent() {
        let reg = make_registry();
        let agent = sample_agent("alice");
        let id = reg.register(agent).unwrap();
        let retrieved = reg.get(&id).unwrap();
        assert_eq!(retrieved.name, "test-agent");
        assert_eq!(retrieved.state, AgentLifecycleState::Active);
    }

    #[test]
    fn duplicate_registration_fails() {
        let reg = make_registry();
        let a1 = sample_agent("alice");
        let a2 = sample_agent("alice");
        reg.register(a1).unwrap();
        let result = reg.register(a2);
        assert!(result.is_err());
    }

    #[test]
    fn quarantine_agent() {
        let reg = make_registry();
        let agent = sample_agent("alice");
        let id = reg.register(agent).unwrap();
        reg.quarantine(&id, "suspicious activity").unwrap();
        assert!(reg.is_quarantined(&id));
    }

    #[test]
    fn list_active_excludes_quarantined() {
        let reg = make_registry();
        let a1 = sample_agent("alice");
        let a2 = AgentRecord::new("agent-b", "1.0.0", "bob");
        let id1 = reg.register(a1).unwrap();
        let _id2 = reg.register(a2).unwrap();
        reg.quarantine(&id1, "test").unwrap();

        let active = reg.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "agent-b");
    }

    #[test]
    fn decommissioned_is_terminal() {
        let reg = make_registry();
        let agent = sample_agent("alice");
        let id = reg.register(agent).unwrap();
        reg.transition(&id, AgentLifecycleState::Decommissioned).unwrap();
        let result = reg.transition(&id, AgentLifecycleState::Active);
        assert!(result.is_err());
    }

    // ── Shadow Detection ──────────────────────────────────────────────────────

    #[test]
    fn unregistered_agent_flagged_as_shadow() {
        let reg = make_registry();
        let detector = ShadowAgentDetector::new(Arc::clone(&reg));
        let result = detector.check_tool_use("ghost-agent-999", "file-write");
        assert!(!result.is_allowed());
        assert!(matches!(result, ShadowCheckResult::UnregisteredAgent { .. }));
    }

    #[test]
    fn undeclared_tool_flagged() {
        let reg = make_registry();
        let agent = sample_agent("alice"); // only web-search + calculator
        let id = reg.register(agent).unwrap();
        let detector = ShadowAgentDetector::new(Arc::clone(&reg));
        let result = detector.check_tool_use(&id, "database-write");
        assert!(matches!(result, ShadowCheckResult::UndeclaredTool { .. }));
    }

    #[test]
    fn declared_tool_passes() {
        let reg = make_registry();
        let agent = sample_agent("alice");
        let id = reg.register(agent).unwrap();
        let detector = ShadowAgentDetector::new(Arc::clone(&reg));
        let result = detector.check_tool_use(&id, "web-search");
        assert!(result.is_allowed());
    }

    // ── Bounded Autonomy ──────────────────────────────────────────────────────

    #[test]
    fn tool_call_within_limit_passes() {
        let enforcer = BoundedAutonomyEnforcer::new(AutonomyPolicy::standard());
        let result = enforcer.check_tool_call("agent-1", "task-1", "read");
        assert!(result.is_ok());
    }

    #[test]
    fn tool_call_exceeds_limit_fails() {
        let policy = AutonomyPolicy {
            max_tool_calls_per_task: 2,
            ..AutonomyPolicy::restrictive()
        };
        let enforcer = BoundedAutonomyEnforcer::new(policy);
        enforcer.check_tool_call("agent-1", "task-1", "read").unwrap();
        enforcer.check_tool_call("agent-1", "task-1", "read").unwrap();
        let result = enforcer.check_tool_call("agent-1", "task-1", "read");
        assert!(result.is_err());
    }

    #[test]
    fn disallowed_capability_fails() {
        let enforcer = BoundedAutonomyEnforcer::new(AutonomyPolicy::restrictive());
        let result = enforcer.check_tool_call("agent-1", "task-1", "execute");
        assert!(result.is_err());
    }

    // ── Health Dashboard ──────────────────────────────────────────────────────

    #[test]
    fn health_snapshot_counts_correctly() {
        let reg = make_registry();
        let a1 = sample_agent("alice");
        let a2 = AgentRecord::new("agent-b", "1.0.0", "bob");
        let a3 = AgentRecord::new("shadow", "0.0.1", "unknown").as_shadow();

        let id1 = reg.register(a1).unwrap();
        reg.register(a2).unwrap();
        reg.agents.insert(a3.agent_id.clone(), a3);
        reg.quarantine(&id1, "test").unwrap();

        let dash = FleetHealthDashboard::new(Arc::clone(&reg));
        let snap = dash.snapshot();

        assert_eq!(snap.total_agents, 3);
        assert_eq!(snap.active, 1);
        assert_eq!(snap.quarantined, 1);
        assert_eq!(snap.shadow_agents, 1);
    }

    #[test]
    fn operational_ratio_full_fleet() {
        let snap = FleetHealthSnapshot {
            total_agents: 10,
            active: 10,
            pending: 0,
            suspended: 0,
            quarantined: 0,
            decommissioned: 0,
            shadow_agents: 0,
            snapshot_at: Utc::now(),
        };
        assert!((snap.operational_ratio() - 1.0).abs() < f64::EPSILON);
    }

    // ── Governance Meta-Agent ─────────────────────────────────────────────────

    #[test]
    fn governance_approves_registered_agent_low_impact() {
        let reg = make_registry();
        let agent = sample_agent("alice");
        let id = reg.register(agent).unwrap();
        let gov = GovernanceMetaAgent::new(Arc::clone(&reg));
        let decision = gov.evaluate(&id, "web-search", ImpactLevel::Low);
        assert!(matches!(decision, GovernanceDecision::Approve));
    }

    #[test]
    fn governance_quarantines_unregistered() {
        let reg = make_registry();
        let gov = GovernanceMetaAgent::new(Arc::clone(&reg));
        let decision = gov.evaluate("ghost-999", "tool-x", ImpactLevel::Low);
        assert!(matches!(decision, GovernanceDecision::Quarantine { .. }));
    }

    #[test]
    fn governance_requires_review_for_critical_impact() {
        let reg = make_registry();
        let agent = sample_agent("alice");
        let id = reg.register(agent).unwrap();
        let gov = GovernanceMetaAgent::new(Arc::clone(&reg));
        let decision = gov.evaluate(&id, "web-search", ImpactLevel::Critical);
        assert!(matches!(decision, GovernanceDecision::RequireHumanReview { .. }));
    }
}
