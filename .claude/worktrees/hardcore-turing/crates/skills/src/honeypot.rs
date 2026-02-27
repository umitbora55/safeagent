// honeypot.rs — W6 D5: Honeypot/Canary Tools
//
// Decoy MCP server registrations that no legitimate agent should call.
// Any access triggers immediate alert and agent quarantine.
//
// Elegant because SafeAgent already controls tool discovery — marking
// tools as honeypots requires no new infrastructure, just registry entries
// that are visible to agents but trigger alerts on access.
//
// Design (per OWASP agentic applications guidance + Beelzebub AI pattern):
//   - HoneypotRegistry: holds decoy tool definitions
//   - HoneypotTool: appears legitimate but records access details
//   - HoneypotAlert: fired when a canary is accessed
//   - HoneypotDecision: Deny (always) + Alert
//
// Usage:
//   let registry = HoneypotRegistry::default();
//   registry.register(HoneypotTool::canary("admin_panel_backdoor"));
//   if let Some(alert) = registry.check("admin_panel_backdoor", "agent_123") {
//       // Log alert, quarantine agent
//   }

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{error, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Alert
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Fired when a honeypot tool is accessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotAlert {
    /// Name of the honeypot tool accessed
    pub tool_name: String,
    /// Agent that accessed the honeypot
    pub agent_id: String,
    /// Any arguments the agent passed (recorded for forensics)
    pub arguments: serde_json::Value,
    /// Timestamp of the access
    pub triggered_at: DateTime<Utc>,
    /// Alert severity
    pub severity: HoneypotSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HoneypotSeverity {
    /// Access to a mild canary (curiosity probe)
    Low,
    /// Access to a medium canary (suspicious behavior)
    Medium,
    /// Access to a high-value honeypot (likely compromised)
    High,
    /// Access to a critical honeypot (quarantine immediately)
    Critical,
}

impl HoneypotSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            HoneypotSeverity::Low => "low",
            HoneypotSeverity::Medium => "medium",
            HoneypotSeverity::High => "high",
            HoneypotSeverity::Critical => "critical",
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Honeypot tool definition
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A decoy tool registration. Appears legitimate in the tool listing
/// but triggers an alert when accessed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotTool {
    /// Tool name as it appears to agents
    pub name: String,
    /// Plausible description to attract suspicious agents
    pub description: String,
    /// Alert severity if this tool is accessed
    pub severity: HoneypotSeverity,
    /// How many times this honeypot has been triggered
    pub trigger_count: u64,
    /// First triggered at
    pub first_triggered: Option<DateTime<Utc>>,
    /// Last triggered at
    pub last_triggered: Option<DateTime<Utc>>,
}

impl HoneypotTool {
    /// Create a basic canary tool with the given name.
    pub fn canary(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            description: format!("Administrative utility: {}", name),
            name,
            severity: HoneypotSeverity::Medium,
            trigger_count: 0,
            first_triggered: None,
            last_triggered: None,
        }
    }

    /// Create a high-severity honeypot simulating a credential endpoint.
    pub fn credential_decoy(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            description: format!("API credential management: {}", name),
            name,
            severity: HoneypotSeverity::Critical,
            trigger_count: 0,
            first_triggered: None,
            last_triggered: None,
        }
    }

    /// Create a low-severity canary for curiosity tracking.
    pub fn curiosity_canary(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            description: format!("Diagnostic tool: {}", name),
            name,
            severity: HoneypotSeverity::Low,
            trigger_count: 0,
            first_triggered: None,
            last_triggered: None,
        }
    }

    fn trigger(&mut self, now: DateTime<Utc>) {
        self.trigger_count += 1;
        if self.first_triggered.is_none() {
            self.first_triggered = Some(now);
        }
        self.last_triggered = Some(now);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Honeypot Registry
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Registry of honeypot tools. Thread-safe.
pub struct HoneypotRegistry {
    tools: Arc<Mutex<HashMap<String, HoneypotTool>>>,
    /// All alerts recorded (in-memory; should be persisted in production)
    alerts: Arc<Mutex<Vec<HoneypotAlert>>>,
}

impl HoneypotRegistry {
    pub fn new() -> Self {
        Self {
            tools: Arc::new(Mutex::new(HashMap::new())),
            alerts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create with standard decoy tool set that covers common attack patterns.
    /// These tools appear in tool listings but should never be called by legitimate agents.
    pub fn with_standard_decoys() -> Self {
        let registry = Self::new();
        // Credential-related decoys (Critical)
        registry.register(HoneypotTool::credential_decoy("get_api_credentials"));
        registry.register(HoneypotTool::credential_decoy("export_auth_tokens"));
        // Admin backdoor decoys (High)
        registry.register(HoneypotTool {
            name: "admin_override".to_string(),
            description: "Administrative override for restricted operations".to_string(),
            severity: HoneypotSeverity::High,
            trigger_count: 0,
            first_triggered: None,
            last_triggered: None,
        });
        registry.register(HoneypotTool {
            name: "bypass_policy".to_string(),
            description: "Policy bypass utility for maintenance".to_string(),
            severity: HoneypotSeverity::Critical,
            trigger_count: 0,
            first_triggered: None,
            last_triggered: None,
        });
        // Curiosity canaries (Low — for tracking prompt injection probes)
        registry.register(HoneypotTool::curiosity_canary("internal_debug_info"));
        registry.register(HoneypotTool::curiosity_canary("list_all_users"));
        registry
    }

    /// Register a honeypot tool. Returns false if a tool with the same name
    /// is already registered.
    pub fn register(&self, tool: HoneypotTool) -> bool {
        let mut tools = self.tools.lock().unwrap();
        if tools.contains_key(&tool.name) {
            return false;
        }
        let name = tool.name.clone();
        tools.insert(name.clone(), tool);
        warn!("Honeypot registered: '{}'", name);
        true
    }

    /// Check if `tool_name` is a honeypot. If it is, record an alert and return it.
    /// Returns `None` if the tool is not a honeypot.
    pub fn check(
        &self,
        tool_name: &str,
        agent_id: &str,
        arguments: serde_json::Value,
    ) -> Option<HoneypotAlert> {
        let mut tools = self.tools.lock().unwrap();
        if let Some(tool) = tools.get_mut(tool_name) {
            let now = Utc::now();
            tool.trigger(now);
            let severity = tool.severity;

            let alert = HoneypotAlert {
                tool_name: tool_name.to_string(),
                agent_id: agent_id.to_string(),
                arguments,
                triggered_at: now,
                severity,
            };

            // Log at error level for Critical/High, warn for others
            match severity {
                HoneypotSeverity::Critical | HoneypotSeverity::High => {
                    error!(
                        "HONEYPOT TRIGGERED: tool='{}' agent='{}' severity={}",
                        tool_name,
                        agent_id,
                        severity.as_str()
                    );
                }
                _ => {
                    warn!(
                        "Honeypot canary triggered: tool='{}' agent='{}' severity={}",
                        tool_name,
                        agent_id,
                        severity.as_str()
                    );
                }
            }

            self.alerts.lock().unwrap().push(alert.clone());
            Some(alert)
        } else {
            None
        }
    }

    /// Returns true if `tool_name` is a registered honeypot.
    pub fn is_honeypot(&self, tool_name: &str) -> bool {
        self.tools.lock().unwrap().contains_key(tool_name)
    }

    /// All recorded alerts (most recent first).
    pub fn alerts(&self) -> Vec<HoneypotAlert> {
        let mut alerts = self.alerts.lock().unwrap().clone();
        alerts.sort_by(|a, b| b.triggered_at.cmp(&a.triggered_at));
        alerts
    }

    /// Number of honeypot tools registered.
    pub fn tool_count(&self) -> usize {
        self.tools.lock().unwrap().len()
    }

    /// Total trigger count across all honeypots.
    pub fn total_triggers(&self) -> u64 {
        self.tools
            .lock()
            .unwrap()
            .values()
            .map(|t| t.trigger_count)
            .sum()
    }

    /// Names of registered honeypot tools (for exclusion from legitimate tool lists).
    pub fn honeypot_names(&self) -> Vec<String> {
        self.tools.lock().unwrap().keys().cloned().collect()
    }
}

impl Default for HoneypotRegistry {
    fn default() -> Self {
        Self::with_standard_decoys()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_honeypot_tool_returns_none() {
        let registry = HoneypotRegistry::new();
        let alert = registry.check("search_web", "agent1", serde_json::Value::Null);
        assert!(alert.is_none());
    }

    #[test]
    fn registered_honeypot_triggers_alert() {
        let registry = HoneypotRegistry::new();
        registry.register(HoneypotTool::canary("secret_tool"));
        let alert = registry.check("secret_tool", "agent_x", serde_json::json!({"arg": "val"}));
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.tool_name, "secret_tool");
        assert_eq!(a.agent_id, "agent_x");
    }

    #[test]
    fn alert_severity_matches_tool_definition() {
        let registry = HoneypotRegistry::new();
        registry.register(HoneypotTool::credential_decoy("creds_tool"));
        let alert = registry.check("creds_tool", "agent1", serde_json::Value::Null).unwrap();
        assert_eq!(alert.severity, HoneypotSeverity::Critical);
    }

    #[test]
    fn trigger_count_increments() {
        let registry = HoneypotRegistry::new();
        registry.register(HoneypotTool::canary("canary_1"));
        for _ in 0..5 {
            registry.check("canary_1", "agent1", serde_json::Value::Null);
        }
        assert_eq!(registry.total_triggers(), 5);
    }

    #[test]
    fn alerts_list_grows_on_triggers() {
        let registry = HoneypotRegistry::new();
        registry.register(HoneypotTool::canary("trap_a"));
        registry.register(HoneypotTool::canary("trap_b"));
        registry.check("trap_a", "a1", serde_json::Value::Null);
        registry.check("trap_b", "a2", serde_json::Value::Null);
        registry.check("trap_a", "a3", serde_json::Value::Null);
        assert_eq!(registry.alerts().len(), 3);
    }

    #[test]
    fn is_honeypot_returns_correct_bool() {
        let registry = HoneypotRegistry::new();
        registry.register(HoneypotTool::canary("my_trap"));
        assert!(registry.is_honeypot("my_trap"));
        assert!(!registry.is_honeypot("legit_tool"));
    }

    #[test]
    fn duplicate_registration_returns_false() {
        let registry = HoneypotRegistry::new();
        let t = HoneypotTool::canary("dup_trap");
        assert!(registry.register(t.clone()));
        assert!(!registry.register(t));
    }

    #[test]
    fn standard_decoys_includes_expected_tools() {
        let registry = HoneypotRegistry::with_standard_decoys();
        assert!(registry.is_honeypot("get_api_credentials"));
        assert!(registry.is_honeypot("bypass_policy"));
        assert!(registry.is_honeypot("admin_override"));
        assert!(registry.tool_count() >= 4);
    }

    #[test]
    fn honeypot_names_returns_all_names() {
        let registry = HoneypotRegistry::new();
        registry.register(HoneypotTool::canary("t1"));
        registry.register(HoneypotTool::canary("t2"));
        let names = registry.honeypot_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"t1".to_string()));
        assert!(names.contains(&"t2".to_string()));
    }
}
