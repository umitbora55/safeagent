use chrono::{DateTime, Utc};
use dashmap::DashMap;
use safeagent_bridge_common::UserId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::{info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Newtype IDs
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub String);

impl ActionId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Default for ActionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Permission Levels
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionLevel {
    Green,
    Yellow,
    Red,
}

impl PermissionLevel {
    pub fn emoji(&self) -> &'static str {
        match self {
            PermissionLevel::Green => "🟢",
            PermissionLevel::Yellow => "🟡",
            PermissionLevel::Red => "🔴",
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Action Types — stable key() for serialization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    // 🟢 Green defaults
    ReadCalendar,
    ReadWeather,
    SearchWeb,
    SummarizeContent,

    // 🟡 Yellow defaults
    DraftEmail,
    AddCalendarEvent,
    CreateReminder,
    ReadEmail,

    // 🔴 Red defaults
    SendEmail,
    SendMessage,
    DeleteFile,
    DeleteEmail,
    MakePurchase,
    RunShellCommand,

    Custom(String),
}

impl ActionType {
    /// Stable string key — never depends on Debug format
    pub fn key(&self) -> String {
        match self {
            ActionType::Custom(s) => format!("custom:{}", s),
            other => serde_json::to_value(other)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "unknown".to_string()),
        }
    }

    pub fn default_level(&self) -> PermissionLevel {
        match self {
            ActionType::ReadCalendar
            | ActionType::ReadWeather
            | ActionType::SearchWeb
            | ActionType::SummarizeContent => PermissionLevel::Green,

            ActionType::DraftEmail
            | ActionType::AddCalendarEvent
            | ActionType::CreateReminder
            | ActionType::ReadEmail => PermissionLevel::Yellow,

            ActionType::SendEmail
            | ActionType::SendMessage
            | ActionType::DeleteFile
            | ActionType::DeleteEmail
            | ActionType::MakePurchase
            | ActionType::RunShellCommand => PermissionLevel::Red,

            ActionType::Custom(_) => PermissionLevel::Yellow,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Pending Action
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: ActionId,
    pub action_type: ActionType,
    pub level: PermissionLevel,
    pub description: String,
    pub details: serde_json::Value,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ActionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Policy Decision — no hardcoded strings
//  Presentation layer formats the user message
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// 🟢 Execute immediately
    Allow,
    /// 🟡 Execute but notify — presentation layer formats the message
    AllowWithNotification {
        action_type: ActionType,
        description: String,
        timeout_secs: u64,
    },
    /// 🔴 Wait for user approval
    RequireApproval { pending: PendingAction },
    /// ⛔ Blocked
    Deny { reason: String },
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Audit Trail
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub action_id: ActionId,
    pub action_type: ActionType,
    pub decision: String,
    pub decided_at: DateTime<Utc>,
    pub decided_by: Option<UserId>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Policy Config
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Override levels by ActionType::key()
    pub action_overrides: HashMap<String, PermissionLevel>,
    pub yellow_timeout_secs: u64,
    /// Daily spend limit in microdollars ($1.00 = 1_000_000)
    pub daily_spend_limit_microdollars: Option<u64>,
    pub monthly_spend_limit_microdollars: Option<u64>,
    pub blocked_actions: Vec<ActionType>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            action_overrides: HashMap::new(),
            yellow_timeout_secs: 30,
            daily_spend_limit_microdollars: None,
            monthly_spend_limit_microdollars: None,
            blocked_actions: vec![],
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Policy Engine — fully thread-safe, all methods &self
//  Multiple bridge tasks can call evaluate() concurrently
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PolicyEngine {
    config: RwLock<PolicyConfig>,
    pending: DashMap<String, PendingAction>,
    /// Microdollars spent today ($1.50 = 1_500_000)
    daily_spend_microdollars: AtomicU64,
    monthly_spend_microdollars: AtomicU64,
    audit_log: DashMap<String, AuditEntry>,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config: RwLock::new(config),
            pending: DashMap::new(),
            daily_spend_microdollars: AtomicU64::new(0),
            monthly_spend_microdollars: AtomicU64::new(0),
            audit_log: DashMap::new(),
        }
    }

    /// Evaluate an action — thread-safe, takes &self
    pub fn evaluate(
        &self,
        action_type: &ActionType,
        description: &str,
        details: serde_json::Value,
    ) -> PolicyDecision {
        // Lazy cleanup on every evaluate
        self.lazy_expire();

        let config = self.config.read().unwrap();

        // 1. Blocked?
        if config.blocked_actions.contains(action_type) {
            let id = ActionId::new();
            self.record_audit(&id, action_type, "denied", None);
            return PolicyDecision::Deny {
                reason: format!("Action '{}' is blocked by policy", action_type.key()),
            };
        }

        // 2. Effective level (user override or default)
        let level = config
            .action_overrides
            .get(&action_type.key())
            .copied()
            .unwrap_or_else(|| action_type.default_level());

        // 3. Decide
        match level {
            PermissionLevel::Green => {
                let id = ActionId::new();
                self.record_audit(&id, action_type, "allowed", None);
                PolicyDecision::Allow
            }

            PermissionLevel::Yellow => {
                let id = ActionId::new();
                self.record_audit(&id, action_type, "allowed_with_notification", None);
                PolicyDecision::AllowWithNotification {
                    action_type: action_type.clone(),
                    description: description.to_string(),
                    timeout_secs: config.yellow_timeout_secs,
                }
            }

            PermissionLevel::Red => {
                let id = ActionId::new();
                let now = Utc::now();
                let pending = PendingAction {
                    id: id.clone(),
                    action_type: action_type.clone(),
                    level,
                    description: description.to_string(),
                    details,
                    requested_at: now,
                    expires_at: now + chrono::Duration::minutes(5),
                    status: ActionStatus::Pending,
                };
                self.pending.insert(id.0.clone(), pending.clone());
                self.record_audit(&id, action_type, "pending_approval", None);
                PolicyDecision::RequireApproval { pending }
            }
        }
    }

    /// Approve a pending action
    pub fn approve(
        &self,
        action_id: &ActionId,
        approved_by: Option<&UserId>,
    ) -> Option<PendingAction> {
        if let Some(mut entry) = self.pending.get_mut(&action_id.0) {
            entry.status = ActionStatus::Approved;
            let action = entry.clone();
            self.record_audit(action_id, &action.action_type, "approved", approved_by);
            info!("✅ Action approved: {}", action_id);
            Some(action)
        } else {
            None
        }
    }

    /// Reject a pending action
    pub fn reject(
        &self,
        action_id: &ActionId,
        rejected_by: Option<&UserId>,
    ) -> Option<PendingAction> {
        if let Some(mut entry) = self.pending.get_mut(&action_id.0) {
            entry.status = ActionStatus::Rejected;
            let action = entry.clone();
            self.record_audit(action_id, &action.action_type, "rejected", rejected_by);
            info!("❌ Action rejected: {}", action_id);
            Some(action)
        } else {
            None
        }
    }

    /// Record spend in microdollars. Returns false if limit exceeded.
    /// $1.50 = 1_500_000 microdollars
    pub fn record_spend(&self, microdollars: u64) -> bool {
        let new_daily = self
            .daily_spend_microdollars
            .fetch_add(microdollars, Ordering::Relaxed)
            + microdollars;
        let new_monthly = self
            .monthly_spend_microdollars
            .fetch_add(microdollars, Ordering::Relaxed)
            + microdollars;
        let config = self.config.read().unwrap();

        if let Some(limit) = config.daily_spend_limit_microdollars {
            if new_daily > limit {
                warn!(
                    "⚠️ Daily spend limit exceeded: ${:.2} / ${:.2}",
                    new_daily as f64 / 1_000_000.0,
                    limit as f64 / 1_000_000.0
                );
                return false;
            }
        }

        if let Some(limit) = config.monthly_spend_limit_microdollars {
            if new_monthly > limit {
                warn!(
                    "⚠️ Monthly spend limit exceeded: ${:.2} / ${:.2}",
                    new_monthly as f64 / 1_000_000.0,
                    limit as f64 / 1_000_000.0
                );
                return false;
            }
        }

        true
    }

    /// Current daily spend in microdollars
    pub fn daily_spend_microdollars(&self) -> u64 {
        self.daily_spend_microdollars.load(Ordering::Relaxed)
    }

    /// Reset daily spend (call at midnight)
    pub fn reset_daily_spend(&self) {
        self.daily_spend_microdollars.store(0, Ordering::Relaxed);
    }

    /// Current monthly spend in microdollars
    pub fn monthly_spend_microdollars(&self) -> u64 {
        self.monthly_spend_microdollars.load(Ordering::Relaxed)
    }

    /// Reset monthly spend (call at month start)
    pub fn reset_monthly_spend(&self) {
        self.monthly_spend_microdollars.store(0, Ordering::Relaxed);
    }

    /// Check if budget allows a request (without recording spend)
    pub fn check_budget(&self) -> Result<(), String> {
        let config = self.config.read().unwrap();
        let daily = self.daily_spend_microdollars.load(Ordering::Relaxed);
        let monthly = self.monthly_spend_microdollars.load(Ordering::Relaxed);

        if let Some(limit) = config.daily_spend_limit_microdollars {
            if daily >= limit {
                return Err(format!(
                    "Daily budget limit reached (${:.2} / ${:.2}). Resets at midnight UTC.",
                    daily as f64 / 1_000_000.0,
                    limit as f64 / 1_000_000.0
                ));
            }
        }
        if let Some(limit) = config.monthly_spend_limit_microdollars {
            if monthly >= limit {
                return Err(format!(
                    "Monthly budget limit reached (${:.2} / ${:.2}). Resets next month.",
                    monthly as f64 / 1_000_000.0,
                    limit as f64 / 1_000_000.0
                ));
            }
        }
        Ok(())
    }

    /// Get audit log entries (most recent first)
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        let mut entries: Vec<AuditEntry> =
            self.audit_log.iter().map(|e| e.value().clone()).collect();
        entries.sort_by(|a, b| b.decided_at.cmp(&a.decided_at));
        entries
    }

    /// Update config at runtime
    pub fn update_config(&self, config: PolicyConfig) {
        let mut current = self.config.write().unwrap();
        *current = config;
        info!("🔄 Policy config updated");
    }

    /// Lazy expiration — called on each evaluate
    fn lazy_expire(&self) {
        let now = Utc::now();
        let expired_ids: Vec<String> = self
            .pending
            .iter()
            .filter(|entry| {
                entry.value().status == ActionStatus::Pending && entry.value().expires_at < now
            })
            .map(|entry| entry.key().clone())
            .collect();

        for id in expired_ids {
            if let Some(mut entry) = self.pending.get_mut(&id) {
                entry.status = ActionStatus::Expired;
                let action_id = ActionId(id.clone());
                self.record_audit(&action_id, &entry.action_type, "expired", None);
                warn!("⏰ Action expired: {}", id);
            }
        }
    }

    fn record_audit(
        &self,
        action_id: &ActionId,
        action_type: &ActionType,
        decision: &str,
        decided_by: Option<&UserId>,
    ) {
        let entry = AuditEntry {
            action_id: action_id.clone(),
            action_type: action_type.clone(),
            decision: decision.to_string(),
            decided_at: Utc::now(),
            decided_by: decided_by.cloned(),
        };
        self.audit_log.insert(action_id.0.clone(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_green_auto_allows() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let decision = engine.evaluate(
            &ActionType::ReadWeather,
            "Check weather",
            serde_json::Value::Null,
        );
        assert!(matches!(decision, PolicyDecision::Allow));
    }

    #[test]
    fn test_yellow_notifies() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let decision = engine.evaluate(
            &ActionType::DraftEmail,
            "Draft email",
            serde_json::Value::Null,
        );
        assert!(matches!(
            decision,
            PolicyDecision::AllowWithNotification {
                timeout_secs: 30,
                ..
            }
        ));
    }

    #[test]
    fn test_red_requires_approval() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let decision = engine.evaluate(
            &ActionType::SendEmail,
            "Send email",
            serde_json::Value::Null,
        );
        assert!(matches!(decision, PolicyDecision::RequireApproval { .. }));
    }

    #[test]
    fn test_blocked_denied() {
        let config = PolicyConfig {
            blocked_actions: vec![ActionType::RunShellCommand],
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        let decision = engine.evaluate(
            &ActionType::RunShellCommand,
            "Run ls",
            serde_json::Value::Null,
        );
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn test_spend_limit_microdollars() {
        let config = PolicyConfig {
            daily_spend_limit_microdollars: Some(1_000_000), // $1.00
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.record_spend(500_000)); // $0.50 -> ok
        assert!(engine.record_spend(300_000)); // $0.80 -> ok
        assert!(!engine.record_spend(500_000)); // $1.30 -> exceeds
    }

    #[test]
    fn test_approve_pending() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        let decision = engine.evaluate(
            &ActionType::SendEmail,
            "Send email",
            serde_json::Value::Null,
        );

        if let PolicyDecision::RequireApproval { pending } = decision {
            let user = UserId("user1".to_string());
            let approved = engine.approve(&pending.id, Some(&user));
            assert!(approved.is_some());
            assert_eq!(approved.unwrap().status, ActionStatus::Approved);
        } else {
            panic!("Expected RequireApproval");
        }
    }

    #[test]
    fn test_audit_trail() {
        let engine = PolicyEngine::new(PolicyConfig::default());
        engine.evaluate(&ActionType::ReadWeather, "Weather", serde_json::Value::Null);
        engine.evaluate(&ActionType::SendEmail, "Email", serde_json::Value::Null);

        let entries = engine.audit_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_action_type_stable_key() {
        assert_eq!(ActionType::ReadWeather.key(), "read_weather");
        assert_eq!(ActionType::SendEmail.key(), "send_email");
        assert_eq!(
            ActionType::Custom("my_action".to_string()).key(),
            "custom:my_action"
        );
    }

    #[test]
    fn test_override_level() {
        let mut overrides = HashMap::new();
        overrides.insert("send_email".to_string(), PermissionLevel::Green);

        let config = PolicyConfig {
            action_overrides: overrides,
            ..Default::default()
        };
        let engine = PolicyEngine::new(config);
        let decision = engine.evaluate(
            &ActionType::SendEmail,
            "Send email",
            serde_json::Value::Null,
        );
        // Normally Red, but overridden to Green
        assert!(matches!(decision, PolicyDecision::Allow));
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let engine = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        let mut handles = vec![];

        for i in 0..10 {
            let engine = engine.clone();
            handles.push(std::thread::spawn(move || {
                engine.evaluate(
                    &ActionType::ReadWeather,
                    &format!("Weather check {}", i),
                    serde_json::Value::Null,
                );
                engine.record_spend(100_000);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(engine.daily_spend_microdollars(), 1_000_000);
        assert_eq!(engine.audit_entries().len(), 10);
    }
}
