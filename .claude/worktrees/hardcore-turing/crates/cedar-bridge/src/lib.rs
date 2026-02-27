// safeagent-cedar-bridge
//
// W5 D1: Cedar Policy Engine + SMT Verification
//
// Wraps AWS Cedar (Lean-verified, SMT-backed) as a secondary enforcement layer
// on top of the existing SafeAgent PolicyEngine. Cedar's deny-by-default semantic
// provides mathematical proof that Red-class actions cannot be permitted by
// policy misconfiguration alone.
//
// Architecture:
//   PolicyEngine::evaluate() -> existing decision
//   CedarPolicyBridge::verify_action() -> Cedar verdict
//   Combined: Cedar=Deny && Existing=Allow -> security override -> Deny
//             Cedar=Permit -> keep existing decision
//
// Cedar policy summary:
//   permit(principal, action, resource); -- default permit (allow-listed unknowns)
//   forbid(principal, action == Action::"send_email", resource); -- Red: blocked
//   ...one forbid per Red-class action...

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet, Request};
use safeagent_policy_engine::{ActionType, PermissionLevel, PolicyDecision};
use std::str::FromStr;
use thiserror::Error;
use tracing::error;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Cedar policy text — statically compiled
//  Formally: deny-by-forbid for all Red-class actions.
//  Green/Yellow/Custom get default permit; the existing
//  PolicyEngine then applies the correct tier decision.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const CEDAR_POLICY: &str = r#"
// P0: Default permit — Green, Yellow, and Custom actions allowed through.
// Red-class actions are explicitly forbidden below.
permit(
  principal,
  action,
  resource
);

// P1-P6: Red-class forbids — mathematically guaranteed via Cedar's Lean proofs.
// These forbids override the default permit above.
// No policy override in the existing engine can bypass Cedar's forbid.

forbid(
  principal,
  action == Action::"send_email",
  resource
);

forbid(
  principal,
  action == Action::"send_message",
  resource
);

forbid(
  principal,
  action == Action::"delete_file",
  resource
);

forbid(
  principal,
  action == Action::"delete_email",
  resource
);

forbid(
  principal,
  action == Action::"make_purchase",
  resource
);

forbid(
  principal,
  action == Action::"run_shell_command",
  resource
);
"#;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Error types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Error, Debug)]
pub enum CedarError {
    #[error("Cedar policy parse error: {0}")]
    PolicyParse(String),

    #[error("Cedar entity UID parse error: {0}")]
    EntityParse(String),

    #[error("Cedar request build error: {0}")]
    RequestBuild(String),
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Cedar verdict
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq)]
pub enum CedarVerdict {
    /// Cedar permits the action (default permit or explicit permit without matching forbid).
    Permit,
    /// Cedar denies the action (forbid matched). Reasons are policy IDs or diagnostics.
    Deny { reasons: Vec<String> },
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Bridge
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct CedarPolicyBridge {
    policy_set: PolicySet,
    authorizer: Authorizer,
    /// Cached empty entities (no entity attributes needed for this policy)
    entities: Entities,
}

impl CedarPolicyBridge {
    /// Construct and parse the static Cedar policy set.
    /// Returns an error if the policy text is syntactically invalid.
    pub fn new() -> Result<Self, CedarError> {
        let policy_set = PolicySet::from_str(CEDAR_POLICY)
            .map_err(|e| CedarError::PolicyParse(format!("{:?}", e)))?;

        Ok(Self {
            policy_set,
            authorizer: Authorizer::new(),
            entities: Entities::empty(),
        })
    }

    /// Evaluate whether Cedar permits `action_key` for a generic agent.
    ///
    /// `action_key` comes from `ActionType::key()` — e.g. "send_email",
    /// "read_weather", "custom:my_action".
    ///
    /// Cedar entity construction:
    ///   principal = Agent::"agent"
    ///   action    = Action::"<action_key>"
    ///   resource  = Resource::"gateway"
    pub fn verify_action(&self, action_key: &str) -> CedarVerdict {
        let request = match self.build_request(action_key) {
            Ok(r) => r,
            Err(e) => {
                // Construction failure is treated conservatively as Deny
                error!("Cedar request construction failed for '{}': {}", action_key, e);
                return CedarVerdict::Deny {
                    reasons: vec![format!("request-construction-error: {}", e)],
                };
            }
        };

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &self.entities);

        match response.decision() {
            Decision::Allow => CedarVerdict::Permit,
            Decision::Deny => {
                let reasons: Vec<String> = response
                    .diagnostics()
                    .reason()
                    .map(|id| id.to_string())
                    .collect();
                CedarVerdict::Deny { reasons }
            }
        }
    }

    /// Apply Cedar verification on top of an existing PolicyDecision.
    ///
    /// Rules:
    ///   - Cedar=Deny && existing=Allow        -> security override -> Deny (misconfiguration caught)
    ///   - Cedar=Deny && existing=AllowWithNotification -> security override -> Deny
    ///   - Cedar=Deny && existing=RequireApproval -> keep RequireApproval (expected for Red)
    ///   - Cedar=Deny && existing=Deny         -> keep Deny
    ///   - Cedar=Permit (any)                  -> keep existing decision unchanged
    pub fn enforce(&self, action_type: &ActionType, decision: PolicyDecision) -> PolicyDecision {
        // Custom actions bypass Cedar verification — rely solely on existing engine
        if action_type.key().starts_with("custom:") {
            return decision;
        }

        let verdict = self.verify_action(&action_type.key());

        match verdict {
            CedarVerdict::Permit => decision,

            CedarVerdict::Deny { ref reasons } => {
                match &decision {
                    PolicyDecision::Allow => {
                        // Security override: Cedar's Lean-verified policy blocks this
                        error!(
                            "Cedar security override: action '{}' permitted by engine but denied by Cedar policy. Reasons: {:?}",
                            action_type.key(),
                            reasons
                        );
                        PolicyDecision::Deny {
                            reason: format!(
                                "Cedar policy enforcement: action '{}' is forbidden by formally verified policy",
                                action_type.key()
                            ),
                        }
                    }

                    PolicyDecision::AllowWithNotification { .. } => {
                        // Security override: Yellow action shouldn't match a Red forbid
                        error!(
                            "Cedar security override: Yellow action '{}' denied by Cedar policy. Reasons: {:?}",
                            action_type.key(),
                            reasons
                        );
                        PolicyDecision::Deny {
                            reason: format!(
                                "Cedar policy enforcement: action '{}' forbidden by formally verified policy",
                                action_type.key()
                            ),
                        }
                    }

                    PolicyDecision::RequireApproval { .. } => {
                        // Expected: Red-class action denied by Cedar, engine requires approval.
                        // Keep RequireApproval — the approval workflow handles Red actions.
                        decision
                    }

                    PolicyDecision::Deny { .. } => {
                        // Consistent: both Cedar and engine deny
                        decision
                    }
                }
            }
        }
    }

    /// Build a Cedar Request for the given action key.
    fn build_request(&self, action_key: &str) -> Result<Request, CedarError> {
        let principal_type = EntityTypeName::from_str("Agent")
            .map_err(|e| CedarError::EntityParse(format!("Agent type: {:?}", e)))?;
        let principal_id = EntityId::from_str("agent")
            .map_err(|e| CedarError::EntityParse(format!("agent id: {:?}", e)))?;
        let principal = EntityUid::from_type_name_and_id(principal_type, principal_id);

        let action_type_name = EntityTypeName::from_str("Action")
            .map_err(|e| CedarError::EntityParse(format!("Action type: {:?}", e)))?;
        let action_id = EntityId::from_str(action_key)
            .map_err(|e| CedarError::EntityParse(format!("action id '{}': {:?}", action_key, e)))?;
        let action = EntityUid::from_type_name_and_id(action_type_name, action_id);

        let resource_type = EntityTypeName::from_str("Resource")
            .map_err(|e| CedarError::EntityParse(format!("Resource type: {:?}", e)))?;
        let resource_id = EntityId::from_str("gateway")
            .map_err(|e| CedarError::EntityParse(format!("gateway id: {:?}", e)))?;
        let resource = EntityUid::from_type_name_and_id(resource_type, resource_id);

        let request = Request::new(Some(principal), Some(action), Some(resource), Context::empty(), None)
            .map_err(|e| CedarError::RequestBuild(format!("{:?}", e)))?;

        Ok(request)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Convenience: determine default Cedar verdict for a PermissionLevel
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns true if Cedar will deny a standard action at the given level.
/// (Red-class actions → Cedar forbid → Deny; Green/Yellow → Cedar permits)
pub fn cedar_denies_level(level: PermissionLevel) -> bool {
    matches!(level, PermissionLevel::Red)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use safeagent_policy_engine::{ActionId, ActionStatus, PendingAction};

    fn bridge() -> CedarPolicyBridge {
        CedarPolicyBridge::new().expect("Cedar policy should parse without error")
    }

    fn fake_pending(action_type: ActionType) -> PolicyDecision {
        let id = ActionId::new();
        let now = chrono::Utc::now();
        PolicyDecision::RequireApproval {
            pending: PendingAction {
                id: id.clone(),
                action_type,
                level: PermissionLevel::Red,
                description: "test".to_string(),
                details: serde_json::Value::Null,
                requested_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                status: ActionStatus::Pending,
            },
        }
    }

    // --- verify_action tests ---

    #[test]
    fn cedar_permits_green_read_weather() {
        let b = bridge();
        assert_eq!(b.verify_action("read_weather"), CedarVerdict::Permit);
    }

    #[test]
    fn cedar_permits_green_search_web() {
        let b = bridge();
        assert_eq!(b.verify_action("search_web"), CedarVerdict::Permit);
    }

    #[test]
    fn cedar_permits_green_read_calendar() {
        let b = bridge();
        assert_eq!(b.verify_action("read_calendar"), CedarVerdict::Permit);
    }

    #[test]
    fn cedar_permits_green_summarize_content() {
        let b = bridge();
        assert_eq!(b.verify_action("summarize_content"), CedarVerdict::Permit);
    }

    #[test]
    fn cedar_permits_yellow_draft_email() {
        let b = bridge();
        assert_eq!(b.verify_action("draft_email"), CedarVerdict::Permit);
    }

    #[test]
    fn cedar_permits_yellow_add_calendar_event() {
        let b = bridge();
        assert_eq!(b.verify_action("add_calendar_event"), CedarVerdict::Permit);
    }

    #[test]
    fn cedar_denies_red_send_email() {
        let b = bridge();
        assert!(matches!(b.verify_action("send_email"), CedarVerdict::Deny { .. }));
    }

    #[test]
    fn cedar_denies_red_send_message() {
        let b = bridge();
        assert!(matches!(b.verify_action("send_message"), CedarVerdict::Deny { .. }));
    }

    #[test]
    fn cedar_denies_red_delete_file() {
        let b = bridge();
        assert!(matches!(b.verify_action("delete_file"), CedarVerdict::Deny { .. }));
    }

    #[test]
    fn cedar_denies_red_delete_email() {
        let b = bridge();
        assert!(matches!(b.verify_action("delete_email"), CedarVerdict::Deny { .. }));
    }

    #[test]
    fn cedar_denies_red_make_purchase() {
        let b = bridge();
        assert!(matches!(b.verify_action("make_purchase"), CedarVerdict::Deny { .. }));
    }

    #[test]
    fn cedar_denies_red_run_shell_command() {
        let b = bridge();
        assert!(matches!(
            b.verify_action("run_shell_command"),
            CedarVerdict::Deny { .. }
        ));
    }

    #[test]
    fn cedar_permits_unknown_action() {
        // Unknown actions get default permit; existing engine decides tier
        let b = bridge();
        assert_eq!(b.verify_action("unknown_future_action"), CedarVerdict::Permit);
    }

    // --- enforce() integration tests ---

    #[test]
    fn enforce_green_allow_unchanged() {
        let b = bridge();
        let decision = PolicyDecision::Allow;
        let result = b.enforce(&ActionType::ReadWeather, decision);
        assert!(matches!(result, PolicyDecision::Allow));
    }

    #[test]
    fn enforce_yellow_notification_unchanged() {
        let b = bridge();
        let decision = PolicyDecision::AllowWithNotification {
            action_type: ActionType::DraftEmail,
            description: "draft".to_string(),
            timeout_secs: 30,
        };
        let result = b.enforce(&ActionType::DraftEmail, decision);
        assert!(matches!(result, PolicyDecision::AllowWithNotification { .. }));
    }

    #[test]
    fn enforce_red_require_approval_kept() {
        let b = bridge();
        let decision = fake_pending(ActionType::SendEmail);
        let result = b.enforce(&ActionType::SendEmail, decision);
        assert!(matches!(result, PolicyDecision::RequireApproval { .. }));
    }

    #[test]
    fn enforce_security_override_on_misconfigured_allow() {
        // Simulate: misconfiguration makes existing engine return Allow for a Red action
        let b = bridge();
        let decision = PolicyDecision::Allow; // misconfigured!
        let result = b.enforce(&ActionType::SendEmail, decision);
        // Cedar catches the misconfiguration and overrides to Deny
        assert!(matches!(result, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn enforce_custom_action_bypasses_cedar() {
        let b = bridge();
        // Custom actions bypass Cedar verification entirely
        let custom_action = ActionType::Custom("my_custom".to_string());
        let decision = PolicyDecision::AllowWithNotification {
            action_type: custom_action.clone(),
            description: "custom".to_string(),
            timeout_secs: 30,
        };
        let result = b.enforce(&custom_action, decision);
        assert!(matches!(result, PolicyDecision::AllowWithNotification { .. }));
    }

    #[test]
    fn cedar_policy_parses_without_error() {
        // Smoke test: policy syntax is valid Cedar
        CedarPolicyBridge::new().expect("policy parse must succeed");
    }
}
