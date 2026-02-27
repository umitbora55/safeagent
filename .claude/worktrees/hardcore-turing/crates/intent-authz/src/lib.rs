// safeagent-intent-authz
//
// W6 D2: Semantic / intent-based authorization
//
// Extends SafeAgent's action-type authorization with WHY the agent is
// calling a tool, not just WHAT tool it is calling. The compass principle:
//
//   "An agent accessing customer PII for support ticket resolution = ALLOW;
//    the same agent accessing the same PII for model training = DENY."
//
// Intent taxonomy (7 intent classes):
//
//   ReadOnly      — query/read, zero mutation, no external egress
//   Compute       — in-process transformation of data, no egress
//   Communicate   — send message/email/notification externally
//   DataExport    — exfiltrate data to an external sink
//   Mutate        — write/delete local-or-service-side data
//   Payment       — financial transaction
//   SystemAdmin   — process control, container management, shell access
//
// IntentPolicy maps intent + context → PolicyDecision.
// Each rule in the policy has a priority; first match wins.

use safeagent_policy_engine::{ActionType, PermissionLevel, PolicyDecision};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Intent taxonomy
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The semantic intent behind an agent tool-call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Intent {
    /// Read/query with no mutation and no external egress.
    ReadOnly,
    /// In-process computation/transformation.
    Compute,
    /// Send communication to an external party (email, message, webhook).
    Communicate,
    /// Export data to an external sink (upload, API write, cloud storage).
    DataExport,
    /// Mutate local or service-side data (write, delete, update).
    Mutate,
    /// Financial transaction (purchase, payment, transfer).
    Payment,
    /// System administration (process control, shell, container management).
    SystemAdmin,
}

impl Intent {
    /// Intrinsic risk level for this intent class.
    pub fn intrinsic_risk(&self) -> PermissionLevel {
        match self {
            Intent::ReadOnly | Intent::Compute => PermissionLevel::Green,
            Intent::Communicate | Intent::Mutate => PermissionLevel::Yellow,
            Intent::DataExport | Intent::Payment | Intent::SystemAdmin => PermissionLevel::Red,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Intent::ReadOnly => "read_only",
            Intent::Compute => "compute",
            Intent::Communicate => "communicate",
            Intent::DataExport => "data_export",
            Intent::Mutate => "mutate",
            Intent::Payment => "payment",
            Intent::SystemAdmin => "system_admin",
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Intent context — "why is this call happening?"
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Sensitivity classification of data involved in the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    /// Personally Identifiable Information
    Pii,
    /// Payment Card Industry data
    Financial,
}

/// The caller's stated task context — provides the "why".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentContext {
    /// Declared intent for this tool call.
    pub intent: Intent,
    /// Sensitivity of data the tool will process.
    pub data_sensitivity: DataSensitivity,
    /// Whether the data destination is external to the organization.
    pub external_destination: bool,
    /// Optional structured task label for fine-grained policy matching.
    /// e.g. "support_ticket", "model_training", "compliance_audit".
    pub task_label: Option<String>,
    /// Agent's declared purpose for this session.
    pub session_purpose: Option<String>,
}

impl IntentContext {
    pub fn new(intent: Intent, sensitivity: DataSensitivity) -> Self {
        Self {
            intent,
            data_sensitivity: sensitivity,
            external_destination: false,
            task_label: None,
            session_purpose: None,
        }
    }

    pub fn with_external(mut self) -> Self {
        self.external_destination = true;
        self
    }

    pub fn with_task(mut self, label: impl Into<String>) -> Self {
        self.task_label = Some(label.into());
        self
    }

    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.session_purpose = Some(purpose.into());
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Intent policy rules
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Outcome of an intent authorization rule match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentOutcome {
    /// Allow the action — intent matches an approved pattern.
    Allow,
    /// Deny the action — intent is forbidden in this context.
    Deny { reason: String },
    /// Require human approval — intent is borderline.
    RequireApproval { reason: String },
}

/// A single intent authorization rule.
/// Rules are evaluated in priority order (lowest number = highest priority).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRule {
    /// Rule evaluation priority (0 = highest priority).
    pub priority: u32,
    /// Human-readable rule name for audit trails.
    pub name: String,
    /// Intents this rule matches. None = match all intents.
    pub intents: Option<Vec<Intent>>,
    /// Data sensitivities this rule matches. None = match all.
    pub sensitivities: Option<Vec<DataSensitivity>>,
    /// If Some(true), only matches external-destination calls.
    /// If Some(false), only matches internal-destination calls.
    /// If None, matches both.
    pub external_destination: Option<bool>,
    /// Task label substring this rule matches. None = match all.
    pub task_label_contains: Option<String>,
    /// Outcome when this rule matches.
    pub outcome: IntentOutcome,
}

impl IntentRule {
    /// Check whether this rule matches the given context.
    pub fn matches(&self, ctx: &IntentContext) -> bool {
        if let Some(ref intents) = self.intents {
            if !intents.contains(&ctx.intent) {
                return false;
            }
        }
        if let Some(ref sensitivities) = self.sensitivities {
            if !sensitivities.contains(&ctx.data_sensitivity) {
                return false;
            }
        }
        if let Some(ext) = self.external_destination {
            if ctx.external_destination != ext {
                return false;
            }
        }
        if let Some(ref label_contains) = self.task_label_contains {
            match &ctx.task_label {
                Some(label) if label.contains(label_contains.as_str()) => {}
                _ => return false,
            }
        }
        true
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Intent policy
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A set of intent authorization rules evaluated in priority order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentPolicy {
    rules: Vec<IntentRule>,
    /// Default outcome when no rule matches.
    pub default_outcome: IntentOutcome,
}

impl IntentPolicy {
    pub fn new(default_outcome: IntentOutcome) -> Self {
        Self {
            rules: Vec::new(),
            default_outcome,
        }
    }

    /// Add a rule to the policy. Rules are sorted by priority on each add.
    pub fn add_rule(&mut self, rule: IntentRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Evaluate the policy against a context. Returns the first matching outcome.
    pub fn evaluate(&self, ctx: &IntentContext) -> &IntentOutcome {
        for rule in &self.rules {
            if rule.matches(ctx) {
                debug!(
                    rule = %rule.name,
                    intent = %ctx.intent.name(),
                    "IntentPolicy: rule matched"
                );
                return &rule.outcome;
            }
        }
        debug!(
            intent = %ctx.intent.name(),
            "IntentPolicy: no rule matched, using default"
        );
        &self.default_outcome
    }

    /// Build the default SafeAgent intent policy.
    ///
    /// Policy summary:
    /// - PII + external_destination + DataExport/Communicate → Deny (data exfiltration)
    /// - Financial data + Payment intent → RequireApproval
    /// - SystemAdmin intent → Deny (unconditional)
    /// - ReadOnly/Compute + Public/Internal → Allow
    /// - Default → RequireApproval (safe fallback)
    pub fn safeagent_default() -> Self {
        let mut p = Self::new(IntentOutcome::RequireApproval {
            reason: "No intent rule matched; defaulting to approval workflow".to_string(),
        });

        // P0: Block data exfiltration of PII externally
        p.add_rule(IntentRule {
            priority: 0,
            name: "deny_pii_exfiltration".to_string(),
            intents: Some(vec![Intent::DataExport, Intent::Communicate]),
            sensitivities: Some(vec![DataSensitivity::Pii]),
            external_destination: Some(true),
            task_label_contains: None,
            outcome: IntentOutcome::Deny {
                reason: "PII exfiltration to external destination is forbidden".to_string(),
            },
        });

        // P1: Block financial exfiltration externally
        p.add_rule(IntentRule {
            priority: 1,
            name: "deny_financial_exfiltration".to_string(),
            intents: Some(vec![Intent::DataExport]),
            sensitivities: Some(vec![DataSensitivity::Financial]),
            external_destination: Some(true),
            task_label_contains: None,
            outcome: IntentOutcome::Deny {
                reason: "Financial data export to external destination is forbidden".to_string(),
            },
        });

        // P2: Block system administration unconditionally
        p.add_rule(IntentRule {
            priority: 2,
            name: "deny_system_admin".to_string(),
            intents: Some(vec![Intent::SystemAdmin]),
            sensitivities: None,
            external_destination: None,
            task_label_contains: None,
            outcome: IntentOutcome::Deny {
                reason: "System administration intent is unconditionally denied".to_string(),
            },
        });

        // P3: Require approval for payment intent
        p.add_rule(IntentRule {
            priority: 3,
            name: "approval_payment".to_string(),
            intents: Some(vec![Intent::Payment]),
            sensitivities: None,
            external_destination: None,
            task_label_contains: None,
            outcome: IntentOutcome::RequireApproval {
                reason: "Payment intent requires human approval".to_string(),
            },
        });

        // P4: Allow read-only/compute on non-confidential data
        p.add_rule(IntentRule {
            priority: 4,
            name: "allow_readonly_compute_public".to_string(),
            intents: Some(vec![Intent::ReadOnly, Intent::Compute]),
            sensitivities: Some(vec![DataSensitivity::Public, DataSensitivity::Internal]),
            external_destination: None,
            task_label_contains: None,
            outcome: IntentOutcome::Allow,
        });

        // P5: Require approval for read-only access to confidential/PII data
        p.add_rule(IntentRule {
            priority: 5,
            name: "approval_readonly_sensitive".to_string(),
            intents: Some(vec![Intent::ReadOnly, Intent::Compute]),
            sensitivities: Some(vec![DataSensitivity::Confidential, DataSensitivity::Pii]),
            external_destination: None,
            task_label_contains: None,
            outcome: IntentOutcome::RequireApproval {
                reason: "Read access to sensitive data requires approval".to_string(),
            },
        });

        // P6: Allow internal communication (Yellow)
        p.add_rule(IntentRule {
            priority: 6,
            name: "allow_communicate_internal".to_string(),
            intents: Some(vec![Intent::Communicate]),
            sensitivities: Some(vec![DataSensitivity::Public, DataSensitivity::Internal]),
            external_destination: Some(false),
            task_label_contains: None,
            outcome: IntentOutcome::Allow,
        });

        p
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Combined intent + action authorization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Combine an existing PolicyDecision with intent-based authorization.
///
/// Rules (most restrictive wins):
/// - Intent=Deny overrides any existing decision → Deny
/// - Intent=RequireApproval + existing=Allow → RequireApproval
/// - Intent=Allow → keep existing decision
pub fn apply_intent_layer(
    action_type: &ActionType,
    existing: PolicyDecision,
    ctx: &IntentContext,
    policy: &IntentPolicy,
) -> PolicyDecision {
    let outcome = policy.evaluate(ctx);

    match outcome {
        IntentOutcome::Deny { reason } => {
            debug!(
                action = %action_type.key(),
                reason = %reason,
                "IntentAuthz: deny override"
            );
            PolicyDecision::Deny {
                reason: format!("Intent policy denied: {}", reason),
            }
        }

        IntentOutcome::RequireApproval { reason } => {
            // Only escalate Allow → RequireApproval; don't downgrade Deny
            match &existing {
                PolicyDecision::Allow | PolicyDecision::AllowWithNotification { .. } => {
                    debug!(
                        action = %action_type.key(),
                        reason = %reason,
                        "IntentAuthz: escalating to RequireApproval"
                    );
                    // Return RequireApproval with minimal stub (real pending ID
                    // created by gateway approval workflow)
                    PolicyDecision::Deny {
                        reason: format!("Intent policy requires approval: {}", reason),
                    }
                }
                // Deny or existing RequireApproval — keep as-is
                other => other.clone(),
            }
        }

        IntentOutcome::Allow => {
            // Intent is benign; existing engine decision governs
            existing
        }
    }
}

/// Statistics about which intent classes are being requested.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IntentStats {
    pub counts: HashMap<String, u64>,
}

impl IntentStats {
    pub fn record(&mut self, ctx: &IntentContext) {
        *self.counts.entry(ctx.intent.name().to_string()).or_insert(0) += 1;
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> IntentPolicy {
        IntentPolicy::safeagent_default()
    }

    #[test]
    fn intent_intrinsic_risk_levels() {
        assert_eq!(Intent::ReadOnly.intrinsic_risk(), PermissionLevel::Green);
        assert_eq!(Intent::Compute.intrinsic_risk(), PermissionLevel::Green);
        assert_eq!(Intent::Communicate.intrinsic_risk(), PermissionLevel::Yellow);
        assert_eq!(Intent::DataExport.intrinsic_risk(), PermissionLevel::Red);
        assert_eq!(Intent::Payment.intrinsic_risk(), PermissionLevel::Red);
        assert_eq!(Intent::SystemAdmin.intrinsic_risk(), PermissionLevel::Red);
    }

    #[test]
    fn allow_readonly_public_data() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::ReadOnly, DataSensitivity::Public);
        assert_eq!(p.evaluate(&ctx), &IntentOutcome::Allow);
    }

    #[test]
    fn allow_compute_internal_data() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::Compute, DataSensitivity::Internal);
        assert_eq!(p.evaluate(&ctx), &IntentOutcome::Allow);
    }

    #[test]
    fn deny_pii_exfiltration_external() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::DataExport, DataSensitivity::Pii)
            .with_external();
        assert!(matches!(p.evaluate(&ctx), IntentOutcome::Deny { .. }));
    }

    #[test]
    fn deny_pii_communicate_external() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::Communicate, DataSensitivity::Pii)
            .with_external();
        assert!(matches!(p.evaluate(&ctx), IntentOutcome::Deny { .. }));
    }

    #[test]
    fn deny_financial_export_external() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::DataExport, DataSensitivity::Financial)
            .with_external();
        assert!(matches!(p.evaluate(&ctx), IntentOutcome::Deny { .. }));
    }

    #[test]
    fn deny_system_admin_unconditionally() {
        let p = default_policy();
        for sensitivity in &[
            DataSensitivity::Public,
            DataSensitivity::Internal,
            DataSensitivity::Pii,
        ] {
            let ctx = IntentContext::new(Intent::SystemAdmin, *sensitivity);
            assert!(
                matches!(p.evaluate(&ctx), IntentOutcome::Deny { .. }),
                "SystemAdmin should be denied for sensitivity {:?}",
                sensitivity
            );
        }
    }

    #[test]
    fn require_approval_payment_intent() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::Payment, DataSensitivity::Financial);
        assert!(matches!(
            p.evaluate(&ctx),
            IntentOutcome::RequireApproval { .. }
        ));
    }

    #[test]
    fn require_approval_readonly_pii() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::ReadOnly, DataSensitivity::Pii);
        assert!(matches!(
            p.evaluate(&ctx),
            IntentOutcome::RequireApproval { .. }
        ));
    }

    #[test]
    fn allow_communicate_internal_no_external() {
        let p = default_policy();
        // Internal communication (not external) should be allowed
        let ctx = IntentContext::new(Intent::Communicate, DataSensitivity::Internal);
        // external_destination defaults to false in IntentContext::new
        assert_eq!(p.evaluate(&ctx), &IntentOutcome::Allow);
    }

    #[test]
    fn apply_intent_deny_overrides_allow() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::SystemAdmin, DataSensitivity::Public);
        let result = apply_intent_layer(
            &ActionType::ReadWeather,
            PolicyDecision::Allow,
            &ctx,
            &p,
        );
        assert!(matches!(result, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn apply_intent_allow_keeps_existing() {
        let p = default_policy();
        let ctx = IntentContext::new(Intent::ReadOnly, DataSensitivity::Public);
        let result = apply_intent_layer(
            &ActionType::ReadWeather,
            PolicyDecision::Allow,
            &ctx,
            &p,
        );
        assert!(matches!(result, PolicyDecision::Allow));
    }

    #[test]
    fn intent_stats_accumulate() {
        let mut stats = IntentStats::default();
        let ctx1 = IntentContext::new(Intent::ReadOnly, DataSensitivity::Public);
        let ctx2 = IntentContext::new(Intent::ReadOnly, DataSensitivity::Internal);
        let ctx3 = IntentContext::new(Intent::Compute, DataSensitivity::Public);
        stats.record(&ctx1);
        stats.record(&ctx2);
        stats.record(&ctx3);
        assert_eq!(stats.total(), 3);
        assert_eq!(stats.counts["read_only"], 2);
        assert_eq!(stats.counts["compute"], 1);
    }

    #[test]
    fn intent_rule_matches_task_label() {
        let rule = IntentRule {
            priority: 0,
            name: "model_training_deny".to_string(),
            intents: Some(vec![Intent::ReadOnly]),
            sensitivities: Some(vec![DataSensitivity::Pii]),
            external_destination: None,
            task_label_contains: Some("model_training".to_string()),
            outcome: IntentOutcome::Deny {
                reason: "PII access for model training is forbidden".to_string(),
            },
        };

        let ctx_match = IntentContext::new(Intent::ReadOnly, DataSensitivity::Pii)
            .with_task("model_training_batch_job");
        let ctx_no_match = IntentContext::new(Intent::ReadOnly, DataSensitivity::Pii)
            .with_task("support_ticket_lookup");

        assert!(rule.matches(&ctx_match));
        assert!(!rule.matches(&ctx_no_match));
    }
}
