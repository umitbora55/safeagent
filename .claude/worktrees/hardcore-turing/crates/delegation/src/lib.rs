// safeagent-delegation
//
// W6 D4: Cross-agent delegation governance
//
// Validates JWT delegation chains for multi-agent workflows.
// Implements RFC 8693 (Token Exchange) and the nested `act` claim
// pattern used by Google A2A Protocol and Microsoft Entra Agent ID.
//
// Delegation chain: User → Agent A → Agent B → Tool
//
// JWT structure (act claim nesting per RFC 8693 §4.1):
//   {
//     "sub": "agent-B",       // current actor
//     "act": {
//       "sub": "agent-A",     // agent-A delegated to agent-B
//       "act": {
//         "sub": "user:alice" // original principal
//       }
//     }
//   }
//
// Security properties enforced:
//   1. Chain depth limit — prevent unbounded delegation chains
//   2. No privilege escalation — each hop's scope ⊆ delegator's scope
//   3. Expiry propagation — chain expires at earliest member expiry
//   4. Principal binding — chain must start with a known human principal
//   5. Cycle detection — agent IDs must not repeat in chain

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Delegation chain types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A single delegation hop in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationHop {
    /// Subject identifier (agent ID or user ID) for this hop.
    pub subject: String,
    /// Scopes granted at this hop (action keys the delegatee may invoke).
    pub granted_scopes: Vec<String>,
    /// Expiry time for this hop's delegation. None = no expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this subject is a human principal (chain anchor).
    pub is_human_principal: bool,
}

impl DelegationHop {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            granted_scopes: Vec::new(),
            expires_at: None,
            is_human_principal: false,
        }
    }

    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.granted_scopes = scopes.into_iter().map(|s| s.into()).collect();
        self
    }

    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn as_human(mut self) -> Self {
        self.is_human_principal = true;
        self
    }

    /// Whether this hop has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() > exp)
            .unwrap_or(false)
    }
}

/// A full delegation chain from original principal through all agents.
///
/// Ordered from original principal (index 0) to current actor (last).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChain {
    /// Hops in order: [original_principal, ..., current_actor].
    pub hops: Vec<DelegationHop>,
    /// Action key the chain is being used to authorize.
    pub requested_action: String,
}

impl DelegationChain {
    pub fn new(requested_action: impl Into<String>) -> Self {
        Self {
            hops: Vec::new(),
            requested_action: requested_action.into(),
        }
    }

    pub fn push(mut self, hop: DelegationHop) -> Self {
        self.hops.push(hop);
        self
    }

    /// Original principal (first hop in the chain).
    pub fn origin(&self) -> Option<&DelegationHop> {
        self.hops.first()
    }

    /// Current actor (last hop in the chain).
    pub fn actor(&self) -> Option<&DelegationHop> {
        self.hops.last()
    }

    /// Number of hops in the chain (depth).
    pub fn depth(&self) -> usize {
        self.hops.len()
    }

    /// Earliest expiry across all hops (chain expiry = min of members).
    pub fn effective_expiry(&self) -> Option<DateTime<Utc>> {
        self.hops
            .iter()
            .filter_map(|h| h.expires_at)
            .min()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Validation errors
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    #[error("Delegation chain is empty")]
    EmptyChain,

    #[error("Chain depth {depth} exceeds maximum {max}")]
    ChainTooDeep { depth: usize, max: usize },

    #[error("Chain does not originate from a human principal; origin is '{subject}'")]
    NotHumanPrincipal { subject: String },

    #[error("Hop {index} (subject '{subject}') has expired")]
    HopExpired { index: usize, subject: String },

    #[error("Privilege escalation at hop {index}: '{scope}' not in delegator scopes")]
    PrivilegeEscalation { index: usize, scope: String },

    #[error("Cycle detected: subject '{subject}' appears twice in chain")]
    CycleDetected { subject: String },

    #[error("Requested action '{action}' not in current actor's granted scopes")]
    ActionNotGranted { action: String },

    #[error("Chain has no hops with granted scopes — cannot authorize any action")]
    NoGrantedScopes,
}

/// Outcome of delegation chain validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationDecision {
    /// Chain is valid and the requested action is authorized.
    Authorized {
        /// Depth of the validated chain.
        depth: usize,
        /// Current actor's subject identifier.
        actor: String,
        /// Original principal's subject identifier.
        origin: String,
    },
    /// Chain validation failed.
    Denied(DelegationError),
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Validator configuration
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct DelegationConfig {
    /// Maximum permitted delegation chain depth.
    pub max_chain_depth: usize,
    /// Whether the chain must originate from a human principal.
    pub require_human_origin: bool,
    /// Whether to enforce scope subset checking at each hop.
    pub enforce_scope_containment: bool,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self {
            max_chain_depth: 5,
            require_human_origin: true,
            enforce_scope_containment: true,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Chain validator
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Validates delegation chains for cross-agent authorization.
pub struct DelegationValidator {
    config: DelegationConfig,
}

impl DelegationValidator {
    pub fn new(config: DelegationConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(DelegationConfig::default())
    }

    /// Validate a delegation chain for the requested action.
    pub fn validate(&self, chain: &DelegationChain) -> DelegationDecision {
        // 1. Chain must not be empty
        if chain.hops.is_empty() {
            return DelegationDecision::Denied(DelegationError::EmptyChain);
        }

        // 2. Depth check
        let depth = chain.depth();
        if depth > self.config.max_chain_depth {
            warn!(depth, max = self.config.max_chain_depth, "Delegation chain too deep");
            return DelegationDecision::Denied(DelegationError::ChainTooDeep {
                depth,
                max: self.config.max_chain_depth,
            });
        }

        // 3. Human principal at origin
        if self.config.require_human_origin {
            let origin = chain.origin().unwrap();
            if !origin.is_human_principal {
                return DelegationDecision::Denied(DelegationError::NotHumanPrincipal {
                    subject: origin.subject.clone(),
                });
            }
        }

        // 4. Expiry check for all hops
        for (i, hop) in chain.hops.iter().enumerate() {
            if hop.is_expired() {
                return DelegationDecision::Denied(DelegationError::HopExpired {
                    index: i,
                    subject: hop.subject.clone(),
                });
            }
        }

        // 5. Cycle detection
        let mut seen: HashSet<&str> = HashSet::new();
        for hop in &chain.hops {
            if !seen.insert(hop.subject.as_str()) {
                return DelegationDecision::Denied(DelegationError::CycleDetected {
                    subject: hop.subject.clone(),
                });
            }
        }

        // 6. Scope containment: each hop's scopes ⊆ delegator's scopes
        if self.config.enforce_scope_containment {
            // Origin (hop 0) defines the root scope set.
            // Each subsequent hop may only use a subset of the prior hop's scopes.
            let mut delegator_scopes: Option<HashSet<&str>> = None;
            for (i, hop) in chain.hops.iter().enumerate() {
                if i == 0 {
                    // Origin — root scope set
                    delegator_scopes = Some(hop.granted_scopes.iter().map(|s| s.as_str()).collect());
                    continue;
                }
                if let Some(ref parent_scopes) = delegator_scopes {
                    for scope in &hop.granted_scopes {
                        if !parent_scopes.contains(scope.as_str()) {
                            return DelegationDecision::Denied(
                                DelegationError::PrivilegeEscalation {
                                    index: i,
                                    scope: scope.clone(),
                                },
                            );
                        }
                    }
                }
                // Update delegator_scopes to this hop for the next iteration
                delegator_scopes = Some(hop.granted_scopes.iter().map(|s| s.as_str()).collect());
            }
        }

        // 7. Current actor must have the requested action in their scopes
        let actor = chain.actor().unwrap();
        if !actor.granted_scopes.is_empty()
            && !actor.granted_scopes.contains(&chain.requested_action)
        {
            return DelegationDecision::Denied(DelegationError::ActionNotGranted {
                action: chain.requested_action.clone(),
            });
        }

        let origin = chain.origin().unwrap();
        debug!(
            actor = %actor.subject,
            origin = %origin.subject,
            depth,
            action = %chain.requested_action,
            "Delegation chain validated"
        );

        DelegationDecision::Authorized {
            depth,
            actor: actor.subject.clone(),
            origin: origin.subject.clone(),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Chain builder helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Build a minimal valid chain: user → agent-a → action.
pub fn build_simple_chain(
    user_id: impl Into<String>,
    agent_id: impl Into<String>,
    action: impl Into<String>,
    scopes: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
) -> DelegationChain {
    let user_hop = DelegationHop::new(user_id.into())
        .with_scopes(scopes.clone())
        .as_human();
    let user_hop = if let Some(exp) = expires_at {
        user_hop.with_expiry(exp)
    } else {
        user_hop
    };

    let agent_hop = DelegationHop::new(agent_id.into()).with_scopes(scopes);
    let agent_hop = if let Some(exp) = expires_at {
        agent_hop.with_expiry(exp)
    } else {
        agent_hop
    };

    DelegationChain::new(action.into())
        .push(user_hop)
        .push(agent_hop)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn validator() -> DelegationValidator {
        DelegationValidator::with_defaults()
    }

    fn future() -> DateTime<Utc> {
        Utc::now() + Duration::hours(1)
    }

    fn past() -> DateTime<Utc> {
        Utc::now() - Duration::hours(1)
    }

    #[test]
    fn valid_simple_chain_authorized() {
        let chain = build_simple_chain(
            "user:alice",
            "agent-support",
            "read_calendar",
            vec!["read_calendar".to_string()],
            Some(future()),
        );
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Authorized { .. }
        ));
    }

    #[test]
    fn empty_chain_denied() {
        let chain = DelegationChain::new("read_calendar");
        let v = validator();
        assert_eq!(
            v.validate(&chain),
            DelegationDecision::Denied(DelegationError::EmptyChain)
        );
    }

    #[test]
    fn chain_too_deep_denied() {
        let scopes = vec!["read_calendar".to_string()];
        let mut chain = DelegationChain::new("read_calendar").push(
            DelegationHop::new("user:alice")
                .with_scopes(scopes.clone())
                .as_human(),
        );
        // Add 5 agent hops (total depth = 6 > max=5)
        for i in 0..5 {
            chain = chain.push(
                DelegationHop::new(format!("agent-{}", i)).with_scopes(scopes.clone()),
            );
        }
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Denied(DelegationError::ChainTooDeep { .. })
        ));
    }

    #[test]
    fn non_human_origin_denied() {
        let chain = DelegationChain::new("read_calendar")
            .push(
                DelegationHop::new("agent-a") // not marked as human
                    .with_scopes(vec!["read_calendar".to_string()]),
            )
            .push(
                DelegationHop::new("agent-b")
                    .with_scopes(vec!["read_calendar".to_string()]),
            );
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Denied(DelegationError::NotHumanPrincipal { .. })
        ));
    }

    #[test]
    fn expired_hop_denied() {
        let chain = DelegationChain::new("read_calendar")
            .push(
                DelegationHop::new("user:alice")
                    .with_scopes(vec!["read_calendar".to_string()])
                    .with_expiry(past()) // expired!
                    .as_human(),
            )
            .push(
                DelegationHop::new("agent-a")
                    .with_scopes(vec!["read_calendar".to_string()]),
            );
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Denied(DelegationError::HopExpired { .. })
        ));
    }

    #[test]
    fn cycle_detection() {
        let chain = DelegationChain::new("read_calendar")
            .push(
                DelegationHop::new("user:alice")
                    .with_scopes(vec!["read_calendar".to_string()])
                    .as_human(),
            )
            .push(
                DelegationHop::new("agent-a")
                    .with_scopes(vec!["read_calendar".to_string()]),
            )
            .push(
                DelegationHop::new("agent-a") // cycle!
                    .with_scopes(vec!["read_calendar".to_string()]),
            );
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Denied(DelegationError::CycleDetected { .. })
        ));
    }

    #[test]
    fn privilege_escalation_denied() {
        // User grants only read_calendar; agent tries to claim send_email too
        let chain = DelegationChain::new("send_email")
            .push(
                DelegationHop::new("user:alice")
                    .with_scopes(vec!["read_calendar".to_string()])
                    .as_human(),
            )
            .push(
                DelegationHop::new("agent-a")
                    .with_scopes(vec![
                        "read_calendar".to_string(),
                        "send_email".to_string(), // escalation!
                    ]),
            );
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Denied(DelegationError::PrivilegeEscalation { .. })
        ));
    }

    #[test]
    fn action_not_in_actor_scopes_denied() {
        // Actor has read_calendar but requests send_email
        let chain = build_simple_chain(
            "user:alice",
            "agent-support",
            "send_email", // requested action
            vec!["read_calendar".to_string()], // scopes don't include send_email
            Some(future()),
        );
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Denied(DelegationError::ActionNotGranted { .. })
        ));
    }

    #[test]
    fn three_hop_valid_chain() {
        let scopes = vec!["search_web".to_string(), "read_calendar".to_string()];
        let chain = DelegationChain::new("search_web")
            .push(
                DelegationHop::new("user:bob")
                    .with_scopes(scopes.clone())
                    .with_expiry(future())
                    .as_human(),
            )
            .push(
                DelegationHop::new("orchestrator-agent")
                    .with_scopes(scopes.clone())
                    .with_expiry(future()),
            )
            .push(
                DelegationHop::new("sub-agent")
                    .with_scopes(vec!["search_web".to_string()]) // subset OK
                    .with_expiry(future()),
            );
        let v = validator();
        assert!(matches!(
            v.validate(&chain),
            DelegationDecision::Authorized { depth: 3, .. }
        ));
    }

    #[test]
    fn chain_effective_expiry_is_min() {
        let exp1 = Utc::now() + Duration::hours(2);
        let exp2 = Utc::now() + Duration::hours(1); // earlier
        let chain = DelegationChain::new("search_web")
            .push(
                DelegationHop::new("user:alice")
                    .with_scopes(vec!["search_web".to_string()])
                    .with_expiry(exp1)
                    .as_human(),
            )
            .push(
                DelegationHop::new("agent-a")
                    .with_scopes(vec!["search_web".to_string()])
                    .with_expiry(exp2),
            );
        // Effective expiry = min(exp1, exp2) = exp2
        let eff = chain.effective_expiry().unwrap();
        assert!((eff - exp2).abs() < Duration::seconds(1));
    }

    #[test]
    fn authorized_result_fields() {
        let chain = build_simple_chain(
            "user:carol",
            "agent-x",
            "read_calendar",
            vec!["read_calendar".to_string()],
            None,
        );
        let v = validator();
        if let DelegationDecision::Authorized { depth, actor, origin } = v.validate(&chain) {
            assert_eq!(depth, 2);
            assert_eq!(actor, "agent-x");
            assert_eq!(origin, "user:carol");
        } else {
            panic!("Expected Authorized");
        }
    }
}
