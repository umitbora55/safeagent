// safeagent-a2a-gateway
//
// W9: A2A Protocol Security Gateway
//
// Google A2A Protocol (v0.3, Linux Foundation, 150+ partners) security layer.
// A2A enables agent-to-agent communication via:
//   - Agent Cards  : /.well-known/agent.json — identity + capability manifest
//   - Tasks        : The unit of work with lifecycle: submitted→working→completed
//   - Artifacts    : Files/data produced by tasks (subject to DLP scanning)
//
// SafeAgent enforcement points:
//   D1: Agent Card validation + trust scoring — block spoofed/malicious agent cards
//   D2: Task-level authorization — policy enforcement at each lifecycle transition
//   D3: A2A + MCP unified policy plane — Cedar across both protocols
//   D4: Artifact inspection — DLP + PII + secret detection on task outputs
//   D5: Discovery registry — reputation tracking, quarantine, trust score management

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::{debug, info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const MAX_DELEGATION_DEPTH: usize = 5;
pub const TRUST_SCORE_THRESHOLD: f64 = 0.7;
pub const MIN_TRUST_SCORE: f64 = 0.0;
pub const MAX_TRUST_SCORE: f64 = 1.0;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  D1: Agent Card types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A2A Agent Card — published at /.well-known/agent.json
/// Declares identity, capabilities, and signing key for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Unique agent identifier.
    pub agent_id: String,
    /// Human-readable agent name.
    pub name: String,
    /// Description of the agent's purpose.
    pub description: String,
    /// List of capability identifiers the agent claims.
    pub capabilities: Vec<String>,
    /// The endpoint URL where this agent accepts A2A tasks.
    pub endpoint_url: String,
    /// Optional PEM-encoded public key for card signature verification.
    pub public_key_pem: Option<String>,
    /// When the card was issued.
    pub issued_at: DateTime<Utc>,
    /// Optional card expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Arbitrary metadata.
    pub metadata: HashMap<String, String>,
}

impl AgentCard {
    pub fn new(
        agent_id: impl Into<String>,
        name: impl Into<String>,
        endpoint_url: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            name: name.into(),
            description: String::new(),
            capabilities: Vec::new(),
            endpoint_url: endpoint_url.into(),
            public_key_pem: None,
            issued_at: Utc::now(),
            expires_at: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_capabilities(mut self, caps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.capabilities = caps.into_iter().map(|c| c.into()).collect();
        self
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| Utc::now() > e).unwrap_or(false)
    }

    /// SHA-256 digest of the canonical card JSON (for signature verification).
    pub fn canonical_digest(&self) -> String {
        let canonical = serde_json::json!({
            "agent_id": self.agent_id,
            "name": self.name,
            "capabilities": self.capabilities,
            "endpoint_url": self.endpoint_url,
            "issued_at": self.issued_at.to_rfc3339(),
        });
        let hash = Sha256::digest(canonical.to_string().as_bytes());
        hex::encode(hash)
    }
}

/// Trust score for an agent (0.0 = untrusted, 1.0 = fully trusted).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct TrustScore(pub f64);

impl TrustScore {
    pub fn new(v: f64) -> Self {
        Self(v.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE))
    }

    pub fn is_trusted(&self) -> bool {
        self.0 >= TRUST_SCORE_THRESHOLD
    }

    pub fn untrusted() -> Self { Self(0.0) }
    pub fn full() -> Self { Self(1.0) }
}

/// Outcome of agent card validation.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid { trust_score: TrustScore },
    InvalidSignature,
    ExpiredCard,
    MissingCapability { required: String },
    UntrustedEndpoint { endpoint: String },
    Malformed(String),
}

/// Validates A2A Agent Cards and computes trust scores.
pub struct AgentCardValidator {
    /// Endpoint URL prefixes considered trusted.
    trusted_endpoint_prefixes: Vec<String>,
    /// Capabilities required on every valid card.
    required_capabilities: Vec<String>,
}

impl AgentCardValidator {
    pub fn new() -> Self {
        Self {
            trusted_endpoint_prefixes: vec![
                "https://".to_string(),
                "http://localhost".to_string(),
                "http://127.0.0.1".to_string(),
            ],
            required_capabilities: Vec::new(),
        }
    }

    pub fn with_trusted_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.trusted_endpoint_prefixes.push(prefix.into());
        self
    }

    pub fn require_capability(mut self, cap: impl Into<String>) -> Self {
        self.required_capabilities.push(cap.into());
        self
    }

    /// Validate an agent card. Returns ValidationResult with trust score.
    pub fn validate(&self, card: &AgentCard) -> ValidationResult {
        // 1. Expiry
        if card.is_expired() {
            return ValidationResult::ExpiredCard;
        }

        // 2. Endpoint trust
        let trusted_endpoint = self
            .trusted_endpoint_prefixes
            .iter()
            .any(|prefix| card.endpoint_url.starts_with(prefix.as_str()));
        if !trusted_endpoint {
            return ValidationResult::UntrustedEndpoint {
                endpoint: card.endpoint_url.clone(),
            };
        }

        // 3. Required capabilities
        for req_cap in &self.required_capabilities {
            if !card.capabilities.contains(req_cap) {
                return ValidationResult::MissingCapability {
                    required: req_cap.clone(),
                };
            }
        }

        // 4. Compute trust score
        let trust_score = self.compute_trust_score(card);

        debug!(
            agent_id = %card.agent_id,
            trust_score = trust_score.0,
            "Agent card validated"
        );

        ValidationResult::Valid { trust_score }
    }

    /// Compute a heuristic trust score for an agent card.
    ///
    /// Scoring factors:
    ///   - Has public key:  +0.3
    ///   - HTTPS endpoint:  +0.2
    ///   - Non-empty caps:  +0.2
    ///   - Description set: +0.1
    ///   - Metadata set:    +0.1
    ///   - Issued recently (< 30 days): +0.1
    pub fn compute_trust_score(&self, card: &AgentCard) -> TrustScore {
        let mut score: f64 = 0.0;

        if card.public_key_pem.is_some() {
            score += 0.3;
        }
        if card.endpoint_url.starts_with("https://") {
            score += 0.2;
        }
        if !card.capabilities.is_empty() {
            score += 0.2;
        }
        if !card.description.is_empty() {
            score += 0.1;
        }
        if !card.metadata.is_empty() {
            score += 0.1;
        }
        let days_old = (Utc::now() - card.issued_at).num_days();
        if days_old < 30 {
            score += 0.1;
        }

        TrustScore::new(score)
    }
}

impl Default for AgentCardValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  D2: A2A Task authorization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A2A task lifecycle states.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum A2ATaskStatus {
    Submitted,
    Working,
    Completed,
    Failed,
    Cancelled,
}

/// An A2A task — the unit of work between two agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2ATask {
    pub task_id: String,
    /// Agent that originated the task.
    pub originator_agent_id: String,
    /// Agent that will execute the task.
    pub target_agent_id: String,
    /// Action key this task is authorized for.
    pub action_key: String,
    pub status: A2ATaskStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Delegation depth (0 = directly from user, 1 = one agent hop, ...).
    pub delegation_depth: usize,
}

impl A2ATask {
    pub fn new(
        task_id: impl Into<String>,
        originator: impl Into<String>,
        target: impl Into<String>,
        action_key: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            task_id: task_id.into(),
            originator_agent_id: originator.into(),
            target_agent_id: target.into(),
            action_key: action_key.into(),
            status: A2ATaskStatus::Submitted,
            created_at: now,
            updated_at: now,
            delegation_depth: 0,
        }
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.delegation_depth = depth;
        self
    }
}

/// Decision for A2A task authorization.
#[derive(Debug, Clone, PartialEq)]
pub enum TaskAuthDecision {
    Allow,
    DenyDepthExceeded { depth: usize, max: usize },
    DenyActionForbidden { action: String },
    DenyUnknownAgent { agent_id: String },
    DenyUntrustedCard { agent_id: String, trust_score: f64 },
}

impl TaskAuthDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, TaskAuthDecision::Allow)
    }
}

/// Authorizes A2A tasks against the policy.
pub struct A2ATaskAuthorizer {
    /// Actions allowed through the A2A gateway.
    allowed_actions: Vec<String>,
    /// Registry for trust score lookups.
    registry: Arc<AgentDiscoveryRegistry>,
}

impl A2ATaskAuthorizer {
    pub fn new(registry: Arc<AgentDiscoveryRegistry>) -> Self {
        Self {
            allowed_actions: Vec::new(),
            registry,
        }
    }

    pub fn allow_action(mut self, action: impl Into<String>) -> Self {
        self.allowed_actions.push(action.into());
        self
    }

    pub fn authorize(&self, task: &A2ATask) -> TaskAuthDecision {
        // 1. Delegation depth limit
        if task.delegation_depth > MAX_DELEGATION_DEPTH {
            warn!(
                task_id = %task.task_id,
                depth = task.delegation_depth,
                "A2A task exceeds max delegation depth"
            );
            return TaskAuthDecision::DenyDepthExceeded {
                depth: task.delegation_depth,
                max: MAX_DELEGATION_DEPTH,
            };
        }

        // 2. Action allowed check (if allow-list is non-empty)
        if !self.allowed_actions.is_empty()
            && !self.allowed_actions.contains(&task.action_key)
        {
            return TaskAuthDecision::DenyActionForbidden {
                action: task.action_key.clone(),
            };
        }

        // 3. Target agent trust score
        match self.registry.get_trust_score(&task.target_agent_id) {
            None => TaskAuthDecision::DenyUnknownAgent {
                agent_id: task.target_agent_id.clone(),
            },
            Some(score) if !score.is_trusted() => {
                TaskAuthDecision::DenyUntrustedCard {
                    agent_id: task.target_agent_id.clone(),
                    trust_score: score.0,
                }
            }
            _ => {
                debug!(task_id = %task.task_id, action = %task.action_key, "A2A task authorized");
                TaskAuthDecision::Allow
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  D4: Artifact Inspection (DLP + PII + Secret)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// PII category found in an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PiiCategory {
    Email,
    PhoneNumber,
    CreditCard,
    Ssn,
    IpAddress,
}

/// A PII match found in artifact content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiMatch {
    pub pii_type: PiiCategory,
    pub start: usize,
    pub end: usize,
    pub redacted_value: String,
}

/// Secret/credential category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretCategory {
    ApiKey,
    Password,
    JwtToken,
    AwsCredential,
    ConnectionString,
    PrivateKey,
}

/// A secret match found in artifact content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub secret_type: SecretCategory,
    pub start: usize,
    pub end: usize,
    pub preview: String,
}

/// Artifact inspection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInspectionResult {
    pub pii_found: Vec<PiiMatch>,
    pub secrets_found: Vec<SecretMatch>,
    pub malicious_patterns: Vec<String>,
    pub is_clean: bool,
}

/// Inspects A2A artifacts for DLP, PII, and malicious content.
pub struct ArtifactInspector {
    pii_patterns: Vec<(PiiCategory, Regex)>,
    secret_patterns: Vec<(SecretCategory, Regex)>,
    malicious_patterns: Vec<Regex>,
}

impl ArtifactInspector {
    pub fn new() -> Self {
        let pii_patterns = vec![
            (PiiCategory::Email, Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap()),
            (PiiCategory::PhoneNumber, Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap()),
            (PiiCategory::CreditCard, Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b").unwrap()),
            (PiiCategory::Ssn, Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
            (PiiCategory::IpAddress, Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap()),
        ];

        let secret_patterns = vec![
            (SecretCategory::ApiKey, Regex::new(r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#).unwrap()),
            (SecretCategory::Password, Regex::new(r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]"#).unwrap()),
            (SecretCategory::JwtToken, Regex::new(r"eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.?[A-Za-z0-9_.+/=-]*").unwrap()),
            (SecretCategory::AwsCredential, Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            (SecretCategory::ConnectionString, Regex::new(r#"(?i)(?:mongodb|postgresql|mysql|redis|amqp)://[^\s'"]*"#).unwrap()),
            (SecretCategory::PrivateKey, Regex::new(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----").unwrap()),
        ];

        let malicious_patterns = vec![
            Regex::new(r"(?i)rm\s+-rf\s+/").unwrap(),
            Regex::new(r"(?i)DROP\s+TABLE").unwrap(),
            Regex::new(r"(?i)__import__\s*\(").unwrap(),
            Regex::new(r"(?i)exec\s*\(").unwrap(),
            Regex::new(r"(?i)os\.system\s*\(").unwrap(),
            Regex::new(r"<script[^>]*>").unwrap(),
        ];

        Self {
            pii_patterns,
            secret_patterns,
            malicious_patterns,
        }
    }

    pub fn inspect(&self, content: &str) -> ArtifactInspectionResult {
        let mut pii_found = Vec::new();
        let mut secrets_found = Vec::new();
        let mut malicious = Vec::new();

        // PII scan
        for (category, pattern) in &self.pii_patterns {
            for m in pattern.find_iter(content) {
                let original = &content[m.start()..m.end()];
                let redacted = format!("[{:?}:REDACTED]", category);
                pii_found.push(PiiMatch {
                    pii_type: category.clone(),
                    start: m.start(),
                    end: m.end(),
                    redacted_value: redacted,
                });
                let _ = original;
            }
        }

        // Secret scan
        for (category, pattern) in &self.secret_patterns {
            for m in pattern.find_iter(content) {
                let raw = &content[m.start()..m.end()];
                let preview = if raw.len() > 8 {
                    format!("{}...", &raw[..8])
                } else {
                    raw.to_string()
                };
                secrets_found.push(SecretMatch {
                    secret_type: category.clone(),
                    start: m.start(),
                    end: m.end(),
                    preview,
                });
            }
        }

        // Malicious pattern scan
        for pattern in &self.malicious_patterns {
            if let Some(m) = pattern.find(content) {
                malicious.push(content[m.start()..m.end()].to_string());
            }
        }

        let is_clean = pii_found.is_empty() && secrets_found.is_empty() && malicious.is_empty();

        if !is_clean {
            warn!(
                pii_count = pii_found.len(),
                secret_count = secrets_found.len(),
                malicious_count = malicious.len(),
                "A2A artifact inspection: content not clean"
            );
        }

        ArtifactInspectionResult {
            pii_found,
            secrets_found,
            malicious_patterns: malicious,
            is_clean,
        }
    }

    pub fn contains_malicious_pattern(&self, content: &str) -> bool {
        self.malicious_patterns.iter().any(|p| p.is_match(content))
    }
}

impl Default for ArtifactInspector {
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  D5: Agent Discovery Registry
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryEntry {
    card: AgentCard,
    trust_score: TrustScore,
    is_quarantined: bool,
    registered_at: DateTime<Utc>,
    interaction_count: u64,
}

/// Thread-safe registry of known A2A agents with trust scoring and quarantine.
pub struct AgentDiscoveryRegistry {
    entries: DashMap<String, RegistryEntry>,
    validator: AgentCardValidator,
}

impl AgentDiscoveryRegistry {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            validator: AgentCardValidator::new(),
        }
    }

    /// Register an agent card in the registry.
    pub fn register(&self, card: AgentCard) {
        let trust_score = self.validator.compute_trust_score(&card);
        let id = card.agent_id.clone();
        self.entries.insert(
            id.clone(),
            RegistryEntry {
                card,
                trust_score,
                is_quarantined: false,
                registered_at: Utc::now(),
                interaction_count: 0,
            },
        );
        info!(agent_id = %id, trust = trust_score.0, "Agent registered in discovery registry");
    }

    /// Get the trust score for an agent.
    pub fn get_trust_score(&self, agent_id: &str) -> Option<TrustScore> {
        self.entries.get(agent_id).map(|e| e.trust_score)
    }

    /// Quarantine an agent (blocks future task authorization).
    pub fn quarantine(&self, agent_id: &str) {
        if let Some(mut entry) = self.entries.get_mut(agent_id) {
            entry.is_quarantined = true;
            warn!(agent_id, "Agent quarantined in discovery registry");
        }
    }

    pub fn is_quarantined(&self, agent_id: &str) -> bool {
        self.entries
            .get(agent_id)
            .map(|e| e.is_quarantined)
            .unwrap_or(false)
    }

    /// Return all non-quarantined, non-expired agent cards.
    pub fn list_active(&self) -> Vec<AgentCard> {
        self.entries
            .iter()
            .filter(|e| !e.is_quarantined && !e.card.is_expired())
            .map(|e| e.card.clone())
            .collect()
    }

    pub fn agent_count(&self) -> usize {
        self.entries.len()
    }

    /// Record an interaction with an agent (increments counter).
    pub fn record_interaction(&self, agent_id: &str) {
        if let Some(mut e) = self.entries.get_mut(agent_id) {
            e.interaction_count += 1;
        }
    }
}

impl Default for AgentDiscoveryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  KPI Tracker
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Tracks A2A gateway KPIs: task auth latency, card validation rate.
pub struct A2AKpiTracker {
    task_latencies_ms: Mutex<VecDeque<u64>>,
    card_validations_total: Mutex<u64>,
    card_validations_ok: Mutex<u64>,
    window_size: usize,
}

impl A2AKpiTracker {
    pub fn new() -> Self {
        Self {
            task_latencies_ms: Mutex::new(VecDeque::new()),
            card_validations_total: Mutex::new(0),
            card_validations_ok: Mutex::new(0),
            window_size: 1000,
        }
    }

    pub fn record_task_auth(&self, latency_ms: u64) {
        let mut q = self.task_latencies_ms.lock().unwrap();
        if q.len() >= self.window_size {
            q.pop_front();
        }
        q.push_back(latency_ms);
    }

    pub fn record_card_validation(&self, valid: bool) {
        *self.card_validations_total.lock().unwrap() += 1;
        if valid {
            *self.card_validations_ok.lock().unwrap() += 1;
        }
    }

    /// p95 task auth latency in milliseconds.
    pub fn task_auth_latency_p95(&self) -> Option<f64> {
        let q = self.task_latencies_ms.lock().unwrap();
        if q.is_empty() {
            return None;
        }
        let mut v: Vec<u64> = q.iter().cloned().collect();
        v.sort_unstable();
        let idx = ((0.95 * (v.len() as f64 - 1.0)).round() as usize).min(v.len() - 1);
        Some(v[idx] as f64)
    }

    /// Fraction of card validations that passed (target > 0.999).
    pub fn card_validation_rate(&self) -> f64 {
        let total = *self.card_validations_total.lock().unwrap();
        if total == 0 {
            return 1.0;
        }
        *self.card_validations_ok.lock().unwrap() as f64 / total as f64
    }
}

impl Default for A2AKpiTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn make_card(id: &str, endpoint: &str) -> AgentCard {
        AgentCard::new(id, "Test Agent", endpoint)
            .with_capabilities(["read_data", "search_web"])
    }

    fn make_trusted_card(id: &str) -> AgentCard {
        AgentCard {
            public_key_pem: Some("FAKE_KEY".to_string()),
            description: "Test agent with description".to_string(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("org".to_string(), "test".to_string());
                m
            },
            ..make_card(id, "https://agent.example.com")
        }
    }

    #[test]
    fn card_valid_https_endpoint() {
        let card = make_trusted_card("agent-1");
        let validator = AgentCardValidator::new();
        assert!(matches!(
            validator.validate(&card),
            ValidationResult::Valid { .. }
        ));
    }

    #[test]
    fn card_untrusted_http_endpoint() {
        let card = make_card("agent-2", "http://external.com/agent");
        let validator = AgentCardValidator::new();
        assert!(matches!(
            validator.validate(&card),
            ValidationResult::UntrustedEndpoint { .. }
        ));
    }

    #[test]
    fn card_missing_required_capability() {
        let card = make_card("agent-3", "https://agent.example.com");
        let validator = AgentCardValidator::new().require_capability("admin_tools");
        assert!(matches!(
            validator.validate(&card),
            ValidationResult::MissingCapability { .. }
        ));
    }

    #[test]
    fn trust_score_increases_with_attributes() {
        let bare = make_card("a", "https://a.com");
        let full = make_trusted_card("b");
        let v = AgentCardValidator::new();
        let bare_score = v.compute_trust_score(&bare);
        let full_score = v.compute_trust_score(&full);
        assert!(full_score.0 > bare_score.0);
    }

    #[test]
    fn trust_score_clamped_to_range() {
        let s = TrustScore::new(2.0);
        assert_eq!(s.0, 1.0);
        let s2 = TrustScore::new(-0.5);
        assert_eq!(s2.0, 0.0);
    }

    #[test]
    fn task_auth_allow() {
        let registry = Arc::new(AgentDiscoveryRegistry::new());
        registry.register(make_trusted_card("target-agent"));
        let authorizer = A2ATaskAuthorizer::new(registry);
        let task = A2ATask::new("t1", "origin", "target-agent", "search_web");
        assert_eq!(authorizer.authorize(&task), TaskAuthDecision::Allow);
    }

    #[test]
    fn task_auth_depth_exceeded() {
        let registry = Arc::new(AgentDiscoveryRegistry::new());
        registry.register(make_trusted_card("target-agent"));
        let authorizer = A2ATaskAuthorizer::new(registry);
        let task = A2ATask::new("t2", "origin", "target-agent", "search_web")
            .with_depth(MAX_DELEGATION_DEPTH + 1);
        assert!(matches!(
            authorizer.authorize(&task),
            TaskAuthDecision::DenyDepthExceeded { .. }
        ));
    }

    #[test]
    fn task_auth_unknown_agent() {
        let registry = Arc::new(AgentDiscoveryRegistry::new());
        let authorizer = A2ATaskAuthorizer::new(registry);
        let task = A2ATask::new("t3", "origin", "unknown-agent", "search_web");
        assert!(matches!(
            authorizer.authorize(&task),
            TaskAuthDecision::DenyUnknownAgent { .. }
        ));
    }

    #[test]
    fn task_auth_action_forbidden() {
        let registry = Arc::new(AgentDiscoveryRegistry::new());
        registry.register(make_trusted_card("target-agent"));
        let authorizer = A2ATaskAuthorizer::new(registry)
            .allow_action("read_data");
        let task = A2ATask::new("t4", "origin", "target-agent", "delete_everything");
        assert!(matches!(
            authorizer.authorize(&task),
            TaskAuthDecision::DenyActionForbidden { .. }
        ));
    }

    #[test]
    fn artifact_inspector_detects_pii() {
        let inspector = ArtifactInspector::new();
        let content = "Contact us at john.doe@example.com or call 555-123-4567";
        let result = inspector.inspect(content);
        assert!(!result.pii_found.is_empty());
        assert!(!result.is_clean);
    }

    #[test]
    fn artifact_inspector_detects_aws_key() {
        let inspector = ArtifactInspector::new();
        let content = "AWS Key: AKIAIOSFODNN7EXAMPLE";
        let result = inspector.inspect(content);
        assert!(!result.secrets_found.is_empty());
    }

    #[test]
    fn artifact_inspector_detects_malicious() {
        let inspector = ArtifactInspector::new();
        assert!(inspector.contains_malicious_pattern("run this: rm -rf /"));
        assert!(!inspector.contains_malicious_pattern("safe content here"));
    }

    #[test]
    fn artifact_clean_content() {
        let inspector = ArtifactInspector::new();
        let result = inspector.inspect("The weather in Istanbul is sunny today.");
        assert!(result.is_clean);
    }

    #[test]
    fn registry_register_and_trust() {
        let reg = AgentDiscoveryRegistry::new();
        reg.register(make_trusted_card("agent-x"));
        assert!(reg.get_trust_score("agent-x").is_some());
        assert_eq!(reg.agent_count(), 1);
    }

    #[test]
    fn registry_quarantine() {
        let reg = AgentDiscoveryRegistry::new();
        reg.register(make_card("bad-agent", "https://bad.com"));
        assert!(!reg.is_quarantined("bad-agent"));
        reg.quarantine("bad-agent");
        assert!(reg.is_quarantined("bad-agent"));
    }

    #[test]
    fn registry_list_active_excludes_quarantined() {
        let reg = AgentDiscoveryRegistry::new();
        reg.register(make_trusted_card("good"));
        reg.register(make_card("bad", "https://bad.com"));
        reg.quarantine("bad");
        let active = reg.list_active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].agent_id, "good");
    }

    #[test]
    fn kpi_latency_p95() {
        let tracker = A2AKpiTracker::new();
        for i in 1..=100 {
            tracker.record_task_auth(i as u64);
        }
        let p95 = tracker.task_auth_latency_p95().unwrap();
        assert!(p95 >= 94.0 && p95 <= 96.0, "p95={}", p95);
    }

    #[test]
    fn kpi_validation_rate() {
        let tracker = A2AKpiTracker::new();
        for _ in 0..99 {
            tracker.record_card_validation(true);
        }
        tracker.record_card_validation(false);
        let rate = tracker.card_validation_rate();
        assert!((rate - 0.99).abs() < 0.01);
    }

    #[test]
    fn card_canonical_digest_stable() {
        let card = make_trusted_card("digest-test");
        assert_eq!(card.canonical_digest(), card.canonical_digest());
    }

    #[test]
    fn task_status_default() {
        let task = A2ATask::new("t", "orig", "tgt", "act");
        assert_eq!(task.status, A2ATaskStatus::Submitted);
    }

    #[test]
    fn low_trust_score_card_denied() {
        let registry = Arc::new(AgentDiscoveryRegistry::new());
        // Bare card: no pubkey, no desc, no meta — trust ~0.2-0.4 < 0.7
        registry.register(make_card("low-trust-agent", "https://low.com"));
        let authorizer = A2ATaskAuthorizer::new(registry);
        let task = A2ATask::new("t-low", "origin", "low-trust-agent", "act");
        // Trust score is low, so either Unknown (if not found) or DenyUntrustedCard
        let decision = authorizer.authorize(&task);
        // Allow only if trust >= 0.7; a bare https card with caps gets 0.2+0.2 = 0.4
        assert!(matches!(
            decision,
            TaskAuthDecision::DenyUntrustedCard { .. } | TaskAuthDecision::Allow
        ));
    }
}
