/// W21: Multi-Standard Identity Fabric
///
/// SPIFFE/SPIRE SVIDs · WIMSE cross-system token exchange ·
/// OAuth Transaction Tokens (draft-oauth-transaction-tokens-for-agents) ·
/// CHEQ human-confirmation protocol · AAuth non-browser agent auth ·
/// NHI lifecycle governance · On-Behalf-Of delegation chain.
///
/// KPIs:
///   - identity_verification_rate > 99.5 %
///   - token_validation_latency_ms < 5
///   - nhi_lifecycle_coverage > 99 %

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

// ── Reason codes ─────────────────────────────────────────────────────────────
pub const RC_WIMSE_REBIND_FAIL: &str = "RC_WIMSE_REBIND_FAIL";
pub const RC_NHI_EXCESSIVE_PRIV: &str = "RC_NHI_EXCESSIVE_PRIV";
pub const RC_CHEQ_REJECTED: &str = "RC_CHEQ_REJECTED";

// ── Errors ────────────────────────────────────────────────────────────────────
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("SPIFFE SVID invalid: {0}")]
    InvalidSvid(String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Token audience mismatch: expected {expected}, got {got}")]
    AudienceMismatch { expected: String, got: String },
    #[error("WIMSE rebind failure: {0}")]
    WimseRebindFail(String),
    #[error("NHI excessive privilege: {0}")]
    NhiExcessivePrivilege(String),
    #[error("CHEQ human confirmation rejected")]
    CheqRejected,
    #[error("Delegation chain too long: {depth}")]
    DelegationChainTooLong { depth: usize },
    #[error("Identity not found: {0}")]
    NotFound(String),
}

// ── SPIFFE SVID ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpiffeSvid {
    pub spiffe_id: String,      // spiffe://trust-domain/path
    pub trust_domain: String,
    pub subject_alt_name: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub public_key_fingerprint: String,
    pub serial: String,
}

impl SpiffeSvid {
    pub fn new(
        trust_domain: impl Into<String>,
        workload_path: impl Into<String>,
        ttl_seconds: i64,
        public_key_bytes: &[u8],
    ) -> Self {
        let td = trust_domain.into();
        let path = workload_path.into();
        let spiffe_id = format!("spiffe://{}/{}", td, path);
        let fingerprint = hex::encode(Sha256::digest(public_key_bytes));
        let now = Utc::now();
        Self {
            spiffe_id: spiffe_id.clone(),
            trust_domain: td,
            subject_alt_name: spiffe_id,
            issued_at: now,
            expires_at: now + Duration::seconds(ttl_seconds),
            public_key_fingerprint: fingerprint,
            serial: Uuid::new_v4().to_string(),
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.issued_at && now < self.expires_at
    }

    pub fn validate_format(&self) -> Result<(), IdentityError> {
        if !self.spiffe_id.starts_with("spiffe://") {
            return Err(IdentityError::InvalidSvid(
                "Must start with spiffe://".to_string(),
            ));
        }
        if self.trust_domain.is_empty() {
            return Err(IdentityError::InvalidSvid("Empty trust domain".to_string()));
        }
        if !self.is_valid() {
            return Err(IdentityError::TokenExpired);
        }
        Ok(())
    }
}

// ── SPIRE Workload Registry ───────────────────────────────────────────────────
pub struct SpireWorkloadRegistry {
    svids: DashMap<String, SpiffeSvid>, // workload_id → SVID
    verifications: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
}

impl SpireWorkloadRegistry {
    pub fn new() -> Self {
        Self {
            svids: DashMap::new(),
            verifications: Arc::new(AtomicU64::new(0)),
            failures: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn register(&self, workload_id: impl Into<String>, svid: SpiffeSvid) {
        self.svids.insert(workload_id.into(), svid);
    }

    pub fn verify(&self, workload_id: &str) -> Result<SpiffeSvid, IdentityError> {
        self.verifications.fetch_add(1, Ordering::Relaxed);
        let svid = self
            .svids
            .get(workload_id)
            .ok_or_else(|| IdentityError::NotFound(workload_id.to_string()))?
            .clone();
        svid.validate_format().map_err(|e| {
            self.failures.fetch_add(1, Ordering::Relaxed);
            e
        })?;
        Ok(svid)
    }

    pub fn verification_rate(&self) -> f64 {
        let total = self.verifications.load(Ordering::Relaxed);
        let failed = self.failures.load(Ordering::Relaxed);
        if total == 0 {
            return 100.0;
        }
        let success = total.saturating_sub(failed);
        (success as f64 / total as f64) * 100.0
    }
}

impl Default for SpireWorkloadRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── WIMSE Token Exchange ──────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WimseToken {
    pub token_id: String,
    pub issuer: String,
    pub subject: String,       // workload SPIFFE ID
    pub audience: String,      // target system
    pub scope: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub proof_of_possession: String, // DPoP-style binding
    pub workload_attestation: String,
}

impl WimseToken {
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        audience: impl Into<String>,
        scope: Vec<String>,
        ttl_seconds: i64,
        pop_key_fingerprint: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            token_id: Uuid::new_v4().to_string(),
            issuer: issuer.into(),
            subject: subject.into(),
            audience: audience.into(),
            scope,
            issued_at: now,
            expires_at: now + Duration::seconds(ttl_seconds),
            proof_of_possession: pop_key_fingerprint.into(),
            workload_attestation: Uuid::new_v4().to_string(),
        }
    }

    pub fn is_valid_for(&self, audience: &str) -> Result<(), IdentityError> {
        if Utc::now() >= self.expires_at {
            return Err(IdentityError::TokenExpired);
        }
        if self.audience != audience {
            return Err(IdentityError::AudienceMismatch {
                expected: audience.to_string(),
                got: self.audience.clone(),
            });
        }
        Ok(())
    }
}

pub struct WimseTokenExchange {
    issued_tokens: DashMap<String, WimseToken>,
    rebind_failures: Arc<AtomicU64>,
}

impl WimseTokenExchange {
    pub fn new() -> Self {
        Self {
            issued_tokens: DashMap::new(),
            rebind_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn issue(&self, token: WimseToken) -> String {
        let id = token.token_id.clone();
        self.issued_tokens.insert(id.clone(), token);
        id
    }

    /// Exchange a WIMSE token for a new-audience token (rebind)
    pub fn exchange(
        &self,
        token_id: &str,
        new_audience: &str,
        pop_binding: &str,
    ) -> Result<WimseToken, IdentityError> {
        let original = self
            .issued_tokens
            .get(token_id)
            .ok_or_else(|| IdentityError::NotFound(token_id.to_string()))?
            .clone();

        if original.proof_of_possession != pop_binding {
            self.rebind_failures.fetch_add(1, Ordering::Relaxed);
            return Err(IdentityError::WimseRebindFail(
                RC_WIMSE_REBIND_FAIL.to_string(),
            ));
        }
        if Utc::now() >= original.expires_at {
            return Err(IdentityError::TokenExpired);
        }

        let new_token = WimseToken::new(
            original.issuer.clone(),
            original.subject.clone(),
            new_audience,
            original.scope.clone(),
            300, // 5 min downstream TTL
            pop_binding,
        );
        let id = new_token.token_id.clone();
        self.issued_tokens.insert(id, new_token.clone());
        Ok(new_token)
    }

    pub fn rebind_failures(&self) -> u64 {
        self.rebind_failures.load(Ordering::Relaxed)
    }
}

impl Default for WimseTokenExchange {
    fn default() -> Self {
        Self::new()
    }
}

// ── OAuth Transaction Token ───────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTransactionToken {
    pub txn_id: String,
    pub initiator_id: String,
    pub chain: Vec<String>, // delegation chain of agent IDs
    pub context: HashMap<String, String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_chain_depth: usize,
}

impl OAuthTransactionToken {
    pub fn new(
        initiator_id: impl Into<String>,
        context: HashMap<String, String>,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            txn_id: Uuid::new_v4().to_string(),
            initiator_id: initiator_id.into(),
            chain: Vec::new(),
            context,
            issued_at: now,
            expires_at: now + Duration::seconds(ttl_seconds),
            max_chain_depth: 5,
        }
    }

    pub fn delegate_to(&mut self, agent_id: impl Into<String>) -> Result<(), IdentityError> {
        if self.chain.len() >= self.max_chain_depth {
            return Err(IdentityError::DelegationChainTooLong {
                depth: self.chain.len(),
            });
        }
        self.chain.push(agent_id.into());
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

// ── CHEQ Human Confirmation Protocol ─────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheqRequest {
    pub request_id: String,
    pub action_description: String,
    pub risk_level: CheqRiskLevel,
    pub requester_id: String,
    pub expires_at: DateTime<Utc>,
    pub status: CheqStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheqRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheqStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

pub struct CheqProtocol {
    requests: DashMap<String, CheqRequest>,
    approvals: Arc<AtomicU64>,
    rejections: Arc<AtomicU64>,
}

impl CheqProtocol {
    pub fn new() -> Self {
        Self {
            requests: DashMap::new(),
            approvals: Arc::new(AtomicU64::new(0)),
            rejections: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn create_request(
        &self,
        action: impl Into<String>,
        risk: CheqRiskLevel,
        requester: impl Into<String>,
        timeout_seconds: i64,
    ) -> String {
        let req = CheqRequest {
            request_id: Uuid::new_v4().to_string(),
            action_description: action.into(),
            risk_level: risk,
            requester_id: requester.into(),
            expires_at: Utc::now() + Duration::seconds(timeout_seconds),
            status: CheqStatus::Pending,
        };
        let id = req.request_id.clone();
        self.requests.insert(id.clone(), req);
        id
    }

    pub fn respond(&self, request_id: &str, approved: bool) -> Result<(), IdentityError> {
        let mut req = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| IdentityError::NotFound(request_id.to_string()))?;
        if Utc::now() >= req.expires_at {
            req.status = CheqStatus::Expired;
            return Err(IdentityError::TokenExpired);
        }
        if approved {
            req.status = CheqStatus::Approved;
            self.approvals.fetch_add(1, Ordering::Relaxed);
        } else {
            req.status = CheqStatus::Rejected;
            self.rejections.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn check_approval(&self, request_id: &str) -> Result<bool, IdentityError> {
        let req = self
            .requests
            .get(request_id)
            .ok_or_else(|| IdentityError::NotFound(request_id.to_string()))?;
        match req.status {
            CheqStatus::Approved => Ok(true),
            CheqStatus::Rejected => Err(IdentityError::CheqRejected),
            CheqStatus::Expired => Err(IdentityError::TokenExpired),
            CheqStatus::Pending => Ok(false),
        }
    }

    pub fn approval_rate(&self) -> f64 {
        let total = self.approvals.load(Ordering::Relaxed)
            + self.rejections.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        (self.approvals.load(Ordering::Relaxed) as f64 / total as f64) * 100.0
    }
}

impl Default for CheqProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ── NHI Lifecycle Governance ──────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonHumanIdentity {
    pub nhi_id: String,
    pub workload_type: String,
    pub assigned_permissions: Vec<String>,
    pub max_allowed_permissions: usize,
    pub created_at: DateTime<Utc>,
    pub last_rotated: DateTime<Utc>,
    pub rotation_interval_days: i64,
    pub status: NhiStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NhiStatus {
    Active,
    Suspended,
    Revoked,
    PendingRotation,
}

impl NonHumanIdentity {
    pub fn new(
        workload_type: impl Into<String>,
        max_permissions: usize,
        rotation_days: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            nhi_id: Uuid::new_v4().to_string(),
            workload_type: workload_type.into(),
            assigned_permissions: Vec::new(),
            max_allowed_permissions: max_permissions,
            created_at: now,
            last_rotated: now,
            rotation_interval_days: rotation_days,
            status: NhiStatus::Active,
        }
    }

    pub fn is_over_privileged(&self) -> bool {
        self.assigned_permissions.len() > self.max_allowed_permissions
    }

    pub fn needs_rotation(&self) -> bool {
        let deadline = self.last_rotated + Duration::days(self.rotation_interval_days);
        Utc::now() > deadline
    }
}

pub struct NhiLifecycleGovernor {
    identities: DashMap<String, NonHumanIdentity>,
    over_priv_detections: Arc<AtomicU64>,
    rotations_performed: Arc<AtomicU64>,
}

impl NhiLifecycleGovernor {
    pub fn new() -> Self {
        Self {
            identities: DashMap::new(),
            over_priv_detections: Arc::new(AtomicU64::new(0)),
            rotations_performed: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn register(&self, nhi: NonHumanIdentity) -> String {
        let id = nhi.nhi_id.clone();
        self.identities.insert(id.clone(), nhi);
        id
    }

    pub fn assign_permission(
        &self,
        nhi_id: &str,
        permission: impl Into<String>,
    ) -> Result<(), IdentityError> {
        let mut nhi = self
            .identities
            .get_mut(nhi_id)
            .ok_or_else(|| IdentityError::NotFound(nhi_id.to_string()))?;
        let perm = permission.into();
        if nhi.assigned_permissions.len() >= nhi.max_allowed_permissions {
            self.over_priv_detections.fetch_add(1, Ordering::Relaxed);
            return Err(IdentityError::NhiExcessivePrivilege(format!(
                "{}: limit {} {}",
                RC_NHI_EXCESSIVE_PRIV,
                nhi.max_allowed_permissions,
                nhi_id
            )));
        }
        nhi.assigned_permissions.push(perm);
        Ok(())
    }

    pub fn rotate(&self, nhi_id: &str) -> Result<(), IdentityError> {
        let mut nhi = self
            .identities
            .get_mut(nhi_id)
            .ok_or_else(|| IdentityError::NotFound(nhi_id.to_string()))?;
        nhi.last_rotated = Utc::now();
        nhi.status = NhiStatus::Active;
        self.rotations_performed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn audit_all(&self) -> Vec<NhiAuditEvent> {
        let mut events = Vec::new();
        for entry in self.identities.iter() {
            let nhi = entry.value();
            if nhi.is_over_privileged() {
                self.over_priv_detections.fetch_add(1, Ordering::Relaxed);
                events.push(NhiAuditEvent {
                    nhi_id: nhi.nhi_id.clone(),
                    event_type: NhiAuditEventType::ExcessivePrivilege,
                    detail: format!(
                        "Has {} permissions, max {}",
                        nhi.assigned_permissions.len(),
                        nhi.max_allowed_permissions
                    ),
                    reason_code: RC_NHI_EXCESSIVE_PRIV.to_string(),
                    detected_at: Utc::now(),
                });
            }
            if nhi.needs_rotation() {
                events.push(NhiAuditEvent {
                    nhi_id: nhi.nhi_id.clone(),
                    event_type: NhiAuditEventType::RotationRequired,
                    detail: format!(
                        "Last rotated: {}",
                        nhi.last_rotated.format("%Y-%m-%d")
                    ),
                    reason_code: "NHI_ROTATION_OVERDUE".to_string(),
                    detected_at: Utc::now(),
                });
            }
        }
        events
    }

    pub fn lifecycle_coverage(&self) -> f64 {
        if self.identities.is_empty() {
            return 100.0;
        }
        // Coverage = fraction of NHIs that are active and not over-privileged
        let total = self.identities.len() as f64;
        let compliant = self
            .identities
            .iter()
            .filter(|e| e.status == NhiStatus::Active && !e.is_over_privileged())
            .count() as f64;
        (compliant / total) * 100.0
    }

    pub fn over_priv_detections(&self) -> u64 {
        self.over_priv_detections.load(Ordering::Relaxed)
    }
}

impl Default for NhiLifecycleGovernor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NhiAuditEvent {
    pub nhi_id: String,
    pub event_type: NhiAuditEventType,
    pub detail: String,
    pub reason_code: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NhiAuditEventType {
    ExcessivePrivilege,
    RotationRequired,
    StatusChanged,
}

// ── On-Behalf-Of Delegation ───────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChain {
    pub chain_id: String,
    pub original_actor: String,
    pub links: Vec<DelegationLink>,
    pub max_depth: usize,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    pub delegator: String,
    pub delegatee: String,
    pub permissions: Vec<String>,
    pub delegated_at: DateTime<Utc>,
    pub reason: String,
}

impl DelegationChain {
    pub fn new(original_actor: impl Into<String>, max_depth: usize) -> Self {
        Self {
            chain_id: Uuid::new_v4().to_string(),
            original_actor: original_actor.into(),
            links: Vec::new(),
            max_depth,
            created_at: Utc::now(),
        }
    }

    pub fn delegate(
        &mut self,
        delegatee: impl Into<String>,
        permissions: Vec<String>,
        reason: impl Into<String>,
    ) -> Result<(), IdentityError> {
        if self.links.len() >= self.max_depth {
            return Err(IdentityError::DelegationChainTooLong {
                depth: self.links.len(),
            });
        }
        let delegator = self
            .links
            .last()
            .map(|l| l.delegatee.clone())
            .unwrap_or_else(|| self.original_actor.clone());
        self.links.push(DelegationLink {
            delegator,
            delegatee: delegatee.into(),
            permissions,
            delegated_at: Utc::now(),
            reason: reason.into(),
        });
        Ok(())
    }

    pub fn depth(&self) -> usize {
        self.links.len()
    }

    pub fn current_holder(&self) -> &str {
        self.links
            .last()
            .map(|l| l.delegatee.as_str())
            .unwrap_or(&self.original_actor)
    }
}

// ── Identity Fabric KPIs ──────────────────────────────────────────────────────
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IdentityFabricKpis {
    pub svid_verifications: u64,
    pub svid_failures: u64,
    pub wimse_exchanges: u64,
    pub wimse_rebind_failures: u64,
    pub cheq_approvals: u64,
    pub cheq_rejections: u64,
    pub nhi_over_priv_detections: u64,
    pub delegation_chains_created: u64,
}

impl IdentityFabricKpis {
    pub fn identity_verification_rate(&self) -> f64 {
        let total = self.svid_verifications;
        if total == 0 {
            return 100.0;
        }
        let success = total.saturating_sub(self.svid_failures);
        (success as f64 / total as f64) * 100.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── SPIFFE SVID ───────────────────────────────────────────────────────────
    #[test]
    fn test_spiffe_svid_valid() {
        let key = b"test-public-key-bytes";
        let svid = SpiffeSvid::new("example.org", "agent/gateway", 3600, key);
        assert!(svid.spiffe_id.starts_with("spiffe://example.org/"));
        assert!(svid.is_valid());
        assert!(svid.validate_format().is_ok());
    }

    #[test]
    fn test_spiffe_svid_invalid_format() {
        let mut svid = SpiffeSvid::new("example.org", "agent/test", 3600, b"key");
        svid.spiffe_id = "http://not-spiffe".to_string();
        assert!(svid.validate_format().is_err());
    }

    #[test]
    fn test_spire_registry_verify() {
        let registry = SpireWorkloadRegistry::new();
        let svid = SpiffeSvid::new("corp.example", "services/auth", 3600, b"pubkey");
        registry.register("auth-service", svid);
        let result = registry.verify("auth-service");
        assert!(result.is_ok());
        assert!(registry.verification_rate() > 99.0);
    }

    #[test]
    fn test_spire_registry_not_found() {
        let registry = SpireWorkloadRegistry::new();
        let result = registry.verify("unknown-workload");
        assert!(result.is_err());
    }

    // ── WIMSE Token Exchange ──────────────────────────────────────────────────
    #[test]
    fn test_wimse_token_issue_and_validate() {
        let exchange = WimseTokenExchange::new();
        let token = WimseToken::new(
            "issuer.corp",
            "spiffe://corp/agent-1",
            "service-b",
            vec!["read".to_string()],
            300,
            "pop-key-fingerprint-abc",
        );
        let id = exchange.issue(token);
        assert!(!id.is_empty());
    }

    #[test]
    fn test_wimse_exchange_ok() {
        let exchange = WimseTokenExchange::new();
        let token = WimseToken::new(
            "issuer.corp",
            "spiffe://corp/agent-1",
            "service-a",
            vec!["read".to_string()],
            300,
            "pop-fingerprint-xyz",
        );
        let id = exchange.issue(token);
        let new_token = exchange.exchange(&id, "service-b", "pop-fingerprint-xyz");
        assert!(new_token.is_ok());
        assert_eq!(new_token.unwrap().audience, "service-b");
    }

    #[test]
    fn test_wimse_rebind_failure_wrong_pop() {
        let exchange = WimseTokenExchange::new();
        let token = WimseToken::new(
            "issuer",
            "spiffe://corp/a",
            "target",
            vec![],
            300,
            "correct-pop",
        );
        let id = exchange.issue(token);
        let result = exchange.exchange(&id, "other-target", "wrong-pop");
        assert!(matches!(result, Err(IdentityError::WimseRebindFail(_))));
        assert_eq!(exchange.rebind_failures(), 1);
    }

    // ── OAuth Transaction Token ───────────────────────────────────────────────
    #[test]
    fn test_transaction_token_delegation() {
        let mut txn = OAuthTransactionToken::new("human-user", HashMap::new(), 300);
        txn.delegate_to("agent-1").unwrap();
        txn.delegate_to("agent-2").unwrap();
        assert_eq!(txn.chain.len(), 2);
        assert!(txn.is_valid());
    }

    #[test]
    fn test_transaction_token_chain_too_long() {
        let mut txn = OAuthTransactionToken::new("user", HashMap::new(), 300);
        txn.max_chain_depth = 2;
        txn.delegate_to("a1").unwrap();
        txn.delegate_to("a2").unwrap();
        let result = txn.delegate_to("a3");
        assert!(matches!(result, Err(IdentityError::DelegationChainTooLong { .. })));
    }

    // ── CHEQ Protocol ─────────────────────────────────────────────────────────
    #[test]
    fn test_cheq_approve() {
        let cheq = CheqProtocol::new();
        let req_id = cheq.create_request("Delete production DB", CheqRiskLevel::Critical, "agent-1", 60);
        cheq.respond(&req_id, true).unwrap();
        assert_eq!(cheq.check_approval(&req_id).unwrap(), true);
    }

    #[test]
    fn test_cheq_reject() {
        let cheq = CheqProtocol::new();
        let req_id = cheq.create_request("Transfer funds", CheqRiskLevel::High, "agent-2", 60);
        cheq.respond(&req_id, false).unwrap();
        let result = cheq.check_approval(&req_id);
        assert!(matches!(result, Err(IdentityError::CheqRejected)));
    }

    #[test]
    fn test_cheq_pending() {
        let cheq = CheqProtocol::new();
        let req_id = cheq.create_request("Read logs", CheqRiskLevel::Low, "agent-3", 60);
        let result = cheq.check_approval(&req_id).unwrap();
        assert_eq!(result, false);
    }

    // ── NHI Lifecycle ─────────────────────────────────────────────────────────
    #[test]
    fn test_nhi_assign_permissions_ok() {
        let gov = NhiLifecycleGovernor::new();
        let nhi = NonHumanIdentity::new("ml-model-agent", 3, 90);
        let id = gov.register(nhi);
        gov.assign_permission(&id, "read:models").unwrap();
        gov.assign_permission(&id, "write:artifacts").unwrap();
        assert!(gov.over_priv_detections() == 0);
    }

    #[test]
    fn test_nhi_excessive_privilege() {
        let gov = NhiLifecycleGovernor::new();
        let nhi = NonHumanIdentity::new("limited-agent", 2, 90);
        let id = gov.register(nhi);
        gov.assign_permission(&id, "perm1").unwrap();
        gov.assign_permission(&id, "perm2").unwrap();
        let result = gov.assign_permission(&id, "perm3");
        assert!(matches!(result, Err(IdentityError::NhiExcessivePrivilege(_))));
        assert!(gov.over_priv_detections() > 0);
    }

    #[test]
    fn test_nhi_audit_all() {
        let gov = NhiLifecycleGovernor::new();
        let mut nhi = NonHumanIdentity::new("over-priv-agent", 1, 90);
        nhi.assigned_permissions = vec!["p1".to_string(), "p2".to_string(), "p3".to_string()];
        gov.register(nhi);
        let events = gov.audit_all();
        assert!(!events.is_empty());
    }

    #[test]
    fn test_nhi_rotate() {
        let gov = NhiLifecycleGovernor::new();
        let nhi = NonHumanIdentity::new("rotating-agent", 5, 90);
        let id = gov.register(nhi);
        gov.rotate(&id).unwrap();
        // Just check it doesn't error
    }

    // ── Delegation Chain ──────────────────────────────────────────────────────
    #[test]
    fn test_delegation_chain() {
        let mut chain = DelegationChain::new("root-user", 3);
        chain.delegate("agent-a", vec!["read".to_string()], "sub-task").unwrap();
        chain.delegate("agent-b", vec!["analyze".to_string()], "analysis").unwrap();
        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.current_holder(), "agent-b");
    }

    #[test]
    fn test_delegation_chain_too_deep() {
        let mut chain = DelegationChain::new("root", 2);
        chain.delegate("a1", vec![], "r1").unwrap();
        chain.delegate("a2", vec![], "r2").unwrap();
        let result = chain.delegate("a3", vec![], "r3");
        assert!(matches!(result, Err(IdentityError::DelegationChainTooLong { .. })));
    }

    // ── KPIs ──────────────────────────────────────────────────────────────────
    #[test]
    fn test_identity_verification_rate() {
        let kpis = IdentityFabricKpis {
            svid_verifications: 1000,
            svid_failures: 3,
            ..Default::default()
        };
        assert!(kpis.identity_verification_rate() > 99.5);
    }

    #[test]
    fn test_wimse_token_audience_mismatch() {
        let token = WimseToken::new("iss", "spiffe://a", "audience-A", vec![], 300, "pop");
        let result = token.is_valid_for("audience-B");
        assert!(matches!(result, Err(IdentityError::AudienceMismatch { .. })));
    }
}
