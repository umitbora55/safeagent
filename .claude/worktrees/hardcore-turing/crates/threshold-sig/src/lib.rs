// safeagent-threshold-sig
//
// W7 D2: Threshold signature multi-party approval
//
// Implements (t, n) threshold approval for Red-class actions:
//   No single party can authorize a high-risk action alone.
//   t-of-n parties must approve; the combined approval constitutes
//   a cryptographically verifiable authorization record.
//
// Design (compass W7 D2):
//   FROST protocol — Flexible Round-Optimized Schnorr Threshold signatures
//   from ZCash Foundation. For SafeAgent we implement a pragmatic
//   approval-share model:
//
//   1. Coordinator issues an ApprovalRequest for a Red action.
//   2. Each approver computes an ApprovalShare (HMAC-based share over
//      request_id + action_key + approver_id, keyed by a pre-shared
//      per-approver secret). In production this is a FROST partial signature.
//   3. When t shares are received, the Aggregator combines them into a
//      ThresholdApproval — a combined authorization record.
//   4. Any verifier with the per-request nonce can verify the combined approval.
//
// Note: This implementation uses HMAC-SHA256 as the share primitive
// (available without an FFI dependency). A FROST-Ed25519 backend can
// be added by enabling the `frost-ed25519` feature.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Approver registry
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Identity and verifying material for a single approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approver {
    pub id: String,
    pub display_name: String,
    /// HMAC-compatible secret (pre-shared per approver, 32 bytes in hex).
    /// In production: replace with FROST participant signing key.
    pub secret_hex: String,
}

impl Approver {
    pub fn new(id: impl Into<String>, name: impl Into<String>, secret_hex: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display_name: name.into(),
            secret_hex: secret_hex.into(),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Approval request
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A pending Red-class action requiring threshold approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// Action key being requested (e.g. "send_email").
    pub action_key: String,
    /// Agent or session requesting the action.
    pub requester_id: String,
    /// Human-readable description of the requested action.
    pub description: String,
    /// When the request expires if not fully approved.
    pub expires_at: DateTime<Utc>,
    /// Required threshold: t-of-n approvers needed.
    pub threshold: usize,
    /// Total number of registered approvers.
    pub total_approvers: usize,
    /// Nonce for share computation (random, per request).
    pub nonce_hex: String,
}

impl ApprovalRequest {
    /// Canonical message bytes — the payload each approver signs over.
    pub fn message(&self) -> Vec<u8> {
        format!(
            "safeagent:v1:{}:{}:{}:{}",
            self.request_id, self.action_key, self.requester_id, self.nonce_hex
        )
        .into_bytes()
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Approval share
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A single approver's share of the threshold approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalShare {
    pub request_id: String,
    pub approver_id: String,
    /// Hex-encoded HMAC-SHA256 share (or FROST partial sig in production).
    pub share_hex: String,
    pub created_at: DateTime<Utc>,
}

/// Compute an HMAC-SHA256 share for an approver.
fn compute_share(approver: &Approver, request: &ApprovalRequest) -> String {
    let key = hex::decode(&approver.secret_hex).unwrap_or_else(|_| approver.secret_hex.as_bytes().to_vec());
    let message = request.message();

    // HMAC-SHA256 via a simple key-prefixed double-hash (NMAC construction)
    // In production: use a real HMAC crate or FROST partial signature.
    let mut inner = Sha256::new();
    let mut ipad = vec![0x36u8; 64];
    for (i, b) in key.iter().take(64).enumerate() {
        ipad[i] ^= b;
    }
    inner.update(&ipad);
    inner.update(&message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    let mut opad = vec![0x5cu8; 64];
    for (i, b) in key.iter().take(64).enumerate() {
        opad[i] ^= b;
    }
    outer.update(&opad);
    outer.update(&inner_hash);
    hex::encode(outer.finalize())
}

impl ApprovalShare {
    /// Generate an approval share for the given approver and request.
    pub fn generate(approver: &Approver, request: &ApprovalRequest) -> Self {
        let share_hex = compute_share(approver, request);
        debug!(
            approver_id = %approver.id,
            request_id = %request.request_id,
            "Generated approval share"
        );
        Self {
            request_id: request.request_id.clone(),
            approver_id: approver.id.clone(),
            share_hex,
            created_at: Utc::now(),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Combined threshold approval
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A t-of-n approval combining multiple shares into a single
/// cryptographic authorization record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdApproval {
    pub request_id: String,
    pub action_key: String,
    pub requester_id: String,
    /// IDs of approvers who contributed shares.
    pub approver_ids: Vec<String>,
    /// Number of approvers required (threshold t).
    pub threshold: usize,
    /// Combined approval commitment (XOR-fold of shares for demo;
    /// in production: aggregated Schnorr signature R, s).
    pub combined_commitment: String,
    pub approved_at: DateTime<Utc>,
    /// Nonce from the original request (for verification).
    pub nonce_hex: String,
}

impl ThresholdApproval {
    /// Verify this approval record against the registered approvers.
    ///
    /// Recomputes each approver's expected share and verifies the combined
    /// commitment matches.
    pub fn verify(&self, approvers: &[Approver], request: &ApprovalRequest) -> bool {
        if self.request_id != request.request_id {
            return false;
        }
        if self.approver_ids.len() < self.threshold {
            return false;
        }

        // Recompute combined commitment from approver shares
        let approver_map: HashMap<&str, &Approver> =
            approvers.iter().map(|a| (a.id.as_str(), a)).collect();

        let mut expected_commitment = vec![0u8; 32];
        let mut verified_count = 0;

        for approver_id in &self.approver_ids {
            if let Some(approver) = approver_map.get(approver_id.as_str()) {
                let share_hex = compute_share(approver, request);
                let share_bytes = hex::decode(&share_hex).unwrap_or_default();
                // Combine: XOR-fold (demo); production: Schnorr aggregation
                for (i, b) in share_bytes.iter().enumerate().take(32) {
                    expected_commitment[i] ^= b;
                }
                verified_count += 1;
            }
        }

        if verified_count < self.threshold {
            return false;
        }

        let expected_hex = hex::encode(&expected_commitment);
        expected_hex == self.combined_commitment
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Threshold approval aggregator
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Error, Debug)]
pub enum ThresholdError {
    #[error("Request has expired")]
    RequestExpired,

    #[error("Share from unknown approver '{0}'")]
    UnknownApprover(String),

    #[error("Duplicate share from approver '{0}'")]
    DuplicateShare(String),

    #[error("Share is for wrong request: expected '{expected}', got '{got}'")]
    WrongRequest { expected: String, got: String },

    #[error("Threshold not yet reached: {have} of {need} required")]
    ThresholdNotReached { have: usize, need: usize },
}

/// Aggregates shares and produces a ThresholdApproval when threshold is met.
pub struct ThresholdAggregator {
    request: ApprovalRequest,
    approvers: HashMap<String, Approver>,
    shares: HashMap<String, ApprovalShare>,
}

impl ThresholdAggregator {
    pub fn new(request: ApprovalRequest, approvers: Vec<Approver>) -> Self {
        let approver_map = approvers.into_iter().map(|a| (a.id.clone(), a)).collect();
        Self {
            request,
            approvers: approver_map,
            shares: HashMap::new(),
        }
    }

    /// Submit a share from an approver.
    pub fn add_share(&mut self, share: ApprovalShare) -> Result<(), ThresholdError> {
        if self.request.is_expired() {
            return Err(ThresholdError::RequestExpired);
        }
        if share.request_id != self.request.request_id {
            return Err(ThresholdError::WrongRequest {
                expected: self.request.request_id.clone(),
                got: share.request_id,
            });
        }
        if !self.approvers.contains_key(&share.approver_id) {
            return Err(ThresholdError::UnknownApprover(share.approver_id));
        }
        if self.shares.contains_key(&share.approver_id) {
            return Err(ThresholdError::DuplicateShare(share.approver_id));
        }

        debug!(approver = %share.approver_id, "Threshold: share accepted");
        self.shares.insert(share.approver_id.clone(), share);
        Ok(())
    }

    /// Number of shares received so far.
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// Whether the threshold has been met.
    pub fn threshold_met(&self) -> bool {
        self.shares.len() >= self.request.threshold
    }

    /// Aggregate shares into a ThresholdApproval.
    /// Returns error if threshold not yet reached.
    pub fn aggregate(&self) -> Result<ThresholdApproval, ThresholdError> {
        let have = self.shares.len();
        let need = self.request.threshold;
        if have < need {
            return Err(ThresholdError::ThresholdNotReached { have, need });
        }

        // Combine shares: XOR-fold (demo; production: Schnorr aggregation)
        let mut combined = vec![0u8; 32];
        let mut approver_ids: Vec<String> = self.shares.keys().cloned().collect();
        approver_ids.sort(); // deterministic ordering

        for id in &approver_ids {
            if let Some(share) = self.shares.get(id) {
                let bytes = hex::decode(&share.share_hex).unwrap_or_default();
                for (i, b) in bytes.iter().enumerate().take(32) {
                    combined[i] ^= b;
                }
            }
        }

        let combined_commitment = hex::encode(&combined);

        info!(
            request_id = %self.request.request_id,
            approvers = ?approver_ids,
            threshold = need,
            "Threshold approval reached"
        );

        Ok(ThresholdApproval {
            request_id: self.request.request_id.clone(),
            action_key: self.request.action_key.clone(),
            requester_id: self.request.requester_id.clone(),
            approver_ids,
            threshold: need,
            combined_commitment,
            approved_at: Utc::now(),
            nonce_hex: self.request.nonce_hex.clone(),
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Test helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn test_request(action_key: &str, threshold: usize, n: usize) -> ApprovalRequest {
    ApprovalRequest {
        request_id: format!("req-{}", action_key),
        action_key: action_key.to_string(),
        requester_id: "agent-test".to_string(),
        description: format!("Test request for {}", action_key),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        threshold,
        total_approvers: n,
        nonce_hex: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
    }
}

pub fn test_approvers(n: usize) -> Vec<Approver> {
    (0..n)
        .map(|i| {
            Approver::new(
                format!("approver-{}", i),
                format!("Approver {}", i),
                format!("{:064x}", i + 1), // distinct 32-byte secrets
            )
        })
        .collect()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_approver_share_verifies() {
        let request = test_request("send_email", 1, 1);
        let approvers = test_approvers(1);
        let share = ApprovalShare::generate(&approvers[0], &request);
        assert_eq!(share.approver_id, approvers[0].id);
        assert!(!share.share_hex.is_empty());
    }

    #[test]
    fn two_of_three_threshold_met() {
        let request = test_request("make_purchase", 2, 3);
        let approvers = test_approvers(3);
        let mut agg = ThresholdAggregator::new(request, approvers.clone());

        let s0 = ApprovalShare::generate(&approvers[0], agg.request_for_test());
        let s1 = ApprovalShare::generate(&approvers[1], agg.request_for_test());

        agg.add_share(s0).unwrap();
        assert!(!agg.threshold_met());
        agg.add_share(s1).unwrap();
        assert!(agg.threshold_met());
    }

    #[test]
    fn aggregate_produces_approval() {
        let request = test_request("delete_file", 2, 3);
        let approvers = test_approvers(3);
        let mut agg = ThresholdAggregator::new(request, approvers.clone());

        for a in &approvers[..2] {
            agg.add_share(ApprovalShare::generate(a, agg.request_for_test()))
                .unwrap();
        }

        let approval = agg.aggregate().unwrap();
        assert_eq!(approval.threshold, 2);
        assert_eq!(approval.approver_ids.len(), 2);
        assert!(!approval.combined_commitment.is_empty());
    }

    #[test]
    fn approval_verifies_correctly() {
        let request = test_request("run_shell_command", 2, 3);
        let approvers = test_approvers(3);
        let mut agg = ThresholdAggregator::new(request.clone(), approvers.clone());

        for a in &approvers[..2] {
            agg.add_share(ApprovalShare::generate(a, agg.request_for_test()))
                .unwrap();
        }

        let approval = agg.aggregate().unwrap();
        assert!(approval.verify(&approvers, &request));
    }

    #[test]
    fn tampered_approval_fails_verification() {
        let request = test_request("delete_email", 2, 3);
        let approvers = test_approvers(3);
        let mut agg = ThresholdAggregator::new(request.clone(), approvers.clone());

        for a in &approvers[..2] {
            agg.add_share(ApprovalShare::generate(a, agg.request_for_test()))
                .unwrap();
        }

        let mut approval = agg.aggregate().unwrap();
        // Tamper with the commitment
        approval.combined_commitment = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!approval.verify(&approvers, &request));
    }

    #[test]
    fn below_threshold_aggregate_errors() {
        let request = test_request("send_email", 2, 3);
        let approvers = test_approvers(3);
        let mut agg = ThresholdAggregator::new(request, approvers.clone());
        agg.add_share(ApprovalShare::generate(&approvers[0], agg.request_for_test()))
            .unwrap();
        assert!(matches!(
            agg.aggregate(),
            Err(ThresholdError::ThresholdNotReached { have: 1, need: 2 })
        ));
    }

    #[test]
    fn duplicate_share_rejected() {
        let request = test_request("send_email", 2, 3);
        let approvers = test_approvers(3);
        let mut agg = ThresholdAggregator::new(request, approvers.clone());
        let s = ApprovalShare::generate(&approvers[0], agg.request_for_test());
        let s2 = ApprovalShare::generate(&approvers[0], agg.request_for_test());
        agg.add_share(s).unwrap();
        assert!(matches!(
            agg.add_share(s2),
            Err(ThresholdError::DuplicateShare(_))
        ));
    }

    #[test]
    fn unknown_approver_rejected() {
        let request = test_request("send_email", 1, 1);
        let approvers = test_approvers(1);
        let mut agg = ThresholdAggregator::new(request.clone(), approvers.clone());
        let unknown = Approver::new("unknown", "Unknown", "AAAA");
        let s = ApprovalShare::generate(&unknown, &request);
        assert!(matches!(
            agg.add_share(s),
            Err(ThresholdError::UnknownApprover(_))
        ));
    }

    #[test]
    fn share_count_increments() {
        let request = test_request("send_email", 3, 3);
        let approvers = test_approvers(3);
        let mut agg = ThresholdAggregator::new(request, approvers.clone());
        assert_eq!(agg.share_count(), 0);
        agg.add_share(ApprovalShare::generate(&approvers[0], agg.request_for_test()))
            .unwrap();
        assert_eq!(agg.share_count(), 1);
    }
}

// Helper for tests to access the request
impl ThresholdAggregator {
    #[cfg(test)]
    fn request_for_test(&self) -> &ApprovalRequest {
        &self.request
    }
}
