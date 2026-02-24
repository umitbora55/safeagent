//! Audit Log Hash-Chain (Sprint 3 - Forensics)
//!
//! Provides cryptographic integrity verification for audit logs.
//!
//! Each entry contains:
//! - chain_id: Unique identifier for the hash chain
//! - seq: Sequence number (monotonically increasing)
//! - prev_hash: SHA256 hash of the previous entry
//! - entry_hash: SHA256(prev_hash || canonical_json)
//!
//! The hash chain ensures:
//! - Entries cannot be modified without detection
//! - Entries cannot be deleted without detection
//! - Entries cannot be inserted without detection
//! - Sequence integrity is maintained

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Genesis hash for the first entry in a chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Hash-chain enabled audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedAuditEntry {
    /// Chain identifier (UUID)
    pub chain_id: String,

    /// Sequence number (starts at 1)
    pub seq: u64,

    /// Hash of the previous entry (hex-encoded SHA256)
    pub prev_hash: String,

    /// Hash of this entry (hex-encoded SHA256)
    pub entry_hash: String,

    /// Original entry timestamp
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: String,

    /// Model name
    pub model_name: String,

    /// Tier
    pub tier: String,

    /// Platform
    pub platform: String,

    /// Input tokens
    pub input_tokens: u32,

    /// Output tokens
    pub output_tokens: u32,

    /// Cost in microdollars
    pub cost_microdollars: u64,

    /// Cache status
    pub cache_status: String,

    /// Latency in milliseconds
    pub latency_ms: u64,

    /// Success flag
    pub success: bool,

    /// Error message (if any)
    pub error_message: Option<String>,

    /// Additional metadata (JSON)
    pub metadata: String,
}

impl ChainedAuditEntry {
    /// Create the canonical JSON representation for hashing.
    /// Uses BTreeMap to ensure deterministic field ordering.
    pub fn canonical_json(&self) -> String {
        let mut map = BTreeMap::new();
        map.insert("chain_id", serde_json::json!(self.chain_id));
        map.insert("seq", serde_json::json!(self.seq));
        map.insert("prev_hash", serde_json::json!(self.prev_hash));
        map.insert("timestamp", serde_json::json!(self.timestamp.to_rfc3339()));
        map.insert("event_type", serde_json::json!(self.event_type));
        map.insert("model_name", serde_json::json!(self.model_name));
        map.insert("tier", serde_json::json!(self.tier));
        map.insert("platform", serde_json::json!(self.platform));
        map.insert("input_tokens", serde_json::json!(self.input_tokens));
        map.insert("output_tokens", serde_json::json!(self.output_tokens));
        map.insert(
            "cost_microdollars",
            serde_json::json!(self.cost_microdollars),
        );
        map.insert("cache_status", serde_json::json!(self.cache_status));
        map.insert("latency_ms", serde_json::json!(self.latency_ms));
        map.insert("success", serde_json::json!(self.success));
        map.insert(
            "error_message",
            serde_json::json!(self.error_message.as_deref().unwrap_or("")),
        );
        map.insert("metadata", serde_json::json!(self.metadata));

        serde_json::to_string(&map).expect("BTreeMap serialization should not fail")
    }

    /// Compute the entry hash: SHA256(prev_hash || canonical_json)
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(self.canonical_json().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify that the entry_hash matches the computed hash.
    pub fn verify_hash(&self) -> bool {
        self.entry_hash == self.compute_hash()
    }
}

/// Hash chain state.
#[derive(Debug, Clone)]
pub struct HashChainState {
    /// Chain identifier
    pub chain_id: String,

    /// Current sequence number
    pub current_seq: u64,

    /// Hash of the last entry
    pub last_hash: String,
}

impl HashChainState {
    /// Create a new hash chain.
    pub fn new() -> Self {
        Self {
            chain_id: uuid::Uuid::new_v4().to_string(),
            current_seq: 0,
            last_hash: GENESIS_HASH.to_string(),
        }
    }

    /// Create a chain with a specific ID (for deterministic testing).
    pub fn with_id(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            current_seq: 0,
            last_hash: GENESIS_HASH.to_string(),
        }
    }

    /// Resume a chain from a known state.
    pub fn resume(chain_id: &str, current_seq: u64, last_hash: &str) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            current_seq,
            last_hash: last_hash.to_string(),
        }
    }

    /// Prepare the next entry with chain metadata.
    pub fn prepare_entry(&mut self, entry: &crate::AuditEntry) -> ChainedAuditEntry {
        self.current_seq += 1;

        let mut chained = ChainedAuditEntry {
            chain_id: self.chain_id.clone(),
            seq: self.current_seq,
            prev_hash: self.last_hash.clone(),
            entry_hash: String::new(), // Will be computed
            timestamp: entry.timestamp,
            event_type: entry.event_type.clone(),
            model_name: entry.model_name.clone(),
            tier: entry.tier.clone(),
            platform: entry.platform.clone(),
            input_tokens: entry.input_tokens,
            output_tokens: entry.output_tokens,
            cost_microdollars: entry.cost_microdollars,
            cache_status: entry.cache_status.clone(),
            latency_ms: entry.latency_ms,
            success: entry.success,
            error_message: entry.error_message.clone(),
            metadata: entry.metadata.clone(),
        };

        chained.entry_hash = chained.compute_hash();
        self.last_hash = chained.entry_hash.clone();

        chained
    }
}

impl Default for HashChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification result for a single entry.
#[derive(Debug, Clone)]
pub struct EntryVerification {
    pub seq: u64,
    pub valid: bool,
    pub error: Option<String>,
}

/// Overall chain verification result.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub chain_id: String,
    pub total_entries: u64,
    pub valid_entries: u64,
    pub first_invalid_seq: Option<u64>,
    pub errors: Vec<EntryVerification>,
    pub passed: bool,
}

/// Verify a sequence of chained audit entries.
pub fn verify_chain(entries: &[ChainedAuditEntry]) -> ChainVerification {
    if entries.is_empty() {
        return ChainVerification {
            chain_id: String::new(),
            total_entries: 0,
            valid_entries: 0,
            first_invalid_seq: None,
            errors: vec![],
            passed: true,
        };
    }

    let chain_id = entries[0].chain_id.clone();
    let mut errors = Vec::new();
    let mut valid_count = 0u64;
    let mut first_invalid: Option<u64> = None;
    let mut expected_seq = 1u64;
    let mut expected_prev_hash = GENESIS_HASH.to_string();

    for entry in entries {
        let mut entry_valid = true;
        let mut entry_errors = Vec::new();

        // Check chain_id consistency
        if entry.chain_id != chain_id {
            entry_errors.push(format!(
                "chain_id mismatch: expected '{}', got '{}'",
                chain_id, entry.chain_id
            ));
            entry_valid = false;
        }

        // Check sequence
        if entry.seq != expected_seq {
            entry_errors.push(format!(
                "seq mismatch: expected {}, got {}",
                expected_seq, entry.seq
            ));
            entry_valid = false;
        }

        // Check prev_hash linkage
        if entry.prev_hash != expected_prev_hash {
            entry_errors.push(format!(
                "prev_hash mismatch: expected '{}...', got '{}...'",
                &expected_prev_hash[..16.min(expected_prev_hash.len())],
                &entry.prev_hash[..16.min(entry.prev_hash.len())]
            ));
            entry_valid = false;
        }

        // Verify entry hash
        if !entry.verify_hash() {
            entry_errors.push(format!(
                "entry_hash invalid: computed '{}...', stored '{}...'",
                &entry.compute_hash()[..16],
                &entry.entry_hash[..16.min(entry.entry_hash.len())]
            ));
            entry_valid = false;
        }

        if entry_valid {
            valid_count += 1;
        } else {
            if first_invalid.is_none() {
                first_invalid = Some(entry.seq);
            }
            errors.push(EntryVerification {
                seq: entry.seq,
                valid: false,
                error: Some(entry_errors.join("; ")),
            });
        }

        // Update expected values for next iteration
        expected_seq = entry.seq + 1;
        expected_prev_hash = entry.entry_hash.clone();
    }

    ChainVerification {
        chain_id,
        total_entries: entries.len() as u64,
        valid_entries: valid_count,
        first_invalid_seq: first_invalid,
        errors,
        passed: first_invalid.is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditEntry;

    fn sample_entry(event: &str) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now(),
            event_type: event.to_string(),
            model_name: "test-model".to_string(),
            tier: "test".to_string(),
            platform: "test".to_string(),
            input_tokens: 100,
            output_tokens: 50,
            cost_microdollars: 500,
            cache_status: "miss".to_string(),
            latency_ms: 100,
            success: true,
            error_message: None,
            metadata: "{}".to_string(),
        }
    }

    #[test]
    fn test_chain_initialize() {
        let chain = HashChainState::new();
        assert_eq!(chain.current_seq, 0);
        assert_eq!(chain.last_hash, GENESIS_HASH);
        assert!(!chain.chain_id.is_empty());
    }

    #[test]
    fn test_chain_with_id() {
        let chain = HashChainState::with_id("test-chain-id");
        assert_eq!(chain.chain_id, "test-chain-id");
        assert_eq!(chain.current_seq, 0);
    }

    #[test]
    fn test_append_entry() {
        let mut chain = HashChainState::with_id("test-chain");
        let entry = sample_entry("test_event");

        let chained = chain.prepare_entry(&entry);

        assert_eq!(chained.chain_id, "test-chain");
        assert_eq!(chained.seq, 1);
        assert_eq!(chained.prev_hash, GENESIS_HASH);
        assert!(!chained.entry_hash.is_empty());
        assert!(chained.verify_hash());

        // Verify chain state updated
        assert_eq!(chain.current_seq, 1);
        assert_eq!(chain.last_hash, chained.entry_hash);
    }

    #[test]
    fn test_chain_linkage() {
        let mut chain = HashChainState::with_id("test-chain");

        let entry1 = chain.prepare_entry(&sample_entry("event1"));
        let entry2 = chain.prepare_entry(&sample_entry("event2"));
        let entry3 = chain.prepare_entry(&sample_entry("event3"));

        // Verify sequence
        assert_eq!(entry1.seq, 1);
        assert_eq!(entry2.seq, 2);
        assert_eq!(entry3.seq, 3);

        // Verify linkage
        assert_eq!(entry1.prev_hash, GENESIS_HASH);
        assert_eq!(entry2.prev_hash, entry1.entry_hash);
        assert_eq!(entry3.prev_hash, entry2.entry_hash);

        // Verify all hashes
        assert!(entry1.verify_hash());
        assert!(entry2.verify_hash());
        assert!(entry3.verify_hash());
    }

    #[test]
    fn test_verify_valid_chain() {
        let mut chain = HashChainState::with_id("test-chain");
        let entries: Vec<_> = (0..5)
            .map(|i| chain.prepare_entry(&sample_entry(&format!("event{}", i))))
            .collect();

        let result = verify_chain(&entries);

        assert!(result.passed);
        assert_eq!(result.total_entries, 5);
        assert_eq!(result.valid_entries, 5);
        assert!(result.first_invalid_seq.is_none());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_tamper_field_change_detected() {
        let mut chain = HashChainState::with_id("test-chain");
        let mut entries: Vec<_> = (0..3)
            .map(|i| chain.prepare_entry(&sample_entry(&format!("event{}", i))))
            .collect();

        // Tamper with the second entry
        entries[1].event_type = "TAMPERED".to_string();

        let result = verify_chain(&entries);

        assert!(!result.passed);
        assert_eq!(result.first_invalid_seq, Some(2));
    }

    #[test]
    fn test_delete_line_detected() {
        let mut chain = HashChainState::with_id("test-chain");
        let mut entries: Vec<_> = (0..5)
            .map(|i| chain.prepare_entry(&sample_entry(&format!("event{}", i))))
            .collect();

        // Delete the third entry
        entries.remove(2);

        let result = verify_chain(&entries);

        assert!(!result.passed);
        // After deletion, entry with seq=4 will be at position 2
        // but we expect seq=3 at that position
        assert_eq!(result.first_invalid_seq, Some(4));
    }

    #[test]
    fn test_insert_line_detected() {
        let mut chain = HashChainState::with_id("test-chain");
        let mut entries: Vec<_> = (0..3)
            .map(|i| chain.prepare_entry(&sample_entry(&format!("event{}", i))))
            .collect();

        // Create a fake entry and insert it
        let fake = ChainedAuditEntry {
            chain_id: "test-chain".to_string(),
            seq: 2,
            prev_hash: entries[0].entry_hash.clone(),
            entry_hash: "fake_hash".to_string(),
            timestamp: Utc::now(),
            event_type: "INSERTED".to_string(),
            model_name: String::new(),
            tier: String::new(),
            platform: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            cost_microdollars: 0,
            cache_status: String::new(),
            latency_ms: 0,
            success: true,
            error_message: None,
            metadata: "{}".to_string(),
        };

        entries.insert(1, fake);

        let result = verify_chain(&entries);

        assert!(!result.passed);
        assert!(result.first_invalid_seq.is_some());
    }

    #[test]
    fn test_seq_mismatch_detected() {
        let mut chain = HashChainState::with_id("test-chain");
        let mut entries: Vec<_> = (0..3)
            .map(|i| chain.prepare_entry(&sample_entry(&format!("event{}", i))))
            .collect();

        // Modify seq without updating hash
        entries[1].seq = 99;

        let result = verify_chain(&entries);

        assert!(!result.passed);
        assert_eq!(result.first_invalid_seq, Some(99));
    }

    #[test]
    fn test_empty_chain_valid() {
        let result = verify_chain(&[]);
        assert!(result.passed);
        assert_eq!(result.total_entries, 0);
    }

    #[test]
    fn test_canonical_json_deterministic() {
        let mut chain = HashChainState::with_id("test-chain");
        let entry = sample_entry("test");

        let chained1 = chain.prepare_entry(&entry);
        let json1 = chained1.canonical_json();

        // Reset chain and create same entry
        let mut chain2 = HashChainState::with_id("test-chain");
        let chained2 = chain2.prepare_entry(&entry);
        let json2 = chained2.canonical_json();

        // Should be identical (deterministic)
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_hash_is_sha256() {
        let mut chain = HashChainState::with_id("test-chain");
        let entry = chain.prepare_entry(&sample_entry("test"));

        // SHA256 produces 64 hex characters
        assert_eq!(entry.entry_hash.len(), 64);

        // Verify it's valid hex
        assert!(hex::decode(&entry.entry_hash).is_ok());
    }

    #[test]
    fn test_resume_chain() {
        let mut chain = HashChainState::with_id("test-chain");
        let entry1 = chain.prepare_entry(&sample_entry("event1"));
        let entry2 = chain.prepare_entry(&sample_entry("event2"));

        // Resume from entry2
        let mut resumed = HashChainState::resume("test-chain", entry2.seq, &entry2.entry_hash);

        let entry3 = resumed.prepare_entry(&sample_entry("event3"));

        assert_eq!(entry3.seq, 3);
        assert_eq!(entry3.prev_hash, entry2.entry_hash);
        assert!(entry3.verify_hash());

        // Full chain should verify
        let all_entries = vec![entry1, entry2, entry3];
        let result = verify_chain(&all_entries);
        assert!(result.passed);
    }
}
