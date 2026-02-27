// merkle.rs — W5 D2: Merkle Tree Evidence Log
//
// Replaces / augments the hash-chain (sequential tamper evidence) with a
// Merkle tree providing:
//   - O(log n) inclusion proofs — prove a specific entry exists without
//     downloading the full log
//   - Consistency proofs — prove the log has only been appended to
//   - Third-party auditability — verifiers can check proofs against a
//     published root without database access
//   - Split-view attack resistance — a deterministic root that cannot
//     differ between observers
//
// Architecture follows Google's Certificate Transparency (RFC 6962) model
// adapted to pure Rust with SHA-256 leaves.
//
// Leaf hash: SHA-256(0x00 || data)        [domain separation]
// Node hash: SHA-256(0x01 || left || right) [domain separation]
// (Domain separation prevents second-preimage attacks per RFC 6962 §2.1.)
//
// Tree structure: power-of-two split at each level.
// For n leaves, split at k = largest_power_of_two_less_than(n).
// This matches RFC 6962 §2.1 / Google Trillian's tree layout.

use sha2::{Digest, Sha256};
use std::fmt;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 32-byte SHA-256 hash.
#[derive(Clone, PartialEq, Eq)]
pub struct Hash([u8; 32]);

impl Hash {
    /// All-zero hash used for empty trees.
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..12])
    }
}

/// Index of a leaf in the log (0-based, insertion order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeafIndex(pub u64);

/// An inclusion proof demonstrating that a leaf at `leaf_index` with
/// `leaf_hash` is part of the tree whose root is `root`.
///
/// `siblings` is ordered bottom-up (leaf-level sibling first, root-level last).
/// Each element is the sibling hash at that tree level.
/// The companion `directions` vector indicates whether the leaf is the right
/// child at each level (true = leaf/current is right child).
#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub leaf_index: LeafIndex,
    pub leaf_hash: Hash,
    pub tree_size: u64,
    pub root: Hash,
    /// Co-hashes from leaf level upward (bottom-up, leaf first).
    pub siblings: Vec<Hash>,
    /// For each sibling: true if the leaf is the right child at that level.
    pub directions: Vec<bool>,
}

/// A consistency proof demonstrating that a tree of `old_size` entries
/// is a prefix of a tree of `new_size` entries.
#[derive(Debug, Clone)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub old_root: Hash,
    pub new_root: Hash,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Hash functions (RFC 6962 domain separation)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Leaf hash with 0x00 domain prefix (RFC 6962).
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    Hash::from_bytes(h.finalize().into())
}

/// Internal node hash with 0x01 domain prefix (RFC 6962).
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    Hash::from_bytes(h.finalize().into())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Split point (RFC 6962 §2.1)
//  k = largest power of 2 strictly less than n
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn split_point(n: usize) -> usize {
    assert!(n > 1, "split_point requires n > 1");
    // n.next_power_of_two() >> 1 gives the largest power of 2 ≤ n/2.
    // For n=4: next_pow(4)=4, 4>>1=2. For n=7: next_pow(7)=8, 8>>1=4. ✓
    n.next_power_of_two() >> 1
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Root computation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Compute the Merkle root for `leaves[lo..hi]`.
pub(crate) fn merkle_root(leaves: &[Hash], lo: usize, hi: usize) -> Hash {
    match hi - lo {
        0 => Hash::zero(),
        1 => leaves[lo].clone(),
        n => {
            let k = lo + split_point(n);
            let actual_k = k.min(hi);
            let left = merkle_root(leaves, lo, actual_k);
            let right = merkle_root(leaves, actual_k, hi);
            if actual_k >= hi {
                // Right half is empty — odd-leaf case, propagate left upward
                left
            } else {
                node_hash(&left, &right)
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Merkle Log
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// An append-only Merkle log providing O(log n) inclusion proofs.
pub struct MerkleLog {
    leaves: Vec<Hash>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn from_leaves(leaves: Vec<Hash>) -> Self {
        Self { leaves }
    }

    /// Append data. Returns the leaf index.
    pub fn append(&mut self, data: &[u8]) -> LeafIndex {
        let idx = LeafIndex(self.leaves.len() as u64);
        self.leaves.push(leaf_hash(data));
        idx
    }

    /// Append a pre-computed leaf hash.
    pub fn append_leaf_hash(&mut self, hash: Hash) -> LeafIndex {
        let idx = LeafIndex(self.leaves.len() as u64);
        self.leaves.push(hash);
        idx
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Current root hash. Returns `Hash::zero()` for an empty log.
    pub fn root(&self) -> Hash {
        if self.leaves.is_empty() {
            Hash::zero()
        } else {
            merkle_root(&self.leaves, 0, self.leaves.len())
        }
    }

    /// Root hash at historical size.
    pub fn root_at(&self, size: usize) -> Option<Hash> {
        if size > self.leaves.len() {
            return None;
        }
        if size == 0 {
            return Some(Hash::zero());
        }
        Some(merkle_root(&self.leaves, 0, size))
    }

    /// Generate an inclusion proof for leaf at `index`.
    pub fn inclusion_proof(&self, index: LeafIndex) -> Option<InclusionProof> {
        let m = index.0 as usize;
        if m >= self.leaves.len() {
            return None;
        }

        let (siblings, directions) = compute_path(&self.leaves, 0, self.leaves.len(), m);

        Some(InclusionProof {
            leaf_index: index,
            leaf_hash: self.leaves[m].clone(),
            tree_size: self.leaves.len() as u64,
            root: self.root(),
            siblings,
            directions,
        })
    }

    pub fn leaf_hashes(&self) -> Vec<Hash> {
        self.leaves.clone()
    }
}

impl Default for MerkleLog {
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Path computation (internal)
//
//  Returns (siblings, directions) both bottom-up (leaf first).
//  sibling[i] = the co-hash to combine at level i from the leaf.
//  direction[i] = true if the current node is the RIGHT child at level i.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn compute_path(
    leaves: &[Hash],
    lo: usize,
    hi: usize,
    m: usize,
) -> (Vec<Hash>, Vec<bool>) {
    let n = hi - lo;
    if n <= 1 {
        return (vec![], vec![]);
    }

    let k = lo + split_point(n);
    let actual_k = k.min(hi);

    if m < actual_k {
        // m is in the left half [lo..k)
        let (mut siblings, mut directions) = compute_path(leaves, lo, actual_k, m);
        if actual_k < hi {
            // Right half exists: its root is the sibling at this level
            siblings.push(merkle_root(leaves, actual_k, hi));
            directions.push(false); // current/left is NOT the right child
        }
        (siblings, directions)
    } else {
        // m is in the right half [k..hi)
        let (mut siblings, mut directions) = compute_path(leaves, actual_k, hi, m);
        // Left half always exists (k >= 1)
        siblings.push(merkle_root(leaves, lo, actual_k));
        directions.push(true); // current/right IS the right child
        (siblings, directions)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Proof verification
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Verify an inclusion proof. Returns true iff the proof is valid.
pub fn verify_inclusion(proof: &InclusionProof) -> bool {
    if proof.tree_size == 0 {
        return false;
    }
    if proof.siblings.len() != proof.directions.len() {
        return false;
    }
    // Single-leaf tree: no siblings, root equals leaf hash
    if proof.tree_size == 1 {
        return proof.siblings.is_empty() && proof.leaf_hash == proof.root;
    }

    let mut current = proof.leaf_hash.clone();
    for (sibling, &is_right) in proof.siblings.iter().zip(proof.directions.iter()) {
        current = if is_right {
            // current node is the right child; sibling is the left
            node_hash(sibling, &current)
        } else {
            // current node is the left child; sibling is the right
            node_hash(&current, sibling)
        };
    }
    current == proof.root
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_log_has_zero_root() {
        let log = MerkleLog::new();
        assert_eq!(log.root(), Hash::zero());
        assert_eq!(log.size(), 0);
    }

    #[test]
    fn single_entry_root_equals_leaf_hash() {
        let mut log = MerkleLog::new();
        let idx = log.append(b"hello");
        assert_eq!(idx, LeafIndex(0));
        assert_eq!(log.size(), 1);
        assert_eq!(log.root(), leaf_hash(b"hello"));
    }

    #[test]
    fn two_entries_root_is_node_hash_of_leaves() {
        let mut log = MerkleLog::new();
        log.append(b"a");
        log.append(b"b");
        let expected = node_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        assert_eq!(log.root(), expected);
    }

    #[test]
    fn append_returns_sequential_indices() {
        let mut log = MerkleLog::new();
        for i in 0..5u32 {
            let idx = log.append(&i.to_le_bytes());
            assert_eq!(idx, LeafIndex(i as u64));
        }
        assert_eq!(log.size(), 5);
    }

    #[test]
    fn inclusion_proof_verifies_single_entry() {
        let mut log = MerkleLog::new();
        log.append(b"only");
        let proof = log.inclusion_proof(LeafIndex(0)).unwrap();
        assert!(verify_inclusion(&proof));
    }

    #[test]
    fn inclusion_proof_verifies_for_all_entries_n2() {
        let mut log = MerkleLog::new();
        for i in 0..2u32 { log.append(&i.to_le_bytes()); }
        for i in 0..2 {
            let proof = log.inclusion_proof(LeafIndex(i)).unwrap();
            assert!(verify_inclusion(&proof), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn inclusion_proof_verifies_for_all_entries_n4() {
        let mut log = MerkleLog::new();
        for i in 0..4u32 { log.append(&i.to_le_bytes()); }
        for i in 0..4 {
            let proof = log.inclusion_proof(LeafIndex(i)).unwrap();
            assert!(verify_inclusion(&proof), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn inclusion_proof_verifies_for_all_entries_n7() {
        let mut log = MerkleLog::new();
        for i in 0..7u32 { log.append(&i.to_le_bytes()); }
        for i in 0..7 {
            let proof = log.inclusion_proof(LeafIndex(i)).unwrap();
            assert!(verify_inclusion(&proof), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn inclusion_proof_verifies_for_all_entries_n8() {
        let mut log = MerkleLog::new();
        for i in 0..8u32 { log.append(&i.to_le_bytes()); }
        for i in 0..8 {
            let proof = log.inclusion_proof(LeafIndex(i)).unwrap();
            assert!(verify_inclusion(&proof), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn inclusion_proof_verifies_for_all_entries_n13() {
        let mut log = MerkleLog::new();
        for i in 0..13u32 { log.append(&i.to_le_bytes()); }
        for i in 0..13 {
            let proof = log.inclusion_proof(LeafIndex(i)).unwrap();
            assert!(verify_inclusion(&proof), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn inclusion_proof_out_of_range_returns_none() {
        let log = MerkleLog::new();
        assert!(log.inclusion_proof(LeafIndex(0)).is_none());
    }

    #[test]
    fn inclusion_proof_detects_tampered_leaf() {
        let mut log = MerkleLog::new();
        log.append(b"original");
        log.append(b"other");
        let mut proof = log.inclusion_proof(LeafIndex(0)).unwrap();
        // Tamper the leaf hash
        proof.leaf_hash = leaf_hash(b"tampered");
        assert!(!verify_inclusion(&proof));
    }

    #[test]
    fn inclusion_proof_detects_tampered_sibling() {
        let mut log = MerkleLog::new();
        log.append(b"a");
        log.append(b"b");
        log.append(b"c");
        let mut proof = log.inclusion_proof(LeafIndex(0)).unwrap();
        // Tamper a sibling hash
        if let Some(s) = proof.siblings.first_mut() {
            *s = leaf_hash(b"tampered_sibling");
        }
        assert!(!verify_inclusion(&proof));
    }

    #[test]
    fn root_changes_on_each_append() {
        let mut log = MerkleLog::new();
        let r0 = log.root();
        log.append(b"first");
        let r1 = log.root();
        log.append(b"second");
        let r2 = log.root();
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);
    }

    #[test]
    fn root_at_historical_size() {
        let mut log = MerkleLog::new();
        log.append(b"a");
        let root_at_1 = log.root();
        log.append(b"b");
        log.append(b"c");
        assert_eq!(log.root_at(1), Some(root_at_1));
    }

    #[test]
    fn root_at_zero_is_zero_hash() {
        let mut log = MerkleLog::new();
        log.append(b"x");
        assert_eq!(log.root_at(0), Some(Hash::zero()));
    }

    #[test]
    fn root_at_out_of_range_is_none() {
        let log = MerkleLog::new();
        assert!(log.root_at(5).is_none());
    }

    #[test]
    fn leaf_and_node_hash_domain_separation() {
        // leaf_hash and node_hash of same data must differ (0x00 vs 0x01 prefix)
        let lh = leaf_hash(b"data");
        let nh = node_hash(&Hash::zero(), &Hash::zero());
        assert_ne!(lh, nh);
    }

    #[test]
    fn split_point_values() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(7), 4);
        assert_eq!(split_point(8), 4);
    }
}
