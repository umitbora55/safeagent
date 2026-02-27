// safeagent-sigstore-bridge
//
// W5 D6: Sigstore integration for tool manifest and evidence signing
//
// Sigstore (sigstore.dev) provides keyless signing via:
//   Fulcio  — ephemeral certificate authority; signs via OIDC identity
//   Rekor   — immutable transparency log (tile-backed Rekor v2, GA 2025)
//   Cosign  — client tooling for signing/verifying OCI images and blobs
//
// SafeAgent integration points:
//   1. Tool manifests   — Cosign-compatible signature over manifest JSON
//   2. Evidence entries — each audit log entry optionally carries a
//                         Sigstore bundle (Rekor entry + certificate)
//   3. Supply-chain verification — verify MCP server containers via
//                                  Cosign before registering in the tool registry
//
// In this crate we implement:
//   - ManifestDigest — SHA-256 digest of a tool manifest
//   - SigstoreBundle — serialisable Sigstore bundle (RFC 9162 / bundle spec)
//   - BundleVerifier — verifies bundle authenticity (structural + digest)
//   - RekorEntry     — minimal Rekor v2 entry metadata
//
// Note: full Sigstore verification (TUF root, Fulcio CT, network calls)
// requires the `sigstore` Rust crate (sigstore-rs). This crate provides
// the data model and offline/structural validation. Enable the
// `sigstore-client` feature for online verification via sigstore-rs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Digest types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// SHA-256 digest in hex-encoded form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Digest(pub String);

impl Sha256Digest {
    /// Compute the SHA-256 digest of arbitrary bytes.
    pub fn of(data: &[u8]) -> Self {
        let hash = Sha256::digest(data);
        Self(hex::encode(hash))
    }

    /// Compute from a UTF-8 string.
    pub fn of_str(s: &str) -> Self {
        Self::of(s.as_bytes())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tool manifest types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Identifies the signing algorithm used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    EcdsaP256Sha256,
    Ed25519,
    RsaPkcs1v15Sha256,
}

/// A signed tool manifest — the artifact being protected by Sigstore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    /// Tool name (MCP server or individual tool).
    pub tool_name: String,
    /// Semantic version of the tool.
    pub version: String,
    /// OCI image reference (if containerised).
    pub image_ref: Option<String>,
    /// SHA-256 digest of the tool's implementation artifact.
    pub artifact_digest: Sha256Digest,
    /// ISO 8601 publication timestamp.
    pub published_at: DateTime<Utc>,
    /// Publisher's OIDC identity (email from Fulcio certificate).
    pub publisher_identity: String,
}

impl ToolManifest {
    /// Compute the canonical JSON digest of this manifest.
    pub fn canonical_digest(&self) -> Sha256Digest {
        // Serialize deterministically — field order matters for digest stability.
        let canonical = serde_json::json!({
            "tool_name": self.tool_name,
            "version": self.version,
            "image_ref": self.image_ref,
            "artifact_digest": self.artifact_digest.0,
            "published_at": self.published_at.to_rfc3339(),
            "publisher_identity": self.publisher_identity,
        });
        Sha256Digest::of_str(&canonical.to_string())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Sigstore bundle (Cosign bundle spec)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Fulcio-issued X.509 certificate metadata.
/// The certificate binds an ephemeral public key to an OIDC identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulcioCertificate {
    /// PEM-encoded leaf certificate.
    pub pem: String,
    /// OIDC Subject Alternative Name (email or URI).
    pub identity: String,
    /// OIDC issuer (e.g. "https://accounts.google.com").
    pub issuer: String,
    /// Certificate validity window.
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl FulcioCertificate {
    /// Whether the certificate is currently valid.
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }
}

/// Rekor v2 transparency log entry metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorEntry {
    /// Rekor log server URL.
    pub log_url: String,
    /// Integrated time (seconds since Unix epoch) — when Rekor included the entry.
    pub integrated_time: i64,
    /// Log index for this entry.
    pub log_index: u64,
    /// SHA-256 tree hash at inclusion time.
    pub tree_hash: Sha256Digest,
    /// SET (Signed Entry Timestamp) — Rekor's proof of inclusion.
    pub set: String,
}

/// A complete Sigstore bundle containing signature, certificate, and Rekor entry.
///
/// Follows the Sigstore Bundle Specification v0.3+.
/// See: https://github.com/sigstore/protobuf-specs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreBundle {
    /// Digest of the artifact this bundle covers.
    pub artifact_digest: Sha256Digest,
    /// Base64-encoded signature over the artifact digest.
    pub signature_b64: String,
    /// Signing algorithm used.
    pub algorithm: SigningAlgorithm,
    /// Fulcio certificate containing the ephemeral public key.
    pub certificate: FulcioCertificate,
    /// Rekor transparency log entry.
    pub rekor_entry: RekorEntry,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Verification errors
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Error, Debug, Clone)]
pub enum VerificationError {
    #[error("Certificate has expired or is not yet valid")]
    CertificateExpired,

    #[error("Certificate identity '{found}' does not match expected '{expected}'")]
    IdentityMismatch { expected: String, found: String },

    #[error("Certificate issuer '{found}' is not in the trusted issuer list")]
    UntrustedIssuer { found: String },

    #[error("Artifact digest in bundle does not match manifest digest")]
    DigestMismatch,

    #[error("Bundle is missing required field: {0}")]
    MissingField(String),

    #[error("Rekor entry log index {0} is below minimum trusted index")]
    StaleRekorEntry(u64),
}

/// Outcome of bundle verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// Bundle is structurally valid and passes all configured checks.
    Verified {
        identity: String,
        issuer: String,
        log_index: u64,
    },
    /// Bundle failed one or more verification checks.
    Failed(String),
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Bundle verifier
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Configuration for offline/structural bundle verification.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// OIDC issuers considered trustworthy.
    pub trusted_issuers: Vec<String>,
    /// Expected identity (email) for publisher verification. None = any.
    pub expected_identity: Option<String>,
    /// Minimum Rekor log index. Entries older than this are not trusted.
    pub min_log_index: u64,
    /// Whether to enforce certificate temporal validity.
    pub check_cert_validity: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            trusted_issuers: vec![
                "https://accounts.google.com".to_string(),
                "https://github.com/login/oauth".to_string(),
                "https://token.actions.githubusercontent.com".to_string(),
            ],
            expected_identity: None,
            min_log_index: 0,
            check_cert_validity: true,
        }
    }
}

/// Offline bundle verifier — structural and policy checks.
///
/// Does NOT make network calls. For online verification (CT log, Rekor
/// consistency proof), enable the `sigstore-client` feature.
pub struct BundleVerifier {
    config: VerifierConfig,
}

impl BundleVerifier {
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(VerifierConfig::default())
    }

    /// Verify a Sigstore bundle against the expected artifact digest.
    ///
    /// Checks performed:
    ///   1. Artifact digest in bundle matches provided manifest digest
    ///   2. Certificate issuer is in the trusted issuers list
    ///   3. Certificate identity matches expected (if configured)
    ///   4. Certificate temporal validity (if configured)
    ///   5. Rekor log index meets minimum
    pub fn verify(
        &self,
        bundle: &SigstoreBundle,
        manifest_digest: &Sha256Digest,
    ) -> VerificationOutcome {
        // 1. Artifact digest match
        if bundle.artifact_digest != *manifest_digest {
            warn!(
                bundle_digest = %bundle.artifact_digest.0,
                manifest_digest = %manifest_digest.0,
                "Sigstore bundle artifact digest mismatch"
            );
            return VerificationOutcome::Failed(
                VerificationError::DigestMismatch.to_string(),
            );
        }

        // 2. Trusted issuer
        let cert = &bundle.certificate;
        if !self.config.trusted_issuers.contains(&cert.issuer) {
            warn!(issuer = %cert.issuer, "Sigstore: untrusted OIDC issuer");
            return VerificationOutcome::Failed(
                VerificationError::UntrustedIssuer {
                    found: cert.issuer.clone(),
                }
                .to_string(),
            );
        }

        // 3. Identity check
        if let Some(ref expected) = self.config.expected_identity {
            if &cert.identity != expected {
                return VerificationOutcome::Failed(
                    VerificationError::IdentityMismatch {
                        expected: expected.clone(),
                        found: cert.identity.clone(),
                    }
                    .to_string(),
                );
            }
        }

        // 4. Certificate validity
        if self.config.check_cert_validity && !cert.is_valid() {
            return VerificationOutcome::Failed(
                VerificationError::CertificateExpired.to_string(),
            );
        }

        // 5. Rekor log index
        if bundle.rekor_entry.log_index < self.config.min_log_index {
            return VerificationOutcome::Failed(
                VerificationError::StaleRekorEntry(bundle.rekor_entry.log_index).to_string(),
            );
        }

        debug!(
            identity = %cert.identity,
            issuer = %cert.issuer,
            log_index = bundle.rekor_entry.log_index,
            "Sigstore bundle verified"
        );

        VerificationOutcome::Verified {
            identity: cert.identity.clone(),
            issuer: cert.issuer.clone(),
            log_index: bundle.rekor_entry.log_index,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Test helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Build a fake-but-structurally-valid SigstoreBundle for testing.
pub fn test_bundle(artifact_digest: &Sha256Digest, identity: &str) -> SigstoreBundle {
    let now = Utc::now();
    SigstoreBundle {
        artifact_digest: artifact_digest.clone(),
        signature_b64: "AAAA".to_string(),
        algorithm: SigningAlgorithm::EcdsaP256Sha256,
        certificate: FulcioCertificate {
            pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----".to_string(),
            identity: identity.to_string(),
            issuer: "https://accounts.google.com".to_string(),
            not_before: now - chrono::Duration::minutes(5),
            not_after: now + chrono::Duration::hours(1),
        },
        rekor_entry: RekorEntry {
            log_url: "https://rekor.sigstore.dev".to_string(),
            integrated_time: now.timestamp(),
            log_index: 1_000_000,
            tree_hash: Sha256Digest::of_str("root"),
            set: "FAKE_SET".to_string(),
        },
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> BundleVerifier {
        BundleVerifier::with_defaults()
    }

    fn manifest_data() -> &'static str {
        r#"{"tool":"echo","version":"1.0"}"#
    }

    fn manifest_digest() -> Sha256Digest {
        Sha256Digest::of_str(manifest_data())
    }

    #[test]
    fn sha256_digest_of_str_is_deterministic() {
        let d1 = Sha256Digest::of_str("hello");
        let d2 = Sha256Digest::of_str("hello");
        assert_eq!(d1, d2);
    }

    #[test]
    fn sha256_digest_differs_for_different_inputs() {
        let d1 = Sha256Digest::of_str("hello");
        let d2 = Sha256Digest::of_str("world");
        assert_ne!(d1, d2);
    }

    #[test]
    fn sha256_digest_has_correct_format() {
        // Output must be 64 hex characters (32 bytes).
        let d = Sha256Digest::of_str("abc");
        assert_eq!(d.0.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(
            d.0.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA-256 hex must be all hex digits"
        );
        // Must be deterministic.
        assert_eq!(d, Sha256Digest::of_str("abc"));
    }

    #[test]
    fn valid_bundle_verifies() {
        let digest = manifest_digest();
        let bundle = test_bundle(&digest, "publisher@example.com");
        let v = verifier();
        assert!(matches!(
            v.verify(&bundle, &digest),
            VerificationOutcome::Verified { .. }
        ));
    }

    #[test]
    fn digest_mismatch_fails() {
        let bundle_digest = Sha256Digest::of_str("original_data");
        let manifest_digest = Sha256Digest::of_str("different_data");
        let bundle = test_bundle(&bundle_digest, "publisher@example.com");
        let v = verifier();
        assert!(matches!(
            v.verify(&bundle, &manifest_digest),
            VerificationOutcome::Failed(_)
        ));
    }

    #[test]
    fn untrusted_issuer_fails() {
        let digest = manifest_digest();
        let mut bundle = test_bundle(&digest, "publisher@example.com");
        bundle.certificate.issuer = "https://evil-oidc.com".to_string();
        let v = verifier();
        assert!(matches!(
            v.verify(&bundle, &digest),
            VerificationOutcome::Failed(_)
        ));
    }

    #[test]
    fn identity_mismatch_fails() {
        let digest = manifest_digest();
        let bundle = test_bundle(&digest, "publisher@example.com");
        let config = VerifierConfig {
            expected_identity: Some("expected@example.com".to_string()),
            ..Default::default()
        };
        let v = BundleVerifier::new(config);
        assert!(matches!(
            v.verify(&bundle, &digest),
            VerificationOutcome::Failed(_)
        ));
    }

    #[test]
    fn identity_match_verifies() {
        let digest = manifest_digest();
        let bundle = test_bundle(&digest, "expected@example.com");
        let config = VerifierConfig {
            expected_identity: Some("expected@example.com".to_string()),
            ..Default::default()
        };
        let v = BundleVerifier::new(config);
        assert!(matches!(
            v.verify(&bundle, &digest),
            VerificationOutcome::Verified { .. }
        ));
    }

    #[test]
    fn expired_cert_fails() {
        let digest = manifest_digest();
        let mut bundle = test_bundle(&digest, "publisher@example.com");
        // Set certificate to be in the past
        bundle.certificate.not_after = Utc::now() - chrono::Duration::hours(1);
        let v = verifier();
        assert!(matches!(
            v.verify(&bundle, &digest),
            VerificationOutcome::Failed(_)
        ));
    }

    #[test]
    fn stale_rekor_entry_fails() {
        let digest = manifest_digest();
        let mut bundle = test_bundle(&digest, "publisher@example.com");
        bundle.rekor_entry.log_index = 5;
        let config = VerifierConfig {
            min_log_index: 1000,
            ..Default::default()
        };
        let v = BundleVerifier::new(config);
        assert!(matches!(
            v.verify(&bundle, &digest),
            VerificationOutcome::Failed(_)
        ));
    }

    #[test]
    fn tool_manifest_canonical_digest_stable() {
        let m = ToolManifest {
            tool_name: "echo-tool".to_string(),
            version: "1.2.3".to_string(),
            image_ref: Some("ghcr.io/org/echo-tool:1.2.3".to_string()),
            artifact_digest: Sha256Digest::of_str("bytes"),
            published_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            publisher_identity: "dev@safeagent.io".to_string(),
        };
        let d1 = m.canonical_digest();
        let d2 = m.canonical_digest();
        assert_eq!(d1, d2);
    }
}
