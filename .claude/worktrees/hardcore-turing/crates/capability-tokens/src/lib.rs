//! Capability Tokens (G2 Security Feature)
//!
//! PASETO v4.public tokens with:
//! - Mandatory TTL (max 5 minutes)
//! - Scoped permissions
//! - Replay prevention via nonce cache
//! - Runtime enforcement
//!
//! Security guarantees:
//! - Ed25519 signatures (v4.public)
//! - Time-bounded tokens
//! - Single-use nonces
//! - Scope-based access control

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::public;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};
use uuid::Uuid;

/// Maximum allowed TTL for capability tokens (5 minutes).
const MAX_TTL_SECONDS: i64 = 300;

/// Default TTL for capability tokens (1 minute).
const DEFAULT_TTL_SECONDS: i64 = 60;

/// Nonce cache cleanup interval (expired entries older than this are removed).
const NONCE_CACHE_CLEANUP_SECONDS: i64 = 600;

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token has expired")]
    Expired,

    #[error("Token not yet valid (issued in the future)")]
    NotYetValid,

    #[error("Invalid token signature")]
    InvalidSignature,

    #[error("Token has already been used (replay detected)")]
    ReplayDetected,

    #[error("Token scope mismatch: required '{required}', got '{actual}'")]
    ScopeMismatch { required: String, actual: String },

    #[error("Missing required scope: '{0}'")]
    MissingScope(String),

    #[error("TTL exceeds maximum allowed ({0} > {MAX_TTL_SECONDS})")]
    TtlTooLong(i64),

    #[error("Token generation failed: {0}")]
    GenerationFailed(String),

    #[error("Token verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid token format: {0}")]
    InvalidFormat(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
}

/// Scope defines what actions a capability token permits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// Execute a specific skill
    Skill(String),

    /// Read from a specific resource
    Read(String),

    /// Write to a specific resource
    Write(String),

    /// Administrative action
    Admin(String),

    /// Custom scope
    Custom(String),

    /// Wildcard - grants all permissions (use with caution)
    All,
}

impl Scope {
    /// Check if this scope satisfies the required scope.
    pub fn satisfies(&self, required: &Scope) -> bool {
        match self {
            Scope::All => true,
            other => other == required,
        }
    }

    /// Convert scope to string representation.
    pub fn to_scope_string(&self) -> String {
        match self {
            Scope::Skill(s) => format!("skill:{}", s),
            Scope::Read(s) => format!("read:{}", s),
            Scope::Write(s) => format!("write:{}", s),
            Scope::Admin(s) => format!("admin:{}", s),
            Scope::Custom(s) => format!("custom:{}", s),
            Scope::All => "*".to_string(),
        }
    }

    /// Parse scope from string representation.
    pub fn from_scope_string(s: &str) -> Self {
        if s == "*" {
            return Scope::All;
        }

        if let Some(rest) = s.strip_prefix("skill:") {
            Scope::Skill(rest.to_string())
        } else if let Some(rest) = s.strip_prefix("read:") {
            Scope::Read(rest.to_string())
        } else if let Some(rest) = s.strip_prefix("write:") {
            Scope::Write(rest.to_string())
        } else if let Some(rest) = s.strip_prefix("admin:") {
            Scope::Admin(rest.to_string())
        } else if let Some(rest) = s.strip_prefix("custom:") {
            Scope::Custom(rest.to_string())
        } else {
            Scope::Custom(s.to_string())
        }
    }
}

/// Claims embedded in a capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Unique token ID (nonce for replay prevention)
    pub jti: String,

    /// Issued at timestamp
    pub iat: DateTime<Utc>,

    /// Expiration timestamp
    pub exp: DateTime<Utc>,

    /// Not before timestamp
    pub nbf: DateTime<Utc>,

    /// Issuer
    pub iss: String,

    /// Subject (user or service ID)
    pub sub: String,

    /// Granted scopes
    pub scopes: Vec<String>,
}

impl CapabilityClaims {
    /// Create new claims with specified parameters.
    pub fn new(subject: &str, scopes: Vec<Scope>, ttl_seconds: i64) -> Result<Self, TokenError> {
        if ttl_seconds > MAX_TTL_SECONDS {
            return Err(TokenError::TtlTooLong(ttl_seconds));
        }

        let now = Utc::now();
        let ttl = Duration::seconds(ttl_seconds);

        Ok(Self {
            jti: Uuid::new_v4().to_string(),
            iat: now,
            nbf: now,
            exp: now + ttl,
            iss: "safeagent".to_string(),
            sub: subject.to_string(),
            scopes: scopes.iter().map(|s| s.to_scope_string()).collect(),
        })
    }

    /// Create claims with default TTL.
    pub fn with_default_ttl(subject: &str, scopes: Vec<Scope>) -> Result<Self, TokenError> {
        Self::new(subject, scopes, DEFAULT_TTL_SECONDS)
    }

    /// Check if token has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.exp
    }

    /// Check if token is valid (not expired, not future).
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.nbf && now <= self.exp
    }

    /// Get parsed scopes.
    pub fn get_scopes(&self) -> Vec<Scope> {
        self.scopes
            .iter()
            .map(|s| Scope::from_scope_string(s))
            .collect()
    }

    /// Check if claims include a scope that satisfies the required scope.
    pub fn has_scope(&self, required: &Scope) -> bool {
        self.get_scopes().iter().any(|s| s.satisfies(required))
    }
}

/// Nonce entry in the replay prevention cache.
#[derive(Debug)]
struct NonceEntry {
    expires_at: DateTime<Utc>,
}

/// Capability token service.
///
/// Handles token generation, verification, and replay prevention.
pub struct CapabilityTokenService {
    /// Ed25519 verifying key (public) - kept for public key export
    verifying_key: VerifyingKey,

    /// PASETO asymmetric key pair
    key_pair: AsymmetricKeyPair<V4>,

    /// Nonce cache for replay prevention
    nonce_cache: Arc<DashMap<String, NonceEntry>>,

    /// Issuer identifier
    issuer: String,
}

impl CapabilityTokenService {
    /// Create a new service with a randomly generated key pair.
    pub fn new() -> Result<Self, TokenError> {
        Self::with_issuer("safeagent")
    }

    /// Create a new service with a custom issuer.
    pub fn with_issuer(issuer: &str) -> Result<Self, TokenError> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        // PASETO v4 expects a 64-byte secret key (seed + public key)
        // ed25519-dalek provides the keypair bytes via to_keypair_bytes()
        let keypair_bytes = signing_key.to_keypair_bytes();

        let secret_key = AsymmetricSecretKey::<V4>::from(&keypair_bytes[..])
            .map_err(|e| TokenError::KeyGenerationFailed(e.to_string()))?;
        let public_key = AsymmetricPublicKey::<V4>::from(verifying_key.to_bytes().as_slice())
            .map_err(|e| TokenError::KeyGenerationFailed(e.to_string()))?;

        let key_pair = AsymmetricKeyPair {
            secret: secret_key,
            public: public_key,
        };

        Ok(Self {
            verifying_key,
            key_pair,
            nonce_cache: Arc::new(DashMap::new()),
            issuer: issuer.to_string(),
        })
    }

    /// Generate a capability token.
    pub fn generate_token(
        &self,
        subject: &str,
        scopes: Vec<Scope>,
        ttl_seconds: Option<i64>,
    ) -> Result<String, TokenError> {
        let ttl = ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);

        if ttl > MAX_TTL_SECONDS {
            return Err(TokenError::TtlTooLong(ttl));
        }

        let capability_claims = CapabilityClaims::new(subject, scopes, ttl)?;

        // Build PASETO claims
        let mut claims = Claims::new().map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        claims
            .token_identifier(&capability_claims.jti)
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        claims
            .issuer(&self.issuer)
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        claims
            .subject(subject)
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        claims
            .issued_at(&capability_claims.iat.to_rfc3339())
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        claims
            .not_before(&capability_claims.nbf.to_rfc3339())
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        claims
            .expiration(&capability_claims.exp.to_rfc3339())
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        // Add scopes as custom claim
        let scopes_json = serde_json::to_string(&capability_claims.scopes)
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        claims
            .add_additional("scopes", scopes_json)
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        // Sign the token
        let token = public::sign(&self.key_pair.secret, &claims, None, None)
            .map_err(|e| TokenError::GenerationFailed(e.to_string()))?;

        debug!(
            subject = subject,
            jti = %capability_claims.jti,
            ttl_seconds = ttl,
            "Generated capability token"
        );

        Ok(token)
    }

    /// Verify a capability token and return its claims.
    ///
    /// This method:
    /// 1. Verifies the signature
    /// 2. Checks expiration
    /// 3. Checks not-before time
    /// 4. Validates against replay (nonce cache)
    pub fn verify_token(&self, token: &str) -> Result<CapabilityClaims, TokenError> {
        // Parse the untrusted token
        let untrusted = UntrustedToken::<pasetors::Public, V4>::try_from(token)
            .map_err(|e| TokenError::InvalidFormat(e.to_string()))?;

        // Set up validation rules
        let validation_rules = ClaimsValidationRules::new();

        // Verify and extract claims
        let trusted = public::verify(
            &self.key_pair.public,
            &untrusted,
            &validation_rules,
            None,
            None,
        )
        .map_err(|e| {
            warn!(error = %e, "Token verification failed");
            TokenError::VerificationFailed(e.to_string())
        })?;

        // Get the payload as JSON
        let payload = trusted.payload();
        let payload_json: serde_json::Value = serde_json::from_str(payload)
            .map_err(|e| TokenError::InvalidFormat(format!("invalid payload JSON: {}", e)))?;

        // Extract fields from claims
        let jti = payload_json
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::InvalidFormat("missing jti".into()))?
            .to_string();

        let sub = payload_json
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::InvalidFormat("missing sub".into()))?
            .to_string();

        let iss = payload_json
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::InvalidFormat("missing iss".into()))?
            .to_string();

        let iat_str = payload_json
            .get("iat")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::InvalidFormat("missing iat".into()))?;

        let nbf_str = payload_json
            .get("nbf")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::InvalidFormat("missing nbf".into()))?;

        let exp_str = payload_json
            .get("exp")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::InvalidFormat("missing exp".into()))?;

        let scopes_json = payload_json
            .get("scopes")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::InvalidFormat("missing scopes".into()))?;

        // Parse timestamps
        let iat = DateTime::parse_from_rfc3339(iat_str)
            .map_err(|e| TokenError::InvalidFormat(format!("invalid iat: {}", e)))?
            .with_timezone(&Utc);

        let nbf = DateTime::parse_from_rfc3339(nbf_str)
            .map_err(|e| TokenError::InvalidFormat(format!("invalid nbf: {}", e)))?
            .with_timezone(&Utc);

        let exp = DateTime::parse_from_rfc3339(exp_str)
            .map_err(|e| TokenError::InvalidFormat(format!("invalid exp: {}", e)))?
            .with_timezone(&Utc);

        // Parse scopes
        let scopes: Vec<String> = serde_json::from_str(scopes_json)
            .map_err(|e| TokenError::InvalidFormat(format!("invalid scopes: {}", e)))?;

        let claims = CapabilityClaims {
            jti,
            iat,
            nbf,
            exp,
            iss,
            sub,
            scopes,
        };

        // Check time validity
        let now = Utc::now();

        if now < claims.nbf {
            warn!(nbf = %claims.nbf, now = %now, "Token not yet valid");
            return Err(TokenError::NotYetValid);
        }

        if now > claims.exp {
            warn!(exp = %claims.exp, now = %now, "Token expired");
            return Err(TokenError::Expired);
        }

        // Check replay (nonce must not have been seen)
        if self.nonce_cache.contains_key(&claims.jti) {
            warn!(jti = %claims.jti, "Replay attack detected");
            return Err(TokenError::ReplayDetected);
        }

        // Add nonce to cache
        self.nonce_cache.insert(
            claims.jti.clone(),
            NonceEntry {
                expires_at: claims.exp + Duration::seconds(NONCE_CACHE_CLEANUP_SECONDS),
            },
        );

        debug!(
            subject = %claims.sub,
            jti = %claims.jti,
            scopes = ?claims.scopes,
            "Token verified successfully"
        );

        Ok(claims)
    }

    /// Verify a token and check if it has the required scope.
    pub fn verify_with_scope(
        &self,
        token: &str,
        required_scope: &Scope,
    ) -> Result<CapabilityClaims, TokenError> {
        let claims = self.verify_token(token)?;

        if !claims.has_scope(required_scope) {
            return Err(TokenError::MissingScope(required_scope.to_scope_string()));
        }

        Ok(claims)
    }

    /// Clean up expired nonces from the cache.
    pub fn cleanup_nonces(&self) {
        let now = Utc::now();
        let mut removed = 0;

        self.nonce_cache.retain(|_, entry| {
            if now > entry.expires_at {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            debug!(removed = removed, "Cleaned up expired nonces");
        }
    }

    /// Get the number of nonces in the cache.
    pub fn nonce_cache_size(&self) -> usize {
        self.nonce_cache.len()
    }

    /// Get the public key in base64 format (for distribution).
    pub fn public_key_base64(&self) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            self.verifying_key.to_bytes(),
        )
    }
}

impl Default for CapabilityTokenService {
    fn default() -> Self {
        Self::new().expect("Failed to create CapabilityTokenService")
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Runtime Enforcement
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Context for capability-based access control.
#[derive(Debug, Clone)]
pub struct CapabilityContext {
    /// The verified claims from the token
    pub claims: CapabilityClaims,

    /// Token string (for forwarding)
    pub token: String,
}

impl CapabilityContext {
    /// Check if context permits the given scope.
    pub fn permits(&self, scope: &Scope) -> bool {
        self.claims.has_scope(scope)
    }

    /// Get the subject (user/service ID).
    pub fn subject(&self) -> &str {
        &self.claims.sub
    }

    /// Get the token ID (for logging).
    pub fn token_id(&self) -> &str {
        &self.claims.jti
    }
}

/// Enforce capability token before executing an action.
///
/// This function should wrap any capability-protected operation.
pub fn enforce_capability<T, F>(
    service: &CapabilityTokenService,
    token: &str,
    required_scope: &Scope,
    action: F,
) -> Result<T, TokenError>
where
    F: FnOnce(&CapabilityContext) -> T,
{
    let claims = service.verify_with_scope(token, required_scope)?;

    let context = CapabilityContext {
        claims,
        token: token.to_string(),
    };

    Ok(action(&context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration as StdDuration;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Service creation tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_service_creation() {
        let service = CapabilityTokenService::new();
        assert!(service.is_ok());
    }

    #[test]
    fn test_service_with_issuer() {
        let service = CapabilityTokenService::with_issuer("test-issuer").unwrap();
        assert_eq!(service.issuer, "test-issuer");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Token generation tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_generate_token() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service.generate_token(
            "user-123",
            vec![Scope::Skill("web_search".into())],
            Some(60),
        );
        assert!(token.is_ok());
        let token = token.unwrap();
        assert!(token.starts_with("v4.public."));
    }

    #[test]
    fn test_generate_token_default_ttl() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service.generate_token("user-123", vec![Scope::Read("calendar".into())], None);
        assert!(token.is_ok());
    }

    #[test]
    fn test_generate_token_max_ttl() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service.generate_token("user-123", vec![Scope::All], Some(MAX_TTL_SECONDS));
        assert!(token.is_ok());
    }

    #[test]
    fn test_generate_token_ttl_too_long() {
        let service = CapabilityTokenService::new().unwrap();
        let result =
            service.generate_token("user-123", vec![Scope::All], Some(MAX_TTL_SECONDS + 1));
        assert!(matches!(result, Err(TokenError::TtlTooLong(_))));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Token verification tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_verify_valid_token() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service
            .generate_token("user-123", vec![Scope::Skill("shell".into())], Some(60))
            .unwrap();

        let claims = service.verify_token(&token);
        assert!(claims.is_ok());
        let claims = claims.unwrap();
        assert_eq!(claims.sub, "user-123");
        assert!(claims.has_scope(&Scope::Skill("shell".into())));
    }

    #[test]
    fn test_verify_expired_token() {
        let service = CapabilityTokenService::new().unwrap();

        // Generate token with 1 second TTL
        let token = service
            .generate_token("user-123", vec![Scope::All], Some(1))
            .unwrap();

        // Wait for expiration
        sleep(StdDuration::from_secs(2));

        let result = service.verify_token(&token);
        // Token should fail - either as Expired (our check) or VerificationFailed (pasetors check)
        assert!(
            matches!(
                result,
                Err(TokenError::Expired) | Err(TokenError::VerificationFailed(_))
            ),
            "Expected Expired or VerificationFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn test_replay_prevention() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service
            .generate_token("user-123", vec![Scope::All], Some(60))
            .unwrap();

        // First verification should succeed
        let result1 = service.verify_token(&token);
        assert!(result1.is_ok());

        // Second verification should fail (replay)
        let result2 = service.verify_token(&token);
        assert!(matches!(result2, Err(TokenError::ReplayDetected)));
    }

    #[test]
    fn test_invalid_token() {
        let service = CapabilityTokenService::new().unwrap();
        let result = service.verify_token("invalid-token");
        assert!(matches!(result, Err(TokenError::InvalidFormat(_))));
    }

    #[test]
    fn test_token_from_different_service() {
        let service1 = CapabilityTokenService::new().unwrap();
        let service2 = CapabilityTokenService::new().unwrap();

        let token = service1
            .generate_token("user-123", vec![Scope::All], Some(60))
            .unwrap();

        // Verification with different key should fail
        let result = service2.verify_token(&token);
        assert!(matches!(result, Err(TokenError::VerificationFailed(_))));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Scope tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_scope_parsing() {
        assert_eq!(
            Scope::from_scope_string("skill:web_search"),
            Scope::Skill("web_search".into())
        );
        assert_eq!(
            Scope::from_scope_string("read:calendar"),
            Scope::Read("calendar".into())
        );
        assert_eq!(
            Scope::from_scope_string("write:file"),
            Scope::Write("file".into())
        );
        assert_eq!(
            Scope::from_scope_string("admin:users"),
            Scope::Admin("users".into())
        );
        assert_eq!(Scope::from_scope_string("*"), Scope::All);
    }

    #[test]
    fn test_scope_to_string() {
        assert_eq!(
            Scope::Skill("web_search".into()).to_scope_string(),
            "skill:web_search"
        );
        assert_eq!(Scope::All.to_scope_string(), "*");
    }

    #[test]
    fn test_scope_satisfies() {
        let all = Scope::All;
        let skill = Scope::Skill("test".into());

        assert!(all.satisfies(&skill));
        assert!(skill.satisfies(&skill));
        assert!(!skill.satisfies(&Scope::Skill("other".into())));
    }

    #[test]
    fn test_verify_with_scope_success() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service
            .generate_token(
                "user-123",
                vec![
                    Scope::Skill("web_search".into()),
                    Scope::Read("calendar".into()),
                ],
                Some(60),
            )
            .unwrap();

        let result = service.verify_with_scope(&token, &Scope::Skill("web_search".into()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_with_scope_missing() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service
            .generate_token("user-123", vec![Scope::Read("calendar".into())], Some(60))
            .unwrap();

        let result = service.verify_with_scope(&token, &Scope::Skill("shell".into()));
        assert!(matches!(result, Err(TokenError::MissingScope(_))));
    }

    #[test]
    fn test_wildcard_scope_grants_all() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service
            .generate_token("admin", vec![Scope::All], Some(60))
            .unwrap();

        let result = service.verify_with_scope(&token, &Scope::Skill("dangerous_skill".into()));
        assert!(result.is_ok());
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Nonce cache tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_nonce_cache_grows() {
        let service = CapabilityTokenService::new().unwrap();

        assert_eq!(service.nonce_cache_size(), 0);

        for i in 0..5 {
            let token = service
                .generate_token(&format!("user-{}", i), vec![Scope::All], Some(60))
                .unwrap();
            service.verify_token(&token).unwrap();
        }

        assert_eq!(service.nonce_cache_size(), 5);
    }

    #[test]
    fn test_cleanup_removes_expired() {
        let service = CapabilityTokenService::new().unwrap();

        // Generate and verify a token that expires in 1 second
        let token = service
            .generate_token("user-123", vec![Scope::All], Some(1))
            .unwrap();
        service.verify_token(&token).unwrap();

        assert_eq!(service.nonce_cache_size(), 1);

        // Cleanup shouldn't remove it yet (within cleanup window)
        service.cleanup_nonces();
        assert_eq!(service.nonce_cache_size(), 1);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Enforcement tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_enforce_capability_success() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service
            .generate_token("user-123", vec![Scope::Skill("test".into())], Some(60))
            .unwrap();

        let result = enforce_capability(&service, &token, &Scope::Skill("test".into()), |ctx| {
            assert_eq!(ctx.subject(), "user-123");
            "success"
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[test]
    fn test_enforce_capability_missing_scope() {
        let service = CapabilityTokenService::new().unwrap();
        let token = service
            .generate_token("user-123", vec![Scope::Read("file".into())], Some(60))
            .unwrap();

        let result: Result<&str, TokenError> =
            enforce_capability(&service, &token, &Scope::Write("file".into()), |_| {
                "should not reach"
            });

        assert!(matches!(result, Err(TokenError::MissingScope(_))));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Claims tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_claims_creation() {
        let claims = CapabilityClaims::new(
            "test-user",
            vec![Scope::Skill("a".into()), Scope::Read("b".into())],
            120,
        );
        assert!(claims.is_ok());
        let claims = claims.unwrap();
        assert_eq!(claims.sub, "test-user");
        assert_eq!(claims.scopes.len(), 2);
        assert!(claims.is_valid());
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_claims_ttl_too_long() {
        let result = CapabilityClaims::new("user", vec![], MAX_TTL_SECONDS + 1);
        assert!(matches!(result, Err(TokenError::TtlTooLong(_))));
    }

    #[test]
    fn test_claims_with_default_ttl() {
        let claims = CapabilityClaims::with_default_ttl("user", vec![Scope::All]);
        assert!(claims.is_ok());
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Public key export test
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_public_key_export() {
        let service = CapabilityTokenService::new().unwrap();
        let pubkey = service.public_key_base64();
        assert!(!pubkey.is_empty());
        // Ed25519 public key is 32 bytes, base64 encoded should be ~44 chars
        assert!(pubkey.len() >= 40);
    }
}
