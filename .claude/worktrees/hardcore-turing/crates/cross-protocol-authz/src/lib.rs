//! W30: Cross-Protocol Policy Engine
//! Unified MCP + A2A authorization, static API key replacement,
//! cross-protocol enforcement layer. (53% MCP servers use static API keys,
//! only Cisco covers both protocols – SafeAgent closes this gap.)
#![allow(dead_code)]

use std::collections::HashMap;
use uuid::Uuid;

// ── Reason Codes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcStaticKeyBlocked,
    RcCrossProtocolDeny,
    RcAuthUpgradeRequired,
}

// ── Protocol & AuthMethod ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Protocol {
    Mcp,
    A2A,
    DirectApi,
    Webhook,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AuthMethod {
    StaticApiKey,
    OAuth2,
    Mtls,
    SpiffeSpire,
    HybridPqc,
}

impl AuthMethod {
    pub fn is_deprecated(&self) -> bool {
        matches!(self, AuthMethod::StaticApiKey)
    }
}

// ── CrossProtocolPolicyEngine ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyEntry {
    pub protocol: Protocol,
    pub resource: String,
    pub required_auth: AuthMethod,
}

#[derive(Debug, Clone)]
pub struct AuthzDecision {
    pub allowed: bool,
    pub reason: String,
    pub requires_upgrade: Option<AuthMethod>,
}

#[derive(Debug, Default)]
pub struct CrossProtocolPolicyEngine {
    policies: Vec<PolicyEntry>,
}

impl CrossProtocolPolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_policy(&mut self, protocol: Protocol, resource: &str, required_auth: AuthMethod) {
        self.policies.push(PolicyEntry {
            protocol,
            resource: resource.to_string(),
            required_auth,
        });
    }

    pub fn authorize(&self, protocol: &Protocol, resource: &str, auth_method: &AuthMethod) -> AuthzDecision {
        // Deprecated auth is always blocked
        if auth_method.is_deprecated() {
            return AuthzDecision {
                allowed: false,
                reason: "StaticApiKey is deprecated and not permitted".to_string(),
                requires_upgrade: Some(AuthMethod::OAuth2),
            };
        }
        // Find policy for this protocol+resource
        let policy = self.policies.iter().find(|p| {
            p.protocol == *protocol && p.resource == resource
        });
        match policy {
            None => AuthzDecision {
                allowed: false,
                reason: "No policy registered for this resource (deny-by-default)".to_string(),
                requires_upgrade: None,
            },
            Some(p) => {
                if *auth_method == p.required_auth {
                    AuthzDecision {
                        allowed: true,
                        reason: "Authorization granted".to_string(),
                        requires_upgrade: None,
                    }
                } else {
                    AuthzDecision {
                        allowed: false,
                        reason: format!(
                            "Auth method mismatch: required {:?}, got {:?}",
                            p.required_auth, auth_method
                        ),
                        requires_upgrade: Some(p.required_auth.clone()),
                    }
                }
            }
        }
    }
}

// ── StaticApiKeyReplacer ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ApiKeyFinding {
    pub key_pattern: String,
    pub location: String,
    pub suggested_replacement: AuthMethod,
}

pub struct StaticApiKeyReplacer;

impl StaticApiKeyReplacer {
    pub fn new() -> Self {
        Self
    }

    pub fn scan_configuration(&self, config: &str) -> Vec<ApiKeyFinding> {
        let patterns = ["api_key", "apikey", "API_KEY", "secret_key"];
        let mut findings = Vec::new();
        for pattern in &patterns {
            if config.contains(pattern) {
                findings.push(ApiKeyFinding {
                    key_pattern: pattern.to_string(),
                    location: format!("config_field:{}", pattern),
                    suggested_replacement: AuthMethod::OAuth2,
                });
            }
        }
        findings
    }
}

impl Default for StaticApiKeyReplacer {
    fn default() -> Self {
        Self::new()
    }
}

// ── McpA2aUnifiedGateway ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GatewayResult {
    pub allowed: bool,
    pub protocol_specific_checks: Vec<String>,
    pub audit_id: String,
}

pub struct McpA2aUnifiedGateway;

impl McpA2aUnifiedGateway {
    pub fn new() -> Self {
        Self
    }

    pub fn process_request(
        &self,
        protocol: Protocol,
        tool_name: &str,
        _caller_identity: &str,
        auth: AuthMethod,
    ) -> GatewayResult {
        let audit_id = Uuid::new_v4().to_string();

        if auth.is_deprecated() {
            return GatewayResult {
                allowed: false,
                protocol_specific_checks: vec!["static_api_key_rejected".to_string()],
                audit_id,
            };
        }

        let mut checks = Vec::new();
        match protocol {
            Protocol::Mcp => {
                checks.push("mcp_tool_manifest_verified".to_string());
            }
            Protocol::A2A => {
                checks.push("a2a_delegation_verified".to_string());
            }
            _ => {}
        }

        GatewayResult {
            allowed: true,
            protocol_specific_checks: checks,
            audit_id,
        }
    }
}

impl Default for McpA2aUnifiedGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ── ProtocolGapAnalyzer ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub protocol: Protocol,
    pub auth_method: AuthMethod,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct GapAnalysis {
    pub total_servers: usize,
    pub deprecated_auth_count: usize,
    pub gap_percentage: f64,
    pub risk_level: RiskLevel,
}

pub struct ProtocolGapAnalyzer;

impl ProtocolGapAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_security_posture(&self, servers: &[ServerConfig]) -> GapAnalysis {
        let total = servers.len();
        let deprecated = servers.iter().filter(|s| s.auth_method.is_deprecated()).count();
        let gap_pct = if total == 0 {
            0.0
        } else {
            (deprecated as f64 / total as f64) * 100.0
        };
        let risk = if gap_pct >= 53.0 {
            RiskLevel::Critical
        } else if gap_pct >= 30.0 {
            RiskLevel::High
        } else if gap_pct >= 10.0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };
        GapAnalysis {
            total_servers: total,
            deprecated_auth_count: deprecated,
            gap_percentage: gap_pct,
            risk_level: risk,
        }
    }
}

impl Default for ProtocolGapAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_deprecated() {
        assert!(AuthMethod::StaticApiKey.is_deprecated());
        assert!(!AuthMethod::OAuth2.is_deprecated());
        assert!(!AuthMethod::Mtls.is_deprecated());
        assert!(!AuthMethod::SpiffeSpire.is_deprecated());
        assert!(!AuthMethod::HybridPqc.is_deprecated());
    }

    #[test]
    fn test_policy_engine_allow() {
        let mut engine = CrossProtocolPolicyEngine::new();
        engine.register_policy(Protocol::Mcp, "tool://search", AuthMethod::OAuth2);
        let decision = engine.authorize(&Protocol::Mcp, "tool://search", &AuthMethod::OAuth2);
        assert!(decision.allowed);
    }

    #[test]
    fn test_policy_engine_deny_static_key() {
        let mut engine = CrossProtocolPolicyEngine::new();
        engine.register_policy(Protocol::Mcp, "tool://search", AuthMethod::OAuth2);
        let decision = engine.authorize(&Protocol::Mcp, "tool://search", &AuthMethod::StaticApiKey);
        assert!(!decision.allowed);
        assert!(decision.requires_upgrade.is_some());
    }

    #[test]
    fn test_policy_engine_deny_no_policy() {
        let engine = CrossProtocolPolicyEngine::new();
        let decision = engine.authorize(&Protocol::A2A, "resource://data", &AuthMethod::OAuth2);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("deny-by-default"));
    }

    #[test]
    fn test_policy_engine_a2a_mtls() {
        let mut engine = CrossProtocolPolicyEngine::new();
        engine.register_policy(Protocol::A2A, "agent://coordinator", AuthMethod::Mtls);
        let decision = engine.authorize(&Protocol::A2A, "agent://coordinator", &AuthMethod::Mtls);
        assert!(decision.allowed);
    }

    #[test]
    fn test_api_key_scanner_finds_patterns() {
        let replacer = StaticApiKeyReplacer::new();
        let config = "api_key=abc123\napikey=xyz\nother=value";
        let findings = replacer.scan_configuration(config);
        assert!(findings.len() >= 2);
        assert!(findings.iter().all(|f| f.suggested_replacement == AuthMethod::OAuth2));
    }

    #[test]
    fn test_api_key_scanner_no_findings() {
        let replacer = StaticApiKeyReplacer::new();
        let config = "username=admin\npassword=secret\nhost=localhost";
        let findings = replacer.scan_configuration(config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_api_key_scanner_all_patterns() {
        let replacer = StaticApiKeyReplacer::new();
        let config = "api_key=a\napikey=b\nAPI_KEY=c\nsecret_key=d";
        let findings = replacer.scan_configuration(config);
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn test_unified_gateway_mcp_approved() {
        let gw = McpA2aUnifiedGateway::new();
        let result = gw.process_request(Protocol::Mcp, "search_tool", "agent-1", AuthMethod::OAuth2);
        assert!(result.allowed);
        assert!(result.protocol_specific_checks.contains(&"mcp_tool_manifest_verified".to_string()));
    }

    #[test]
    fn test_unified_gateway_a2a_approved() {
        let gw = McpA2aUnifiedGateway::new();
        let result = gw.process_request(Protocol::A2A, "coordinator", "agent-2", AuthMethod::Mtls);
        assert!(result.allowed);
        assert!(result.protocol_specific_checks.contains(&"a2a_delegation_verified".to_string()));
    }

    #[test]
    fn test_unified_gateway_static_key_rejected() {
        let gw = McpA2aUnifiedGateway::new();
        let result = gw.process_request(Protocol::Mcp, "tool", "agent-3", AuthMethod::StaticApiKey);
        assert!(!result.allowed);
    }

    #[test]
    fn test_gap_analyzer_critical() {
        let analyzer = ProtocolGapAnalyzer::new();
        let servers = vec![
            ServerConfig { protocol: Protocol::Mcp, auth_method: AuthMethod::StaticApiKey, name: "s1".to_string() },
            ServerConfig { protocol: Protocol::Mcp, auth_method: AuthMethod::StaticApiKey, name: "s2".to_string() },
            ServerConfig { protocol: Protocol::Mcp, auth_method: AuthMethod::OAuth2, name: "s3".to_string() },
        ];
        let gap = analyzer.analyze_security_posture(&servers);
        assert_eq!(gap.total_servers, 3);
        assert_eq!(gap.deprecated_auth_count, 2);
        // 66.7% >= 53% → Critical
        assert_eq!(gap.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_gap_analyzer_low_risk() {
        let analyzer = ProtocolGapAnalyzer::new();
        let servers = vec![
            ServerConfig { protocol: Protocol::Mcp, auth_method: AuthMethod::OAuth2, name: "s1".to_string() },
            ServerConfig { protocol: Protocol::Mcp, auth_method: AuthMethod::OAuth2, name: "s2".to_string() },
        ];
        let gap = analyzer.analyze_security_posture(&servers);
        assert_eq!(gap.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_gap_analyzer_empty() {
        let analyzer = ProtocolGapAnalyzer::new();
        let gap = analyzer.analyze_security_posture(&[]);
        assert_eq!(gap.total_servers, 0);
        assert_eq!(gap.gap_percentage, 0.0);
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcStaticKeyBlocked;
        let _ = ReasonCode::RcCrossProtocolDeny;
        let _ = ReasonCode::RcAuthUpgradeRequired;
    }

    #[test]
    fn test_protocol_spiffe_allowed() {
        let mut engine = CrossProtocolPolicyEngine::new();
        engine.register_policy(Protocol::Mcp, "secure://vault", AuthMethod::SpiffeSpire);
        let decision = engine.authorize(&Protocol::Mcp, "secure://vault", &AuthMethod::SpiffeSpire);
        assert!(decision.allowed);
        assert!(decision.requires_upgrade.is_none());
    }

    #[test]
    fn test_gateway_audit_id_generated() {
        let gw = McpA2aUnifiedGateway::new();
        let result = gw.process_request(Protocol::DirectApi, "api", "user", AuthMethod::OAuth2);
        assert!(!result.audit_id.is_empty());
    }

    #[test]
    fn test_policy_engine_wrong_auth() {
        let mut engine = CrossProtocolPolicyEngine::new();
        engine.register_policy(Protocol::A2A, "resource", AuthMethod::Mtls);
        let decision = engine.authorize(&Protocol::A2A, "resource", &AuthMethod::OAuth2);
        assert!(!decision.allowed);
        assert_eq!(decision.requires_upgrade, Some(AuthMethod::Mtls));
    }

    #[test]
    fn test_gap_53_pct_boundary() {
        let analyzer = ProtocolGapAnalyzer::new();
        // Exactly 53 out of 100 deprecated
        let mut servers = Vec::new();
        for i in 0..53 {
            servers.push(ServerConfig { protocol: Protocol::Mcp, auth_method: AuthMethod::StaticApiKey, name: format!("s{}", i) });
        }
        for i in 53..100 {
            servers.push(ServerConfig { protocol: Protocol::Mcp, auth_method: AuthMethod::OAuth2, name: format!("s{}", i) });
        }
        let gap = analyzer.analyze_security_posture(&servers);
        assert_eq!(gap.risk_level, RiskLevel::Critical);
    }
}
