//! W46: Competitive Gap Analysis Engine
//! MCP+A2A unified security market analysis.
//! 53% MCP servers use static API keys, only 1/5 vendors cover both protocols.
#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcCompetitiveGapCritical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Competitor {
    CiscoAI,
    MicrosoftAzureAI,
    GoogleVertexAI,
    AwsBedrock,
    HashiCorpVault,
    OtherVendor,
}

#[derive(Debug, Clone)]
pub struct ProtocolSupport {
    pub mcp_support: bool,
    pub a2a_support: bool,
    pub both_protocols: bool,
    pub auth_method: String,
}

#[derive(Debug, Clone)]
pub struct CompetitorProfile {
    pub competitor: Competitor,
    pub protocol_support: ProtocolSupport,
    pub market_share_pct: f64,
    pub key_weaknesses: Vec<String>,
    pub key_strengths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MarketGap {
    pub gap_id: String,
    pub description: String,
    pub current_coverage_pct: f64,
    pub safeagent_advantage: String,
}

#[derive(Debug, Clone)]
pub struct CompetitivePosition {
    pub unique_features: Vec<String>,
    pub parity_features: Vec<String>,
    pub gaps_to_close: Vec<String>,
    pub market_opportunity_score: f64,
}

#[derive(Debug, Clone)]
pub struct ProtocolCoverageReport {
    pub total_vendors: usize,
    pub mcp_only: usize,
    pub a2a_only: usize,
    pub both: usize,
    pub neither: usize,
    pub both_coverage_pct: f64,
}

pub struct CompetitiveGapAnalyzer {
    profiles: Vec<CompetitorProfile>,
}

impl CompetitiveGapAnalyzer {
    pub fn new() -> Self {
        let profiles = vec![
            CompetitorProfile { competitor: Competitor::CiscoAI, protocol_support: ProtocolSupport { mcp_support: true, a2a_support: true, both_protocols: true, auth_method: "oauth2".to_string() }, market_share_pct: 18.0, key_weaknesses: vec!["high_cost".to_string(), "complex_setup".to_string()], key_strengths: vec!["enterprise_integration".to_string()] },
            CompetitorProfile { competitor: Competitor::MicrosoftAzureAI, protocol_support: ProtocolSupport { mcp_support: true, a2a_support: false, both_protocols: false, auth_method: "azure_ad".to_string() }, market_share_pct: 24.0, key_weaknesses: vec!["no_a2a_support".to_string()], key_strengths: vec!["enterprise_integration".to_string(), "large_ecosystem".to_string()] },
            CompetitorProfile { competitor: Competitor::GoogleVertexAI, protocol_support: ProtocolSupport { mcp_support: false, a2a_support: true, both_protocols: false, auth_method: "service_account".to_string() }, market_share_pct: 21.0, key_weaknesses: vec!["no_mcp_support".to_string()], key_strengths: vec!["ml_capabilities".to_string()] },
            CompetitorProfile { competitor: Competitor::AwsBedrock, protocol_support: ProtocolSupport { mcp_support: true, a2a_support: false, both_protocols: false, auth_method: "iam_static_keys".to_string() }, market_share_pct: 19.0, key_weaknesses: vec!["static_keys_53pct".to_string(), "no_a2a".to_string()], key_strengths: vec!["aws_integration".to_string()] },
            CompetitorProfile { competitor: Competitor::HashiCorpVault, protocol_support: ProtocolSupport { mcp_support: false, a2a_support: false, both_protocols: false, auth_method: "token_based".to_string() }, market_share_pct: 8.0, key_weaknesses: vec!["no_mcp".to_string(), "no_a2a".to_string()], key_strengths: vec!["secrets_management".to_string()] },
        ];
        Self { profiles }
    }

    pub fn get_market_gaps(&self) -> Vec<MarketGap> {
        vec![
            MarketGap { gap_id: "GAP-001".to_string(), description: "Only 1/5 vendors support both MCP+A2A".to_string(), current_coverage_pct: 20.0, safeagent_advantage: "unified_cross_protocol_enforcement".to_string() },
            MarketGap { gap_id: "GAP-002".to_string(), description: "53% MCP servers use static API keys".to_string(), current_coverage_pct: 47.0, safeagent_advantage: "automated_key_replacement".to_string() },
            MarketGap { gap_id: "GAP-003".to_string(), description: "No vendor offers ATF progressive trust".to_string(), current_coverage_pct: 0.0, safeagent_advantage: "atf_4_level_trust".to_string() },
        ]
    }

    pub fn analyze_competitive_position(&self, safeagent_features: &[String]) -> CompetitivePosition {
        let all_competitor_strengths: Vec<String> = self.profiles.iter()
            .flat_map(|p| p.key_strengths.iter().cloned())
            .collect();

        let unique: Vec<String> = safeagent_features.iter()
            .filter(|f| !all_competitor_strengths.contains(f))
            .cloned()
            .collect();
        let parity: Vec<String> = safeagent_features.iter()
            .filter(|f| all_competitor_strengths.contains(f))
            .cloned()
            .collect();
        let gaps = self.get_market_gaps();
        let gap_descriptions: Vec<String> = gaps.iter().map(|g| g.safeagent_advantage.clone()).collect();
        let opportunity = (gaps.len() as f64 / 10.0).min(1.0);

        CompetitivePosition {
            unique_features: unique,
            parity_features: parity,
            gaps_to_close: gap_descriptions,
            market_opportunity_score: opportunity,
        }
    }

    pub fn get_protocol_coverage_report(&self) -> ProtocolCoverageReport {
        let total = self.profiles.len();
        let both = self.profiles.iter().filter(|p| p.protocol_support.both_protocols).count();
        let mcp_only = self.profiles.iter().filter(|p| p.protocol_support.mcp_support && !p.protocol_support.a2a_support).count();
        let a2a_only = self.profiles.iter().filter(|p| !p.protocol_support.mcp_support && p.protocol_support.a2a_support).count();
        let neither = self.profiles.iter().filter(|p| !p.protocol_support.mcp_support && !p.protocol_support.a2a_support).count();
        ProtocolCoverageReport { total_vendors: total, mcp_only, a2a_only, both, neither, both_coverage_pct: both as f64 / total as f64 * 100.0 }
    }
}

impl Default for CompetitiveGapAnalyzer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_cisco_supports_both() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let report = analyzer.get_protocol_coverage_report();
        assert_eq!(report.both, 1);
        assert_eq!(report.both_coverage_pct, 20.0);
    }

    #[test]
    fn test_total_vendors() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let report = analyzer.get_protocol_coverage_report();
        assert_eq!(report.total_vendors, 5);
    }

    #[test]
    fn test_market_gaps_count() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let gaps = analyzer.get_market_gaps();
        assert_eq!(gaps.len(), 3);
    }

    #[test]
    fn test_gap_atf_no_coverage() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let gaps = analyzer.get_market_gaps();
        let atf_gap = gaps.iter().find(|g| g.gap_id == "GAP-003").unwrap();
        assert_eq!(atf_gap.current_coverage_pct, 0.0);
    }

    #[test]
    fn test_gap_mcp_static_keys() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let gaps = analyzer.get_market_gaps();
        let key_gap = gaps.iter().find(|g| g.gap_id == "GAP-002").unwrap();
        assert!(key_gap.description.contains("53%"));
    }

    #[test]
    fn test_competitive_position_unique_features() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let features = vec![
            "post_quantum_crypto".to_string(),
            "atf_trust_levels".to_string(),
            "enterprise_integration".to_string(), // parity
        ];
        let position = analyzer.analyze_competitive_position(&features);
        assert!(position.unique_features.contains(&"post_quantum_crypto".to_string()));
        assert!(position.parity_features.contains(&"enterprise_integration".to_string()));
    }

    #[test]
    fn test_market_opportunity_score() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let position = analyzer.analyze_competitive_position(&[]);
        assert!(position.market_opportunity_score > 0.0);
        assert!(position.market_opportunity_score <= 1.0);
    }

    #[test]
    fn test_protocol_coverage_mcp_only() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let report = analyzer.get_protocol_coverage_report();
        assert!(report.mcp_only >= 1); // AWS, MS are mcp_only
    }

    #[test]
    fn test_aws_uses_static_keys() {
        let analyzer = CompetitiveGapAnalyzer::new();
        let aws = analyzer.profiles.iter().find(|p| p.competitor == Competitor::AwsBedrock).unwrap();
        assert!(aws.protocol_support.auth_method.contains("iam_static_keys") || aws.key_weaknesses.iter().any(|w| w.contains("static")));
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcCompetitiveGapCritical;
    }
}
