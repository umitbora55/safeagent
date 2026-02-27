//! W35: Standards Ecosystem Integration
//! OWASP Agentic Top 10, CSA STAR Level 2, NANDA DNS-like agent discovery,
//! OpenFGA relationship-based access control (CNCF incubating, 1M RPS).
#![allow(dead_code)]

use std::collections::HashMap;
use dashmap::DashMap;

// ── Reason Codes ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcOwaspThreatDetected,
    RcCsaStarInsufficient,
    RcNandaUnverified,
}

// ── OWASP Agentic Top 10 ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum AgenticThreat {
    T01PromptInjection,
    T02InsecureOutputHandling,
    T03TrainingDataPoisoning,
    T04ModelDos,
    T05SupplyChainVulnerabilities,
    T06SensitiveInfoDisclosure,
    T07InsecurePluginDesign,
    T08ExcessiveAgencyRisk,
    T09Overreliance,
    T10ModelTheft,
}

impl AgenticThreat {
    pub fn id(&self) -> &'static str {
        match self {
            AgenticThreat::T01PromptInjection => "OWASP-A01",
            AgenticThreat::T02InsecureOutputHandling => "OWASP-A02",
            AgenticThreat::T03TrainingDataPoisoning => "OWASP-A03",
            AgenticThreat::T04ModelDos => "OWASP-A04",
            AgenticThreat::T05SupplyChainVulnerabilities => "OWASP-A05",
            AgenticThreat::T06SensitiveInfoDisclosure => "OWASP-A06",
            AgenticThreat::T07InsecurePluginDesign => "OWASP-A07",
            AgenticThreat::T08ExcessiveAgencyRisk => "OWASP-A08",
            AgenticThreat::T09Overreliance => "OWASP-A09",
            AgenticThreat::T10ModelTheft => "OWASP-A10",
        }
    }
}

pub struct OwaspAgenticTop10;

impl OwaspAgenticTop10 {
    pub fn new() -> Self {
        Self
    }

    pub fn classify_finding(&self, description: &str) -> Vec<AgenticThreat> {
        let lower = description.to_lowercase();
        let mut threats = Vec::new();
        if lower.contains("injection") || lower.contains("prompt") { threats.push(AgenticThreat::T01PromptInjection); }
        if lower.contains("output") || lower.contains("execution") { threats.push(AgenticThreat::T02InsecureOutputHandling); }
        if lower.contains("training") || lower.contains("data poisoning") { threats.push(AgenticThreat::T03TrainingDataPoisoning); }
        if lower.contains("resource exhaustion") || lower.contains("dos") { threats.push(AgenticThreat::T04ModelDos); }
        if lower.contains("supply chain") || lower.contains("dependency") { threats.push(AgenticThreat::T05SupplyChainVulnerabilities); }
        if lower.contains("sensitive") || lower.contains("pii") || lower.contains("leak") { threats.push(AgenticThreat::T06SensitiveInfoDisclosure); }
        if lower.contains("plugin") || lower.contains("tool") { threats.push(AgenticThreat::T07InsecurePluginDesign); }
        if lower.contains("excessive") || lower.contains("privilege") || lower.contains("scope") { threats.push(AgenticThreat::T08ExcessiveAgencyRisk); }
        if lower.contains("overreliance") || lower.contains("hallucination") { threats.push(AgenticThreat::T09Overreliance); }
        if lower.contains("model") || lower.contains("weight") || lower.contains("theft") { threats.push(AgenticThreat::T10ModelTheft); }
        threats
    }

    pub fn get_mitigation(&self, threat: &AgenticThreat) -> String {
        match threat {
            AgenticThreat::T01PromptInjection => "Implement spotlighting and input sanitization".to_string(),
            AgenticThreat::T02InsecureOutputHandling => "Validate and sanitize all LLM outputs before execution".to_string(),
            AgenticThreat::T03TrainingDataPoisoning => "Use cryptographic model signing and dataset fingerprinting".to_string(),
            AgenticThreat::T04ModelDos => "Implement rate limiting and resource quotas".to_string(),
            AgenticThreat::T05SupplyChainVulnerabilities => "SBOM generation and dependency scanning".to_string(),
            AgenticThreat::T06SensitiveInfoDisclosure => "Apply differential privacy and PII detection".to_string(),
            AgenticThreat::T07InsecurePluginDesign => "Tool manifest pinning and capability validation".to_string(),
            AgenticThreat::T08ExcessiveAgencyRisk => "Implement ATF trust levels with least privilege".to_string(),
            AgenticThreat::T09Overreliance => "Human-in-the-loop verification for critical decisions".to_string(),
            AgenticThreat::T10ModelTheft => "TEE-based model execution and watermarking".to_string(),
        }
    }

    pub fn cross_map_to_mitre(&self, threat: &AgenticThreat) -> Vec<String> {
        match threat {
            AgenticThreat::T01PromptInjection => vec!["AML.T0051.000".to_string(), "AML.T0054".to_string()],
            AgenticThreat::T03TrainingDataPoisoning => vec!["AML.T0020".to_string(), "AML.T0018".to_string()],
            AgenticThreat::T06SensitiveInfoDisclosure => vec!["AML.T0056".to_string()],
            AgenticThreat::T10ModelTheft => vec!["AML.T0044".to_string(), "AML.T0043".to_string()],
            _ => vec![],
        }
    }
}

impl Default for OwaspAgenticTop10 {
    fn default() -> Self {
        Self::new()
    }
}

// ── CSA STAR AI Assessor ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceType {
    SelfAttestation,
    ThirdPartyAudit,
    AutomatedMonitoring,
    PenTestReport,
}

#[derive(Debug, Clone)]
pub struct AuditEvidence {
    pub control_id: String,
    pub evidence_type: EvidenceType,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct StarLevel {
    pub level: u8,
    pub score: f64,
    pub gaps: Vec<String>,
    pub certification_ready: bool,
}

pub struct CsaStarAiAssessor;

impl CsaStarAiAssessor {
    pub fn new() -> Self {
        Self
    }

    pub fn assess_for_level(&self, evidence: &[AuditEvidence]) -> StarLevel {
        let verified_count = evidence.iter().filter(|e| e.verified).count();
        let total = evidence.len().max(1);
        let score = verified_count as f64 / total as f64;

        let has_third_party = evidence.iter().any(|e| e.evidence_type == EvidenceType::ThirdPartyAudit);
        let has_automated = evidence.iter().any(|e| e.evidence_type == EvidenceType::AutomatedMonitoring);

        let level = if has_automated && score >= 0.90 {
            3
        } else if has_third_party && score >= 0.75 {
            2
        } else if score >= 0.50 {
            1
        } else {
            0
        };

        let unverified: Vec<String> = evidence
            .iter()
            .filter(|e| !e.verified)
            .map(|e| e.control_id.clone())
            .collect();

        StarLevel { level, score, gaps: unverified, certification_ready: level >= 2 }
    }
}

impl Default for CsaStarAiAssessor {
    fn default() -> Self {
        Self::new()
    }
}

// ── NANDA Agent Discovery ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentFacts {
    pub capabilities: Vec<String>,
    pub trust_level: String,
    pub endpoint: String,
    pub vc_attestation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredAgent {
    pub agent_id: String,
    pub endpoint: String,
    pub trust_level: String,
    pub attestation_verified: bool,
}

pub struct NandaAgentDiscovery {
    registry: DashMap<String, AgentFacts>,
}

impl NandaAgentDiscovery {
    pub fn new() -> Self {
        Self { registry: DashMap::new() }
    }

    pub fn register_agent(&self, agent_id: &str, facts: AgentFacts) {
        self.registry.insert(agent_id.to_string(), facts);
    }

    pub fn discover(&self, capability_query: &str) -> Vec<DiscoveredAgent> {
        self.registry
            .iter()
            .filter(|entry| entry.value().capabilities.iter().any(|c| c.contains(capability_query)))
            .map(|entry| DiscoveredAgent {
                agent_id: entry.key().clone(),
                endpoint: entry.value().endpoint.clone(),
                trust_level: entry.value().trust_level.clone(),
                attestation_verified: entry.value().vc_attestation.is_some(),
            })
            .collect()
    }

    pub fn lookup_agent(&self, agent_id: &str) -> Option<AgentFacts> {
        self.registry.get(agent_id).map(|v| v.clone())
    }
}

impl Default for NandaAgentDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

// ── OpenFGA ReBAC ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TupleKey {
    pub user: String,
    pub relation: String,
    pub object: String,
}

#[derive(Debug, Clone)]
pub struct TypeDefinition {
    pub type_name: String,
    pub computed_relations: HashMap<String, Vec<String>>, // relation → implies these relations
}

pub struct OpenFgaRebaC {
    tuples: Vec<TupleKey>,
    types: HashMap<String, TypeDefinition>,
}

impl OpenFgaRebaC {
    pub fn new() -> Self {
        Self { tuples: Vec::new(), types: HashMap::new() }
    }

    pub fn define_type(&mut self, type_name: &str, computed_from: HashMap<String, Vec<String>>) {
        self.types.insert(type_name.to_string(), TypeDefinition {
            type_name: type_name.to_string(),
            computed_relations: computed_from,
        });
    }

    pub fn write_tuple(&mut self, user: &str, relation: &str, object: &str) {
        self.tuples.push(TupleKey {
            user: user.to_string(),
            relation: relation.to_string(),
            object: object.to_string(),
        });
    }

    pub fn check(&self, user: &str, relation: &str, object: &str) -> bool {
        if self.tuples.iter().any(|t| t.user == user && t.relation == relation && t.object == object) {
            return true;
        }
        // Check computed relations: if user has "editor" → also has "viewer"
        if let Some(type_def) = self.get_type_for_object(object) {
            if let Some(implied_by) = type_def.computed_relations.get(relation) {
                for implied_rel in implied_by {
                    if self.check(user, implied_rel, object) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn get_type_for_object(&self, _object: &str) -> Option<&TypeDefinition> {
        // Simplified: return first matching type
        self.types.values().next()
    }

    pub fn expand_relations(&self, object: &str) -> HashMap<String, Vec<String>> {
        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        for tuple in &self.tuples {
            if tuple.object == object {
                result.entry(tuple.relation.clone()).or_default().push(tuple.user.clone());
            }
        }
        result
    }

    pub fn check_with_context(
        &self,
        user: &str,
        relation: &str,
        object: &str,
        _conditions: &HashMap<String, String>,
    ) -> bool {
        self.check(user, relation, object)
    }
}

impl Default for OpenFgaRebaC {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owasp_prompt_injection() {
        let checker = OwaspAgenticTop10::new();
        let threats = checker.classify_finding("prompt injection attack detected");
        assert!(threats.contains(&AgenticThreat::T01PromptInjection));
    }

    #[test]
    fn test_owasp_supply_chain() {
        let checker = OwaspAgenticTop10::new();
        let threats = checker.classify_finding("supply chain dependency compromise");
        assert!(threats.contains(&AgenticThreat::T05SupplyChainVulnerabilities));
    }

    #[test]
    fn test_owasp_sensitive_info() {
        let checker = OwaspAgenticTop10::new();
        let threats = checker.classify_finding("PII data leak detected");
        assert!(threats.contains(&AgenticThreat::T06SensitiveInfoDisclosure));
    }

    #[test]
    fn test_owasp_model_theft() {
        let checker = OwaspAgenticTop10::new();
        let threats = checker.classify_finding("model weight theft attempt");
        assert!(threats.contains(&AgenticThreat::T10ModelTheft));
    }

    #[test]
    fn test_owasp_mitigation_not_empty() {
        let checker = OwaspAgenticTop10::new();
        for threat in &[
            AgenticThreat::T01PromptInjection,
            AgenticThreat::T04ModelDos,
            AgenticThreat::T08ExcessiveAgencyRisk,
        ] {
            assert!(!checker.get_mitigation(threat).is_empty());
        }
    }

    #[test]
    fn test_owasp_mitre_mapping() {
        let checker = OwaspAgenticTop10::new();
        let mitre = checker.cross_map_to_mitre(&AgenticThreat::T01PromptInjection);
        assert!(!mitre.is_empty());
    }

    #[test]
    fn test_csa_star_level2() {
        let assessor = CsaStarAiAssessor::new();
        let evidence = vec![
            AuditEvidence { control_id: "c1".to_string(), evidence_type: EvidenceType::ThirdPartyAudit, verified: true },
            AuditEvidence { control_id: "c2".to_string(), evidence_type: EvidenceType::SelfAttestation, verified: true },
            AuditEvidence { control_id: "c3".to_string(), evidence_type: EvidenceType::SelfAttestation, verified: true },
            AuditEvidence { control_id: "c4".to_string(), evidence_type: EvidenceType::SelfAttestation, verified: true },
        ];
        let star = assessor.assess_for_level(&evidence);
        assert_eq!(star.level, 2);
        assert!(star.certification_ready);
    }

    #[test]
    fn test_csa_star_level3() {
        let assessor = CsaStarAiAssessor::new();
        let evidence = vec![
            AuditEvidence { control_id: "c1".to_string(), evidence_type: EvidenceType::ThirdPartyAudit, verified: true },
            AuditEvidence { control_id: "c2".to_string(), evidence_type: EvidenceType::AutomatedMonitoring, verified: true },
            AuditEvidence { control_id: "c3".to_string(), evidence_type: EvidenceType::PenTestReport, verified: true },
            AuditEvidence { control_id: "c4".to_string(), evidence_type: EvidenceType::SelfAttestation, verified: true },
            AuditEvidence { control_id: "c5".to_string(), evidence_type: EvidenceType::SelfAttestation, verified: true },
        ];
        let star = assessor.assess_for_level(&evidence);
        assert_eq!(star.level, 3);
    }

    #[test]
    fn test_csa_star_not_certified() {
        let assessor = CsaStarAiAssessor::new();
        let evidence = vec![
            AuditEvidence { control_id: "c1".to_string(), evidence_type: EvidenceType::SelfAttestation, verified: false },
            AuditEvidence { control_id: "c2".to_string(), evidence_type: EvidenceType::SelfAttestation, verified: false },
        ];
        let star = assessor.assess_for_level(&evidence);
        assert_eq!(star.level, 0);
        assert!(!star.certification_ready);
    }

    #[test]
    fn test_nanda_register_and_discover() {
        let discovery = NandaAgentDiscovery::new();
        discovery.register_agent("agent-search", AgentFacts {
            capabilities: vec!["web_search".to_string(), "summarize".to_string()],
            trust_level: "Senior".to_string(),
            endpoint: "https://agent.example.com".to_string(),
            vc_attestation: Some("vc://proof123".to_string()),
        });
        let found = discovery.discover("web_search");
        assert!(!found.is_empty());
        assert!(found[0].attestation_verified);
    }

    #[test]
    fn test_nanda_no_attestation() {
        let discovery = NandaAgentDiscovery::new();
        discovery.register_agent("agent-basic", AgentFacts {
            capabilities: vec!["compute".to_string()],
            trust_level: "Junior".to_string(),
            endpoint: "https://basic.example.com".to_string(),
            vc_attestation: None,
        });
        let found = discovery.discover("compute");
        assert!(!found.is_empty());
        assert!(!found[0].attestation_verified);
    }

    #[test]
    fn test_nanda_lookup() {
        let discovery = NandaAgentDiscovery::new();
        discovery.register_agent("a1", AgentFacts {
            capabilities: vec![],
            trust_level: "Intern".to_string(),
            endpoint: "https://a1.example.com".to_string(),
            vc_attestation: None,
        });
        assert!(discovery.lookup_agent("a1").is_some());
        assert!(discovery.lookup_agent("a2").is_none());
    }

    #[test]
    fn test_openfga_direct_check() {
        let mut fga = OpenFgaRebaC::new();
        fga.write_tuple("user:alice", "viewer", "doc:readme");
        assert!(fga.check("user:alice", "viewer", "doc:readme"));
        assert!(!fga.check("user:alice", "editor", "doc:readme"));
    }

    #[test]
    fn test_openfga_computed_relation() {
        let mut fga = OpenFgaRebaC::new();
        // editor implies viewer
        let mut computed = HashMap::new();
        computed.insert("viewer".to_string(), vec!["editor".to_string()]);
        fga.define_type("document", computed);
        fga.write_tuple("user:bob", "editor", "doc:report");
        // bob has editor, so should also have viewer via computed relation
        assert!(fga.check("user:bob", "editor", "doc:report"));
        assert!(fga.check("user:bob", "viewer", "doc:report"));
    }

    #[test]
    fn test_openfga_expand_relations() {
        let mut fga = OpenFgaRebaC::new();
        fga.write_tuple("user:alice", "viewer", "doc:readme");
        fga.write_tuple("user:bob", "editor", "doc:readme");
        let expanded = fga.expand_relations("doc:readme");
        assert!(expanded.contains_key("viewer"));
        assert!(expanded.contains_key("editor"));
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcOwaspThreatDetected;
        let _ = ReasonCode::RcCsaStarInsufficient;
        let _ = ReasonCode::RcNandaUnverified;
    }

    #[test]
    fn test_owasp_threat_ids() {
        assert_eq!(AgenticThreat::T01PromptInjection.id(), "OWASP-A01");
        assert_eq!(AgenticThreat::T10ModelTheft.id(), "OWASP-A10");
    }
}
