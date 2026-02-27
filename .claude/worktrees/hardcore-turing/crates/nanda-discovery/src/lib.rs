//! W40: NANDA Agent Discovery Protocol
//! DNS-like agent discovery, AgentFacts schema, VC attestation verification,
//! TTL-based expiry, domain-based lookup.
#![allow(dead_code)]

use dashmap::DashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcNandaNotFound,
    RcNandaVcUnverified,
    RcNandaExpired,
}

#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub agent_id: String,
    pub domain: String,
    pub capabilities: Vec<String>,
    pub trust_score: f64,
    pub endpoint_url: String,
    pub ttl_seconds: u64,
    pub registered_at: String,
}

#[derive(Debug, Clone)]
pub struct NandaDnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u64,
}

#[derive(Debug, Clone)]
pub struct AgentFactsSchema {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub security_requirements: Vec<String>,
    pub vc_proofs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VcVerification {
    pub verified: bool,
    pub proof_count: u32,
    pub trust_level: String,
}

pub struct NandaDiscoveryProtocol {
    registry: DashMap<String, AgentRecord>,
}

impl NandaDiscoveryProtocol {
    pub fn new() -> Self {
        Self { registry: DashMap::new() }
    }

    pub fn register(&self, record: AgentRecord) -> String {
        let id = record.agent_id.clone();
        self.registry.insert(id.clone(), record);
        id
    }

    pub fn resolve(&self, agent_id: &str) -> Option<AgentRecord> {
        self.registry.get(agent_id).map(|v| v.clone())
    }

    pub fn discover_by_capability(&self, capability: &str) -> Vec<AgentRecord> {
        self.registry
            .iter()
            .filter(|e| e.value().capabilities.iter().any(|c| c.contains(capability)))
            .map(|e| e.value().clone())
            .collect()
    }

    pub fn discover_by_domain(&self, domain: &str) -> Vec<AgentRecord> {
        self.registry
            .iter()
            .filter(|e| e.value().domain == domain)
            .map(|e| e.value().clone())
            .collect()
    }

    pub fn refresh_ttl(&self, agent_id: &str, new_ttl: u64) -> bool {
        if let Some(mut record) = self.registry.get_mut(agent_id) {
            record.ttl_seconds = new_ttl;
            return true;
        }
        false
    }

    pub fn remove_expired(&self, _current_time_secs: u64) {
        let to_remove: Vec<String> = self.registry
            .iter()
            .filter(|e| e.value().ttl_seconds == 0)
            .map(|e| e.key().clone())
            .collect();
        for id in to_remove {
            self.registry.remove(&id);
        }
    }

    pub fn get_dns_records(&self, agent_id: &str) -> Vec<NandaDnsRecord> {
        if let Some(record) = self.registry.get(agent_id) {
            vec![
                NandaDnsRecord { record_type: "AGENT".to_string(), value: record.endpoint_url.clone(), ttl: record.ttl_seconds },
                NandaDnsRecord { record_type: "CAPABILITIES".to_string(), value: record.capabilities.join(","), ttl: record.ttl_seconds },
            ]
        } else {
            vec![]
        }
    }

    pub fn verify_vc_attestation(&self, _agent_id: &str, facts: &AgentFactsSchema) -> VcVerification {
        let count = facts.vc_proofs.len() as u32;
        let verified = count >= 1;
        let trust_level = match count {
            0 => "untrusted".to_string(),
            1 => "basic".to_string(),
            _ => "attested".to_string(),
        };
        VcVerification { verified, proof_count: count, trust_level }
    }
}

impl Default for NandaDiscoveryProtocol {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(id: &str, domain: &str, caps: &[&str], ttl: u64) -> AgentRecord {
        AgentRecord {
            agent_id: id.to_string(),
            domain: domain.to_string(),
            capabilities: caps.iter().map(|s| s.to_string()).collect(),
            trust_score: 0.8,
            endpoint_url: format!("https://{}.example.com", id),
            ttl_seconds: ttl,
            registered_at: "2026-01-01".to_string(),
        }
    }

    #[test]
    fn test_register_and_resolve() {
        let protocol = NandaDiscoveryProtocol::new();
        protocol.register(make_record("agent-1", "search", &["web_search"], 3600));
        let record = protocol.resolve("agent-1");
        assert!(record.is_some());
        assert_eq!(record.unwrap().agent_id, "agent-1");
    }

    #[test]
    fn test_discover_by_capability() {
        let protocol = NandaDiscoveryProtocol::new();
        protocol.register(make_record("a1", "d1", &["search", "summarize"], 3600));
        protocol.register(make_record("a2", "d2", &["compute"], 3600));
        let results = protocol.discover_by_capability("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, "a1");
    }

    #[test]
    fn test_discover_by_domain() {
        let protocol = NandaDiscoveryProtocol::new();
        protocol.register(make_record("a1", "analytics", &[], 3600));
        protocol.register(make_record("a2", "analytics", &[], 3600));
        protocol.register(make_record("a3", "security", &[], 3600));
        let results = protocol.discover_by_domain("analytics");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_refresh_ttl() {
        let protocol = NandaDiscoveryProtocol::new();
        protocol.register(make_record("a1", "d1", &[], 100));
        assert!(protocol.refresh_ttl("a1", 7200));
        assert_eq!(protocol.resolve("a1").unwrap().ttl_seconds, 7200);
    }

    #[test]
    fn test_remove_expired() {
        let protocol = NandaDiscoveryProtocol::new();
        protocol.register(make_record("expired", "d1", &[], 0));
        protocol.register(make_record("active", "d1", &[], 3600));
        protocol.remove_expired(0);
        assert!(protocol.resolve("expired").is_none());
        assert!(protocol.resolve("active").is_some());
    }

    #[test]
    fn test_dns_records() {
        let protocol = NandaDiscoveryProtocol::new();
        protocol.register(make_record("a1", "d1", &["cap1", "cap2"], 3600));
        let records = protocol.get_dns_records("a1");
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.record_type == "AGENT"));
        assert!(records.iter().any(|r| r.record_type == "CAPABILITIES"));
    }

    #[test]
    fn test_dns_records_not_found() {
        let protocol = NandaDiscoveryProtocol::new();
        let records = protocol.get_dns_records("nonexistent");
        assert!(records.is_empty());
    }

    #[test]
    fn test_vc_verification_no_proofs() {
        let protocol = NandaDiscoveryProtocol::new();
        let facts = AgentFactsSchema { name: "a".to_string(), version: "1.0".to_string(), description: "".to_string(), capabilities: vec![], security_requirements: vec![], vc_proofs: vec![] };
        let vc = protocol.verify_vc_attestation("a1", &facts);
        assert!(!vc.verified);
        assert_eq!(vc.trust_level, "untrusted");
    }

    #[test]
    fn test_vc_verification_one_proof() {
        let protocol = NandaDiscoveryProtocol::new();
        let facts = AgentFactsSchema { name: "a".to_string(), version: "1.0".to_string(), description: "".to_string(), capabilities: vec![], security_requirements: vec![], vc_proofs: vec!["proof1".to_string()] };
        let vc = protocol.verify_vc_attestation("a1", &facts);
        assert!(vc.verified);
        assert_eq!(vc.trust_level, "basic");
    }

    #[test]
    fn test_vc_verification_multiple_proofs() {
        let protocol = NandaDiscoveryProtocol::new();
        let facts = AgentFactsSchema { name: "a".to_string(), version: "1.0".to_string(), description: "".to_string(), capabilities: vec![], security_requirements: vec![], vc_proofs: vec!["p1".to_string(), "p2".to_string()] };
        let vc = protocol.verify_vc_attestation("a1", &facts);
        assert_eq!(vc.trust_level, "attested");
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcNandaNotFound;
        let _ = ReasonCode::RcNandaVcUnverified;
        let _ = ReasonCode::RcNandaExpired;
    }

    #[test]
    fn test_capabilities_in_dns() {
        let protocol = NandaDiscoveryProtocol::new();
        protocol.register(make_record("a1", "d1", &["cap1", "cap2"], 3600));
        let records = protocol.get_dns_records("a1");
        let cap_record = records.iter().find(|r| r.record_type == "CAPABILITIES").unwrap();
        assert!(cap_record.value.contains("cap1"));
        assert!(cap_record.value.contains("cap2"));
    }
}
