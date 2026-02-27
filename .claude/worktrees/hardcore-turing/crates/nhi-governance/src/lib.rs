//! W37: NHI Governance Platform
//! Non-human identity lifecycle governance (82 machine IDs/employee,
//! 97% over-privileged). Detect stale, over-privileged, high-risk identities.
#![allow(dead_code)]

use dashmap::DashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ReasonCode {
    RcNhiOverPrivileged,
    RcNhiStale,
    RcNhiHighRisk,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NhiType {
    ServiceAccount,
    ApiKey,
    CertificateBased,
    OAuthClient,
    SpiffeIdentity,
}

#[derive(Debug, Clone)]
pub struct MachineIdentity {
    pub id: String,
    pub identity_type: NhiType,
    pub permissions: Vec<String>,
    pub created_at: String,
    pub last_rotated: String,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct NhiReport {
    pub total_identities: usize,
    pub over_privileged_count: usize,
    pub api_key_count: usize,
    pub avg_risk_score: f64,
    pub high_risk_ids: Vec<String>,
}

pub struct NhiGovernancePlatform {
    identities: DashMap<String, MachineIdentity>,
}

impl NhiGovernancePlatform {
    pub fn new() -> Self {
        Self { identities: DashMap::new() }
    }

    pub fn register_identity(&self, identity: MachineIdentity) -> String {
        let id = identity.id.clone();
        self.identities.insert(id.clone(), identity);
        id
    }

    pub fn get_identity(&self, id: &str) -> Option<MachineIdentity> {
        self.identities.get(id).map(|v| v.clone())
    }

    pub fn detect_over_privileged(&self, max_permissions: usize) -> Vec<String> {
        self.identities
            .iter()
            .filter(|entry| entry.value().permissions.len() > max_permissions)
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn rotate_identity(&self, id: &str, new_timestamp: &str) -> bool {
        if let Some(mut identity) = self.identities.get_mut(id) {
            identity.last_rotated = new_timestamp.to_string();
            return true;
        }
        false
    }

    pub fn detect_stale_identities(&self, days_threshold: u32) -> Vec<String> {
        // Simplified: year < (2026 - years_threshold/365) as stale
        let threshold_year = 2026u32.saturating_sub(days_threshold / 365);
        self.identities
            .iter()
            .filter(|entry| {
                let year: u32 = entry.value().last_rotated
                    .split('-')
                    .next()
                    .and_then(|y| y.parse().ok())
                    .unwrap_or(2026);
                year < threshold_year
            })
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn get_identity_risk_score(&self, id: &str) -> f64 {
        if let Some(identity) = self.identities.get(id) {
            let base = match identity.identity_type {
                NhiType::ApiKey => 0.7,
                NhiType::ServiceAccount => 0.4,
                NhiType::OAuthClient => 0.3,
                NhiType::CertificateBased => 0.2,
                NhiType::SpiffeIdentity => 0.1,
            };
            let excess = identity.permissions.len().saturating_sub(10);
            let perm_penalty = (excess as f64 / 5.0) * 0.1;
            (base + perm_penalty).min(1.0)
        } else {
            0.0
        }
    }

    pub fn generate_nhi_report(&self) -> NhiReport {
        let all: Vec<MachineIdentity> = self.identities.iter().map(|e| e.value().clone()).collect();
        let total = all.len();
        let over_priv = all.iter().filter(|i| i.permissions.len() > 10).count();
        let api_count = all.iter().filter(|i| i.identity_type == NhiType::ApiKey).count();
        let scores: Vec<f64> = all.iter().map(|i| self.get_identity_risk_score(&i.id)).collect();
        let avg = if scores.is_empty() { 0.0 } else { scores.iter().sum::<f64>() / scores.len() as f64 };
        let high_risk: Vec<String> = all.iter()
            .filter(|i| self.get_identity_risk_score(&i.id) >= 0.7)
            .map(|i| i.id.clone())
            .collect();
        NhiReport { total_identities: total, over_privileged_count: over_priv, api_key_count: api_count, avg_risk_score: avg, high_risk_ids: high_risk }
    }
}

impl Default for NhiGovernancePlatform {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(id: &str, nhi_type: NhiType, perms: usize, year: &str) -> MachineIdentity {
        MachineIdentity {
            id: id.to_string(),
            identity_type: nhi_type,
            permissions: (0..perms).map(|i| format!("perm-{}", i)).collect(),
            created_at: "2024-01-01".to_string(),
            last_rotated: format!("{}-01-01", year),
            is_active: true,
        }
    }

    #[test]
    fn test_register_and_get() {
        let platform = NhiGovernancePlatform::new();
        let id = platform.register_identity(make_identity("svc-1", NhiType::ServiceAccount, 5, "2025"));
        assert_eq!(id, "svc-1");
        assert!(platform.get_identity("svc-1").is_some());
    }

    #[test]
    fn test_detect_over_privileged() {
        let platform = NhiGovernancePlatform::new();
        platform.register_identity(make_identity("svc-1", NhiType::ServiceAccount, 15, "2025"));
        platform.register_identity(make_identity("svc-2", NhiType::ServiceAccount, 3, "2025"));
        let over_priv = platform.detect_over_privileged(10);
        assert!(over_priv.contains(&"svc-1".to_string()));
        assert!(!over_priv.contains(&"svc-2".to_string()));
    }

    #[test]
    fn test_rotate_identity() {
        let platform = NhiGovernancePlatform::new();
        platform.register_identity(make_identity("key-1", NhiType::ApiKey, 5, "2023"));
        let result = platform.rotate_identity("key-1", "2026-02-27");
        assert!(result);
        assert_eq!(platform.get_identity("key-1").unwrap().last_rotated, "2026-02-27");
    }

    #[test]
    fn test_rotate_nonexistent() {
        let platform = NhiGovernancePlatform::new();
        assert!(!platform.rotate_identity("nonexistent", "2026-01-01"));
    }

    #[test]
    fn test_detect_stale() {
        let platform = NhiGovernancePlatform::new();
        platform.register_identity(make_identity("old-1", NhiType::ApiKey, 5, "2020"));
        platform.register_identity(make_identity("new-1", NhiType::ApiKey, 5, "2025"));
        // 1825 days = 5 years threshold → year < 2021
        let stale = platform.detect_stale_identities(1825);
        assert!(stale.contains(&"old-1".to_string()));
    }

    #[test]
    fn test_risk_score_api_key_highest() {
        let platform = NhiGovernancePlatform::new();
        platform.register_identity(make_identity("key-1", NhiType::ApiKey, 5, "2025"));
        platform.register_identity(make_identity("spiffe-1", NhiType::SpiffeIdentity, 5, "2025"));
        let api_score = platform.get_identity_risk_score("key-1");
        let spiffe_score = platform.get_identity_risk_score("spiffe-1");
        assert!(api_score > spiffe_score);
    }

    #[test]
    fn test_risk_score_excess_permissions() {
        let platform = NhiGovernancePlatform::new();
        platform.register_identity(make_identity("svc-big", NhiType::ServiceAccount, 20, "2025"));
        let score = platform.get_identity_risk_score("svc-big");
        assert!(score > 0.4); // base 0.4 + excess penalty
    }

    #[test]
    fn test_risk_score_capped() {
        let platform = NhiGovernancePlatform::new();
        platform.register_identity(make_identity("mega", NhiType::ApiKey, 100, "2025"));
        let score = platform.get_identity_risk_score("mega");
        assert!(score <= 1.0);
    }

    #[test]
    fn test_generate_report() {
        let platform = NhiGovernancePlatform::new();
        platform.register_identity(make_identity("key-1", NhiType::ApiKey, 15, "2025"));
        platform.register_identity(make_identity("svc-1", NhiType::ServiceAccount, 5, "2025"));
        let report = platform.generate_nhi_report();
        assert_eq!(report.total_identities, 2);
        assert_eq!(report.api_key_count, 1);
        assert!(report.over_privileged_count >= 1);
    }

    #[test]
    fn test_reason_codes() {
        let _ = ReasonCode::RcNhiOverPrivileged;
        let _ = ReasonCode::RcNhiStale;
        let _ = ReasonCode::RcNhiHighRisk;
    }
}
