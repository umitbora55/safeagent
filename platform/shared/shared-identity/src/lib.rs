use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

fn default_exp() -> u64 {
    0
}

fn default_nbf() -> u64 {
    0
}

fn default_nonce() -> String {
    String::new()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TenantId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UserId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub scopes: Vec<String>,
    #[serde(default = "default_exp")]
    pub exp: u64,
    #[serde(default = "default_nbf")]
    pub nbf: u64,
    #[serde(default = "default_nonce")]
    pub nonce: String,
}

pub fn cert_fingerprint_sha256(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

pub fn node_id_from_cert(der: &[u8]) -> Result<NodeId, String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("Invalid certificate DER: {}", e))?;

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in san.value.general_names.iter() {
            match name {
                GeneralName::URI(uri) => {
                    if let Some(id) = uri.strip_prefix("safeagent://node/") {
                        return Ok(NodeId(id.to_string()));
                    }
                }
                GeneralName::DNSName(dns) => {
                    if let Some(id) = dns.strip_prefix("worker-") {
                        return Ok(NodeId(id.to_string()));
                    }
                }
                _ => {}
            }
        }
    }

    Err("NodeId not found in certificate SAN".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, SanType};

    #[test]
    fn fingerprint_sha256_is_deterministic() {
        let data = b"test-cert";
        let a = cert_fingerprint_sha256(data);
        let b = cert_fingerprint_sha256(data);
        assert_eq!(a, b);
    }

    #[test]
    fn parse_node_id_from_san_uri() {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "worker-001");
        params
            .subject_alt_names
            .push(SanType::URI("safeagent://node/worker-001".parse().unwrap()));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        let node = node_id_from_cert(&der).unwrap();
        assert_eq!(node, NodeId("worker-001".to_string()));
    }
}
