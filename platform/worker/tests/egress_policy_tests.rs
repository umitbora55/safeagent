#[cfg(target_os = "linux")]
use safeagent_worker::network_policy::{self, AllowedTarget, DnsResolver, NetworkPolicy};
#[cfg(target_os = "linux")]
use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::net::IpAddr;

#[cfg(target_os = "linux")]
fn allowlist_with_hosts(hosts: &[(&str, u16, Option<&str>)]) -> NetworkPolicy {
    NetworkPolicy::new(
        hosts
            .iter()
            .map(|(host, port, scheme)| AllowedTarget {
                host: (*host).to_string(),
                port: *port,
                scheme: scheme.map(ToString::to_string),
            })
            .collect(),
        false,
        true,
    )
}

#[cfg(target_os = "linux")]
struct SequenceDnsResolver {
    sequence: std::sync::Mutex<VecDeque<Vec<IpAddr>>>,
}

#[cfg(target_os = "linux")]
impl SequenceDnsResolver {
    fn new(values: Vec<Vec<IpAddr>>) -> Self {
        Self {
            sequence: std::sync::Mutex::new(VecDeque::from(values)),
        }
    }
}

#[cfg(target_os = "linux")]
impl DnsResolver for SequenceDnsResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
        let mut sequence = self
            .sequence
            .lock()
            .map_err(|_| "dns sequence resolver state poisoned".to_string())?;
        sequence
            .pop_front()
            .ok_or_else(|| "dns sequence exhausted".to_string())
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn egress_denies_unallowlisted_host_port() {
    let policy = NetworkPolicy::default();
    let err = network_policy::enforce_on_request(&policy, "https://1.1.1.1:443");
    assert!(err.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn egress_allows_public_allowlisted_target() {
    let policy = allowlist_with_hosts(&[("example.com", 443, Some("https"))]);
    let result = network_policy::enforce_on_request(&policy, "https://example.com:443");
    assert!(
        result.is_ok(),
        "allowlisted target should pass policy: {result:?}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn egress_rejects_private_ip_target() {
    let policy = allowlist_with_hosts(&[("10.0.0.1", 443, Some("https"))]);
    let result = network_policy::enforce_on_request(&policy, "https://10.0.0.1:443");
    assert!(result.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn egress_rejects_localhost_target() {
    let policy = allowlist_with_hosts(&[("localhost", 443, Some("https"))]);
    let result = network_policy::enforce_on_request(&policy, "https://localhost:443");
    assert!(result.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn egress_rejects_metadata_endpoint() {
    let policy = allowlist_with_hosts(&[("169.254.169.254", 443, Some("https"))]);
    let result = network_policy::enforce_on_request(&policy, "https://169.254.169.254:443");
    assert!(result.is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn egress_rejects_redirect_to_disallowed_target() {
    let policy = allowlist_with_hosts(&[("example.com", 443, Some("https"))]);
    assert!(network_policy::validate_redirect_target(
        &policy,
        "https://example.com/login",
        "https://malicious.example.net/callback",
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn dns_rebinding_detected_with_pinning() {
    let policy = NetworkPolicy::new(
        vec![AllowedTarget {
            host: "example.com".to_string(),
            port: 443,
            scheme: Some("https".to_string()),
        }],
        true,
        true,
    );
    let resolver = SequenceDnsResolver::new(vec![
        vec!["93.184.216.34".parse::<IpAddr>().expect("ip")],
        vec!["10.0.0.1".parse::<IpAddr>().expect("ip")],
    ]);

    assert!(network_policy::enforce_on_request_with_resolver(
        &policy,
        "https://example.com:443",
        &resolver
    )
    .is_ok());
    assert!(network_policy::enforce_on_request_with_resolver(
        &policy,
        "https://example.com:443",
        &resolver
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn userinfo_trick_blocked() {
    let policy = allowlist_with_hosts(&[("evil.com", 443, Some("https"))]);
    assert!(network_policy::validate_url(&policy, "https://127.0.0.1@evil.com:443/?x=1").is_err());
}
