#[cfg(target_os = "linux")]
use safeagent_worker::network_policy::{self, AllowedTarget, NetworkPolicy};

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
