use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedTarget {
    pub host: String,
    pub port: u16,
    pub scheme: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    pub allowlist: Vec<AllowedTarget>,
    pub dns_pin: bool,
    pub block_private_ip: bool,
    dns_pins: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
}

#[derive(Debug, Clone)]
pub struct PinnedResolution {
    pub host: String,
    pub allowed_ips: Vec<IpAddr>,
}

pub trait DnsResolver: Send + Sync {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

#[derive(Debug, Clone, Copy)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let mut ips: Vec<IpAddr> = (host, 443)
            .to_socket_addrs()
            .map_err(|err| format!("dns resolve failed: {err}"))?
            .map(|addr| addr.ip())
            .collect();
        if ips.is_empty() {
            return Err("dns resolve produced no addresses".to_string());
        }
        ips.sort_by_key(|ip| ip.to_string());
        ips.dedup();
        Ok(ips)
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            dns_pin: false,
            block_private_ip: true,
            dns_pins: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl NetworkPolicy {
    pub fn new(allowlist: Vec<AllowedTarget>, dns_pin: bool, block_private_ip: bool) -> Self {
        Self {
            allowlist,
            dns_pin,
            block_private_ip,
            dns_pins: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Self {
        let allowlist = parse_allowlist(std::env::var("WORKER_EGRESS_ALLOWLIST").ok().as_deref());
        let dns_pin = std::env::var("WORKER_DNS_PIN")
            .ok()
            .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let block_private_ip = std::env::var("WORKER_BLOCK_PRIVATE_IP")
            .ok()
            .map(|value| !matches!(value.to_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);
        Self {
            allowlist,
            dns_pin,
            block_private_ip,
            dns_pins: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_allowed(&self, host: &str, port: u16, scheme: Option<&str>) -> bool {
        self.allowlist.iter().any(|entry| {
            normalize_host(&entry.host) == normalize_host(host)
                && entry.port == port
                && match (&entry.scheme, scheme) {
                    (Some(allowed), Some(candidate)) => allowed.eq_ignore_ascii_case(candidate),
                    (None, _) => true,
                    (Some(_), None) => false,
                }
        })
    }
}

fn parse_allowlist(raw: Option<&str>) -> Vec<AllowedTarget> {
    match raw {
        None => Vec::new(),
        Some(value) => value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .filter_map(parse_allowlist_entry)
            .collect(),
    }
}

fn parse_allowlist_entry(raw: &str) -> Option<AllowedTarget> {
    let mut parts = raw.split(':');
    let host = parts.next()?.trim();
    let port = parts.next()?.trim().parse::<u16>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(AllowedTarget {
        host: normalize_host(host),
        port,
        scheme: None,
    })
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_lowercase()
}

pub fn validate_host_port(
    policy: &NetworkPolicy,
    host: &str,
    port: u16,
    scheme: &str,
) -> Result<(), String> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if is_localhost_host(&host) {
        return Err("localhost is denied".to_string());
    }
    if port == 0 {
        return Err("invalid port".to_string());
    }
    if !policy.is_allowed(&host, port, Some(scheme)) {
        return Err(format!("{}:{} not in allowlist", host, port));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct UrlTarget {
    pub host: String,
    pub port: u16,
    pub scheme: String,
}

pub fn validate_url(policy: &NetworkPolicy, url: &str) -> Result<UrlTarget, String> {
    let parsed = Url::parse(url).map_err(|err| format!("invalid url: {err}"))?;
    if !parsed.username().is_empty() {
        return Err("userinfo is not allowed".to_string());
    }
    if parsed.password().is_some() {
        return Err("userinfo is not allowed".to_string());
    }

    let scheme = parsed.scheme().to_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(format!("unsupported scheme: {scheme}"));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "missing host".to_string())?;
    let host = normalize_host(host);
    if is_localhost_host(&host) {
        return Err("localhost is denied".to_string());
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "invalid port".to_string())?;
    validate_host_port(policy, &host, port, &scheme)?;

    Ok(UrlTarget { host, port, scheme })
}

fn resolve_and_validate_inner(
    host: &str,
    block_private_ip: bool,
    resolver: &dyn DnsResolver,
) -> Result<Vec<IpAddr>, String> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    if is_localhost_host(&host) {
        return Err("localhost is denied".to_string());
    }
    if host == "169.254.169.254" {
        return Err("metadata endpoint blocked".to_string());
    }

    let mut ips = resolver.resolve(&host)?;
    if ips.is_empty() {
        return Err("dns resolve produced no addresses".to_string());
    }

    ips.sort_by_key(|ip| ip.to_string());
    ips.dedup();

    if block_private_ip && ips.iter().any(|ip| is_private_or_blocked_ip(*ip)) {
        return Err("private/loopback address resolved".to_string());
    }
    Ok(ips)
}

pub fn resolve_and_validate(host: &str) -> Result<Vec<IpAddr>, String> {
    let resolver = SystemDnsResolver;
    resolve_and_validate_with_resolver(host, &resolver)
}

pub fn resolve_and_validate_with_resolver(
    host: &str,
    resolver: &dyn DnsResolver,
) -> Result<Vec<IpAddr>, String> {
    resolve_and_validate_inner(host, true, resolver)
}

pub fn enforce_on_request(policy: &NetworkPolicy, url: &str) -> Result<(), String> {
    let _ = enforce_on_request_with_resolver(policy, url, &SystemDnsResolver)?;
    Ok(())
}

pub fn enforce_on_request_with_resolver(
    policy: &NetworkPolicy,
    url: &str,
    resolver: &dyn DnsResolver,
) -> Result<PinnedResolution, String> {
    let target = validate_url(policy, url)?;
    let ips = resolve_and_validate_inner(&target.host, policy.block_private_ip, resolver)?;
    if policy.dns_pin {
        enforce_dns_pin(policy, &target.host, &ips)?;
    }
    Ok(PinnedResolution {
        host: target.host,
        allowed_ips: ips,
    })
}

pub fn validate_redirect_target(
    policy: &NetworkPolicy,
    target_url: &str,
    location: &str,
) -> Result<(), String> {
    let base = Url::parse(target_url).map_err(|err| format!("invalid target url: {err}"))?;
    let next = base
        .join(location)
        .map_err(|err| format!("invalid redirect location: {err}"))?;
    enforce_on_request(policy, next.as_str())
}

fn enforce_dns_pin(policy: &NetworkPolicy, host: &str, ips: &[IpAddr]) -> Result<(), String> {
    if !policy.dns_pin {
        return Ok(());
    }
    let mut pins = policy
        .dns_pins
        .lock()
        .map_err(|_| "dns pin state poisoned".to_string())?;
    let now = unique_sorted_ips(ips);
    match pins.get(host) {
        Some(pinned) => {
            if *pinned != now {
                return Err("dns rebinding detected".to_string());
            }
        }
        None => {
            pins.insert(host.to_string(), now);
        }
    }
    Ok(())
}

fn unique_sorted_ips(ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut values = ips.to_vec();
    values.sort_by_key(|ip| ip.to_string());
    values.dedup();
    values
}

fn is_private_or_blocked_ip(ip: IpAddr) -> bool {
    if is_localhost_host(&ip.to_string()) {
        return true;
    }
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            addr.is_private()
                || addr.is_link_local()
                || octets[0] == 0
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 10)
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || addr.is_broadcast()
                || addr.is_unspecified()
        }
        IpAddr::V6(addr) => {
            addr.is_loopback()
                || addr.is_unique_local()
                || addr.is_unspecified()
                || addr.is_multicast()
        }
    }
}

fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn ip(addr: &str) -> IpAddr {
        addr.parse().expect("valid ip")
    }

    #[test]
    fn allowlisted_host_port_is_allowed() {
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "1.1.1.1".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            false,
            true,
        );
        assert!(enforce_on_request(&policy, "https://1.1.1.1:443").is_ok());
    }

    #[test]
    fn unlisted_target_is_denied() {
        let policy = NetworkPolicy::new(Vec::new(), false, true);
        assert!(enforce_on_request(&policy, "https://1.1.1.1:443").is_err());
    }

    #[test]
    fn private_ip_target_is_denied() {
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "10.0.0.1".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            false,
            true,
        );
        assert!(enforce_on_request(&policy, "https://10.0.0.1:443").is_err());
    }

    #[test]
    fn localhost_target_is_denied() {
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "localhost".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            false,
            true,
        );
        assert!(enforce_on_request(&policy, "https://localhost:443").is_err());
    }

    #[test]
    fn metadata_target_is_denied() {
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "169.254.169.254".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            false,
            true,
        );
        assert!(enforce_on_request(&policy, "https://169.254.169.254:443").is_err());
    }

    #[test]
    fn rejects_userinfo_trick() {
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "evil.com".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            false,
            true,
        );
        assert!(validate_url(&policy, "https://127.0.0.1@evil.com:443/?x=1").is_err());
    }

    #[test]
    fn rejects_file_scheme() {
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "example.com".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            false,
            true,
        );
        assert!(validate_url(&policy, "file:///etc/passwd").is_err());
    }

    #[test]
    fn redirect_to_disallowed_host_is_rejected() {
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "example.com".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            false,
            true,
        );
        assert!(validate_redirect_target(
            &policy,
            "https://example.com/login",
            "https://evil.example.net/callback"
        )
        .is_err());
    }

    #[test]
    fn redirect_to_allowed_host_is_allowed() {
        let policy = NetworkPolicy::new(
            vec![
                AllowedTarget {
                    host: "example.com".to_string(),
                    port: 443,
                    scheme: Some("https".to_string()),
                },
                AllowedTarget {
                    host: "trusted.example.net".to_string(),
                    port: 443,
                    scheme: Some("https".to_string()),
                },
            ],
            false,
            true,
        );
        assert!(validate_redirect_target(
            &policy,
            "https://example.com/login",
            "https://trusted.example.net/callback"
        )
        .is_ok());
    }

    #[test]
    fn dns_rebinding_is_detected_when_pin_enabled() {
        let resolver = FakeDnsResolver::new(&[(
            "example.com",
            vec![vec![ip("93.184.216.34")], vec![ip("10.0.0.1")]],
        )]);
        let policy = NetworkPolicy::new(
            vec![AllowedTarget {
                host: "example.com".to_string(),
                port: 443,
                scheme: Some("https".to_string()),
            }],
            true,
            true,
        );

        assert!(
            enforce_on_request_with_resolver(&policy, "https://example.com:443", &resolver).is_ok()
        );
        let err = enforce_on_request_with_resolver(&policy, "https://example.com:443", &resolver)
            .expect_err("second call must fail");
        assert_eq!(err, "dns rebinding detected");
    }

    #[derive(Debug)]
    struct FakeDnsResolver {
        responses: HashMap<String, std::sync::Mutex<VecDeque<Vec<IpAddr>>>>,
    }

    impl FakeDnsResolver {
        fn new(entries: &[(&str, Vec<Vec<IpAddr>>)]) -> Self {
            Self {
                responses: entries
                    .iter()
                    .map(|(host, values)| {
                        (
                            normalize_host(host),
                            std::sync::Mutex::new(VecDeque::from(values.clone())),
                        )
                    })
                    .collect(),
            }
        }
    }

    impl DnsResolver for FakeDnsResolver {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
            let host = normalize_host(host);
            let entries = self
                .responses
                .get(&host)
                .ok_or_else(|| format!("dns resolve failed for host: {host}"))?;
            let mut entries = entries
                .lock()
                .map_err(|_| "dns resolver state poisoned".to_string())?;
            entries
                .pop_front()
                .ok_or_else(|| format!("dns resolved no further entries for host: {host}"))
        }
    }
}
