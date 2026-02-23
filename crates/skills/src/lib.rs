pub mod web_search;
pub mod url_fetcher;
pub mod file_reader;
pub mod google_oauth;
pub mod calendar_reader;
pub mod email_reader;
pub mod file_writer;
pub mod calendar_writer;
pub mod email_sender;
pub mod voice;
pub mod browser_control;
pub mod shell_executor;
pub mod image_processor;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Permission required by a skill.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission(pub String);

impl Permission {
    pub fn read_web() -> Self { Self("read:web".into()) }
    pub fn read_fs() -> Self { Self("read:fs".into()) }
    pub fn read_calendar() -> Self { Self("read:calendar".into()) }
    pub fn read_email() -> Self { Self("read:email".into()) }
    pub fn write_email() -> Self { Self("write:email".into()) }
    pub fn write_fs() -> Self { Self("write:fs".into()) }
}

/// Result returned by a skill invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillResult {
    pub success: bool,
    pub output: String,
    pub metadata: HashMap<String, String>,
}

impl SkillResult {
    pub fn ok(output: String) -> Self {
        Self { success: true, output, metadata: HashMap::new() }
    }

    pub fn err(msg: String) -> Self {
        Self { success: false, output: msg, metadata: HashMap::new() }
    }

    pub fn with_meta(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Skill configuration from safeagent.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillConfig {
    pub enabled: bool,
    pub rate_limit_per_minute: u32,
    pub max_response_bytes: usize,
    pub timeout_secs: u64,
}

impl Default for SkillConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_per_minute: 10,
            max_response_bytes: 1_048_576, // 1MB
            timeout_secs: 30,
        }
    }
}

/// The core Skill trait.
#[async_trait]
pub trait Skill: Send + Sync {
    /// Unique skill identifier.
    fn id(&self) -> &str;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Description for the LLM to decide when to invoke.
    fn description(&self) -> &str;

    /// Permissions this skill requires.
    fn permissions(&self) -> Vec<Permission>;

    /// Execute the skill with given input.
    async fn execute(&self, input: &str) -> SkillResult;
}

/// Re-validate URL after redirect to prevent DNS rebinding attacks.
/// Call this after following redirects to ensure the resolved IP is still safe.
pub fn validate_url_post_redirect(final_url: &str) -> Result<(), String> {
    // Same validation as initial URL check — blocks private IPs after redirect
    validate_url(final_url)?;
    Ok(())
}

/// Check if an IP address is private/reserved (SSRF protection).
pub fn is_private_ip(ip: &str) -> bool {
    // IPv4 private ranges
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip == "127.0.0.1" || ip == "0.0.0.0" {
        return true;
    }
    // 172.16.0.0 - 172.31.255.255
    if ip.starts_with("172.") {
        if let Some(second) = ip.split('.').nth(1) {
            if let Ok(n) = second.parse::<u8>() {
                if (16..=31).contains(&n) { return true; }
            }
        }
    }
    // Link-local and metadata
    if ip.starts_with("169.254.") { return true; }
    // IPv6 loopback/private
    if ip == "::1" || ip.starts_with("fc") || ip.starts_with("fd") || ip.starts_with("fe80") {
        return true;
    }
    false
}

/// Validate a URL for safety (no private IPs, no file://, etc.)
pub fn validate_url(url: &str) -> Result<(), String> {
    let lower = url.to_lowercase();

    // Only allow http/https
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err("Only http:// and https:// URLs are allowed".into());
    }

    // Extract host
    let without_scheme = if lower.starts_with("https://") {
        &url[8..]
    } else {
        &url[7..]
    };
    let host = without_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or(""); // remove port

    if host.is_empty() {
        return Err("Empty host".into());
    }

    // Block localhost variants
    if host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || host == "[::1]" {
        return Err("Localhost URLs are blocked".into());
    }

    // Block obvious private IPs
    if is_private_ip(host) {
        return Err(format!("Private IP {} is blocked (SSRF protection)", host));
    }

    // Block cloud metadata endpoints
    if host == "169.254.169.254" || host == "metadata.google.internal" {
        return Err("Cloud metadata endpoint is blocked".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("169.254.169.254"));
        assert!(is_private_ip("::1"));
        assert!(is_private_ip("fc00::1"));

        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("172.32.0.1"));
    }

    #[test]
    fn test_url_validation() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://api.brave.com/search").is_ok());

        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("ftp://server.com").is_err());
        assert!(validate_url("http://127.0.0.1/admin").is_err());
        assert!(validate_url("http://localhost:8080").is_err());
        assert!(validate_url("http://169.254.169.254/latest").is_err());
        assert!(validate_url("http://10.0.0.1/internal").is_err());
        assert!(validate_url("http://192.168.1.1").is_err());
        assert!(validate_url("http://metadata.google.internal").is_err());
    }

    #[test]
    fn test_skill_result() {
        let r = SkillResult::ok("hello".into()).with_meta("source", "test");
        assert!(r.success);
        assert_eq!(r.output, "hello");
        assert_eq!(r.metadata.get("source").unwrap(), "test");

        let e = SkillResult::err("failed".into());
        assert!(!e.success);
    }

    #[test]
    fn test_permissions() {
        assert_eq!(Permission::read_web().0, "read:web");
        assert_eq!(Permission::write_email().0, "write:email");
    }
}
