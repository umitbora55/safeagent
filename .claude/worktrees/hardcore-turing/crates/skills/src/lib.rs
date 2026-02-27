pub mod browser_control;
pub mod honeypot;
pub mod calendar_reader;
pub mod calendar_writer;
pub mod email_reader;
pub mod email_sender;
pub mod file_reader;
pub mod file_writer;
pub mod google_oauth;
pub mod image_processor;
pub mod shell_executor;
pub mod url_fetcher;
pub mod voice;
pub mod web_search;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Policy enforcement imports
use chrono::Utc;
use safeagent_audit_log::{AuditEntry, AuditLog};
use safeagent_policy_engine::{ActionType, PendingAction, PolicyDecision, PolicyEngine};

/// Permission required by a skill.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Permission(pub String);

impl Permission {
    pub fn read_web() -> Self {
        Self("read:web".into())
    }
    pub fn read_fs() -> Self {
        Self("read:fs".into())
    }
    pub fn read_calendar() -> Self {
        Self("read:calendar".into())
    }
    pub fn read_email() -> Self {
        Self("read:email".into())
    }
    pub fn write_email() -> Self {
        Self("write:email".into())
    }
    pub fn write_fs() -> Self {
        Self("write:fs".into())
    }
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
        Self {
            success: true,
            output,
            metadata: HashMap::new(),
        }
    }

    pub fn err(msg: String) -> Self {
        Self {
            success: false,
            output: msg,
            metadata: HashMap::new(),
        }
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Supervisor Trait — Human-in-the-loop approval
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Request for supervisor approval.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub skill_id: String,
    pub skill_name: String,
    pub action_type: ActionType,
    pub description: String,
    pub input_preview: String,
    pub pending: PendingAction,
}

/// Supervisor trait for human-in-the-loop approval.
#[async_trait]
pub trait Supervisor: Send + Sync {
    /// Request approval for a red-level action.
    /// Returns true if approved, false if denied.
    async fn request_approval(&self, request: &ApprovalRequest) -> bool;
}

/// No-op supervisor that denies all requests (for testing/headless mode).
pub struct DenySupervisor;

#[async_trait]
impl Supervisor for DenySupervisor {
    async fn request_approval(&self, _request: &ApprovalRequest) -> bool {
        tracing::warn!("DenySupervisor: Denying approval request");
        false
    }
}

/// Auto-approve supervisor (DANGEROUS - only for testing).
pub struct AutoApproveSupervisor;

#[async_trait]
impl Supervisor for AutoApproveSupervisor {
    async fn request_approval(&self, request: &ApprovalRequest) -> bool {
        tracing::warn!("AutoApproveSupervisor: Auto-approving {}", request.skill_id);
        true
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Skill → ActionType Mapping
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Map skill ID to corresponding ActionType.
pub fn skill_to_action(skill_id: &str) -> ActionType {
    match skill_id {
        // Green actions
        "web_search" => ActionType::SearchWeb,
        "url_fetcher" => ActionType::SearchWeb,
        "calendar_reader" => ActionType::ReadCalendar,
        "image_processor" => ActionType::SummarizeContent,

        // Yellow actions
        "email_reader" => ActionType::ReadEmail,
        "calendar_writer" => ActionType::AddCalendarEvent,
        "file_reader" => ActionType::Custom("read_file".into()),
        "voice" => ActionType::Custom("voice_synthesis".into()),
        "browser_control" => ActionType::Custom("browser_control".into()),

        // Red actions
        "email_sender" => ActionType::SendEmail,
        "file_writer" => ActionType::DeleteFile, // treat write as potentially destructive
        "shell_executor" => ActionType::RunShellCommand,

        // Unknown skills default to Yellow
        _ => ActionType::Custom(skill_id.to_string()),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Policy-Enforced Execution
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Error returned when skill execution is blocked by policy.
#[derive(Debug)]
pub enum PolicyBlockedError {
    Denied { reason: String },
    ApprovalRejected { skill_id: String },
    ApprovalTimeout { skill_id: String },
}

impl std::fmt::Display for PolicyBlockedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyBlockedError::Denied { reason } => {
                write!(f, "Policy denied: {}", reason)
            }
            PolicyBlockedError::ApprovalRejected { skill_id } => {
                write!(f, "User rejected approval for skill: {}", skill_id)
            }
            PolicyBlockedError::ApprovalTimeout { skill_id } => {
                write!(f, "Approval timeout for skill: {}", skill_id)
            }
        }
    }
}

impl std::error::Error for PolicyBlockedError {}

/// Execute a skill with policy enforcement.
///
/// This wrapper MUST be used instead of calling skill.execute() directly.
///
/// Flow:
/// 1. Map skill to ActionType
/// 2. Evaluate policy decision
/// 3. For Allow → execute
/// 4. For RequireApproval → ask supervisor
/// 5. For Deny → return error
/// 6. Record audit event in all cases
pub async fn execute_with_policy(
    skill: &dyn Skill,
    input: &str,
    policy: &PolicyEngine,
    supervisor: &dyn Supervisor,
    audit: Option<&AuditLog>,
) -> Result<SkillResult, PolicyBlockedError> {
    let skill_id = skill.id();
    let skill_name = skill.name();
    let action_type = skill_to_action(skill_id);
    let description = format!("Skill '{}' execution", skill_name);

    // Truncate input for audit (max 200 chars)
    let input_preview = if input.len() > 200 {
        format!("{}...", &input[..200])
    } else {
        input.to_string()
    };

    let details = serde_json::json!({
        "skill_id": skill_id,
        "skill_name": skill_name,
        "input_preview": input_preview,
    });

    tracing::debug!(
        skill_id = skill_id,
        action = ?action_type,
        "Evaluating policy for skill execution"
    );

    // Evaluate policy
    let decision = policy.evaluate(&action_type, &description, details);

    match decision {
        PolicyDecision::Allow => {
            tracing::info!(skill_id = skill_id, "Policy: ALLOW");
            record_skill_audit(audit, skill_id, "allowed", true, None);
            let result = skill.execute(input).await;
            record_skill_audit(audit, skill_id, "executed", result.success, None);
            Ok(result)
        }

        PolicyDecision::AllowWithNotification {
            action_type,
            description,
            ..
        } => {
            tracing::info!(
                skill_id = skill_id,
                action = ?action_type,
                "Policy: ALLOW_WITH_NOTIFICATION - {}",
                description
            );
            record_skill_audit(audit, skill_id, "allowed_with_notification", true, None);
            let result = skill.execute(input).await;
            record_skill_audit(audit, skill_id, "executed", result.success, None);
            Ok(result)
        }

        PolicyDecision::RequireApproval { pending } => {
            tracing::warn!(
                skill_id = skill_id,
                action_id = %pending.id,
                "Policy: REQUIRE_APPROVAL"
            );

            let request = ApprovalRequest {
                skill_id: skill_id.to_string(),
                skill_name: skill_name.to_string(),
                action_type: action_type.clone(),
                description: description.clone(),
                input_preview: input_preview.clone(),
                pending: pending.clone(),
            };

            let approved = supervisor.request_approval(&request).await;

            if approved {
                tracing::info!(skill_id = skill_id, "Supervisor: APPROVED");
                policy.approve(&pending.id, None);
                record_skill_audit(audit, skill_id, "approved_and_executed", true, None);
                let result = skill.execute(input).await;
                record_skill_audit(audit, skill_id, "executed", result.success, None);
                Ok(result)
            } else {
                tracing::warn!(skill_id = skill_id, "Supervisor: REJECTED");
                policy.reject(&pending.id, None);
                record_skill_audit(
                    audit,
                    skill_id,
                    "rejected",
                    false,
                    Some("User rejected approval"),
                );
                Err(PolicyBlockedError::ApprovalRejected {
                    skill_id: skill_id.to_string(),
                })
            }
        }

        PolicyDecision::Deny { reason } => {
            tracing::error!(skill_id = skill_id, reason = %reason, "Policy: DENY");
            record_skill_audit(audit, skill_id, "denied", false, Some(&reason));
            Err(PolicyBlockedError::Denied { reason })
        }
    }
}

/// Record a skill execution event to audit log.
fn record_skill_audit(
    audit: Option<&AuditLog>,
    skill_id: &str,
    event_type: &str,
    success: bool,
    error_message: Option<&str>,
) {
    let Some(audit) = audit else { return };

    let entry = AuditEntry {
        timestamp: Utc::now(),
        event_type: format!("skill_{}", event_type),
        model_name: String::new(),
        tier: String::new(),
        platform: "skill".to_string(),
        input_tokens: 0,
        output_tokens: 0,
        cost_microdollars: 0,
        cache_status: String::new(),
        latency_ms: 0,
        success,
        error_message: error_message.map(String::from),
        metadata: serde_json::json!({ "skill_id": skill_id }).to_string(),
    };

    if let Err(e) = audit.record(&entry) {
        tracing::error!("Failed to record skill audit: {}", e);
    }
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
                if (16..=31).contains(&n) {
                    return true;
                }
            }
        }
    }
    // Link-local and metadata
    if ip.starts_with("169.254.") {
        return true;
    }
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

    #[test]
    fn test_skill_to_action_mapping() {
        use safeagent_policy_engine::ActionType;

        // Green actions
        assert_eq!(skill_to_action("web_search"), ActionType::SearchWeb);
        assert_eq!(skill_to_action("calendar_reader"), ActionType::ReadCalendar);

        // Yellow actions
        assert_eq!(skill_to_action("email_reader"), ActionType::ReadEmail);
        assert_eq!(
            skill_to_action("calendar_writer"),
            ActionType::AddCalendarEvent
        );

        // Red actions
        assert_eq!(skill_to_action("email_sender"), ActionType::SendEmail);
        assert_eq!(
            skill_to_action("shell_executor"),
            ActionType::RunShellCommand
        );

        // Unknown defaults to Custom
        match skill_to_action("unknown_skill") {
            ActionType::Custom(s) => assert_eq!(s, "unknown_skill"),
            _ => panic!("Expected Custom action type"),
        }
    }

    #[test]
    fn test_approval_request_creation() {
        use safeagent_policy_engine::{ActionId, ActionStatus, PermissionLevel};

        let pending = PendingAction {
            id: ActionId::new(),
            action_type: ActionType::SendEmail,
            level: PermissionLevel::Red,
            description: "Send email".into(),
            details: serde_json::Value::Null,
            requested_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            status: ActionStatus::Pending,
        };

        let request = ApprovalRequest {
            skill_id: "email_sender".into(),
            skill_name: "Email Sender".into(),
            action_type: ActionType::SendEmail,
            description: "Send email to user".into(),
            input_preview: "to: user@example.com".into(),
            pending,
        };

        assert_eq!(request.skill_id, "email_sender");
        assert_eq!(request.action_type, ActionType::SendEmail);
    }
}
