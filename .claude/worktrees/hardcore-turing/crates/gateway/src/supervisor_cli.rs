//! CLI-based supervisor for human-in-the-loop approval.
//!
//! Prompts the user via stdin when a red-level action requires approval.

use async_trait::async_trait;
use chrono::Utc;
use safeagent_audit_log::{AuditEntry, AuditLog};
use safeagent_skills::{ApprovalRequest, Supervisor};
use std::io::{self, BufRead, Write};
use std::time::Duration;
use tokio::time::timeout;

/// Default timeout for approval requests (30 seconds).
const APPROVAL_TIMEOUT_SECS: u64 = 30;

/// CLI-based supervisor that prompts via stdin.
pub struct CliSupervisor {
    timeout: Duration,
    audit: Option<AuditLog>,
}

impl CliSupervisor {
    /// Create a new CLI supervisor with default timeout (30s).
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(APPROVAL_TIMEOUT_SECS),
            audit: None,
        }
    }

    /// Create with custom timeout.
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            audit: None,
        }
    }

    /// Create with audit logging.
    pub fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Record approval decision to audit log.
    fn record_audit(&self, skill_id: &str, decision: &str, approved: bool) {
        let Some(ref audit) = self.audit else { return };

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: "supervisor_decision".into(),
            model_name: String::new(),
            tier: String::new(),
            platform: "cli".into(),
            input_tokens: 0,
            output_tokens: 0,
            cost_microdollars: 0,
            cache_status: String::new(),
            latency_ms: 0,
            success: approved,
            error_message: if approved {
                None
            } else {
                Some(decision.into())
            },
            metadata: serde_json::json!({
                "skill_id": skill_id,
                "decision": decision,
            })
            .to_string(),
        };

        if let Err(e) = audit.record(&entry) {
            tracing::error!("Failed to record supervisor audit: {}", e);
        }
    }
}

impl Default for CliSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Supervisor for CliSupervisor {
    async fn request_approval(&self, request: &ApprovalRequest) -> bool {
        // Print approval prompt
        println!();
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║                    🔴 APPROVAL REQUIRED                          ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║ Skill:       {:<52} ║", request.skill_name);
        println!(
            "║ Action:      {:<52} ║",
            format!("{:?}", request.action_type)
        );
        println!(
            "║ Description: {:<52} ║",
            truncate(&request.description, 52)
        );
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║ Input Preview:                                                   ║");

        // Print input preview (truncated and wrapped)
        for line in wrap_text(&request.input_preview, 64) {
            println!("║   {:<64} ║", line);
        }

        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!(
            "║ Timeout: {} seconds                                              ║",
            self.timeout.as_secs()
        );
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!();
        print!("Approve? [y/N]: ");
        let _ = io::stdout().flush();

        // Read input with timeout
        let result = timeout(self.timeout, read_stdin_line()).await;

        match result {
            Ok(Some(line)) => {
                let response = line.trim().to_lowercase();
                let approved = response == "y" || response == "yes";

                if approved {
                    println!("✅ Approved");
                    self.record_audit(&request.skill_id, "approved", true);
                } else {
                    println!("❌ Denied");
                    self.record_audit(&request.skill_id, "denied", false);
                }

                approved
            }
            Ok(None) => {
                println!("❌ No input received");
                self.record_audit(&request.skill_id, "no_input", false);
                false
            }
            Err(_) => {
                println!();
                println!("⏰ Timeout - request denied");
                self.record_audit(&request.skill_id, "timeout", false);
                false
            }
        }
    }
}

/// Read a line from stdin asynchronously.
async fn read_stdin_line() -> Option<String> {
    tokio::task::spawn_blocking(|| {
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        let mut line = String::new();
        match handle.read_line(&mut line) {
            Ok(0) => None, // EOF
            Ok(_) => Some(line),
            Err(_) => None,
        }
    })
    .await
    .ok()
    .flatten()
}

/// Truncate a string to max length with ellipsis.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Wrap text to specified width.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    // Limit to 3 lines max
    if lines.len() > 3 {
        lines.truncate(2);
        lines.push("...".to_string());
    }

    if lines.is_empty() {
        lines.push("(empty)".to_string());
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("hi", 10), "hi");
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn test_wrap_text() {
        let text = "This is a test string that should be wrapped";
        let lines = wrap_text(text, 20);
        assert!(lines.len() > 1);
        for line in &lines {
            assert!(line.len() <= 20 || line == "...");
        }
    }

    #[test]
    fn test_wrap_empty() {
        let lines = wrap_text("", 20);
        assert_eq!(lines, vec!["(empty)"]);
    }

    #[test]
    fn test_cli_supervisor_creation() {
        let supervisor = CliSupervisor::new();
        assert_eq!(supervisor.timeout.as_secs(), 30);

        let supervisor = CliSupervisor::with_timeout(60);
        assert_eq!(supervisor.timeout.as_secs(), 60);
    }

    #[test]
    fn test_default_supervisor() {
        let supervisor = CliSupervisor::default();
        assert_eq!(supervisor.timeout.as_secs(), 30);
    }
}
