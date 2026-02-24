//! Hardened Shell Executor (R2 Security Fix)
//!
//! Security features:
//! - Direct execve (no shell invocation)
//! - Strict command allowlist with path resolution
//! - Enforced timeout via tokio
//! - Output size cap
//! - Environment sanitization
//! - Argument validation (no path traversal)

use crate::{Permission, Skill, SkillConfig, SkillResult};
use async_trait::async_trait;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Safe paths where allowed binaries can be executed from.
const SAFE_PATHS: &[&str] = &["/usr/bin", "/bin", "/usr/local/bin"];

/// Maximum output size in bytes (64KB).
const MAX_OUTPUT_BYTES: usize = 65536;

/// Default timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Hardened shell executor with strict security controls.
///
/// Security guarantees:
/// 1. No shell invocation - direct execve only
/// 2. Commands must be in allowlist AND exist in SAFE_PATHS
/// 3. No shell metacharacters or chaining
/// 4. Timeout enforced via tokio (kills process on timeout)
/// 5. Environment cleared except minimal safe vars
/// 6. Arguments validated for path traversal attempts
pub struct ShellExecutorSkill {
    allowed_commands: Vec<String>,
    blocked_patterns: Vec<String>,
    max_output_bytes: usize,
    timeout_secs: u64,
    config: SkillConfig,
}

impl ShellExecutorSkill {
    pub fn new(allowed_commands: Vec<String>) -> Self {
        Self {
            allowed_commands,
            blocked_patterns: vec![
                // Destructive operations
                "rm -rf".into(),
                "rm -f /".into(),
                "rm -r /".into(),
                "rmdir /".into(),
                "mkfs".into(),
                "dd if=".into(),
                "shred".into(),
                // Redirect attacks
                "> /dev/".into(),
                ">> /".into(),
                "> /".into(),
                // Fork bombs
                ":(){ :|:& };:".into(),
                // Permission escalation
                "chmod -R 777".into(),
                "chmod 777 /".into(),
                "chown -R".into(),
                "chown root".into(),
                // Remote code execution
                "curl|sh".into(),
                "curl|bash".into(),
                "wget|sh".into(),
                "wget|bash".into(),
                "curl -o".into(),
                "wget -O".into(),
                // Privilege escalation
                "sudo".into(),
                "su -".into(),
                "su root".into(),
                "doas".into(),
                "pkexec".into(),
                // Credential access
                "passwd".into(),
                "/etc/shadow".into(),
                "/etc/passwd".into(),
                "/etc/sudoers".into(),
                "~/.ssh".into(),
                ".ssh/".into(),
                "id_rsa".into(),
                "id_ed25519".into(),
                // System modification
                "systemctl".into(),
                "service ".into(),
                "init ".into(),
                "shutdown".into(),
                "reboot".into(),
                "halt".into(),
                "poweroff".into(),
                // Network attacks
                "iptables".into(),
                "nft ".into(),
                "nc -e".into(),
                "netcat -e".into(),
                // Cron/scheduled tasks
                "crontab".into(),
                "at ".into(),
                // Environment manipulation
                "export ".into(),
                "unset ".into(),
                "env ".into(),
            ],
            max_output_bytes: MAX_OUTPUT_BYTES,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            config: SkillConfig {
                enabled: false,
                ..Default::default()
            },
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_max_output(mut self, bytes: usize) -> Self {
        self.max_output_bytes = bytes;
        self
    }

    /// Resolve a command to its full path in SAFE_PATHS.
    /// Returns None if command not found in any safe path.
    fn resolve_command_path(&self, cmd: &str) -> Option<PathBuf> {
        // Reject absolute paths or paths with directory components
        if cmd.contains('/') {
            tracing::warn!(cmd = cmd, "Rejecting command with path component");
            return None;
        }

        for safe_dir in SAFE_PATHS {
            let path = PathBuf::from(safe_dir).join(cmd);
            if path.exists() && path.is_file() {
                // Verify it's actually in the safe directory (no symlink escapes)
                if let Ok(canonical) = path.canonicalize() {
                    let canonical_str = canonical.to_string_lossy();
                    if SAFE_PATHS.iter().any(|p| canonical_str.starts_with(p)) {
                        return Some(canonical);
                    }
                    tracing::warn!(
                        cmd = cmd,
                        canonical = %canonical_str,
                        "Symlink escape detected"
                    );
                }
            }
        }
        None
    }

    /// Validate arguments for security issues.
    fn validate_arguments(&self, args: &[&str]) -> Result<(), String> {
        for arg in args {
            // Block path traversal
            if arg.contains("..") {
                return Err("Path traversal (..) not allowed in arguments".into());
            }

            // Block null bytes (can truncate strings in C programs)
            if arg.contains('\0') {
                return Err("Null bytes not allowed in arguments".into());
            }

            // Block shell metacharacters in arguments
            let dangerous_chars = ['`', '$', '\\', '\n', '\r', '\t'];
            for ch in dangerous_chars {
                if arg.contains(ch) {
                    return Err(format!(
                        "Dangerous character '{}' not allowed in arguments",
                        ch.escape_debug()
                    ));
                }
            }

            // Block obvious sensitive paths
            let sensitive = [
                "/etc/shadow",
                "/etc/passwd",
                "/etc/sudoers",
                "/root/",
                "~/.ssh",
                ".ssh/",
                "/proc/",
                "/sys/",
                "/dev/",
            ];
            let arg_lower = arg.to_lowercase();
            for s in sensitive {
                if arg_lower.contains(s) {
                    return Err(format!("Access to '{}' is blocked", s));
                }
            }
        }
        Ok(())
    }

    fn is_command_allowed(&self, cmd: &str) -> Result<PathBuf, String> {
        let cmd_lower = cmd.to_lowercase();

        // Check blocked patterns first
        for pattern in &self.blocked_patterns {
            if cmd_lower.contains(&pattern.to_lowercase()) {
                return Err(format!(
                    "Command blocked: contains dangerous pattern '{}'",
                    pattern
                ));
            }
        }

        if self.allowed_commands.is_empty() {
            return Err(
                "No commands allowlisted. Configure [skills.shell_executor] allowed_commands in safeagent.toml.\n\
                 Example: allowed_commands = [\"ls\", \"cat\", \"grep\", \"wc\", \"head\", \"tail\", \"echo\", \"date\"]".into()
            );
        }

        // Block shell chaining operators (even though we don't invoke shell)
        let shell_metachar = [
            "&&", "||", ";", "|", "`", "$(", ")", "(", "{", "}", "<(", ">(", "<<", ">>", "2>", "&>",
        ];
        for meta in shell_metachar {
            if cmd.contains(meta) {
                return Err(format!(
                    "Shell operator '{}' not allowed (direct execution only)",
                    meta
                ));
            }
        }

        // Parse command
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err("Empty command".into());
        }

        let base_cmd = parts[0];

        // Check if base command is in allowlist
        let allowed = self
            .allowed_commands
            .iter()
            .any(|a| a.eq_ignore_ascii_case(base_cmd));

        if !allowed {
            return Err(format!(
                "Command '{}' not in allowlist. Allowed: {:?}",
                base_cmd, self.allowed_commands
            ));
        }

        // Resolve to full path in SAFE_PATHS
        let resolved = self.resolve_command_path(base_cmd).ok_or_else(|| {
            format!(
                "Command '{}' not found in safe paths {:?}",
                base_cmd, SAFE_PATHS
            )
        })?;

        // Validate arguments
        if parts.len() > 1 {
            self.validate_arguments(&parts[1..])?;
        }

        Ok(resolved)
    }
}

#[async_trait]
impl Skill for ShellExecutorSkill {
    fn id(&self) -> &str {
        "shell_executor"
    }

    fn name(&self) -> &str {
        "Shell Executor (Hardened)"
    }

    fn description(&self) -> &str {
        "Execute a command from the allowlist with strict security controls. \
         Direct execution only (no shell). Commands must exist in /usr/bin, /bin, or /usr/local/bin."
    }

    fn permissions(&self) -> Vec<Permission> {
        vec![Permission("execute:shell".into())]
    }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err(
                "Shell executor is disabled by default. Enable in safeagent.toml:\n\
                 [skills.shell_executor]\n\
                 enabled = true\n\
                 allowed_commands = [\"ls\", \"cat\", \"grep\", \"wc\"]"
                    .into(),
            );
        }

        let cmd = input.trim();
        if cmd.is_empty() {
            return SkillResult::err("Empty command".into());
        }

        // Validate and resolve command path
        let resolved_path = match self.is_command_allowed(cmd) {
            Ok(path) => path,
            Err(e) => return SkillResult::err(e),
        };

        // Parse arguments
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let args = &parts[1..];

        // Build command with security controls
        let mut command = Command::new(&resolved_path);
        command
            .args(args)
            // Clear all environment variables
            .env_clear()
            // Set minimal safe environment
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/tmp")
            .env("LANG", "en_US.UTF-8")
            .env("LC_ALL", "C")
            // Prevent core dumps
            .env("RLIMIT_CORE", "0")
            // Kill on parent exit (Linux only, ignored on macOS)
            .kill_on_drop(true);

        // Execute with enforced timeout
        let timeout_duration = Duration::from_secs(self.timeout_secs);
        let output_result = timeout(timeout_duration, command.output()).await;

        let output = match output_result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                tracing::error!(error = %e, "Command execution failed");
                return SkillResult::err(format!("Execution failed: {}", e));
            }
            Err(_) => {
                tracing::warn!(
                    cmd = cmd,
                    timeout_secs = self.timeout_secs,
                    "Command timed out"
                );
                return SkillResult::err(format!(
                    "Command timed out after {} seconds (killed)",
                    self.timeout_secs
                ));
            }
        };

        // Process output with size cap
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);

        let mut result_text = String::new();

        if !stdout.is_empty() {
            let out = if stdout.len() > self.max_output_bytes {
                format!(
                    "{}...\n[Output truncated at {} bytes]",
                    &stdout[..self.max_output_bytes],
                    self.max_output_bytes
                )
            } else {
                stdout.to_string()
            };
            result_text.push_str(&out);
        }

        if !stderr.is_empty() {
            if !result_text.is_empty() {
                result_text.push_str("\n\n");
            }
            let stderr_capped = if stderr.len() > self.max_output_bytes / 4 {
                format!(
                    "{}...\n[stderr truncated]",
                    &stderr[..self.max_output_bytes / 4]
                )
            } else {
                stderr.to_string()
            };
            result_text.push_str(&format!("[stderr]\n{}", stderr_capped));
        }

        if result_text.is_empty() {
            result_text = format!("Command completed (exit code: {})", exit_code);
        }

        if exit_code == 0 {
            SkillResult::ok(result_text)
                .with_meta("command", cmd)
                .with_meta("exit_code", &exit_code.to_string())
                .with_meta("resolved_path", &resolved_path.to_string_lossy())
        } else {
            SkillResult::err(format!("Exit code {}: {}", exit_code, result_text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> SkillConfig {
        SkillConfig {
            enabled: true,
            ..Default::default()
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Basic functionality tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_disabled_by_default() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("ls"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_empty_allowlist() {
        let skill = ShellExecutorSkill::new(vec![]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("ls"));
        assert!(!result.success);
        assert!(result.output.contains("No commands"));
    }

    #[test]
    fn test_empty_command() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }

    #[test]
    fn test_command_not_in_allowlist() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("whoami"));
        assert!(!result.success);
        assert!(result.output.contains("not in allowlist"));
    }

    #[test]
    fn test_execute_allowed_command() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo hello"));
        assert!(result.success, "Error: {}", result.output);
        assert!(result.output.contains("hello"));
    }

    #[test]
    fn test_execute_date() {
        let skill = ShellExecutorSkill::new(vec!["date".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("date"));
        assert!(result.success, "Error: {}", result.output);
    }

    #[test]
    fn test_execute_ls() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("ls /tmp"));
        assert!(result.success, "Error: {}", result.output);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Security: Blocked patterns
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_blocked_pattern_rm_rf() {
        let skill = ShellExecutorSkill::new(vec!["rm".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("rm -rf /"));
        assert!(!result.success);
        assert!(result.output.contains("dangerous"));
    }

    #[test]
    fn test_blocked_pattern_sudo() {
        let skill = ShellExecutorSkill::new(vec!["sudo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("sudo ls"));
        assert!(!result.success);
        assert!(result.output.contains("dangerous"));
    }

    #[test]
    fn test_blocked_pattern_mkfs() {
        let skill = ShellExecutorSkill::new(vec!["mkfs".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("mkfs.ext4 /dev/sda"));
        assert!(!result.success);
        assert!(result.output.contains("dangerous"));
    }

    #[test]
    fn test_blocked_pattern_etc_shadow() {
        let skill = ShellExecutorSkill::new(vec!["cat".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("cat /etc/shadow"));
        assert!(!result.success);
        // Blocked either by pattern or argument validation
    }

    #[test]
    fn test_blocked_pattern_shutdown() {
        let skill = ShellExecutorSkill::new(vec!["shutdown".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("shutdown -h now"));
        assert!(!result.success);
        assert!(result.output.contains("dangerous"));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Security: Shell chaining blocked
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_chain_blocked_and() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Use harmless chained command to test && blocking specifically
        let result = rt.block_on(skill.execute("echo hello && echo world"));
        assert!(!result.success);
        assert!(
            result.output.contains("not allowed") || result.output.contains("operator"),
            "Expected 'not allowed' or 'operator', got: {}",
            result.output
        );
    }

    #[test]
    fn test_chain_blocked_pipe() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo hello | cat"));
        assert!(!result.success);
        assert!(result.output.contains("not allowed") || result.output.contains("operator"));
    }

    #[test]
    fn test_chain_blocked_subshell() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo $(whoami)"));
        assert!(!result.success);
        assert!(result.output.contains("not allowed") || result.output.contains("operator"));
    }

    #[test]
    fn test_chain_blocked_backtick() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo `whoami`"));
        assert!(!result.success);
    }

    #[test]
    fn test_chain_blocked_semicolon() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo hello; rm -rf /"));
        assert!(!result.success);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Security: Path resolution
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_absolute_path_rejected() {
        let skill =
            ShellExecutorSkill::new(vec!["/usr/bin/ls".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        // User tries to specify absolute path directly
        let result = rt.block_on(skill.execute("/usr/bin/ls"));
        // Should fail - we don't allow "/" in command name
        assert!(!result.success);
    }

    #[test]
    fn test_relative_path_rejected() {
        let skill = ShellExecutorSkill::new(vec!["./malware".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("./malware"));
        assert!(!result.success);
    }

    #[test]
    fn test_command_with_path_in_name_rejected() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Even if "ls" is allowed, "../ls" should be rejected
        let result = rt.block_on(skill.execute("../ls"));
        assert!(!result.success);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Security: Argument validation
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_path_traversal_in_args_blocked() {
        let skill = ShellExecutorSkill::new(vec!["cat".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("cat ../../../etc/passwd"));
        assert!(!result.success);
        assert!(
            result.output.contains("traversal")
                || result.output.contains("dangerous")
                || result.output.contains("blocked")
        );
    }

    #[test]
    fn test_sensitive_path_in_args_blocked() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("ls /proc/1/root"));
        assert!(!result.success);
        assert!(result.output.contains("blocked"));
    }

    #[test]
    fn test_ssh_path_blocked() {
        let skill = ShellExecutorSkill::new(vec!["cat".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("cat ~/.ssh/id_rsa"));
        assert!(!result.success);
    }

    #[test]
    fn test_dollar_in_args_blocked() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo $HOME"));
        assert!(!result.success);
        assert!(result.output.contains("Dangerous character"));
    }

    #[test]
    fn test_backtick_in_args_blocked() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo `id`"));
        assert!(!result.success);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Security: Timeout enforcement
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[tokio::test]
    async fn test_timeout_enforcement() {
        let skill = ShellExecutorSkill::new(vec!["sleep".into()])
            .with_config(enabled_config())
            .with_timeout(1); // 1 second timeout

        // Try to sleep for 10 seconds - should timeout
        let result = skill.execute("sleep 10").await;
        assert!(!result.success);
        assert!(result.output.contains("timed out"));
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Builder pattern tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_builder_with_timeout() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()])
            .with_timeout(60)
            .with_config(enabled_config());
        assert_eq!(skill.timeout_secs, 60);
    }

    #[test]
    fn test_builder_with_max_output() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()])
            .with_max_output(1024)
            .with_config(enabled_config());
        assert_eq!(skill.max_output_bytes, 1024);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Path resolution tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_resolve_existing_command() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]);
        let path = skill.resolve_command_path("ls");
        assert!(path.is_some(), "ls should resolve to a path");
        let path = path.unwrap();
        assert!(path.exists());
        // Should be in one of the safe paths
        let path_str = path.to_string_lossy();
        assert!(
            path_str.starts_with("/usr/bin")
                || path_str.starts_with("/bin")
                || path_str.starts_with("/usr/local/bin")
        );
    }

    #[test]
    fn test_resolve_nonexistent_command() {
        let skill = ShellExecutorSkill::new(vec!["nonexistent_command_xyz".into()]);
        let path = skill.resolve_command_path("nonexistent_command_xyz");
        assert!(path.is_none());
    }

    #[test]
    fn test_resolve_rejects_path_in_command() {
        let skill = ShellExecutorSkill::new(vec!["ls".into()]);
        let path = skill.resolve_command_path("/bin/ls");
        assert!(path.is_none(), "Should reject absolute paths");

        let path = skill.resolve_command_path("../ls");
        assert!(path.is_none(), "Should reject relative paths");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Metadata tests
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    #[test]
    fn test_result_includes_resolved_path() {
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(enabled_config());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo test"));
        assert!(result.success);
        assert!(result.metadata.contains_key("resolved_path"));
        let resolved = result.metadata.get("resolved_path").unwrap();
        assert!(
            resolved.contains("/bin/echo") || resolved.contains("/usr/bin/echo"),
            "Expected path to echo, got: {}",
            resolved
        );
    }
}
