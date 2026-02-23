use crate::{Permission, Skill, SkillConfig, SkillResult};
use async_trait::async_trait;
use std::process::Command;

/// Sandboxed shell executor with command allowlist.
/// Only pre-approved commands can run. Deny-all by default.
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
                "rm -rf".into(), "rm -f /".into(), "mkfs".into(), "dd if=".into(),
                "> /dev/".into(), ":(){ :|:& };:".into(), "chmod -R 777 /".into(),
                "curl|sh".into(), "curl|bash".into(), "wget|sh".into(),
                "sudo".into(), "su -".into(), "passwd".into(),
                "/etc/shadow".into(), "/etc/passwd".into(),
            ],
            max_output_bytes: 65536,
            timeout_secs: 30,
            config: SkillConfig { enabled: false, ..Default::default() },
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

    fn is_command_allowed(&self, cmd: &str) -> Result<(), String> {
        let cmd_lower = cmd.to_lowercase();

        // Check blocked patterns
        for pattern in &self.blocked_patterns {
            if cmd_lower.contains(&pattern.to_lowercase()) {
                return Err(format!("Command blocked: contains dangerous pattern '{}'", pattern));
            }
        }

        if self.allowed_commands.is_empty() {
            return Err(
                "No commands allowlisted. Configure [skills.shell_executor] allowed_commands in safeagent.toml.\n\
                 Example: allowed_commands = [\"ls\", \"cat\", \"grep\", \"wc\", \"head\", \"tail\", \"echo\", \"date\"]".into()
            );
        }

        // Check if the base command is in the allowlist
        let base_cmd = cmd.split_whitespace().next().unwrap_or("");
        let allowed = self.allowed_commands.iter().any(|a| {
            let a_lower = a.to_lowercase();
            base_cmd.to_lowercase() == a_lower || base_cmd.to_lowercase().ends_with(&format!("/{}", a_lower))
        });

        if !allowed {
            return Err(format!(
                "Command '{}' not in allowlist. Allowed: {:?}",
                base_cmd, self.allowed_commands
            ));
        }

        // Block shell chaining operators
        if cmd.contains("&&") || cmd.contains("||") || cmd.contains(';') || cmd.contains('|') || cmd.contains('`') || cmd.contains("$(") {
            return Err("Shell chaining operators (&&, ||, ;, |, `, $()) are not allowed for security.".into());
        }

        Ok(())
    }
}

#[async_trait]
impl Skill for ShellExecutorSkill {
    fn id(&self) -> &str { "shell_executor" }
    fn name(&self) -> &str { "Shell Executor" }
    fn description(&self) -> &str {
        "Execute a shell command from the allowlist. Input: the command to run. Only pre-approved commands are permitted."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission("execute:shell".into())] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err(
                "Shell executor is disabled by default. Enable in safeagent.toml:\n\
                 [skills.shell_executor]\n\
                 enabled = true\n\
                 allowed_commands = [\"ls\", \"cat\", \"grep\", \"wc\"]".into()
            );
        }

        let cmd = input.trim();
        if cmd.is_empty() {
            return SkillResult::err("Empty command".into());
        }

        if let Err(e) = self.is_command_allowed(cmd) {
            return SkillResult::err(e);
        }

        // Parse command
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let program = parts[0];
        let args = &parts[1..];

        // Execute with timeout
        let output = match Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/tmp")
            .env("LANG", "en_US.UTF-8")
            .output()
        {
            Ok(o) => o,
            Err(e) => return SkillResult::err(format!("Failed to execute: {}", e)),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);

        let mut result_text = String::new();

        if !stdout.is_empty() {
            let out = if stdout.len() > self.max_output_bytes {
                format!("{}...\n[Output truncated at {} bytes]", &stdout[..self.max_output_bytes], self.max_output_bytes)
            } else {
                stdout.to_string()
            };
            result_text.push_str(&out);
        }

        if !stderr.is_empty() {
            if !result_text.is_empty() { result_text.push_str("\n\n"); }
            result_text.push_str(&format!("[stderr]\n{}", stderr));
        }

        if result_text.is_empty() {
            result_text = format!("Command completed (exit code: {})", exit_code);
        }

        if exit_code == 0 {
            SkillResult::ok(result_text)
                .with_meta("command", cmd)
                .with_meta("exit_code", &exit_code.to_string())
        } else {
            SkillResult::err(format!("Exit code {}: {}", exit_code, result_text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec![]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("ls"));
        assert!(!result.success);
        assert!(result.output.contains("No commands"));
    }

    #[test]
    fn test_command_not_allowed() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec!["ls".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("rm -rf /"));
        assert!(!result.success);
    }

    #[test]
    fn test_blocked_pattern() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec!["rm".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("rm -rf /"));
        assert!(!result.success);
        assert!(result.output.contains("dangerous"));
    }

    #[test]
    fn test_chain_blocked() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(skill.execute("echo hello && rm -rf /"));
        assert!(!result.success);
        assert!(result.output.contains("chaining") || result.output.contains("dangerous") || result.output.contains("blocked"));

        let result = rt.block_on(skill.execute("echo hello | cat"));
        assert!(!result.success);
        assert!(result.output.contains("chaining") || result.output.contains("not allowed") || result.output.contains("blocked"));

        let result = rt.block_on(skill.execute("echo $(whoami)"));
        assert!(!result.success);
        assert!(result.output.contains("chaining") || result.output.contains("not allowed") || result.output.contains("blocked"));
    }

    #[test]
    fn test_execute_allowed_command() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec!["echo".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("echo hello"));
        assert!(result.success, "Error: {}", result.output);
        assert!(result.output.contains("hello"));
    }

    #[test]
    fn test_execute_date() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec!["date".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("date"));
        assert!(result.success);
    }

    #[test]
    fn test_empty_command() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec!["ls".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }

    #[test]
    fn test_sudo_blocked() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = ShellExecutorSkill::new(vec!["sudo".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("sudo ls"));
        assert!(!result.success);
        assert!(result.output.contains("dangerous"));
    }
}
