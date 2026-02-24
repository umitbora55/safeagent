//! Skill dispatch with mandatory policy enforcement.
//!
//! All skill execution MUST go through this module.
//! Direct calls to skill.execute() are forbidden.

use safeagent_audit_log::AuditLog;
use safeagent_policy_engine::PolicyEngine;
use safeagent_skills::{execute_with_policy, PolicyBlockedError, Skill, SkillResult, Supervisor};
use std::collections::HashMap;
use std::sync::Arc;

/// Central skill dispatcher that enforces policy on all skill executions.
pub struct SkillDispatcher {
    skills: HashMap<String, Arc<dyn Skill>>,
    policy: Arc<PolicyEngine>,
    supervisor: Arc<dyn Supervisor>,
    audit: Option<Arc<AuditLog>>,
}

impl SkillDispatcher {
    /// Create a new skill dispatcher.
    pub fn new(
        policy: Arc<PolicyEngine>,
        supervisor: Arc<dyn Supervisor>,
        audit: Option<Arc<AuditLog>>,
    ) -> Self {
        Self {
            skills: HashMap::new(),
            policy,
            supervisor,
            audit,
        }
    }

    /// Register a skill. All registered skills will be policy-enforced.
    pub fn register<S: Skill + 'static>(&mut self, skill: S) {
        let id = skill.id().to_string();
        self.skills.insert(id, Arc::new(skill));
    }

    /// Register a skill from an Arc.
    pub fn register_arc(&mut self, skill: Arc<dyn Skill>) {
        let id = skill.id().to_string();
        self.skills.insert(id, skill);
    }

    /// Get list of available skill IDs.
    pub fn available_skills(&self) -> Vec<&str> {
        self.skills.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a skill is registered.
    pub fn has_skill(&self, skill_id: &str) -> bool {
        self.skills.contains_key(skill_id)
    }

    /// Execute a skill with MANDATORY policy enforcement.
    ///
    /// This is the ONLY way skills should be executed.
    /// Direct calls to skill.execute() bypass policy and are forbidden.
    pub async fn execute(
        &self,
        skill_id: &str,
        input: &str,
    ) -> Result<SkillResult, SkillDispatchError> {
        let skill = self
            .skills
            .get(skill_id)
            .ok_or_else(|| SkillDispatchError::SkillNotFound(skill_id.to_string()))?;

        tracing::info!(
            skill_id = skill_id,
            "Dispatching skill with policy enforcement"
        );

        // Execute through policy wrapper - this is mandatory
        let result = execute_with_policy(
            skill.as_ref(),
            input,
            &self.policy,
            self.supervisor.as_ref(),
            self.audit.as_ref().map(|a| a.as_ref()),
        )
        .await
        .map_err(SkillDispatchError::PolicyBlocked)?;

        Ok(result)
    }

    /// Execute a skill and return JSON result for tool_result format.
    pub async fn execute_for_tool(&self, skill_id: &str, input: &str) -> serde_json::Value {
        match self.execute(skill_id, input).await {
            Ok(result) => {
                serde_json::json!({
                    "success": result.success,
                    "output": result.output,
                    "metadata": result.metadata,
                })
            }
            Err(e) => {
                serde_json::json!({
                    "success": false,
                    "error": e.to_string(),
                })
            }
        }
    }
}

/// Errors that can occur during skill dispatch.
#[derive(Debug)]
pub enum SkillDispatchError {
    /// Skill not found in registry.
    SkillNotFound(String),
    /// Policy blocked the execution.
    PolicyBlocked(PolicyBlockedError),
}

impl std::fmt::Display for SkillDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkillDispatchError::SkillNotFound(id) => {
                write!(f, "Skill '{}' not found", id)
            }
            SkillDispatchError::PolicyBlocked(e) => {
                write!(f, "Policy blocked: {}", e)
            }
        }
    }
}

impl std::error::Error for SkillDispatchError {}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use safeagent_policy_engine::PolicyConfig;
    use safeagent_skills::{DenySupervisor, Permission};

    /// Test skill that always succeeds.
    struct TestSkill {
        id: String,
    }

    impl TestSkill {
        fn new(id: &str) -> Self {
            Self { id: id.to_string() }
        }
    }

    #[async_trait]
    impl Skill for TestSkill {
        fn id(&self) -> &str {
            &self.id
        }

        fn name(&self) -> &str {
            "Test Skill"
        }

        fn description(&self) -> &str {
            "A test skill"
        }

        fn permissions(&self) -> Vec<Permission> {
            vec![Permission::read_web()]
        }

        async fn execute(&self, input: &str) -> SkillResult {
            SkillResult::ok(format!("Executed with input: {}", input))
        }
    }

    #[tokio::test]
    async fn test_skill_not_found() {
        let policy = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let dispatcher = SkillDispatcher::new(policy, supervisor, None);

        let result = dispatcher.execute("nonexistent", "input").await;
        assert!(matches!(result, Err(SkillDispatchError::SkillNotFound(_))));
    }

    #[tokio::test]
    async fn test_green_skill_allowed() {
        let policy = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let mut dispatcher = SkillDispatcher::new(policy, supervisor, None);

        // Register a skill that maps to SearchWeb (Green action)
        dispatcher.register(TestSkill::new("web_search"));

        let result = dispatcher.execute("web_search", "test query").await;
        assert!(result.is_ok());
        assert!(result.unwrap().success);
    }

    #[tokio::test]
    async fn test_red_skill_denied_by_supervisor() {
        let policy = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        // DenySupervisor will reject all approval requests
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let mut dispatcher = SkillDispatcher::new(policy, supervisor, None);

        // Register a skill that maps to RunShellCommand (Red action)
        dispatcher.register(TestSkill::new("shell_executor"));

        let result = dispatcher.execute("shell_executor", "ls -la").await;
        assert!(matches!(
            result,
            Err(SkillDispatchError::PolicyBlocked(
                PolicyBlockedError::ApprovalRejected { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn test_blocked_action_denied() {
        use safeagent_policy_engine::ActionType;

        let config = PolicyConfig {
            blocked_actions: vec![ActionType::SearchWeb],
            ..Default::default()
        };
        let policy = Arc::new(PolicyEngine::new(config));
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let mut dispatcher = SkillDispatcher::new(policy, supervisor, None);

        dispatcher.register(TestSkill::new("web_search"));

        let result = dispatcher.execute("web_search", "test").await;
        assert!(matches!(
            result,
            Err(SkillDispatchError::PolicyBlocked(
                PolicyBlockedError::Denied { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn test_has_skill() {
        let policy = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let mut dispatcher = SkillDispatcher::new(policy, supervisor, None);

        assert!(!dispatcher.has_skill("web_search"));
        dispatcher.register(TestSkill::new("web_search"));
        assert!(dispatcher.has_skill("web_search"));
    }

    #[tokio::test]
    async fn test_available_skills() {
        let policy = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let mut dispatcher = SkillDispatcher::new(policy, supervisor, None);

        dispatcher.register(TestSkill::new("skill_a"));
        dispatcher.register(TestSkill::new("skill_b"));

        let available = dispatcher.available_skills();
        assert_eq!(available.len(), 2);
        assert!(available.contains(&"skill_a"));
        assert!(available.contains(&"skill_b"));
    }

    #[tokio::test]
    async fn test_execute_for_tool_success() {
        let policy = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let mut dispatcher = SkillDispatcher::new(policy, supervisor, None);

        dispatcher.register(TestSkill::new("web_search"));

        let result = dispatcher.execute_for_tool("web_search", "test").await;
        assert_eq!(result["success"], true);
        assert!(result["output"].as_str().unwrap().contains("test"));
    }

    #[tokio::test]
    async fn test_execute_for_tool_error() {
        let policy = Arc::new(PolicyEngine::new(PolicyConfig::default()));
        let supervisor: Arc<dyn Supervisor> = Arc::new(DenySupervisor);
        let dispatcher = SkillDispatcher::new(policy, supervisor, None);

        let result = dispatcher.execute_for_tool("nonexistent", "test").await;
        assert_eq!(result["success"], false);
        assert!(result["error"].as_str().is_some());
    }
}
