use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, SkillError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillExecutionOutput {
    pub output: String,
    pub metadata: HashMap<String, String>,
}

impl SkillExecutionOutput {
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            output: output.into(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_meta(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillPolicyMetadata {
    pub required_scope: String,
    pub requires_approval: bool,
    pub category: String,
}

impl SkillPolicyMetadata {
    pub fn new(required_scope: impl Into<String>) -> Self {
        Self {
            required_scope: required_scope.into(),
            requires_approval: false,
            category: "default".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillDefinition {
    pub id: String,
    pub description: String,
    pub required_scope: String,
    pub policy_metadata: SkillPolicyMetadata,
}

#[derive(Debug)]
pub enum SkillError {
    Denied { reason: String },
    ScopeMissing { required_scope: String },
    Internal(String),
}

impl core::fmt::Display for SkillError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Denied { reason } => write!(f, "Skill blocked: {reason}"),
            Self::ScopeMissing { required_scope } => {
                write!(f, "Missing scope: {required_scope}")
            }
            Self::Internal(msg) => write!(f, "{msg}"),
        }
    }
}

impl core::fmt::Display for SkillPolicyMetadata {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "required_scope={}, requires_approval={}",
            self.required_scope, self.requires_approval
        )
    }
}

#[derive(Clone)]
pub struct SkillPolicyHooks {
    pub metadata: SkillPolicyMetadata,
}

impl Default for SkillPolicyHooks {
    fn default() -> Self {
        Self {
            metadata: SkillPolicyMetadata::new("skill:basic"),
        }
    }
}

#[async_trait]
pub trait SkillV2 {
    fn id(&self) -> &str;
    fn required_scope(&self) -> &str;

    fn policy_metadata(&self) -> SkillPolicyHooks {
        SkillPolicyHooks {
            metadata: SkillPolicyMetadata::new(self.required_scope()),
        }
    }

    async fn execute(&self, input: &str) -> Result<SkillExecutionOutput>;
}

pub fn scope_allows(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|scope| scope == required || scope == "*")
}

pub struct HarnessCase {
    pub required_scopes: Vec<String>,
    pub input: String,
}

pub async fn run_skill_with_policy<S: SkillV2 + ?Sized>(
    skill: &S,
    case: HarnessCase,
) -> Result<SkillExecutionOutput> {
    if !scope_allows(&case.required_scopes, skill.required_scope()) {
        return Err(SkillError::ScopeMissing {
            required_scope: skill.required_scope().to_string(),
        });
    }
    let output = skill.execute(&case.input).await?;
    if output.output.trim().is_empty() {
        return Err(SkillError::Denied {
            reason: "empty output".to_string(),
        });
    }
    Ok(output)
}

#[derive(Default)]
pub struct SkillRegistry {
    skills: HashMap<String, Box<dyn SkillV2>>,
}

impl SkillRegistry {
    pub fn register<S>(&mut self, skill: S)
    where
        S: SkillV2 + 'static,
    {
        self.skills.insert(skill.id().to_string(), Box::new(skill));
    }

    pub fn count(&self) -> usize {
        self.skills.len()
    }

    pub fn skill_ids(&self) -> Vec<String> {
        self.skills.keys().cloned().collect()
    }

    pub fn has_skill(&self, id: &str) -> bool {
        self.skills.contains_key(id)
    }

    pub async fn execute(
        &self,
        skill_id: &str,
        scopes: &[String],
        input: &str,
    ) -> Result<SkillExecutionOutput> {
        let skill = self
            .skills
            .get(skill_id)
            .ok_or_else(|| SkillError::Denied {
                reason: format!("missing skill: {skill_id}"),
            })?;
        run_skill_with_policy(
            skill.as_ref(),
            HarnessCase {
                required_scopes: scopes.to_vec(),
                input: input.to_string(),
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct EchoSkill;

    #[async_trait]
    impl SkillV2 for EchoSkill {
        fn id(&self) -> &str {
            "echo"
        }

        fn required_scope(&self) -> &str {
            "skill:echo"
        }

        async fn execute(&self, input: &str) -> Result<SkillExecutionOutput> {
            if input.trim().is_empty() {
                return Err(SkillError::Internal("empty input".into()));
            }
            Ok(SkillExecutionOutput::ok(format!("echo:{input}")))
        }
    }

    #[tokio::test]
    async fn execute_with_required_scope_passes() {
        let output = run_skill_with_policy(
            &EchoSkill,
            HarnessCase {
                required_scopes: vec!["skill:echo".to_string()],
                input: "hello".to_string(),
            },
        )
        .await
        .expect("run");
        assert_eq!(output.output, "echo:hello");
    }

    #[tokio::test]
    async fn execute_with_missing_scope_fails() {
        let err = run_skill_with_policy(
            &EchoSkill,
            HarnessCase {
                required_scopes: vec!["skill:admin".to_string()],
                input: "hello".to_string(),
            },
        )
        .await
        .unwrap_err();
        match err {
            SkillError::ScopeMissing { required_scope } => {
                assert_eq!(required_scope, "skill:echo");
            }
            _ => panic!("unexpected"),
        }
    }
}
