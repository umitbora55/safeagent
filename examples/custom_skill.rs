use safeagent_skills_sdk::{run_skill_with_policy, HarnessCase, SkillExecutionOutput, SkillV2};
use async_trait::async_trait;

#[derive(Default)]
struct EchoSkill;

#[async_trait]
impl SkillV2 for EchoSkill {
    fn id(&self) -> &str {
        "echo"
    }

    fn required_scope(&self) -> &str {
        "skill:echo"
    }

    async fn execute(&self, input: &str) -> safeagent_skills_sdk::Result<SkillExecutionOutput> {
        Ok(SkillExecutionOutput {
            output: format!("echo:{input}"),
            metadata: Default::default(),
        })
    }
}

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let output = rt
        .block_on(async {
            run_skill_with_policy(
                &EchoSkill,
                HarnessCase {
                    required_scopes: vec!["skill:echo".to_string()],
                    input: "hello".to_string(),
                },
            )
            .await
        })
        .expect("run");
    assert_eq!(output.output, "echo:hello");
}
