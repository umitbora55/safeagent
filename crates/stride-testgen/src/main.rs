//! STRIDE Threat Model → Test Case Generator
//!
//! Reads a STRIDE threat model YAML and generates:
//! - red_team_scenarios/*.yaml
//! - chaos_scenarios/*.yaml
//!
//! Usage:
//!   stride-testgen threat_model/stride.yaml --red-team red_team_scenarios --chaos chaos_scenarios

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "stride-testgen")]
#[command(about = "Generate test scenarios from STRIDE threat model")]
struct Args {
    /// Path to the STRIDE threat model YAML
    #[arg(required = true)]
    input: PathBuf,

    /// Output directory for red team scenarios
    #[arg(long, default_value = "red_team_scenarios")]
    red_team: PathBuf,

    /// Output directory for chaos scenarios
    #[arg(long, default_value = "chaos_scenarios")]
    chaos: PathBuf,

    /// Dry run - don't write files
    #[arg(long)]
    dry_run: bool,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Input Schema (STRIDE Model)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StrideModel {
    version: String,
    generated: String,
    system: String,
    threats: Vec<Threat>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Threat {
    id: String,
    category: String,
    title: String,
    description: String,
    component: String,
    assets: Vec<String>,
    likelihood: String,
    impact: String,
    mitigations: Vec<String>,
    test_templates: TestTemplates,
}

#[derive(Debug, Deserialize)]
struct TestTemplates {
    red_team: Vec<RedTeamTemplate>,
    chaos: Vec<ChaosTemplate>,
}

#[derive(Debug, Deserialize)]
struct RedTeamTemplate {
    action: String,
    input: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct ChaosTemplate {
    fault: String,
    expected: String,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Output Schema (Test Scenarios)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Serialize)]
struct RedTeamScenario {
    id: String,
    name: String,
    threat_ref: String,
    category: String,
    component: String,
    description: String,
    steps: Vec<RedTeamStep>,
    assertions: Vec<Assertion>,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct RedTeamStep {
    step: u32,
    action: String,
    input: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct ChaosScenario {
    id: String,
    name: String,
    threat_ref: String,
    category: String,
    component: String,
    description: String,
    fault_injection: FaultInjection,
    assertions: Vec<Assertion>,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct FaultInjection {
    fault_type: String,
    target: String,
    duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct Assertion {
    assertion: String,
    expected_outcome: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Read and parse STRIDE model
    let input_content = fs::read_to_string(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;

    let model: StrideModel =
        serde_yaml::from_str(&input_content).with_context(|| "Failed to parse STRIDE model")?;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              STRIDE Test Generator                           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("System:  {}", model.system);
    println!("Version: {}", model.version);
    println!("Threats: {}", model.threats.len());
    println!();

    // Create output directories
    if !args.dry_run {
        fs::create_dir_all(&args.red_team)?;
        fs::create_dir_all(&args.chaos)?;
    }

    let mut red_team_count = 0;
    let mut chaos_count = 0;

    for threat in &model.threats {
        // Generate red team scenarios
        for (i, template) in threat.test_templates.red_team.iter().enumerate() {
            let scenario_id = if threat.test_templates.red_team.len() > 1 {
                format!("RT-{}-{}", threat.id, i + 1)
            } else {
                format!("RT-{}", threat.id)
            };

            let scenario = generate_red_team_scenario(threat, template, &scenario_id);
            let yaml = serde_yaml::to_string(&scenario)?;

            let filename = format!("{}.yaml", scenario_id);
            let path = args.red_team.join(&filename);

            if args.dry_run {
                println!("Would write: {}", path.display());
            } else {
                fs::write(&path, &yaml)?;
                println!("Generated: {}", path.display());
            }
            red_team_count += 1;
        }

        // Generate chaos scenarios
        for (i, template) in threat.test_templates.chaos.iter().enumerate() {
            let scenario_id = if threat.test_templates.chaos.len() > 1 {
                format!("CH-{}-{}", threat.id, i + 1)
            } else {
                format!("CH-{}", threat.id)
            };

            let scenario = generate_chaos_scenario(threat, template, &scenario_id);
            let yaml = serde_yaml::to_string(&scenario)?;

            let filename = format!("{}.yaml", scenario_id);
            let path = args.chaos.join(&filename);

            if args.dry_run {
                println!("Would write: {}", path.display());
            } else {
                fs::write(&path, &yaml)?;
                println!("Generated: {}", path.display());
            }
            chaos_count += 1;
        }
    }

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Generated {} red team scenarios", red_team_count);
    println!("Generated {} chaos scenarios", chaos_count);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(())
}

fn generate_red_team_scenario(
    threat: &Threat,
    template: &RedTeamTemplate,
    scenario_id: &str,
) -> RedTeamScenario {
    let mut metadata = BTreeMap::new();
    metadata.insert("likelihood".to_string(), threat.likelihood.clone());
    metadata.insert("impact".to_string(), threat.impact.clone());
    metadata.insert("category".to_string(), threat.category.clone());
    metadata.insert("mitigations".to_string(), threat.mitigations.join(", "));

    RedTeamScenario {
        id: scenario_id.to_string(),
        name: format!("Red Team: {}", threat.title),
        threat_ref: threat.id.clone(),
        category: threat.category.clone(),
        component: threat.component.clone(),
        description: format!(
            "Verify that '{}' is mitigated. {}",
            threat.title, threat.description
        ),
        steps: vec![
            RedTeamStep {
                step: 1,
                action: "setup".to_string(),
                input: "initialize_test_environment".to_string(),
                description: format!("Set up test environment for {} component", threat.component),
            },
            RedTeamStep {
                step: 2,
                action: template.action.clone(),
                input: template.input.clone(),
                description: format!("Attempt {} with malicious input", template.action),
            },
            RedTeamStep {
                step: 3,
                action: "verify".to_string(),
                input: "check_outcome".to_string(),
                description: format!("Verify expected outcome: {}", template.expected),
            },
        ],
        assertions: vec![
            Assertion {
                assertion: format!("action_{}_blocked", template.action),
                expected_outcome: template.expected.clone(),
            },
            Assertion {
                assertion: "no_unauthorized_access".to_string(),
                expected_outcome: "true".to_string(),
            },
            Assertion {
                assertion: "audit_event_logged".to_string(),
                expected_outcome: "true".to_string(),
            },
        ],
        metadata,
    }
}

fn generate_chaos_scenario(
    threat: &Threat,
    template: &ChaosTemplate,
    scenario_id: &str,
) -> ChaosScenario {
    let mut metadata = BTreeMap::new();
    metadata.insert("likelihood".to_string(), threat.likelihood.clone());
    metadata.insert("impact".to_string(), threat.impact.clone());
    metadata.insert("category".to_string(), threat.category.clone());

    ChaosScenario {
        id: scenario_id.to_string(),
        name: format!("Chaos: {} under {}", threat.component, template.fault),
        threat_ref: threat.id.clone(),
        category: threat.category.clone(),
        component: threat.component.clone(),
        description: format!(
            "Test {} resilience when {} occurs. Related threat: {}",
            threat.component, template.fault, threat.title
        ),
        fault_injection: FaultInjection {
            fault_type: template.fault.clone(),
            target: threat.component.clone(),
            duration_ms: Some(5000),
        },
        assertions: vec![
            Assertion {
                assertion: "system_behavior".to_string(),
                expected_outcome: template.expected.clone(),
            },
            Assertion {
                assertion: "no_data_corruption".to_string(),
                expected_outcome: "true".to_string(),
            },
            Assertion {
                assertion: "graceful_recovery".to_string(),
                expected_outcome: "true".to_string(),
            },
        ],
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_STRIDE: &str = r#"
version: "1.0"
generated: "2026-02-24"
system: "Test System"
threats:
  - id: "T-001"
    category: "Tampering"
    title: "Test threat"
    description: "Test description"
    component: "test-component"
    assets: ["asset1"]
    likelihood: "medium"
    impact: "high"
    mitigations: ["mitigation1"]
    test_templates:
      red_team:
        - action: "test_action"
          input: "test_input"
          expected: "test_expected"
      chaos:
        - fault: "test_fault"
          expected: "test_recovery"
"#;

    #[test]
    fn test_parse_stride_model() {
        let model: StrideModel = serde_yaml::from_str(SAMPLE_STRIDE).unwrap();
        assert_eq!(model.version, "1.0");
        assert_eq!(model.threats.len(), 1);
        assert_eq!(model.threats[0].id, "T-001");
    }

    #[test]
    fn test_generate_red_team_scenario() {
        let model: StrideModel = serde_yaml::from_str(SAMPLE_STRIDE).unwrap();
        let threat = &model.threats[0];
        let template = &threat.test_templates.red_team[0];

        let scenario = generate_red_team_scenario(threat, template, "RT-T-001");

        assert_eq!(scenario.id, "RT-T-001");
        assert_eq!(scenario.threat_ref, "T-001");
        assert_eq!(scenario.steps.len(), 3);
        assert_eq!(scenario.assertions.len(), 3);
    }

    #[test]
    fn test_generate_chaos_scenario() {
        let model: StrideModel = serde_yaml::from_str(SAMPLE_STRIDE).unwrap();
        let threat = &model.threats[0];
        let template = &threat.test_templates.chaos[0];

        let scenario = generate_chaos_scenario(threat, template, "CH-T-001");

        assert_eq!(scenario.id, "CH-T-001");
        assert_eq!(scenario.fault_injection.fault_type, "test_fault");
        assert!(scenario.fault_injection.duration_ms.is_some());
    }

    #[test]
    fn test_deterministic_output() {
        let model: StrideModel = serde_yaml::from_str(SAMPLE_STRIDE).unwrap();
        let threat = &model.threats[0];
        let template = &threat.test_templates.red_team[0];

        let scenario1 = generate_red_team_scenario(threat, template, "RT-T-001");
        let scenario2 = generate_red_team_scenario(threat, template, "RT-T-001");

        let yaml1 = serde_yaml::to_string(&scenario1).unwrap();
        let yaml2 = serde_yaml::to_string(&scenario2).unwrap();

        assert_eq!(yaml1, yaml2, "Output must be deterministic");
    }

    #[test]
    fn test_missing_field_fails() {
        let bad_yaml = r#"
version: "1.0"
threats:
  - id: "T-001"
"#;
        let result: Result<StrideModel, _> = serde_yaml::from_str(bad_yaml);
        assert!(result.is_err());
    }
}
