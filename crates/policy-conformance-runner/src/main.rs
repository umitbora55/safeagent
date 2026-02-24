//! Policy Conformance Test Runner
//!
//! Runs conformance tests against the policy engine to verify
//! correct behavior according to the specification.
//!
//! Usage:
//!   policy-conformance-runner policy_conformance/cases/

use anyhow::{Context, Result};
use clap::Parser;
use safeagent_policy_engine::{
    ActionType, PermissionLevel, PolicyConfig, PolicyDecision, PolicyEngine,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "policy-conformance-runner")]
#[command(about = "Run policy conformance tests")]
struct Args {
    /// Directory containing conformance test YAML files
    #[arg(required = true)]
    cases_dir: PathBuf,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Test Case Schema
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
struct TestSuite {
    version: String,
    suite: String,
    cases: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    id: String,
    name: String,
    action_type: String,
    description: String,
    config: TestConfig,
    #[serde(default)]
    pre_spend_microdollars: Option<u64>,
    #[allow(dead_code)]
    #[serde(default)]
    pre_spend_monthly_microdollars: Option<u64>,
    #[serde(default)]
    spend_microdollars: Option<u64>,
    expected: Expected,
}

#[derive(Debug, Deserialize, Default)]
struct TestConfig {
    #[serde(default)]
    action_overrides: HashMap<String, String>,
    #[serde(default)]
    blocked_actions: Vec<String>,
    #[serde(default)]
    yellow_timeout_secs: Option<u64>,
    #[serde(default)]
    daily_spend_limit_microdollars: Option<u64>,
    #[serde(default)]
    monthly_spend_limit_microdollars: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct Expected {
    decision: String,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    reason_contains: Option<String>,
    #[serde(default)]
    budget_ok: Option<bool>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Test Results
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug)]
struct TestResult {
    id: String,
    name: String,
    passed: bool,
    error: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           Policy Conformance Test Runner                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let mut total_cases = 0;
    let mut passed_cases = 0;
    let mut failed_results: Vec<TestResult> = Vec::new();

    // Find all YAML files in the cases directory
    let entries = fs::read_dir(&args.cases_dir)
        .with_context(|| format!("Failed to read directory: {}", args.cases_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            println!("Loading: {}", path.display());

            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;

            let suite: TestSuite = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", path.display()))?;

            println!("Suite: {} ({})", suite.suite, suite.version);
            println!("Cases: {}", suite.cases.len());
            println!();

            for case in &suite.cases {
                total_cases += 1;
                let result = run_test_case(case, args.verbose);

                if result.passed {
                    passed_cases += 1;
                    if args.verbose {
                        println!("  ✓ {} - {}", result.id, result.name);
                    }
                } else {
                    println!("  ✗ {} - {}", result.id, result.name);
                    if let Some(ref err) = result.error {
                        println!("    Error: {}", err);
                    }
                    failed_results.push(result);
                }
            }
        }
    }

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Total:  {} cases", total_cases);
    println!("Passed: {} cases", passed_cases);
    println!("Failed: {} cases", failed_results.len());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if failed_results.is_empty() {
        println!();
        println!("┌──────────────────────────────────────────────────────────────┐");
        println!("│                      ✓ PASS                                  │");
        println!("│           All conformance tests passed.                      │");
        println!("└──────────────────────────────────────────────────────────────┘");
        std::process::exit(0);
    } else {
        println!();
        println!("┌──────────────────────────────────────────────────────────────┐");
        println!("│                      ✗ FAIL                                  │");
        println!("│           Some conformance tests failed.                     │");
        println!("└──────────────────────────────────────────────────────────────┘");
        println!();
        println!("Failed tests:");
        for r in &failed_results {
            println!("  - {}: {}", r.id, r.error.as_deref().unwrap_or("unknown"));
        }
        std::process::exit(1);
    }
}

fn run_test_case(case: &TestCase, verbose: bool) -> TestResult {
    // Build policy config
    let config = build_policy_config(&case.config);
    let engine = PolicyEngine::new(config);

    // Pre-spend if configured
    if let Some(pre_spend) = case.pre_spend_microdollars {
        engine.record_spend(pre_spend);
    }

    // Parse action type
    let action_type = parse_action_type(&case.action_type);

    // Evaluate
    let decision = engine.evaluate(&action_type, &case.description, serde_json::Value::Null);

    // Check decision
    let decision_match = check_decision(&decision, &case.expected);

    if !decision_match.0 {
        return TestResult {
            id: case.id.clone(),
            name: case.name.clone(),
            passed: false,
            error: Some(decision_match.1),
        };
    }

    // Check budget if configured
    if let Some(spend) = case.spend_microdollars {
        let budget_ok = engine.record_spend(spend);
        if let Some(expected_ok) = case.expected.budget_ok {
            if budget_ok != expected_ok {
                return TestResult {
                    id: case.id.clone(),
                    name: case.name.clone(),
                    passed: false,
                    error: Some(format!(
                        "budget_ok mismatch: expected {}, got {}",
                        expected_ok, budget_ok
                    )),
                };
            }
        }
    }

    if verbose {
        // Additional logging could go here
    }

    TestResult {
        id: case.id.clone(),
        name: case.name.clone(),
        passed: true,
        error: None,
    }
}

fn build_policy_config(config: &TestConfig) -> PolicyConfig {
    let mut overrides = HashMap::new();
    for (key, value) in &config.action_overrides {
        let level = match value.as_str() {
            "green" => PermissionLevel::Green,
            "yellow" => PermissionLevel::Yellow,
            "red" => PermissionLevel::Red,
            _ => PermissionLevel::Yellow,
        };
        overrides.insert(key.clone(), level);
    }

    let blocked: Vec<ActionType> = config
        .blocked_actions
        .iter()
        .map(|s| parse_action_type(s))
        .collect();

    PolicyConfig {
        action_overrides: overrides,
        blocked_actions: blocked,
        yellow_timeout_secs: config.yellow_timeout_secs.unwrap_or(30),
        daily_spend_limit_microdollars: config.daily_spend_limit_microdollars,
        monthly_spend_limit_microdollars: config.monthly_spend_limit_microdollars,
    }
}

fn parse_action_type(s: &str) -> ActionType {
    match s {
        "read_calendar" => ActionType::ReadCalendar,
        "read_weather" => ActionType::ReadWeather,
        "search_web" => ActionType::SearchWeb,
        "summarize_content" => ActionType::SummarizeContent,
        "draft_email" => ActionType::DraftEmail,
        "add_calendar_event" => ActionType::AddCalendarEvent,
        "create_reminder" => ActionType::CreateReminder,
        "read_email" => ActionType::ReadEmail,
        "send_email" => ActionType::SendEmail,
        "send_message" => ActionType::SendMessage,
        "delete_file" => ActionType::DeleteFile,
        "delete_email" => ActionType::DeleteEmail,
        "make_purchase" => ActionType::MakePurchase,
        "run_shell_command" => ActionType::RunShellCommand,
        other => {
            if let Some(name) = other.strip_prefix("custom:") {
                ActionType::Custom(name.to_string())
            } else {
                ActionType::Custom(other.to_string())
            }
        }
    }
}

fn check_decision(decision: &PolicyDecision, expected: &Expected) -> (bool, String) {
    match decision {
        PolicyDecision::Allow => {
            if expected.decision == "allow" {
                (true, String::new())
            } else {
                (
                    false,
                    format!("expected '{}', got 'allow'", expected.decision),
                )
            }
        }
        PolicyDecision::AllowWithNotification { timeout_secs, .. } => {
            if expected.decision != "allow_with_notification" {
                return (
                    false,
                    format!(
                        "expected '{}', got 'allow_with_notification'",
                        expected.decision
                    ),
                );
            }

            if let Some(expected_timeout) = expected.timeout_secs {
                if *timeout_secs != expected_timeout {
                    return (
                        false,
                        format!(
                            "timeout_secs mismatch: expected {}, got {}",
                            expected_timeout, timeout_secs
                        ),
                    );
                }
            }

            (true, String::new())
        }
        PolicyDecision::RequireApproval { pending } => {
            if expected.decision != "require_approval" {
                return (
                    false,
                    format!("expected '{}', got 'require_approval'", expected.decision),
                );
            }

            if let Some(ref expected_level) = expected.level {
                let actual_level = match pending.level {
                    PermissionLevel::Green => "green",
                    PermissionLevel::Yellow => "yellow",
                    PermissionLevel::Red => "red",
                };
                if actual_level != expected_level {
                    return (
                        false,
                        format!(
                            "level mismatch: expected '{}', got '{}'",
                            expected_level, actual_level
                        ),
                    );
                }
            }

            (true, String::new())
        }
        PolicyDecision::Deny { reason } => {
            if expected.decision != "deny" {
                return (
                    false,
                    format!("expected '{}', got 'deny'", expected.decision),
                );
            }

            if let Some(ref contains) = expected.reason_contains {
                if !reason.to_lowercase().contains(&contains.to_lowercase()) {
                    return (
                        false,
                        format!("reason does not contain '{}': {}", contains, reason),
                    );
                }
            }

            (true, String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_action_type() {
        assert!(matches!(
            parse_action_type("read_weather"),
            ActionType::ReadWeather
        ));
        assert!(matches!(
            parse_action_type("send_email"),
            ActionType::SendEmail
        ));
        assert!(matches!(
            parse_action_type("custom:my_action"),
            ActionType::Custom(_)
        ));
    }

    #[test]
    fn test_build_policy_config() {
        let config = TestConfig {
            action_overrides: [("send_email".to_string(), "green".to_string())]
                .into_iter()
                .collect(),
            blocked_actions: vec!["run_shell_command".to_string()],
            yellow_timeout_secs: Some(45),
            daily_spend_limit_microdollars: Some(1000000),
            monthly_spend_limit_microdollars: None,
        };

        let policy = build_policy_config(&config);
        assert_eq!(policy.yellow_timeout_secs, 45);
        assert!(policy.action_overrides.contains_key("send_email"));
        assert_eq!(policy.blocked_actions.len(), 1);
    }

    #[test]
    fn test_check_decision_allow() {
        let decision = PolicyDecision::Allow;
        let expected = Expected {
            decision: "allow".to_string(),
            level: None,
            timeout_secs: None,
            reason_contains: None,
            budget_ok: None,
        };
        let (passed, _) = check_decision(&decision, &expected);
        assert!(passed);
    }

    #[test]
    fn test_check_decision_deny() {
        let decision = PolicyDecision::Deny {
            reason: "Action is blocked by policy".to_string(),
        };
        let expected = Expected {
            decision: "deny".to_string(),
            level: None,
            timeout_secs: None,
            reason_contains: Some("blocked".to_string()),
            budget_ok: None,
        };
        let (passed, _) = check_decision(&decision, &expected);
        assert!(passed);
    }
}
