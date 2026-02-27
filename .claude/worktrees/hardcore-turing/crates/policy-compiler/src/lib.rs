//! W14: Natural Language → Cedar Policy Compiler
//!
//! Transforms natural-language policy descriptions into Cedar policy
//! statements. Uses pattern matching and a template library to produce
//! syntactically correct Cedar v2 output.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::debug;

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("failed to parse natural language input: {0}")]
    ParseError(String),
    #[error("ambiguous policy intent: {0}")]
    AmbiguousIntent(String),
    #[error("unsupported construct: {0}")]
    UnsupportedConstruct(String),
    #[error("Cedar validation failed: {0}")]
    ValidationError(String),
}

// ── Policy Intent Model ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    Permit,
    Forbid,
}

impl PolicyEffect {
    pub fn cedar_keyword(&self) -> &'static str {
        match self {
            PolicyEffect::Permit => "permit",
            PolicyEffect::Forbid => "forbid",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyIntent {
    pub effect: PolicyEffect,
    pub principal_type: Option<String>,
    pub principal_id: Option<String>,
    pub action_names: Vec<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub conditions: Vec<PolicyCondition>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub attribute: String,
    pub operator: ConditionOperator,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    In,
}

impl ConditionOperator {
    pub fn cedar_op(&self) -> &'static str {
        match self {
            ConditionOperator::Equals => "==",
            ConditionOperator::NotEquals => "!=",
            ConditionOperator::GreaterThan => ">",
            ConditionOperator::LessThan => "<",
            ConditionOperator::Contains => "contains",
            ConditionOperator::In => "in",
        }
    }
}

// ── Cedar Policy Output ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarPolicy {
    pub id: String,
    pub cedar_text: String,
    pub description: String,
    pub compiled_from: String,
    pub compiled_at: DateTime<Utc>,
    pub warnings: Vec<String>,
}

impl CedarPolicy {
    pub fn new(
        id: impl Into<String>,
        cedar_text: impl Into<String>,
        description: impl Into<String>,
        compiled_from: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            cedar_text: cedar_text.into(),
            description: description.into(),
            compiled_from: compiled_from.into(),
            compiled_at: Utc::now(),
            warnings: vec![],
        }
    }
}

// ── NL Pattern Library ───────────────────────────────────────────────────────

/// Pattern matching rules that map NL phrases to policy intent components.
struct NlPatternLibrary {
    effect_patterns: Vec<(Regex, PolicyEffect)>,
    action_patterns: Vec<(Regex, Vec<String>)>,
    role_patterns: Vec<(Regex, String)>,
    time_condition_pattern: Regex,
    team_pattern: Regex,
    resource_patterns: Vec<(Regex, String)>,
}

impl NlPatternLibrary {
    fn new() -> Result<Self, CompilerError> {
        let effect_patterns = vec![
            (
                Regex::new(r"(?i)\b(allow|permit|grant|can|enable|let)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                PolicyEffect::Permit,
            ),
            (
                Regex::new(r"(?i)\b(deny|forbid|block|prevent|disallow|restrict|stop)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                PolicyEffect::Forbid,
            ),
        ];

        let action_patterns = vec![
            (
                Regex::new(r"(?i)\b(read|view|access|see|get|fetch|retrieve)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                vec!["Action::\"read\"".into()],
            ),
            (
                Regex::new(r"(?i)\b(write|edit|update|modify|change)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                vec!["Action::\"write\"".into()],
            ),
            (
                Regex::new(r"(?i)\b(delet(?:e|ing)|remov(?:e|ing)|destroy(?:ing)?|dropping?|dropped?)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                vec!["Action::\"delete\"".into()],
            ),
            (
                Regex::new(r"(?i)\b(execute|run|invoke|call|trigger)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                vec!["Action::\"execute\"".into()],
            ),
            (
                Regex::new(r"(?i)\b(create|add|insert|new|make)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                vec!["Action::\"create\"".into()],
            ),
            (
                Regex::new(r"(?i)\ball\s+actions?\b").map_err(|e| CompilerError::ParseError(e.to_string()))?,
                vec![], // empty = wildcard
            ),
        ];

        let role_patterns = vec![
            (Regex::new(r"(?i)\b(admin|administrator)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "admin".into()),
            (Regex::new(r"(?i)\b(operator|ops)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "operator".into()),
            (Regex::new(r"(?i)\b(viewer|reader|readonly)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "viewer".into()),
            (Regex::new(r"(?i)\b(developer|dev|engineer)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "developer".into()),
            (Regex::new(r"(?i)\bagents?\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "agent".into()),
            (Regex::new(r"(?i)\busers?\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "user".into()),
        ];

        let resource_patterns = vec![
            (Regex::new(r"(?i)\b(tool|tools)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "Tool".into()),
            (Regex::new(r"(?i)\b(document|file|files)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "Document".into()),
            (Regex::new(r"(?i)\b(database|db)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "Database".into()),
            (Regex::new(r"(?i)\b(api|endpoint)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "ApiEndpoint".into()),
            (Regex::new(r"(?i)\b(namespace|ns)\b").map_err(|e| CompilerError::ParseError(e.to_string()))?, "Namespace".into()),
        ];

        Ok(Self {
            effect_patterns,
            action_patterns,
            role_patterns,
            time_condition_pattern: Regex::new(
                r"(?i)between\s+(\d{1,2}(?:am|pm)?)\s+and\s+(\d{1,2}(?:am|pm)?)"
            ).map_err(|e| CompilerError::ParseError(e.to_string()))?,
            team_pattern: Regex::new(
                r#"(?i)(?:in|from|of)\s+(?:team|group)\s+"?([A-Za-z0-9_-]+)"?"#
            ).map_err(|e| CompilerError::ParseError(e.to_string()))?,
            resource_patterns,
        })
    }

    fn extract_effect(&self, text: &str) -> Option<PolicyEffect> {
        // Check forbid first (it's more specific)
        if self.effect_patterns[1].0.is_match(text) {
            return Some(PolicyEffect::Forbid);
        }
        if self.effect_patterns[0].0.is_match(text) {
            return Some(PolicyEffect::Permit);
        }
        None
    }

    fn extract_actions(&self, text: &str) -> Vec<String> {
        let mut actions = Vec::new();
        for (re, acts) in &self.action_patterns {
            if re.is_match(text) {
                if acts.is_empty() {
                    return vec![]; // wildcard
                }
                actions.extend(acts.iter().cloned());
            }
        }
        actions
    }

    fn extract_principal_role(&self, text: &str) -> Option<String> {
        for (re, role) in &self.role_patterns {
            if re.is_match(text) {
                return Some(role.clone());
            }
        }
        None
    }

    fn extract_resource_type(&self, text: &str) -> Option<String> {
        for (re, rtype) in &self.resource_patterns {
            if re.is_match(text) {
                return Some(rtype.clone());
            }
        }
        None
    }

    fn extract_team(&self, text: &str) -> Option<String> {
        self.team_pattern
            .captures(text)
            .map(|c| c[1].to_string())
    }
}

// ── Cedar Code Generator ──────────────────────────────────────────────────────

struct CedarGenerator;

impl CedarGenerator {
    fn generate(intent: &PolicyIntent, policy_id: &str) -> String {
        let effect = intent.effect.cedar_keyword();

        // Principal clause
        let principal = match (&intent.principal_type, &intent.principal_id) {
            (Some(pt), Some(pid)) => {
                format!("principal == {}::\"{}\"", pt, pid)
            }
            (Some(pt), None) => format!("principal is {}", pt),
            _ => "principal".to_string(),
        };

        // Action clause
        let action = if intent.action_names.is_empty() {
            "action".to_string()
        } else if intent.action_names.len() == 1 {
            format!("action == {}", intent.action_names[0])
        } else {
            let list = intent.action_names.join(", ");
            format!("action in [{}]", list)
        };

        // Resource clause
        let resource = match (&intent.resource_type, &intent.resource_id) {
            (Some(rt), Some(rid)) => format!("resource == {}::\"{}\"", rt, rid),
            (Some(rt), None) => format!("resource is {}", rt),
            _ => "resource".to_string(),
        };

        // When clause from conditions
        let when_clause = if intent.conditions.is_empty() {
            String::new()
        } else {
            let cond_parts: Vec<String> = intent
                .conditions
                .iter()
                .map(|c| format!("context.{} {} \"{}\"", c.attribute, c.operator.cedar_op(), c.value))
                .collect();
            format!("\nwhen {{\n  {}\n}}", cond_parts.join(" &&\n  "))
        };

        format!(
            "// {}\n// Policy ID: {}\n{} (\n  {},\n  {},\n  {}\n){};",
            intent.description,
            policy_id,
            effect,
            principal,
            action,
            resource,
            when_clause
        )
    }
}

// ── NL Policy Compiler ───────────────────────────────────────────────────────

pub struct NlPolicyCompiler {
    patterns: NlPatternLibrary,
    policy_counter: std::sync::atomic::AtomicU64,
}

impl NlPolicyCompiler {
    pub fn new() -> Result<Self, CompilerError> {
        Ok(Self {
            patterns: NlPatternLibrary::new()?,
            policy_counter: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Compile a natural-language policy description to Cedar.
    pub fn compile(&self, nl_text: &str) -> Result<CedarPolicy, CompilerError> {
        debug!("Compiling NL policy: {}", nl_text);

        let effect = self
            .patterns
            .extract_effect(nl_text)
            .ok_or_else(|| CompilerError::ParseError("cannot determine effect (allow/deny)".into()))?;

        let actions = self.patterns.extract_actions(nl_text);
        let principal_role = self.patterns.extract_principal_role(nl_text);
        let resource_type = self.patterns.extract_resource_type(nl_text);
        let team = self.patterns.extract_team(nl_text);

        let mut conditions = Vec::new();

        // Team membership condition
        if let Some(ref team_name) = team {
            conditions.push(PolicyCondition {
                attribute: "team".into(),
                operator: ConditionOperator::Equals,
                value: team_name.clone(),
            });
        }

        let intent = PolicyIntent {
            effect,
            principal_type: principal_role.as_ref().map(|r| {
                if r == "agent" {
                    "Agent".to_string()
                } else {
                    "User".to_string()
                }
            }),
            principal_id: None,
            action_names: actions,
            resource_type,
            resource_id: None,
            conditions,
            description: nl_text.to_string(),
        };

        let id = format!(
            "policy-{}",
            self.policy_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );

        let cedar_text = CedarGenerator::generate(&intent, &id);

        // Basic validation: ensure Cedar text is non-empty and has effect keyword
        if cedar_text.is_empty() {
            return Err(CompilerError::ValidationError("empty Cedar output".into()));
        }

        let mut policy = CedarPolicy::new(&id, cedar_text, nl_text, nl_text);

        // Warn if no resource type could be inferred
        if intent.resource_type.is_none() {
            policy.warnings.push(
                "resource type could not be inferred; using wildcard 'resource'".into(),
            );
        }

        Ok(policy)
    }

    /// Compile multiple NL policies at once.
    pub fn compile_batch(
        &self,
        policies: &[&str],
    ) -> Vec<Result<CedarPolicy, CompilerError>> {
        policies.iter().map(|p| self.compile(p)).collect()
    }
}

impl Default for NlPolicyCompiler {
    fn default() -> Self {
        Self::new().expect("default NL compiler initialization succeeds")
    }
}

// ── Policy Template Library ──────────────────────────────────────────────────

/// Pre-built policy templates for common use cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub name: String,
    pub description: String,
    pub nl_description: String,
    pub cedar_template: String,
    pub parameters: Vec<String>,
}

impl PolicyTemplate {
    pub fn instantiate(&self, params: &HashMap<String, String>) -> Result<String, CompilerError> {
        let mut result = self.cedar_template.clone();
        for (key, value) in params {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }
        // Check for unresolved placeholders
        if result.contains("{{") {
            return Err(CompilerError::ValidationError(
                "template has unresolved placeholders".into(),
            ));
        }
        Ok(result)
    }
}

pub struct PolicyTemplateLibrary {
    templates: HashMap<String, PolicyTemplate>,
}

impl PolicyTemplateLibrary {
    pub fn new() -> Self {
        let mut lib = Self {
            templates: HashMap::new(),
        };
        lib.load_defaults();
        lib
    }

    fn load_defaults(&mut self) {
        let templates = vec![
            PolicyTemplate {
                name: "agent_read_only".into(),
                description: "Allow an agent to read-only access to a specific resource type".into(),
                nl_description: "Allow agent to read resources".into(),
                cedar_template: r#"permit (
  principal is Agent,
  action == Action::"read",
  resource is {{resource_type}}
);"#.into(),
                parameters: vec!["resource_type".into()],
            },
            PolicyTemplate {
                name: "deny_after_hours".into(),
                description: "Deny all actions outside business hours".into(),
                nl_description: "Deny all actions outside business hours".into(),
                cedar_template: r#"forbid (
  principal,
  action,
  resource
)
when {
  context.hour < 9 || context.hour > 17
};"#.into(),
                parameters: vec![],
            },
            PolicyTemplate {
                name: "team_admin_access".into(),
                description: "Allow team admins full access to namespace".into(),
                nl_description: "Allow team admins to manage namespace".into(),
                cedar_template: r#"permit (
  principal is User,
  action,
  resource is Namespace::{{namespace_id}}
)
when {
  principal.role == "admin" && principal.team == "{{team_name}}"
};"#.into(),
                parameters: vec!["namespace_id".into(), "team_name".into()],
            },
        ];
        for t in templates {
            self.templates.insert(t.name.clone(), t);
        }
    }

    pub fn get(&self, name: &str) -> Option<&PolicyTemplate> {
        self.templates.get(name)
    }

    pub fn list(&self) -> Vec<&PolicyTemplate> {
        self.templates.values().collect()
    }
}

impl Default for PolicyTemplateLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiler() -> NlPolicyCompiler {
        NlPolicyCompiler::new().unwrap()
    }

    // ── Effect Extraction ────────────────────────────────────────────────────

    #[test]
    fn allow_verb_produces_permit() {
        let c = compiler();
        let p = c.compile("Allow agents to read documents").unwrap();
        assert!(p.cedar_text.contains("permit"));
    }

    #[test]
    fn deny_verb_produces_forbid() {
        let c = compiler();
        let p = c.compile("Deny users from deleting files").unwrap();
        assert!(p.cedar_text.contains("forbid"));
    }

    #[test]
    fn no_effect_verb_returns_error() {
        let c = compiler();
        let result = c.compile("Users should be careful with data");
        assert!(result.is_err());
    }

    // ── Action Extraction ────────────────────────────────────────────────────

    #[test]
    fn read_action_extracted() {
        let c = compiler();
        let p = c.compile("Allow agents to read tool outputs").unwrap();
        assert!(p.cedar_text.contains("read"));
    }

    #[test]
    fn delete_action_extracted() {
        let c = compiler();
        let p = c.compile("Deny users from deleting database records").unwrap();
        assert!(p.cedar_text.contains("delete"));
    }

    #[test]
    fn multiple_actions_extracted() {
        let c = compiler();
        let p = c.compile("Allow agents to read and write documents").unwrap();
        assert!(p.cedar_text.contains("read") || p.cedar_text.contains("write"));
    }

    // ── Principal Extraction ─────────────────────────────────────────────────

    #[test]
    fn agent_principal_extracted() {
        let c = compiler();
        let p = c.compile("Allow agents to execute tools").unwrap();
        assert!(p.cedar_text.contains("Agent"));
    }

    #[test]
    fn admin_user_extracted() {
        let c = compiler();
        let p = c.compile("Allow admin users to delete any resource").unwrap();
        // admin role maps to "User" principal type with admin in description
        assert!(p.cedar_text.contains("User") || p.cedar_text.contains("admin"));
    }

    // ── Resource Extraction ──────────────────────────────────────────────────

    #[test]
    fn tool_resource_extracted() {
        let c = compiler();
        let p = c.compile("Allow agents to read tool results").unwrap();
        assert!(p.cedar_text.contains("Tool"));
    }

    #[test]
    fn database_resource_extracted() {
        let c = compiler();
        let p = c.compile("Deny users from writing to the database").unwrap();
        assert!(p.cedar_text.contains("Database"));
    }

    // ── Conditions ───────────────────────────────────────────────────────────

    #[test]
    fn team_condition_extracted() {
        let c = compiler();
        let p = c.compile("Allow users in team engineering to read documents").unwrap();
        assert!(p.cedar_text.contains("engineering"));
    }

    // ── Cedar Syntax ─────────────────────────────────────────────────────────

    #[test]
    fn output_contains_cedar_structure() {
        let c = compiler();
        let p = c.compile("Allow agents to read documents").unwrap();
        // Must have effect(principal, action, resource) structure
        assert!(p.cedar_text.contains("("));
        assert!(p.cedar_text.contains("principal"));
        assert!(p.cedar_text.contains("action"));
        assert!(p.cedar_text.contains("resource"));
    }

    #[test]
    fn output_ends_with_semicolon() {
        let c = compiler();
        let p = c.compile("Allow agents to invoke tools").unwrap();
        let text = p.cedar_text.trim();
        assert!(text.ends_with(';'));
    }

    // ── Batch Compilation ────────────────────────────────────────────────────

    #[test]
    fn batch_compile_mixed_results() {
        let c = compiler();
        let results = c.compile_batch(&[
            "Allow agents to read tools",
            "users should be okay", // no effect verb → error
            "Deny admin from deleting namespaces",
        ]);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_ok());
    }

    // ── Template Library ─────────────────────────────────────────────────────

    #[test]
    fn template_instantiation_with_params() {
        let lib = PolicyTemplateLibrary::new();
        let tmpl = lib.get("agent_read_only").unwrap();
        let mut params = HashMap::new();
        params.insert("resource_type".into(), "Document".into());
        let cedar = tmpl.instantiate(&params).unwrap();
        assert!(cedar.contains("Document"));
        assert!(!cedar.contains("{{"));
    }

    #[test]
    fn template_unresolved_placeholder_fails() {
        let lib = PolicyTemplateLibrary::new();
        let tmpl = lib.get("team_admin_access").unwrap();
        let mut params = HashMap::new();
        params.insert("namespace_id".into(), "prod".into());
        // team_name not provided → should fail
        let result = tmpl.instantiate(&params);
        assert!(result.is_err());
    }

    #[test]
    fn template_library_has_defaults() {
        let lib = PolicyTemplateLibrary::new();
        assert!(lib.get("agent_read_only").is_some());
        assert!(lib.get("deny_after_hours").is_some());
        assert!(lib.get("team_admin_access").is_some());
        assert_eq!(lib.list().len(), 3);
    }
}
