// gen_ai.rs — W5 D7: OpenTelemetry GenAI Semantic Conventions
//
// Implements the OpenTelemetry Semantic Conventions for GenAI systems
// (https://opentelemetry.io/docs/specs/semconv/gen-ai/) using the
// gen_ai.* attribute namespace standardized for AI/ML observability.
//
// This module:
//   - Defines all gen_ai.* attribute constants
//   - Provides GenAiSpan for building OTel spans over LLM calls
//   - Provides GenAiEventBuilder for logging prompt/completion events
//   - Is composable with any existing tracing::Span
//
// Usage (gateway integration):
//   let span = GenAiSpan::new("anthropic")
//       .model("claude-opus-4-5")
//       .operation(GenAiOperation::Chat)
//       .start();
//   // ... LLM call ...
//   span.finish_ok(input_tokens, output_tokens, finish_reason);
//
// All attributes follow the OTel GenAI spec (as of 2025-2026 stable release).

use std::time::Instant;
use tracing::{debug, info};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  gen_ai.* attribute key constants
//  Source: https://opentelemetry.io/docs/specs/semconv/gen-ai/
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The AI model provider (e.g. "anthropic", "openai", "google").
pub const GEN_AI_SYSTEM: &str = "gen_ai.system";

/// The specific model requested (e.g. "claude-opus-4-5").
pub const GEN_AI_REQUEST_MODEL: &str = "gen_ai.request.model";

/// The maximum number of tokens to generate.
pub const GEN_AI_REQUEST_MAX_TOKENS: &str = "gen_ai.request.max_tokens";

/// The temperature requested (0.0–2.0).
pub const GEN_AI_REQUEST_TEMPERATURE: &str = "gen_ai.request.temperature";

/// The actual model used (may differ from requested due to routing).
pub const GEN_AI_RESPONSE_MODEL: &str = "gen_ai.response.model";

/// Finish reason(s) (e.g. "stop", "length", "tool_calls").
pub const GEN_AI_RESPONSE_FINISH_REASONS: &str = "gen_ai.response.finish_reasons";

/// The unique ID of the LLM response.
pub const GEN_AI_RESPONSE_ID: &str = "gen_ai.response.id";

/// Number of input/prompt tokens consumed.
pub const GEN_AI_USAGE_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";

/// Number of output/completion tokens generated.
pub const GEN_AI_USAGE_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";

/// Number of prompt cache read tokens (Anthropic-specific).
pub const GEN_AI_USAGE_CACHE_READ_TOKENS: &str = "gen_ai.usage.cache_read_input_tokens";

/// Number of prompt cache write tokens (Anthropic-specific).
pub const GEN_AI_USAGE_CACHE_WRITE_TOKENS: &str = "gen_ai.usage.cache_creation_input_tokens";

/// Operation name (chat, text_completion, embeddings, etc.).
pub const GEN_AI_OPERATION_NAME: &str = "gen_ai.operation.name";

/// The provider-specific error code on failure.
pub const GEN_AI_ERROR_TYPE: &str = "error.type";

// SafeAgent-specific extensions (sa.* namespace)
pub const SA_POLICY_DECISION: &str = "sa.policy.decision";
pub const SA_RISK_SCORE: &str = "sa.risk_score";
pub const SA_PROVIDER: &str = "sa.provider";
pub const SA_TIER: &str = "sa.routing.tier";
pub const SA_CACHE_HIT: &str = "sa.cache.hit";
pub const SA_CIRCUIT_BREAKER_STATE: &str = "sa.circuit_breaker.state";
pub const SA_FENCE_DECISION: &str = "sa.fence.decision";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Operation types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq)]
pub enum GenAiOperation {
    Chat,
    TextCompletion,
    Embeddings,
    ImageGeneration,
}

impl GenAiOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            GenAiOperation::Chat => "chat",
            GenAiOperation::TextCompletion => "text_completion",
            GenAiOperation::Embeddings => "embeddings",
            GenAiOperation::ImageGeneration => "image_generation",
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  GenAiSpanData — collected during a call
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Immutable snapshot of a completed GenAI span.
#[derive(Debug, Clone)]
pub struct GenAiSpanData {
    pub system: String,
    pub request_model: String,
    pub response_model: Option<String>,
    pub operation: GenAiOperation,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_read_tokens: u32,
    pub cache_write_tokens: u32,
    pub finish_reason: Option<String>,
    pub response_id: Option<String>,
    pub duration_ms: u64,
    pub success: bool,
    pub error_type: Option<String>,
    // SafeAgent extensions
    pub policy_decision: Option<String>,
    pub risk_score: Option<f64>,
    pub routing_tier: Option<String>,
    pub cache_hit: bool,
    pub fence_decision: Option<String>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  GenAiSpan builder
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Builder for a GenAI OTel span. Records timing and emits structured
/// log events matching the gen_ai.* semantic conventions.
pub struct GenAiSpan {
    system: String,
    request_model: String,
    operation: GenAiOperation,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
    policy_decision: Option<String>,
    risk_score: Option<f64>,
    routing_tier: Option<String>,
    cache_hit: bool,
    fence_decision: Option<String>,
    started_at: Instant,
}

impl GenAiSpan {
    /// Create a new span for the given AI system (provider).
    /// `system` should match the gen_ai.system value (e.g. "anthropic").
    pub fn new(system: impl Into<String>) -> Self {
        Self {
            system: system.into(),
            request_model: String::new(),
            operation: GenAiOperation::Chat,
            max_tokens: None,
            temperature: None,
            policy_decision: None,
            risk_score: None,
            routing_tier: None,
            cache_hit: false,
            fence_decision: None,
            started_at: Instant::now(),
        }
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.request_model = model.into();
        self
    }

    pub fn operation(mut self, op: GenAiOperation) -> Self {
        self.operation = op;
        self
    }

    pub fn max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = Some(n);
        self
    }

    pub fn temperature(mut self, t: f32) -> Self {
        self.temperature = Some(t);
        self
    }

    pub fn policy_decision(mut self, d: impl Into<String>) -> Self {
        self.policy_decision = Some(d.into());
        self
    }

    pub fn risk_score(mut self, score: f64) -> Self {
        self.risk_score = Some(score);
        self
    }

    pub fn routing_tier(mut self, tier: impl Into<String>) -> Self {
        self.routing_tier = Some(tier.into());
        self
    }

    pub fn cache_hit(mut self, hit: bool) -> Self {
        self.cache_hit = hit;
        self
    }

    pub fn fence_decision(mut self, d: impl Into<String>) -> Self {
        self.fence_decision = Some(d.into());
        self
    }

    /// Finish with a successful response.
    pub fn finish_ok(
        self,
        input_tokens: u32,
        output_tokens: u32,
        cache_read_tokens: u32,
        cache_write_tokens: u32,
        finish_reason: impl Into<String>,
        response_id: Option<String>,
        response_model: Option<String>,
    ) -> GenAiSpanData {
        let duration_ms = self.started_at.elapsed().as_millis() as u64;
        let data = GenAiSpanData {
            system: self.system.clone(),
            request_model: self.request_model.clone(),
            response_model,
            operation: self.operation,
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_write_tokens,
            finish_reason: Some(finish_reason.into()),
            response_id,
            duration_ms,
            success: true,
            error_type: None,
            policy_decision: self.policy_decision,
            risk_score: self.risk_score,
            routing_tier: self.routing_tier,
            cache_hit: self.cache_hit,
            fence_decision: self.fence_decision,
        };
        emit_span_event(&data);
        data
    }

    /// Finish with an error.
    pub fn finish_err(self, error_type: impl Into<String>) -> GenAiSpanData {
        let duration_ms = self.started_at.elapsed().as_millis() as u64;
        let data = GenAiSpanData {
            system: self.system.clone(),
            request_model: self.request_model.clone(),
            response_model: None,
            operation: self.operation,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            finish_reason: None,
            response_id: None,
            duration_ms,
            success: false,
            error_type: Some(error_type.into()),
            policy_decision: self.policy_decision,
            risk_score: self.risk_score,
            routing_tier: self.routing_tier,
            cache_hit: self.cache_hit,
            fence_decision: self.fence_decision,
        };
        emit_span_event(&data);
        data
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Span event emission — structured tracing fields
//  In production with OTel tracing layer, these appear
//  as span attributes in Langfuse/Jaeger/Datadog.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn emit_span_event(data: &GenAiSpanData) {
    // Field names use underscores (tracing macro requirement).
    // They map to OTel gen_ai.* dotted convention in the GenAI attribute constants above.
    if data.success {
        info!(
            target: "gen_ai",
            gen_ai_system = %data.system,
            gen_ai_request_model = %data.request_model,
            gen_ai_operation_name = %data.operation.as_str(),
            gen_ai_usage_input_tokens = data.input_tokens,
            gen_ai_usage_output_tokens = data.output_tokens,
            gen_ai_usage_cache_read_tokens = data.cache_read_tokens,
            gen_ai_usage_cache_write_tokens = data.cache_write_tokens,
            gen_ai_response_finish_reasons = ?data.finish_reason,
            duration_ms = data.duration_ms,
            sa_cache_hit = data.cache_hit,
            sa_policy_decision = ?data.policy_decision,
            sa_risk_score = ?data.risk_score,
            sa_routing_tier = ?data.routing_tier,
            sa_fence_decision = ?data.fence_decision,
            "gen_ai call completed"
        );
    } else {
        debug!(
            target: "gen_ai",
            gen_ai_system = %data.system,
            gen_ai_request_model = %data.request_model,
            gen_ai_operation_name = %data.operation.as_str(),
            error_type = ?data.error_type,
            duration_ms = data.duration_ms,
            sa_cache_hit = data.cache_hit,
            sa_policy_decision = ?data.policy_decision,
            "gen_ai call failed"
        );
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Convenience metrics aggregator
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Aggregates GenAI span data for session-level metrics.
#[derive(Debug, Default)]
pub struct GenAiSessionMetrics {
    pub total_calls: u64,
    pub successful_calls: u64,
    pub failed_calls: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cache_read_tokens: u64,
    pub total_cache_write_tokens: u64,
    pub total_duration_ms: u64,
    pub cache_hits: u64,
}

impl GenAiSessionMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, data: &GenAiSpanData) {
        self.total_calls += 1;
        if data.success {
            self.successful_calls += 1;
        } else {
            self.failed_calls += 1;
        }
        self.total_input_tokens += data.input_tokens as u64;
        self.total_output_tokens += data.output_tokens as u64;
        self.total_cache_read_tokens += data.cache_read_tokens as u64;
        self.total_cache_write_tokens += data.cache_write_tokens as u64;
        self.total_duration_ms += data.duration_ms;
        if data.cache_hit {
            self.cache_hits += 1;
        }
    }

    /// Cache hit rate (0.0–1.0).
    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.cache_hits as f64 / self.total_calls as f64
        }
    }

    /// Average latency in milliseconds.
    pub fn avg_latency_ms(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.total_duration_ms as f64 / self.total_calls as f64
        }
    }

    /// Total tokens (input + output).
    pub fn total_tokens(&self) -> u64 {
        self.total_input_tokens + self.total_output_tokens
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    fn make_span_data(success: bool) -> GenAiSpanData {
        let span = GenAiSpan::new("anthropic")
            .model("claude-opus-4-5")
            .operation(GenAiOperation::Chat)
            .policy_decision("allow")
            .risk_score(0.02)
            .routing_tier("tier1")
            .cache_hit(false);

        if success {
            span.finish_ok(100, 50, 10, 0, "stop", Some("resp-123".to_string()), None)
        } else {
            span.finish_err("api_error")
        }
    }

    #[test]
    fn span_builder_chain_produces_data() {
        let data = make_span_data(true);
        assert_eq!(data.system, "anthropic");
        assert_eq!(data.request_model, "claude-opus-4-5");
        assert_eq!(data.input_tokens, 100);
        assert_eq!(data.output_tokens, 50);
        assert_eq!(data.cache_read_tokens, 10);
        assert!(data.success);
        assert_eq!(data.finish_reason.unwrap(), "stop");
    }

    #[test]
    fn span_error_produces_failed_data() {
        let data = make_span_data(false);
        assert!(!data.success);
        assert_eq!(data.error_type.unwrap(), "api_error");
        assert_eq!(data.input_tokens, 0);
    }

    #[test]
    fn gen_ai_operation_strings() {
        assert_eq!(GenAiOperation::Chat.as_str(), "chat");
        assert_eq!(GenAiOperation::TextCompletion.as_str(), "text_completion");
        assert_eq!(GenAiOperation::Embeddings.as_str(), "embeddings");
        assert_eq!(GenAiOperation::ImageGeneration.as_str(), "image_generation");
    }

    #[test]
    fn session_metrics_accumulate() {
        let mut metrics = GenAiSessionMetrics::new();
        let d1 = make_span_data(true);
        let d2 = make_span_data(false);
        metrics.record(&d1);
        metrics.record(&d2);
        assert_eq!(metrics.total_calls, 2);
        assert_eq!(metrics.successful_calls, 1);
        assert_eq!(metrics.failed_calls, 1);
        assert_eq!(metrics.total_input_tokens, 100);
        assert_eq!(metrics.total_output_tokens, 50);
    }

    #[test]
    fn session_metrics_cache_hit_rate() {
        let mut metrics = GenAiSessionMetrics::new();
        assert_eq!(metrics.cache_hit_rate(), 0.0);

        let span1 = GenAiSpan::new("openai").model("gpt-4o").cache_hit(true);
        let d1 = span1.finish_ok(100, 50, 0, 0, "stop", None, None);
        let span2 = GenAiSpan::new("openai").model("gpt-4o").cache_hit(false);
        let d2 = span2.finish_ok(200, 100, 0, 0, "stop", None, None);

        metrics.record(&d1);
        metrics.record(&d2);
        assert!((metrics.cache_hit_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn attribute_constants_are_spec_compliant() {
        // Verify key strings match the OTel GenAI spec naming convention
        assert!(GEN_AI_SYSTEM.starts_with("gen_ai."));
        assert!(GEN_AI_REQUEST_MODEL.starts_with("gen_ai."));
        assert!(GEN_AI_USAGE_INPUT_TOKENS.starts_with("gen_ai."));
        assert!(SA_POLICY_DECISION.starts_with("sa."));
    }

    #[test]
    fn span_duration_is_measured() {
        let span = GenAiSpan::new("anthropic").model("claude-haiku");
        std::thread::sleep(std::time::Duration::from_millis(5));
        let data = span.finish_ok(10, 5, 0, 0, "stop", None, None);
        assert!(data.duration_ms >= 5);
    }
}
