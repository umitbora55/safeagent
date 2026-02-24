//! Multi-provider abstraction for LLM APIs.
//! Supports Anthropic, OpenAI, and Google Gemini.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════
//  Provider Trait
// ═══════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProviderType {
    Anthropic,
    OpenAI,
    Gemini,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Anthropic => write!(f, "anthropic"),
            ProviderType::OpenAI => write!(f, "openai"),
            ProviderType::Gemini => write!(f, "gemini"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub provider_type: ProviderType,
    pub api_key: String,
    pub base_url: String,
    pub default_model: String,
    pub enabled: bool,
    pub priority: u32, // Lower = higher priority for fallback
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedRequest {
    pub model: String,
    pub messages: Vec<UnifiedMessage>,
    pub system_prompt: Option<String>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedResponse {
    pub content: String,
    pub model: String,
    pub provider: ProviderType,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub id: String,
    pub provider: ProviderType,
    pub tier: String,
    pub input_price_per_mtok: f64,
    pub output_price_per_mtok: f64,
    pub max_context: u32,
}

// ═══════════════════════════════════════════════
//  Provider Implementations
// ═══════════════════════════════════════════════

pub struct AnthropicProvider {
    pub config: ProviderConfig,
}

impl AnthropicProvider {
    pub fn new(api_key: &str) -> Self {
        Self {
            config: ProviderConfig {
                provider_type: ProviderType::Anthropic,
                api_key: api_key.to_string(),
                base_url: "https://api.anthropic.com/v1".into(),
                default_model: "claude-sonnet-4-5-20250514".into(),
                enabled: true,
                priority: 1,
            },
        }
    }

    pub fn models() -> Vec<ModelInfo> {
        vec![
            ModelInfo {
                id: "claude-haiku-4-5-20250514".into(),
                provider: ProviderType::Anthropic,
                tier: "economy".into(),
                input_price_per_mtok: 0.80,
                output_price_per_mtok: 4.0,
                max_context: 200_000,
            },
            ModelInfo {
                id: "claude-sonnet-4-5-20250514".into(),
                provider: ProviderType::Anthropic,
                tier: "standard".into(),
                input_price_per_mtok: 3.0,
                output_price_per_mtok: 15.0,
                max_context: 200_000,
            },
            ModelInfo {
                id: "claude-opus-4-5-20250514".into(),
                provider: ProviderType::Anthropic,
                tier: "premium".into(),
                input_price_per_mtok: 15.0,
                output_price_per_mtok: 75.0,
                max_context: 200_000,
            },
        ]
    }

    pub fn build_request_body(&self, req: &UnifiedRequest) -> serde_json::Value {
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|m| serde_json::json!({ "role": m.role, "content": m.content }))
            .collect();

        let mut body = serde_json::json!({
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": messages,
        });

        if let Some(sys) = &req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }
        if req.temperature != 1.0 {
            body["temperature"] = serde_json::json!(req.temperature);
        }
        body
    }

    pub fn parse_response(&self, body: &serde_json::Value) -> Result<UnifiedResponse, String> {
        let content = body["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let model = body["model"].as_str().unwrap_or("").to_string();
        let input = body["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32;
        let output = body["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32;

        Ok(UnifiedResponse {
            content,
            model,
            provider: ProviderType::Anthropic,
            input_tokens: input,
            output_tokens: output,
            latency_ms: 0,
        })
    }
}

pub struct OpenAIProvider {
    pub config: ProviderConfig,
}

impl OpenAIProvider {
    pub fn new(api_key: &str) -> Self {
        Self {
            config: ProviderConfig {
                provider_type: ProviderType::OpenAI,
                api_key: api_key.to_string(),
                base_url: "https://api.openai.com/v1".into(),
                default_model: "gpt-4o".into(),
                enabled: true,
                priority: 2,
            },
        }
    }

    pub fn models() -> Vec<ModelInfo> {
        vec![
            ModelInfo {
                id: "gpt-4o-mini".into(),
                provider: ProviderType::OpenAI,
                tier: "economy".into(),
                input_price_per_mtok: 0.15,
                output_price_per_mtok: 0.60,
                max_context: 128_000,
            },
            ModelInfo {
                id: "gpt-4o".into(),
                provider: ProviderType::OpenAI,
                tier: "standard".into(),
                input_price_per_mtok: 2.50,
                output_price_per_mtok: 10.0,
                max_context: 128_000,
            },
            ModelInfo {
                id: "o1".into(),
                provider: ProviderType::OpenAI,
                tier: "premium".into(),
                input_price_per_mtok: 15.0,
                output_price_per_mtok: 60.0,
                max_context: 200_000,
            },
        ]
    }

    pub fn build_request_body(&self, req: &UnifiedRequest) -> serde_json::Value {
        let mut messages: Vec<serde_json::Value> = vec![];

        if let Some(sys) = &req.system_prompt {
            messages.push(serde_json::json!({ "role": "system", "content": sys }));
        }

        for m in &req.messages {
            messages.push(serde_json::json!({ "role": m.role, "content": m.content }));
        }

        serde_json::json!({
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": messages,
            "temperature": req.temperature,
            "stream": req.stream,
        })
    }

    pub fn parse_response(&self, body: &serde_json::Value) -> Result<UnifiedResponse, String> {
        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let model = body["model"].as_str().unwrap_or("").to_string();
        let input = body["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32;
        let output = body["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32;

        Ok(UnifiedResponse {
            content,
            model,
            provider: ProviderType::OpenAI,
            input_tokens: input,
            output_tokens: output,
            latency_ms: 0,
        })
    }
}

pub struct GeminiProvider {
    pub config: ProviderConfig,
}

impl GeminiProvider {
    pub fn new(api_key: &str) -> Self {
        Self {
            config: ProviderConfig {
                provider_type: ProviderType::Gemini,
                api_key: api_key.to_string(),
                base_url: "https://generativelanguage.googleapis.com/v1beta".into(),
                default_model: "gemini-2.0-flash".into(),
                enabled: true,
                priority: 3,
            },
        }
    }

    pub fn models() -> Vec<ModelInfo> {
        vec![
            ModelInfo {
                id: "gemini-2.0-flash".into(),
                provider: ProviderType::Gemini,
                tier: "economy".into(),
                input_price_per_mtok: 0.075,
                output_price_per_mtok: 0.30,
                max_context: 1_000_000,
            },
            ModelInfo {
                id: "gemini-2.0-pro".into(),
                provider: ProviderType::Gemini,
                tier: "standard".into(),
                input_price_per_mtok: 1.25,
                output_price_per_mtok: 5.0,
                max_context: 2_000_000,
            },
        ]
    }

    pub fn build_request_body(&self, req: &UnifiedRequest) -> serde_json::Value {
        let parts: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "role": if m.role == "assistant" { "model" } else { "user" },
                    "parts": [{ "text": m.content }]
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "contents": parts,
            "generationConfig": {
                "maxOutputTokens": req.max_tokens,
                "temperature": req.temperature,
            }
        });

        if let Some(sys) = &req.system_prompt {
            body["systemInstruction"] = serde_json::json!({
                "parts": [{ "text": sys }]
            });
        }
        body
    }

    pub fn parse_response(&self, body: &serde_json::Value) -> Result<UnifiedResponse, String> {
        let content = body["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let input = body["usageMetadata"]["promptTokenCount"]
            .as_u64()
            .unwrap_or(0) as u32;
        let output = body["usageMetadata"]["candidatesTokenCount"]
            .as_u64()
            .unwrap_or(0) as u32;

        Ok(UnifiedResponse {
            content,
            model: "gemini".into(),
            provider: ProviderType::Gemini,
            input_tokens: input,
            output_tokens: output,
            latency_ms: 0,
        })
    }
}

// ═══════════════════════════════════════════════
//  Multi-Provider Router
// ═══════════════════════════════════════════════

#[derive(Debug, Clone)]
pub enum RoutingStrategy {
    CostOptimized,
    LatencyOptimized,
    Fallback,
    RoundRobin,
}

pub struct MultiProviderRouter {
    providers: Vec<ProviderConfig>,
    strategy: RoutingStrategy,
}

impl MultiProviderRouter {
    pub fn new(strategy: RoutingStrategy) -> Self {
        Self {
            providers: vec![],
            strategy,
        }
    }

    pub fn add_provider(&mut self, config: ProviderConfig) {
        self.providers.push(config);
    }

    pub fn enabled_providers(&self) -> Vec<&ProviderConfig> {
        self.providers.iter().filter(|p| p.enabled).collect()
    }

    /// Select best provider based on strategy
    pub fn select_provider(&self, _tier: &str) -> Option<&ProviderConfig> {
        let enabled = self.enabled_providers();
        if enabled.is_empty() {
            return None;
        }

        match &self.strategy {
            RoutingStrategy::CostOptimized => {
                // Pick cheapest provider for this tier
                enabled.first().copied()
            }
            RoutingStrategy::Fallback => {
                // Pick highest priority (lowest number)
                enabled.iter().min_by_key(|p| p.priority).copied()
            }
            RoutingStrategy::RoundRobin => {
                // Simple: just pick first enabled
                enabled.first().copied()
            }
            RoutingStrategy::LatencyOptimized => enabled.first().copied(),
        }
    }

    /// Get fallback chain (ordered by priority)
    pub fn fallback_chain(&self) -> Vec<&ProviderConfig> {
        let mut providers = self.enabled_providers();
        providers.sort_by_key(|p| p.priority);
        providers
    }

    pub fn all_models(&self) -> Vec<ModelInfo> {
        let mut models = vec![];
        for p in &self.providers {
            if !p.enabled {
                continue;
            }
            match p.provider_type {
                ProviderType::Anthropic => models.extend(AnthropicProvider::models()),
                ProviderType::OpenAI => models.extend(OpenAIProvider::models()),
                ProviderType::Gemini => models.extend(GeminiProvider::models()),
            }
        }
        models
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_request_format() {
        let provider = AnthropicProvider::new("sk-test");
        let req = UnifiedRequest {
            model: "claude-haiku-4-5-20250514".into(),
            messages: vec![UnifiedMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            system_prompt: Some("You are helpful".into()),
            max_tokens: 1024,
            temperature: 0.7,
            stream: false,
        };
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "claude-haiku-4-5-20250514");
        assert_eq!(body["system"], "You are helpful");
        assert_eq!(body["messages"][0]["role"], "user");
    }

    #[test]
    fn test_openai_request_format() {
        let provider = OpenAIProvider::new("sk-test");
        let req = UnifiedRequest {
            model: "gpt-4o".into(),
            messages: vec![UnifiedMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            system_prompt: Some("You are helpful".into()),
            max_tokens: 1024,
            temperature: 0.7,
            stream: false,
        };
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4o");
        // System prompt is first message for OpenAI
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][1]["role"], "user");
    }

    #[test]
    fn test_gemini_request_format() {
        let provider = GeminiProvider::new("key-test");
        let req = UnifiedRequest {
            model: "gemini-2.0-flash".into(),
            messages: vec![UnifiedMessage {
                role: "user".into(),
                content: "Hello".into(),
            }],
            system_prompt: Some("Be brief".into()),
            max_tokens: 512,
            temperature: 0.5,
            stream: false,
        };
        let body = provider.build_request_body(&req);
        assert!(body["contents"][0]["parts"][0]["text"].as_str().is_some());
        assert!(body["systemInstruction"]["parts"][0]["text"]
            .as_str()
            .is_some());
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 512);
    }

    #[test]
    fn test_anthropic_parse_response() {
        let provider = AnthropicProvider::new("sk-test");
        let body = serde_json::json!({
            "content": [{ "text": "Hello!", "type": "text" }],
            "model": "claude-haiku-4-5-20250514",
            "usage": { "input_tokens": 10, "output_tokens": 5 }
        });
        let resp = provider.parse_response(&body).unwrap();
        assert_eq!(resp.content, "Hello!");
        assert_eq!(resp.input_tokens, 10);
        assert_eq!(resp.output_tokens, 5);
        assert_eq!(resp.provider, ProviderType::Anthropic);
    }

    #[test]
    fn test_openai_parse_response() {
        let provider = OpenAIProvider::new("sk-test");
        let body = serde_json::json!({
            "choices": [{ "message": { "content": "Hi there!" } }],
            "model": "gpt-4o",
            "usage": { "prompt_tokens": 8, "completion_tokens": 3 }
        });
        let resp = provider.parse_response(&body).unwrap();
        assert_eq!(resp.content, "Hi there!");
        assert_eq!(resp.input_tokens, 8);
        assert_eq!(resp.output_tokens, 3);
        assert_eq!(resp.provider, ProviderType::OpenAI);
    }

    #[test]
    fn test_gemini_parse_response() {
        let provider = GeminiProvider::new("key-test");
        let body = serde_json::json!({
            "candidates": [{ "content": { "parts": [{ "text": "Merhaba!" }] } }],
            "usageMetadata": { "promptTokenCount": 5, "candidatesTokenCount": 2 }
        });
        let resp = provider.parse_response(&body).unwrap();
        assert_eq!(resp.content, "Merhaba!");
        assert_eq!(resp.input_tokens, 5);
        assert_eq!(resp.provider, ProviderType::Gemini);
    }

    #[test]
    fn test_multi_provider_router() {
        let mut router = MultiProviderRouter::new(RoutingStrategy::Fallback);
        router.add_provider(AnthropicProvider::new("sk-ant").config);
        router.add_provider(OpenAIProvider::new("sk-oai").config);
        router.add_provider(GeminiProvider::new("key-gem").config);

        let chain = router.fallback_chain();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].provider_type, ProviderType::Anthropic); // priority 1
        assert_eq!(chain[1].provider_type, ProviderType::OpenAI); // priority 2
        assert_eq!(chain[2].provider_type, ProviderType::Gemini); // priority 3
    }

    #[test]
    fn test_all_models() {
        let mut router = MultiProviderRouter::new(RoutingStrategy::CostOptimized);
        router.add_provider(AnthropicProvider::new("k").config);
        router.add_provider(OpenAIProvider::new("k").config);
        router.add_provider(GeminiProvider::new("k").config);

        let models = router.all_models();
        assert_eq!(models.len(), 8); // 3 + 3 + 2
        assert!(models.iter().any(|m| m.id.contains("haiku")));
        assert!(models.iter().any(|m| m.id.contains("gpt-4o")));
        assert!(models.iter().any(|m| m.id.contains("gemini")));
    }

    #[test]
    fn test_disabled_provider_skipped() {
        let mut router = MultiProviderRouter::new(RoutingStrategy::Fallback);
        let mut anthropic = AnthropicProvider::new("k").config;
        anthropic.enabled = false;
        router.add_provider(anthropic);
        router.add_provider(OpenAIProvider::new("k").config);

        let chain = router.fallback_chain();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].provider_type, ProviderType::OpenAI);
    }

    #[test]
    fn test_provider_display() {
        assert_eq!(ProviderType::Anthropic.to_string(), "anthropic");
        assert_eq!(ProviderType::OpenAI.to_string(), "openai");
        assert_eq!(ProviderType::Gemini.to_string(), "gemini");
    }
}
