use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::{debug, info, warn};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Provider & Model Config
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenAI,
    DeepSeek,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelTier {
    Economy,
    Standard,
    Premium,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub id: String,
    pub provider: Provider,
    pub model_name: String,
    pub api_key_ref: String,
    pub api_base_url: Option<String>,
    pub tier: ModelTier,
    pub cost_per_1k_input_microdollars: u64,
    pub cost_per_1k_output_microdollars: u64,
    pub max_context_tokens: u32,
    pub supports_vision: bool,
    pub supports_tools: bool,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Secret Resolver trait
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve(&self, key_ref: &str) -> anyhow::Result<String>;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Routing
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    Economy,
    Balanced,
    Performance,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskComplexity {
    Simple,
    Medium,
    Complex,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Task Type Classification (Phase 1 research)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TaskType {
    SimpleQA,           // Basit soru-cevap → Haiku
    Classification,     // Sınıflandırma → Haiku
    Extraction,         // Veri çıkarma → Haiku
    Summarization,      // Özetleme → Haiku/Sonnet
    Translation,        // Çeviri → Haiku/Sonnet
    CodeGeneration,     // Kod yazma → Sonnet
    CodeReview,         // Kod inceleme → Sonnet
    ContentCreation,    // İçerik oluşturma → Sonnet
    MultiStepAnalysis,  // Çok adımlı analiz → Sonnet/Opus
    DeepReasoning,      // Derin mantık → Opus
    Architecture,       // Mimari tasarım → Opus
    ScientificAnalysis, // Bilimsel analiz → Opus
    Conversation,       // Genel sohbet → Haiku
    Unknown,
}

impl TaskType {
    /// Default tier mapping from research
    pub fn default_tier(&self) -> ModelTier {
        match self {
            TaskType::SimpleQA
            | TaskType::Classification
            | TaskType::Extraction
            | TaskType::Conversation => ModelTier::Economy,

            TaskType::Summarization
            | TaskType::Translation
            | TaskType::CodeGeneration
            | TaskType::CodeReview
            | TaskType::ContentCreation => ModelTier::Standard,

            TaskType::MultiStepAnalysis
            | TaskType::DeepReasoning
            | TaskType::Architecture
            | TaskType::ScientificAnalysis => ModelTier::Premium,

            TaskType::Unknown => ModelTier::Standard,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Feature Extraction (Phase 1: rule-based)
//  Research: "token count alone is a weak signal"
//  Multi-signal approach from RouteLLM/FrugalGPT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize)]
pub struct QueryFeatures {
    pub word_count: usize,
    pub task_type: TaskType,
    pub has_code: bool,
    pub has_math: bool,
    pub constraint_count: usize,
    pub conversation_depth: usize,
    pub system_prompt_length: usize,
    pub requires_vision: bool,
    pub requires_tools: bool,
    pub estimated_output_tokens: u32,
    pub complexity_score: u32,
}

pub fn extract_features(request: &LlmRequest) -> QueryFeatures {
    let msg = request.messages.last().map(|m| m.content.as_str()).unwrap_or("");
    let lower = msg.to_lowercase();
    let word_count = msg.split_whitespace().count();

    let task_type = classify_task(&lower, msg);
    let has_code = detect_code(msg);
    let has_math = detect_math(msg);
    let constraint_count = count_constraints(msg);
    let conversation_depth = request.messages.len();
    let system_prompt_length = request.system_prompt.len();

    let estimated_output_tokens = estimate_output_tokens(&task_type, word_count);

    // Multi-signal scoring
    let mut score: u32 = 0;

    // Signal 1: Task type is the strongest signal (research confirmed)
    score += match task_type.default_tier() {
        ModelTier::Economy => 0,
        ModelTier::Standard => 3,
        ModelTier::Premium => 6,
    };

    // Signal 2: Code presence
    if has_code { score += 2; }

    // Signal 3: Math/logic presence
    if has_math { score += 2; }

    // Signal 4: Constraint count (multi-step instructions)
    score += match constraint_count {
        0..=1 => 0,
        2..=3 => 1,
        _ => 2,
    };

    // Signal 5: Word count (weak signal per research, low weight)
    score += match word_count {
        0..=10 => 0,
        11..=50 => 1,
        _ => 2,
    };

    // Signal 6: Conversation depth (reduced weight from research)
    score += match conversation_depth {
        0..=8 => 0,
        9..=16 => 1,
        _ => 2,
    };

    // Signal 7: System prompt complexity
    if system_prompt_length > 1000 { score += 1; }

    // Signal 8: Vision/tools
    if request.requires_vision || request.requires_tools {
        score = score.max(3);
    }

    QueryFeatures {
        word_count,
        task_type,
        has_code,
        has_math,
        constraint_count,
        conversation_depth,
        system_prompt_length,
        requires_vision: request.requires_vision,
        requires_tools: request.requires_tools,
        estimated_output_tokens,
        complexity_score: score,
    }
}

pub fn features_to_complexity(features: &QueryFeatures) -> TaskComplexity {
    // Short-circuit: trivial messages always Simple
    if features.word_count <= 3
        && !features.has_code
        && !features.has_math
        && matches!(features.task_type,
            TaskType::SimpleQA | TaskType::Conversation | TaskType::Unknown)
    {
        return TaskComplexity::Simple;
    }

    match features.complexity_score {
        0..=2 => TaskComplexity::Simple,
        3..=5 => TaskComplexity::Medium,
        _ => TaskComplexity::Complex,
    }
}

// Backward-compatible wrapper
pub fn assess_complexity(request: &LlmRequest) -> TaskComplexity {
    let features = extract_features(request);
    features_to_complexity(&features)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Task Classification (regex + keyword)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn classify_task(lower: &str, original: &str) -> TaskType {
    // Code detection is high priority
    if detect_code(original) {
        if has_any(lower, &["review", "incele", "kontrol", "fix", "düzelt", "bug", "hata"]) {
            return TaskType::CodeReview;
        }
        return TaskType::CodeGeneration;
    }

    // Deep reasoning signals (Opus territory)
    // "prove", "derive" gibi kelimeler tek başına yeterli — constraint şartı kaldırıldı
    if has_any(lower, &[
        "prove", "kanıtla", "derive", "türet",
        "why does", "neden böyle", "explain why",
        "trade-off", "tradeoff",
        "what would happen if", "ne olurdu",
        "undecidable", "karar verilemez",
        "diagonaliz", "induction", "tümevarım",
    ]) {
        return TaskType::DeepReasoning;
    }

    // Architecture / design
    if has_any(lower, &[
        "architect", "mimari", "design system", "sistem tasarla",
        "infrastructure", "altyapı", "scalab", "ölçeklen",
    ]) {
        return TaskType::Architecture;
    }

    // Scientific
    if has_any(lower, &[
        "scientific", "bilimsel", "hypothesis", "hipotez",
        "experiment", "deney", "peer review", "literature",
    ]) {
        return TaskType::ScientificAnalysis;
    }

    // Multi-step analysis
    if has_any(lower, &[
        "analyze", "analiz", "compare", "karşılaştır",
        "evaluate", "değerlendir", "assess", "research", "araştır",
    ]) {
        return TaskType::MultiStepAnalysis;
    }

    // Content creation
    if has_any(lower, &[
        "write", "yaz", "create", "oluştur", "draft", "taslak",
        "compose", "blog", "article", "makale", "essay",
    ]) {
        return TaskType::ContentCreation;
    }

    // Summarization
    if has_any(lower, &["summarize", "özetle", "summary", "özet", "tl;dr", "kısaca"]) {
        return TaskType::Summarization;
    }

    // Translation
    if has_any(lower, &["translate", "çevir", "translation", "çeviri"]) {
        return TaskType::Translation;
    }

    // Classification / extraction
    if has_any(lower, &[
        "classify", "sınıfla", "categorize", "kategori",
        "extract", "çıkar", "parse", "ayrıştır",
        "list all", "listele",
    ]) {
        return TaskType::Extraction;
    }

    // Math detection
    if detect_math(original) {
        return TaskType::DeepReasoning;
    }

    // Question patterns → SimpleQA
    if lower.ends_with('?')
        || lower.starts_with("what")
        || lower.starts_with("who")
        || lower.starts_with("when")
        || lower.starts_with("where")
        || lower.starts_with("ne ")
        || lower.starts_with("kim")
        || lower.starts_with("nerede")
        || lower.starts_with("nasıl")
        || lower.starts_with("kaç")
    {
        if count_constraints(original) <= 1 {
            return TaskType::SimpleQA;
        }
        return TaskType::MultiStepAnalysis;
    }

    // Short conversational messages
    if original.split_whitespace().count() <= 5 {
        return TaskType::Conversation;
    }

    TaskType::Unknown
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Detection helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn has_any(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| text.contains(p))
}

fn detect_code(text: &str) -> bool {
    // ``` tek başına yeterli — kesin kod bloğu
    if text.contains("```") {
        return true;
    }

    // Diğer marker'lar context gerektirir — en az 2 tanesi birlikte olmalı
    let markers = [
        text.contains("fn ") && text.contains("("),
        text.contains("def ") && text.contains(":"),
        text.contains("function ") && text.contains("{"),
        text.contains("class ") && (text.contains("{") || text.contains(":")),
        text.contains("#include"),
        text.contains("import ") && (text.contains("from ") || text.contains(";")),
        text.contains("const ") && text.contains("="),
        text.contains("let ") && text.contains("="),
        text.contains("var ") && text.contains("="),
        text.contains("async ") && text.contains("await"),
        text.contains("=>") && text.contains("("),
        text.contains("->") && (text.contains("fn ") || text.contains("{")),
    ];

    markers.iter().filter(|&&m| m).count() >= 1
}

fn detect_math(text: &str) -> bool {
    text.contains("∫") || text.contains("∑") || text.contains("√")
        || text.contains("equation") || text.contains("denklem")
        || text.contains("integral") || text.contains("derivative") || text.contains("türev")
        || text.contains("matrix") || text.contains("matris")
        || text.contains("probability") || text.contains("olasılık")
        || text.contains("theorem") || text.contains("teorem")
        // LaTeX patterns
        || text.contains("\\frac") || text.contains("\\sum")
        || text.contains("\\int") || text.contains("^{")
}

/// Count constraints/requirements (multi-step detection)
fn count_constraints(text: &str) -> usize {
    let mut count = 0;

    // Numbered items: "1.", "2.", etc.
    for i in 1..=10 {
        if text.contains(&format!("{}.", i)) || text.contains(&format!("{})", i)) {
            count += 1;
        }
    }

    // Bullet points
    count += text.lines().filter(|l| {
        let t = l.trim();
        t.starts_with("- ") || t.starts_with("* ") || t.starts_with("• ")
    }).count();

    // Imperative verbs (task indicators)
    let lower = text.to_lowercase();
    let imperatives = [
        "must", "should", "need to", "make sure", "ensure",
        "first", "then", "finally", "also", "additionally",
        "olmalı", "gerekiyor", "emin ol", "ayrıca", "önce", "sonra",
    ];
    for imp in imperatives {
        if lower.contains(imp) { count += 1; }
    }

    count
}

fn estimate_output_tokens(task_type: &TaskType, input_words: usize) -> u32 {
    match task_type {
        TaskType::SimpleQA | TaskType::Conversation => 50 + (input_words as u32 / 2),
        TaskType::Classification | TaskType::Extraction => 100,
        TaskType::Summarization => (input_words as u32 / 3).max(100),
        TaskType::Translation => input_words as u32 + 50,
        TaskType::CodeGeneration | TaskType::CodeReview => 500,
        TaskType::ContentCreation => 800,
        TaskType::MultiStepAnalysis => 600,
        TaskType::DeepReasoning | TaskType::Architecture | TaskType::ScientificAnalysis => 1000,
        TaskType::Unknown => 300,
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  LLM Request / Response
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingScores {
    pub economy: f32,
    pub standard: f32,
    pub premium: f32,
}

impl EmbeddingScores {
    pub fn winner(&self) -> ModelTier {
        if self.economy >= self.standard && self.economy >= self.premium {
            ModelTier::Economy
        } else if self.standard >= self.premium {
            ModelTier::Standard
        } else {
            ModelTier::Premium
        }
    }

    pub fn confidence(&self) -> f32 {
        let mut scores = [self.economy, self.standard, self.premium];
        scores.sort_by(|a, b| b.partial_cmp(a).unwrap());
        scores[0] - scores[1]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmRequest {
    pub system_prompt: String,
    pub messages: Vec<LlmMessage>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub force_model: Option<String>,
    pub requires_vision: bool,
    pub requires_tools: bool,
    pub embedding_scores: Option<EmbeddingScores>,
}

impl LlmRequest {
    pub fn simple(system: &str, user_msg: &str) -> Self {
        Self {
            system_prompt: system.into(),
            messages: vec![LlmMessage { role: "user".into(), content: user_msg.into() }],
            max_tokens: None,
            temperature: None,
            force_model: None,
            requires_vision: false,
            requires_tools: false,
            embedding_scores: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub model_used: String,
    pub provider: Provider,
    pub tier: ModelTier,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cost_microdollars: u64,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RawLlmResponse {
    pub content: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn complete(
        &self,
        model: &ModelConfig,
        api_key: &str,
        request: &LlmRequest,
    ) -> anyhow::Result<RawLlmResponse>;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Usage Stats
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Default)]
pub struct UsageStats {
    pub total_requests: AtomicU64,
    pub total_input_tokens: AtomicU64,
    pub total_output_tokens: AtomicU64,
    pub total_cost_microdollars: AtomicU64,
}

impl UsageStats {
    pub fn record(&self, input_tokens: u32, output_tokens: u32, cost_microdollars: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_input_tokens.fetch_add(input_tokens as u64, Ordering::Relaxed);
        self.total_output_tokens.fetch_add(output_tokens as u64, Ordering::Relaxed);
        self.total_cost_microdollars.fetch_add(cost_microdollars, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> UsageSnapshot {
        UsageSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_input_tokens: self.total_input_tokens.load(Ordering::Relaxed),
            total_output_tokens: self.total_output_tokens.load(Ordering::Relaxed),
            total_cost_microdollars: self.total_cost_microdollars.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageSnapshot {
    pub total_requests: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_microdollars: u64,
}

impl UsageSnapshot {
    pub fn cost_usd(&self) -> f64 {
        self.total_cost_microdollars as f64 / 1_000_000.0
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Model Health
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug)]
pub struct ModelHealth {
    pub success_count: AtomicU64,
    pub error_count: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub circuit_open: std::sync::atomic::AtomicBool,
}

impl Default for ModelHealth {
    fn default() -> Self {
        Self {
            success_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            circuit_open: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl ModelHealth {
    pub fn record_success(&self, latency_ms: u64) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        let errors = self.error_count.fetch_add(1, Ordering::Relaxed) + 1;
        let total = self.success_count.load(Ordering::Relaxed) + errors;
        if total >= 5 && errors * 2 > total {
            self.circuit_open.store(true, Ordering::Relaxed);
            warn!("🔴 Circuit breaker opened");
        }
    }

    pub fn is_healthy(&self) -> bool {
        !self.circuit_open.load(Ordering::Relaxed)
    }

    pub fn avg_latency_ms(&self) -> u64 {
        let s = self.success_count.load(Ordering::Relaxed);
        if s == 0 { return 0; }
        self.total_latency_ms.load(Ordering::Relaxed) / s
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Retry Config
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub fallback_tier: Option<ModelTier>,
    pub retry_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self { max_retries: 2, fallback_tier: None, retry_delay_ms: 1000 }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  LLM Router
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct LlmRouter {
    models: RwLock<Vec<ModelConfig>>,
    mode: RwLock<RoutingMode>,
    default_model_id: RwLock<Option<String>>,
    stats: UsageStats,
    health: dashmap::DashMap<String, ModelHealth>,
    retry_config: RwLock<RetryConfig>,
}

impl LlmRouter {
    pub fn new(models: Vec<ModelConfig>, mode: RoutingMode) -> Self {
        let health = dashmap::DashMap::new();
        for m in &models {
            health.insert(m.id.clone(), ModelHealth::default());
        }
        Self {
            models: RwLock::new(models),
            mode: RwLock::new(mode),
            default_model_id: RwLock::new(None),
            stats: UsageStats::default(),
            health,
            retry_config: RwLock::new(RetryConfig::default()),
        }
    }

    /// Select model with full feature extraction
    pub fn select_model(&self, request: &LlmRequest) -> Option<ModelConfig> {
        let models = self.models.read().unwrap();
        let mode = *self.mode.read().unwrap();

        if let Some(forced_id) = &request.force_model {
            return models.iter().find(|m| &m.id == forced_id).cloned();
        }

        let target_tier = match mode {
            RoutingMode::Economy => ModelTier::Economy,
            RoutingMode::Performance => ModelTier::Premium,
            RoutingMode::Balanced => {
                let features = extract_features(request);
                let complexity = features_to_complexity(&features);
                if let Some(ref emb) = request.embedding_scores {
                    let emb_tier = emb.winner();
                    let conf = emb.confidence();
                    debug!(
                        "Embedding: {:?} conf={:.4} | Rule: {:?}",
                        emb_tier, conf, complexity
                    );
                    // Dinamik threshold: max skor yüksekse (>0.5) daha düşük conf yeterli
                    let max_score = emb.economy.max(emb.standard).max(emb.premium);
                    let dynamic_threshold = if max_score > 0.55 { 0.005 } else { 0.015 };
                    if conf > dynamic_threshold {
                        return models
                            .iter()
                            .filter(|m| m.tier == emb_tier)
                            .filter(|m| !request.requires_vision || m.supports_vision)
                            .filter(|m| self.health.get(&m.id).map(|h| h.is_healthy()).unwrap_or(true))
                            .min_by_key(|m| m.cost_per_1k_input_microdollars)
                            .cloned();
                    }
                }
                debug!(
                    "Route: {:?} | task={:?} | score={} | words={} | code={} | math={} | constraints={}",
                    complexity, features.task_type, features.complexity_score,
                    features.word_count, features.has_code, features.has_math,
                    features.constraint_count
                );
                match complexity {
                    TaskComplexity::Simple => ModelTier::Economy,
                    TaskComplexity::Medium => ModelTier::Standard,
                    TaskComplexity::Complex => ModelTier::Premium,
                }
            }
            RoutingMode::Manual => {
                let default_id = self.default_model_id.read().unwrap();
                return default_id
                    .as_ref()
                    .and_then(|id| models.iter().find(|m| &m.id == id))
                    .cloned();
            }
        };

        models
            .iter()
            .filter(|m| m.tier == target_tier)
            .filter(|m| !request.requires_vision || m.supports_vision)
            .filter(|m| !request.requires_tools || m.supports_tools)
            .filter(|m| self.health.get(&m.id).map(|h| h.is_healthy()).unwrap_or(true))
            .min_by_key(|m| m.cost_per_1k_input_microdollars)
            .cloned()
            .or_else(|| {
                warn!("No healthy model for {:?}, fallback", target_tier);
                models
                    .iter()
                    .filter(|m| !request.requires_vision || m.supports_vision)
                    .filter(|m| !request.requires_tools || m.supports_tools)
                    .filter(|m| self.health.get(&m.id).map(|h| h.is_healthy()).unwrap_or(true))
                    .min_by_key(|m| m.cost_per_1k_input_microdollars)
                    .cloned()
            })
    }

    /// Ceiling division cost calculation
    pub fn calculate_cost(model: &ModelConfig, input_tokens: u32, output_tokens: u32) -> u64 {
        let input_cost = (input_tokens as u64 * model.cost_per_1k_input_microdollars + 999) / 1000;
        let output_cost = (output_tokens as u64 * model.cost_per_1k_output_microdollars + 999) / 1000;
        input_cost + output_cost
    }

    pub fn record_usage(&self, input_tokens: u32, output_tokens: u32, cost_microdollars: u64) {
        self.stats.record(input_tokens, output_tokens, cost_microdollars);
    }

    pub fn record_model_success(&self, model_id: &str, latency_ms: u64) {
        if let Some(h) = self.health.get(model_id) { h.record_success(latency_ms); }
    }

    pub fn record_model_error(&self, model_id: &str) {
        if let Some(h) = self.health.get(model_id) { h.record_error(); }
    }

    pub fn usage_snapshot(&self) -> UsageSnapshot { self.stats.snapshot() }

    pub fn set_mode(&self, mode: RoutingMode) {
        *self.mode.write().unwrap() = mode;
        info!("🔄 Routing mode: {:?}", mode);
    }

    pub fn set_default_model(&self, model_id: String) {
        *self.default_model_id.write().unwrap() = Some(model_id);
    }

    pub fn add_model(&self, model: ModelConfig) {
        self.health.insert(model.id.clone(), ModelHealth::default());
        self.models.write().unwrap().push(model);
    }

    pub fn retry_config(&self) -> RetryConfig {
        self.retry_config.read().unwrap().clone()
    }

    pub fn set_retry_config(&self, config: RetryConfig) {
        *self.retry_config.write().unwrap() = config;
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Embedding Router — Centroids & Cosine Similarity
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const CENTROIDS_JSON: &str = include_str!("../centroids.json");

#[derive(Debug, Clone, Deserialize)]
struct Centroids {
    economy: Vec<f32>,
    standard: Vec<f32>,
    premium: Vec<f32>,
}

pub fn load_centroids() -> Option<(Vec<f32>, Vec<f32>, Vec<f32>)> {
    let c: Centroids = serde_json::from_str(CENTROIDS_JSON).ok()?;
    Some((c.economy, c.standard, c.premium))
}

pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

pub fn embedding_to_scores(embedding: &[f32], centroids: &(Vec<f32>, Vec<f32>, Vec<f32>)) -> EmbeddingScores {
    EmbeddingScores {
        economy: cosine_similarity(embedding, &centroids.0),
        standard: cosine_similarity(embedding, &centroids.1),
        premium: cosine_similarity(embedding, &centroids.2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_models() -> Vec<ModelConfig> {
        vec![
            ModelConfig {
                id: "haiku".into(), provider: Provider::Anthropic,
                model_name: "claude-haiku-4-5-20251001".into(),
                api_key_ref: "key".into(), api_base_url: None,
                tier: ModelTier::Economy,
                cost_per_1k_input_microdollars: 800,
                cost_per_1k_output_microdollars: 3200,
                max_context_tokens: 200_000,
                supports_vision: true, supports_tools: true,
            },
            ModelConfig {
                id: "sonnet".into(), provider: Provider::Anthropic,
                model_name: "claude-sonnet-4-5-20250929".into(),
                api_key_ref: "key".into(), api_base_url: None,
                tier: ModelTier::Standard,
                cost_per_1k_input_microdollars: 3000,
                cost_per_1k_output_microdollars: 15000,
                max_context_tokens: 200_000,
                supports_vision: true, supports_tools: true,
            },
            ModelConfig {
                id: "opus".into(), provider: Provider::Anthropic,
                model_name: "claude-opus-4-6".into(),
                api_key_ref: "key".into(), api_base_url: None,
                tier: ModelTier::Premium,
                cost_per_1k_input_microdollars: 15000,
                cost_per_1k_output_microdollars: 75000,
                max_context_tokens: 200_000,
                supports_vision: true, supports_tools: true,
            },
            ModelConfig {
                id: "deepseek".into(), provider: Provider::DeepSeek,
                model_name: "deepseek-chat".into(),
                api_key_ref: "key".into(),
                api_base_url: Some("https://api.deepseek.com".into()),
                tier: ModelTier::Economy,
                cost_per_1k_input_microdollars: 140,
                cost_per_1k_output_microdollars: 280,
                max_context_tokens: 64_000,
                supports_vision: false, supports_tools: false,
            },
        ]
    }

    fn req(msg: &str) -> LlmRequest { LlmRequest::simple("You are helpful.", msg) }

    // ─── Short-circuit tests ────────────────────────────

    #[test]
    fn test_selam_goes_to_haiku() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req("Selam")).unwrap();
        assert_eq!(model.tier, ModelTier::Economy, "Short greeting should go to Haiku");
    }

    #[test]
    fn test_hi_goes_to_haiku() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req("Hi")).unwrap();
        assert_eq!(model.tier, ModelTier::Economy);
    }

    #[test]
    fn test_ok_goes_to_haiku() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req("ok teşekkürler")).unwrap();
        assert_eq!(model.tier, ModelTier::Economy);
    }

    // ─── Task type tests ────────────────────────────────

    #[test]
    fn test_simple_question_haiku() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req("Türkiye'nin başkenti neresi?")).unwrap();
        assert_eq!(model.tier, ModelTier::Economy);
    }

    #[test]
    fn test_code_gen_sonnet() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req("Write a function to sort a linked list")).unwrap();
        assert_eq!(model.tier, ModelTier::Standard);
    }

    #[test]
    fn test_analysis_opus() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req(
            "Analyze the architectural tradeoffs between microservices and monolith, \
             then compare their scalability characteristics with concrete examples"
        )).unwrap();
        assert_eq!(model.tier, ModelTier::Premium);
    }

    #[test]
    fn test_deep_reasoning_opus() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req(
            "Prove that the halting problem is undecidable using a diagonalization argument"
        )).unwrap();
        assert_eq!(model.tier, ModelTier::Premium);
    }

    #[test]
    fn test_summarize_sonnet() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let model = router.select_model(&req("Şu makaleyi özetle")).unwrap();
        assert_eq!(model.tier, ModelTier::Standard);
    }

    // ─── Task classification tests ──────────────────────

    #[test]
    fn test_classify_conversation() {
        assert_eq!(classify_task("selam", "Selam"), TaskType::Conversation);
        assert_eq!(classify_task("merhaba nasılsın", "Merhaba nasılsın"), TaskType::Conversation);
    }

    #[test]
    fn test_classify_code() {
        assert_eq!(
            classify_task("write a function to sort", "Write a function to sort\n```python\ndef sort_list(lst):\n```"),
            TaskType::CodeGeneration
        );
        // "write a function" without code markers → ContentCreation (correct behavior)
        assert_eq!(
            classify_task("write a function to sort", "Write a function to sort"),
            TaskType::ContentCreation
        );
    }

    #[test]
    fn test_classify_analysis() {
        assert_eq!(
            classify_task("analyze the performance", "Analyze the performance"),
            TaskType::MultiStepAnalysis
        );
    }

    // ─── Feature extraction tests ───────────────────────

    #[test]
    fn test_feature_extraction() {
        let features = extract_features(&req("Selam"));
        assert_eq!(features.word_count, 1);
        assert!(!features.has_code);
        assert!(!features.has_math);
        assert_eq!(features.task_type, TaskType::Conversation);
    }

    #[test]
    fn test_code_detection() {
        assert!(detect_code("```rust\nfn main() {}\n```"));
        assert!(detect_code("def hello():"));
        assert!(!detect_code("Hello world"));
    }

    #[test]
    fn test_math_detection() {
        assert!(detect_math("Find the integral of x²"));
        assert!(detect_math("∫ x dx"));
        assert!(!detect_math("Hello world"));
    }

    #[test]
    fn test_constraint_counting() {
        assert_eq!(count_constraints("Do this"), 0);
        assert!(count_constraints("1. First 2. Then 3. Finally") >= 3);
        assert!(count_constraints("You must ensure that it should also handle") >= 2);
    }

    // ─── Existing tests ─────────────────────────────────

    #[test]
    fn test_economy_mode_always_cheap() {
        let router = LlmRouter::new(test_models(), RoutingMode::Economy);
        let model = router.select_model(&req("Analyze quantum computing deeply")).unwrap();
        assert_eq!(model.tier, ModelTier::Economy);
    }

    #[test]
    fn test_performance_mode_always_best() {
        let router = LlmRouter::new(test_models(), RoutingMode::Performance);
        let model = router.select_model(&req("Hi")).unwrap();
        assert_eq!(model.tier, ModelTier::Premium);
    }

    #[test]
    fn test_force_model() {
        let router = LlmRouter::new(test_models(), RoutingMode::Economy);
        let mut r = req("Hi");
        r.force_model = Some("opus".into());
        assert_eq!(router.select_model(&r).unwrap().id, "opus");
    }

    #[test]
    fn test_cost_ceiling_division() {
        let model = &test_models()[0];
        let cost = LlmRouter::calculate_cost(model, 1, 1);
        assert!(cost > 0);
    }

    #[test]
    fn test_usage_tracking() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        router.record_usage(1000, 500, 2400);
        router.record_usage(2000, 1000, 4800);
        let snap = router.usage_snapshot();
        assert_eq!(snap.total_requests, 2);
        assert_eq!(snap.total_cost_microdollars, 7200);
    }

    #[test]
    fn test_vision_filter() {
        let router = LlmRouter::new(test_models(), RoutingMode::Economy);
        let mut r = req("Describe image");
        r.requires_vision = true;
        assert!(router.select_model(&r).unwrap().supports_vision);
    }

    #[test]
    fn test_circuit_breaker() {
        let router = LlmRouter::new(test_models(), RoutingMode::Economy);
        for _ in 0..5 { router.record_model_error("haiku"); }
        let model = router.select_model(&req("Hi")).unwrap();
        assert_ne!(model.id, "haiku");
    }

    #[test]
    fn test_concurrent_usage() {
        use std::sync::Arc;
        let router = Arc::new(LlmRouter::new(test_models(), RoutingMode::Balanced));
        let mut handles = vec![];
        for _ in 0..10 {
            let r = router.clone();
            handles.push(std::thread::spawn(move || {
                let _ = r.select_model(&req("Hi"));
                r.record_usage(100, 50, 240);
            }));
        }
        for h in handles { h.join().unwrap(); }
        assert_eq!(router.usage_snapshot().total_requests, 10);
    }

    // ─── Conversation depth shouldn't override short messages ───

    #[test]
    fn test_selam_stays_haiku_with_history() {
        let router = LlmRouter::new(test_models(), RoutingMode::Balanced);
        let request = LlmRequest {
            system_prompt: "You are helpful.".into(),
            messages: vec![
                LlmMessage { role: "user".into(), content: "Merhaba".into() },
                LlmMessage { role: "assistant".into(), content: "Merhaba!".into() },
                LlmMessage { role: "user".into(), content: "Nasılsın".into() },
                LlmMessage { role: "assistant".into(), content: "İyiyim!".into() },
                LlmMessage { role: "user".into(), content: "Selam".into() },
            ],
            max_tokens: None,
            temperature: None,
            force_model: None,
            requires_vision: false,
            requires_tools: false,
            embedding_scores: None,
        };
        let model = router.select_model(&request).unwrap();
        assert_eq!(model.tier, ModelTier::Economy, "Short message should stay Haiku regardless of history");
    }
}
