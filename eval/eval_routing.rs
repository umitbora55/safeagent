//! Routing Evaluation Harness
//! Runs offline against a labeled dataset to measure routing accuracy.
//! Usage: cargo run --bin eval_routing -- --dataset eval/anchor_dataset.jsonl

use safeagent_llm_router::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct EvalPrompt {
    prompt: String,
    expected_tier: String, // "economy", "standard", "premium"
    task_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvalResult {
    total: usize,
    correct: usize,
    quality_miss: usize,
    cost_miss: usize,
    accuracy_pct: f64,
    overspend_rate_pct: f64,
    quality_miss_rate_pct: f64,
    per_tier: TierBreakdown,
}

#[derive(Debug, Serialize)]
struct TierBreakdown {
    economy_total: usize,
    economy_correct: usize,
    standard_total: usize,
    standard_correct: usize,
    premium_total: usize,
    premium_correct: usize,
}

fn tier_rank(tier: &str) -> u8 {
    match tier {
        "economy" => 0,
        "standard" => 1,
        "premium" => 2,
        _ => 1,
    }
}

fn model_tier_str(tier: ModelTier) -> &'static str {
    match tier {
        ModelTier::Economy => "economy",
        ModelTier::Standard => "standard",
        ModelTier::Premium => "premium",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dataset_path = if args.len() > 2 && args[1] == "--dataset" {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from("eval/anchor_dataset.jsonl")
    };

    if !dataset_path.exists() {
        eprintln!("Dataset not found: {}", dataset_path.display());
        eprintln!("Create eval/anchor_dataset.jsonl with labeled prompts.");
        eprintln!("Format: {{\"prompt\": \"...\", \"expected_tier\": \"economy|standard|premium\"}}");
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&dataset_path).expect("Failed to read dataset");
    let prompts: Vec<EvalPrompt> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .filter_map(|(i, line)| {
            serde_json::from_str(line)
                .map_err(|e| eprintln!("  Warning: line {} parse error: {}", i + 1, e))
                .ok()
        })
        .collect();

    if prompts.is_empty() {
        eprintln!("No valid prompts found in dataset.");
        std::process::exit(1);
    }

    let models = vec![
        ModelConfig {
            id: "haiku".into(), provider: Provider::Anthropic,
            model_name: "claude-haiku-4-5-20251001".into(),
            api_key_ref: "anthropic_key".into(), api_base_url: None,
            tier: ModelTier::Economy, cost_per_1k_input_microdollars: 800,
            cost_per_1k_output_microdollars: 3200, max_context_tokens: 200_000,
            supports_vision: true, supports_tools: true,
        },
        ModelConfig {
            id: "sonnet".into(), provider: Provider::Anthropic,
            model_name: "claude-sonnet-4-5-20250929".into(),
            api_key_ref: "anthropic_key".into(), api_base_url: None,
            tier: ModelTier::Standard, cost_per_1k_input_microdollars: 3000,
            cost_per_1k_output_microdollars: 15000, max_context_tokens: 200_000,
            supports_vision: true, supports_tools: true,
        },
        ModelConfig {
            id: "opus".into(), provider: Provider::Anthropic,
            model_name: "claude-opus-4-6".into(),
            api_key_ref: "anthropic_key".into(), api_base_url: None,
            tier: ModelTier::Premium, cost_per_1k_input_microdollars: 15000,
            cost_per_1k_output_microdollars: 75000, max_context_tokens: 200_000,
            supports_vision: true, supports_tools: true,
        },
    ];

    let router = LlmRouter::new(models.clone(), RoutingMode::Balanced);

    let mut total = 0usize;
    let mut correct = 0usize;
    let mut quality_miss = 0usize;
    let mut cost_miss = 0usize;

    let mut eco_total = 0usize; let mut eco_correct = 0usize;
    let mut std_total = 0usize; let mut std_correct = 0usize;
    let mut pre_total = 0usize; let mut pre_correct = 0usize;

    println!();
    println!("  ╭──────────────────────────────────────────╮");
    println!("  │  SafeAgent Routing Evaluation Harness     │");
    println!("  ╰──────────────────────────────────────────╯");
    println!();
    println!("  Dataset: {} ({} prompts)", dataset_path.display(), prompts.len());
    println!();

    for (i, p) in prompts.iter().enumerate() {
        let request = LlmRequest {
            system_prompt: String::new(),
            messages: vec![LlmMessage { role: "user".into(), content: p.prompt.clone() }],
            max_tokens: Some(4096),
            temperature: Some(0.7),
            force_model: None,
            requires_vision: false,
            requires_tools: false,
            embedding_scores: None,
        };

        let selected = router.select_model(&request);
        let selected_tier = selected.as_ref()
            .map(|m| model_tier_str(m.tier))
            .unwrap_or("none");

        let expected_rank = tier_rank(&p.expected_tier);
        let selected_rank = tier_rank(selected_tier);

        total += 1;
        match p.expected_tier.as_str() {
            "economy" => eco_total += 1,
            "standard" => std_total += 1,
            "premium" => pre_total += 1,
            _ => {}
        }

        if selected_tier == p.expected_tier {
            correct += 1;
            match p.expected_tier.as_str() {
                "economy" => eco_correct += 1,
                "standard" => std_correct += 1,
                "premium" => pre_correct += 1,
                _ => {}
            }
        } else if selected_rank > expected_rank {
            cost_miss += 1; // over-provisioned (safe miss)
        } else {
            quality_miss += 1; // under-provisioned (failure)
            println!("  ❌ #{}: expected={} got={} | {:40}",
                i + 1, p.expected_tier, selected_tier,
                if p.prompt.len() > 40 { &p.prompt[..40] } else { &p.prompt });
        }
    }

    let accuracy = if total > 0 {
        (correct as f64 / (correct + quality_miss) as f64) * 100.0
    } else { 0.0 };

    let overspend_rate = if total > 0 {
        (cost_miss as f64 / total as f64) * 100.0
    } else { 0.0 };

    let quality_miss_rate = if total > 0 {
        (quality_miss as f64 / total as f64) * 100.0
    } else { 0.0 };

    println!();
    println!("  ─────────────────────────────────────────────");
    println!("  Routing Evaluation Report — SafeAgent v{}", env!("CARGO_PKG_VERSION"));
    println!("  ─────────────────────────────────────────────");
    println!("  Accuracy:        {:.1}% (target: >85%)", accuracy);
    println!("  Over-spend rate: {:.1}% (router chose higher tier than needed)", overspend_rate);
    println!("  Quality miss:    {:.1}% (router chose lower tier than needed)", quality_miss_rate);
    println!();
    println!("  Per-tier breakdown:");
    println!("    Economy:  {}/{} correct", eco_correct, eco_total);
    println!("    Standard: {}/{} correct", std_correct, std_total);
    println!("    Premium:  {}/{} correct", pre_correct, pre_total);
    println!();
    println!("  Total: {} prompts | ✅ {} correct | ⚠️ {} over-spend | ❌ {} quality miss",
        total, correct, cost_miss, quality_miss);
    println!();

    // Write JSON report
    let result = EvalResult {
        total, correct, quality_miss, cost_miss,
        accuracy_pct: accuracy,
        overspend_rate_pct: overspend_rate,
        quality_miss_rate_pct: quality_miss_rate,
        per_tier: TierBreakdown {
            economy_total: eco_total, economy_correct: eco_correct,
            standard_total: std_total, standard_correct: std_correct,
            premium_total: pre_total, premium_correct: pre_correct,
        },
    };

    let report_path = PathBuf::from("eval/eval_report.json");
    if let Ok(json) = serde_json::to_string_pretty(&result) {
        let _ = std::fs::write(&report_path, &json);
        println!("  Report saved: {}", report_path.display());
    }
}
