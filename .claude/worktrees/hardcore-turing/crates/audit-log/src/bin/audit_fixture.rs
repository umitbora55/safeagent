//! Deterministic audit log fixture generator for verification.
//!
//! Usage:
//!   audit_fixture <output.jsonl>

use safeagent_audit_log::hashchain::HashChainState;
use safeagent_audit_log::AuditEntry;
use std::env;
use std::fs::{create_dir_all, File};
use std::io::{BufWriter, Write};
use std::path::Path;

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let output = args
        .get(1)
        .ok_or_else(|| "Usage: audit_fixture <output.jsonl>".to_string())?;

    let output_path = Path::new(output);
    if let Some(parent) = output_path.parent() {
        create_dir_all(parent).map_err(|e| format!("Failed to create dir: {}", e))?;
    }

    let mut chain = HashChainState::with_id("fixture-chain-0001");
    let entries = vec![
        fixture_entry("fixture_event_1", "2024-01-01T00:00:00Z"),
        fixture_entry("fixture_event_2", "2024-01-01T00:00:01Z"),
        fixture_entry("fixture_event_3", "2024-01-01T00:00:02Z"),
    ];

    let file = File::create(output_path).map_err(|e| format!("Failed to open file: {}", e))?;
    let mut writer = BufWriter::new(file);

    for entry in entries {
        let chained = chain.prepare_entry(&entry);
        let line = serde_json::to_string(&chained)
            .map_err(|e| format!("Failed to serialize entry: {}", e))?;
        writeln!(writer, "{}", line).map_err(|e| format!("Failed to write: {}", e))?;
    }

    Ok(())
}

fn fixture_entry(event_type: &str, timestamp: &str) -> AuditEntry {
    let ts = chrono::DateTime::parse_from_rfc3339(timestamp)
        .expect("fixture timestamp must be RFC3339")
        .with_timezone(&chrono::Utc);

    AuditEntry {
        timestamp: ts,
        event_type: event_type.to_string(),
        model_name: "fixture-model".to_string(),
        tier: "fixture-tier".to_string(),
        platform: "fixture-platform".to_string(),
        input_tokens: 100,
        output_tokens: 50,
        cost_microdollars: 250,
        cache_status: "miss".to_string(),
        latency_ms: 42,
        success: true,
        error_message: None,
        metadata: "{}".to_string(),
    }
}
