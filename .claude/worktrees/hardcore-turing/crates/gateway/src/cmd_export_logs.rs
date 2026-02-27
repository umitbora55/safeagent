use anyhow::Result;
use safeagent_audit_log::AuditLog;
use safeagent_cost_ledger::CostLedger;
use std::path::Path;

pub fn run_export_logs(data_dir: &Path) -> Result<()> {
    let audit_path = data_dir.join("audit.db");
    let ledger_path = data_dir.join("cost_ledger.db");

    if !audit_path.exists() && !ledger_path.exists() {
        println!();
        println!("  📦 No log data to export.");
        println!("  Run `safeagent run` first to generate data.");
        println!();
        return Ok(());
    }

    let output_path = data_dir.join("export_anonymized.jsonl");
    let mut lines: Vec<String> = Vec::new();

    if audit_path.exists() {
        let audit = AuditLog::new(audit_path, 30, 200).map_err(|e| anyhow::anyhow!("{}", e))?;
        let entries = audit
            .recent_entries(10000)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        for e in &entries {
            let line = serde_json::json!({
                "source": "audit",
                "timestamp": e.timestamp.to_rfc3339(),
                "event_type": e.event_type,
                "model_name": e.model_name,
                "tier": e.tier,
                "platform": e.platform,
                "input_tokens": e.input_tokens,
                "output_tokens": e.output_tokens,
                "cost_microdollars": e.cost_microdollars,
                "cache_status": e.cache_status,
                "latency_ms": e.latency_ms,
                "success": e.success,
                "safeagent_version": env!("CARGO_PKG_VERSION"),
                "os_family": std::env::consts::OS,
            });
            lines.push(serde_json::to_string(&line)?);
        }
    }

    if ledger_path.exists() {
        let ledger = CostLedger::new(ledger_path).map_err(|e| anyhow::anyhow!("{}", e))?;

        if let Ok(summary) = ledger.total_summary() {
            let line = serde_json::json!({
                "source": "cost_summary",
                "total_requests": summary.total_requests,
                "total_input_tokens": summary.total_input_tokens,
                "total_output_tokens": summary.total_output_tokens,
                "total_cost_microdollars": summary.total_cost_microdollars,
                "total_cache_read_tokens": summary.total_cache_read_tokens,
                "total_cache_write_tokens": summary.total_cache_write_tokens,
                "safeagent_version": env!("CARGO_PKG_VERSION"),
                "os_family": std::env::consts::OS,
            });
            lines.push(serde_json::to_string(&line)?);
        }
    }

    let output_text = lines.join("\n");
    let secret_patterns = ["sk-ant-", "pa-", "GOCSPX-"];
    for pattern in &secret_patterns {
        if output_text.contains(pattern) {
            anyhow::bail!(
                "⚠️ Export aborted: potential secret detected (pattern: '{}'). Please report this bug.",
                pattern
            );
        }
    }

    std::fs::write(&output_path, output_text)?;

    println!();
    println!("  📦 Anonymized logs exported: {}", output_path.display());
    println!("  {} entries written (JSONL format)", lines.len());
    println!();
    println!("  Included: timestamp, event_type, model, tier, tokens, cost, latency");
    println!("  Excluded: API keys, messages, user identity, file paths");
    println!();
    println!("  SafeAgent never uploads automatically. Share manually if desired.");
    println!();

    Ok(())
}
