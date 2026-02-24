use anyhow::Result;
use safeagent_audit_log::AuditLog;
use std::path::Path;

pub fn run_audit(data_dir: &Path) -> Result<()> {
    let audit_path = data_dir.join("audit.db");
    if !audit_path.exists() {
        println!();
        println!("  📋 No audit data yet.");
        println!("  Run `safeagent run` and send some messages first.");
        println!();
        return Ok(());
    }

    let audit = AuditLog::new(audit_path, 30, 200).map_err(|e| anyhow::anyhow!("{}", e))?;

    let count = audit.entry_count().map_err(|e| anyhow::anyhow!("{}", e))?;
    let entries = audit
        .recent_entries(25)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!();
    println!(
        "  📋 SafeAgent Audit Log ({} total entries, showing last {})",
        count,
        entries.len()
    );
    println!("  ─────────────────────────────────────────────────────────────────────");
    println!();

    if entries.is_empty() {
        println!("  No entries.");
        println!();
        return Ok(());
    }

    for e in &entries {
        let status = if e.success { "✅" } else { "❌" };
        let cost_str = if e.cost_microdollars > 0 {
            format!("${:.4}", e.cost_microdollars as f64 / 1_000_000.0)
        } else {
            "—".to_string()
        };
        let time = e.timestamp.format("%m-%d %H:%M:%S");

        println!(
            "  {} [{}] {} | {} | {} | {}in/{}out | {} | {}ms",
            status,
            time,
            e.event_type,
            e.model_name,
            e.platform,
            e.input_tokens,
            e.output_tokens,
            cost_str,
            e.latency_ms
        );

        if let Some(ref err) = e.error_message {
            println!("     └─ {}", err);
        }
    }

    // Prune old entries
    let pruned = audit.prune().map_err(|e| anyhow::anyhow!("{}", e))?;
    if pruned > 0 {
        println!();
        println!("  🧹 Pruned {} old entries", pruned);
    }

    println!();
    Ok(())
}
