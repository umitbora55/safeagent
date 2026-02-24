use anyhow::Result;
use safeagent_cost_ledger::CostLedger;
use std::path::Path;

pub fn run_stats(data_dir: &Path) -> Result<()> {
    let ledger_path = data_dir.join("cost_ledger.db");
    if !ledger_path.exists() {
        println!();
        println!("  📊 No cost data yet.");
        println!("  Run `safeagent run` and send some messages first.");
        println!();
        return Ok(());
    }

    let ledger = CostLedger::new(ledger_path).map_err(|e| anyhow::anyhow!("{}", e))?;

    let today = ledger
        .today_summary()
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let week = ledger
        .week_summary()
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let month = ledger
        .month_summary()
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let total = ledger
        .total_summary()
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!();
    println!("  📊 SafeAgent Cost Report");
    println!("  ─────────────────────────────────────────────");
    println!();
    println!("  Period        Requests    Cost         Tokens (in/out)");
    println!("  ──────────    ────────    ──────────   ───────────────");
    print_row("Today", &today);
    print_row("This week", &week);
    print_row("This month", &month);
    print_row("All time", &total);
    println!();

    if total.total_input_tokens > 0 {
        let cache_rate = if total.total_cache_read_tokens > 0 {
            total.total_cache_read_tokens as f64
                / (total.total_input_tokens + total.total_cache_read_tokens) as f64
                * 100.0
        } else {
            0.0
        };
        println!(
            "  Cache read tokens: {}  ({:.1}% of total input)",
            total.total_cache_read_tokens, cache_rate
        );
        println!("  Cache write tokens: {}", total.total_cache_write_tokens);
        println!();
    }

    let breakdown = ledger
        .model_breakdown_since("1970-01-01T00:00:00")
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if !breakdown.is_empty() {
        println!("  Model Breakdown (all time)");
        println!("  ──────────────────────────────────────────");
        println!("  Model                       Reqs    Cost");
        println!("  ─────────────────────────   ─────   ──────────");
        for m in &breakdown {
            println!(
                "  {:<27} {:>5}   ${:.4}",
                m.model_name,
                m.request_count,
                m.cost_usd()
            );
        }
        println!();
    }

    let daily = ledger
        .daily_costs(7)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    if !daily.is_empty() {
        println!("  Last 7 Days");
        println!("  ──────────────────────────────────────────");
        for d in &daily {
            let bar_len = (d.cost_usd() * 200.0).min(30.0) as usize;
            let bar = "█".repeat(bar_len.max(1));
            println!(
                "  {}  {:>4} reqs  ${:<8.4}  {}",
                d.date,
                d.request_count,
                d.cost_usd(),
                bar
            );
        }
        println!();
    }

    Ok(())
}

fn print_row(label: &str, s: &safeagent_cost_ledger::CostSummary) {
    println!(
        "  {:<12}    {:>6}      ${:<8.4}   {}/{}",
        label,
        s.total_requests,
        s.cost_usd(),
        s.total_input_tokens,
        s.total_output_tokens
    );
}
