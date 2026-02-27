use clap::Parser;
use safeagent_diff_canary::{parse_seed, DiffCheckConfig, run_diff_canary_check};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "diff-canary")]
#[command(about = "Differential testing + canary leak detection for model/provider responses.")]
struct Cli {
    #[arg(long, default_value = "0xC0FFEE")]
    seed: String,

    #[arg(long, default_value_t = 100)]
    runs: usize,

    #[arg(long, default_value = "logs/diff_canary_results_v2.jsonl")]
    out: PathBuf,

    #[arg(long, default_value = "mock")]
    mode: DiffModeCli,

    #[arg(long, default_value_t = 0)]
    max_divergence: usize,

    #[arg(long, default_value_t = 0)]
    max_leaks: usize,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DiffModeCli {
    #[value(name = "mock")]
    Mock,
    #[value(name = "live")]
    Live,
}

impl From<DiffModeCli> for safeagent_diff_canary::DiffMode {
    fn from(value: DiffModeCli) -> Self {
        match value {
            DiffModeCli::Mock => safeagent_diff_canary::DiffMode::Mock,
            DiffModeCli::Live => safeagent_diff_canary::DiffMode::Live,
        }
    }
}

fn main() {
    if let Err(err) = execute(Cli::parse()) {
        eprintln!("diff-canary failed: {err}");
        std::process::exit(1);
    }
}

fn execute(cli: Cli) -> Result<(), String> {
    let seed = parse_seed(&cli.seed)?;
    let config = DiffCheckConfig {
        seed,
        runs: cli.runs,
        mode: cli.mode.into(),
        out_path: cli.out,
        max_divergence: cli.max_divergence,
        max_leaks: cli.max_leaks,
    };

    let result = run_diff_canary_check(&config)?;
    println!("total_runs={}", result.runs);
    println!("findings={}", result.findings.len());
    println!("leak_count={}", result.total_leaks);
    println!("divergence_count={}", result.total_divergences);
    Ok(())
}
