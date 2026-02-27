use clap::Parser;
use safeagent_context_poison_sim::{run_context_poison_harness, parse_seed, PoisonMode, PoisonRunConfig};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "context-poison-sim")]
#[command(about = "Deterministic context poisoning simulator for lab adversarial checks.")]
struct Cli {
    #[arg(long, default_value = "0xC0FFEE")]
    seed: String,

    #[arg(long, default_value_t = 200)]
    runs: usize,

    #[arg(long, default_value = "hybrid")]
    mode: PoisonModeCli,

    #[arg(long, default_value = "logs/context_poison_findings_v2.jsonl")]
    out: PathBuf,

    #[arg(long, default_value_t = 0)]
    max_findings: usize,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum PoisonModeCli {
    #[value(name = "tool_output")]
    ToolOutput,
    #[value(name = "memory")]
    Memory,
    #[value(name = "hybrid")]
    Hybrid,
}

impl From<PoisonModeCli> for PoisonMode {
    fn from(value: PoisonModeCli) -> Self {
        match value {
            PoisonModeCli::ToolOutput => PoisonMode::ToolOutput,
            PoisonModeCli::Memory => PoisonMode::Memory,
            PoisonModeCli::Hybrid => PoisonMode::Hybrid,
        }
    }
}

fn main() {
    if let Err(err) = execute(Cli::parse()) {
        eprintln!("context-poison-sim failed: {err}");
        std::process::exit(1);
    }
}

fn execute(cli: Cli) -> Result<(), String> {
    let seed = parse_seed(&cli.seed)?;
    let config = PoisonRunConfig {
        seed,
        runs: cli.runs,
        mode: cli.mode.into(),
        out_path: cli.out,
        max_findings: cli.max_findings,
    };

    let result = run_context_poison_harness(&config)?;
    println!("total_runs={}", result.runs);
    println!("findings={}", result.findings.len());
    Ok(())
}
