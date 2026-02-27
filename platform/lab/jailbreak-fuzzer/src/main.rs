use clap::Parser;
use safeagent_jailbreak_fuzzer::{run_adversarial_harness, parse_seed, FuzzRunConfig};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "jailbreak-fuzzer")]
#[command(about = "Deterministic adversarial fuzz harness for prompt/chain safety checks.")]
struct Cli {
    #[arg(long, default_value = "0xC0FFEE")]
    seed: String,

    #[arg(long, default_value_t = 500)]
    runs: usize,

    #[arg(long)]
    corpus: Option<PathBuf>,

    #[arg(long, default_value = "logs/adversarial_findings_v2.jsonl")]
    out: PathBuf,

    #[arg(long, default_value_t = 0)]
    max_findings: usize,
}

fn main() {
    if let Err(err) = execute(Cli::parse()) {
        eprintln!("jailbreak-fuzzer failed: {err}");
        std::process::exit(1);
    }
}

fn execute(cli: Cli) -> Result<(), String> {
    let seed = parse_seed(&cli.seed)?;
    let config = FuzzRunConfig {
        seed,
        runs: cli.runs,
        corpus_path: cli.corpus,
        out_path: cli.out,
        max_findings: cli.max_findings,
    };

    let result = run_adversarial_harness(&config)?;
    println!("total_runs={}", result.runs);
    println!("findings={}", result.findings.len());
    Ok(())
}
