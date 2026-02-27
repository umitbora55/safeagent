use std::path::PathBuf;

use clap::Parser;

use safeagent_skill_registry_server::RunConfig;

#[derive(Debug, Parser)]
#[command(
    name = "skill-registry-server",
    about = "SafeAgent skill registry server"
)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,
    #[arg(long, default_value = "registry_store")]
    storage: PathBuf,
    #[arg(long, default_value = "registry/publishers/verified.json")]
    publishers: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let config = RunConfig {
        bind: args
            .bind
            .parse()
            .expect("bind address must be in host:port format"),
        storage_root: args.storage,
        verified_publishers: args.publishers,
    };

    if let Err(err) = safeagent_skill_registry_server::run_server(config).await {
        eprintln!("skill registry server failed: {}", err);
        std::process::exit(1);
    }
}
