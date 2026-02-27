use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use flate2::read::GzDecoder;
use reqwest::blocking::{multipart::Form, multipart::Part, Client};
use reqwest::StatusCode;
use safeagent_skill_registry::{
    package_contains_required_files, scan_skill, verify_skill, ScanResult,
};
use serde::Deserialize;
use std::io::Read;
use tar::Archive;
use tempfile::tempdir;

#[derive(Debug, Clone, ValueEnum)]
enum Channel {
    Stable,
    Canary,
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stable => "stable",
            Self::Canary => "canary",
        })
    }
}

#[derive(Debug, Parser)]
#[command(name = "skill", about = "SafeAgent skill package registry tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Pack(Pack),
    Sign(Sign),
    Verify(Verify),
    Scan(Scan),
    PublisherAdd(PublisherAdd),
    Publish(Publish),
    Pull(Pull),
    List(List),
}

#[derive(Debug, Args)]
struct Pack {
    input: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct Sign {
    package: PathBuf,
    #[arg(long)]
    key: PathBuf,
}

#[derive(Debug, Args)]
struct Verify {
    package: PathBuf,
    #[arg(long)]
    publishers: PathBuf,
}

#[derive(Debug, Args)]
struct Scan {
    package: PathBuf,
}

#[derive(Debug, Args)]
struct PublisherAdd {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    publisher_id: String,
    #[arg(long)]
    key_id: String,
    #[arg(long)]
    public_key: String,
}

#[derive(Debug, Args)]
struct Publish {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long)]
    pkg: PathBuf,
    #[arg(long, default_value_t = Channel::Stable)]
    channel: Channel,
    #[arg(long)]
    publishers: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    skip_local_checks: bool,
}

#[derive(Debug, Args)]
struct Pull {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long)]
    id: String,
    #[arg(long)]
    version: Option<String>,
    #[arg(long, default_value_t = Channel::Stable)]
    channel: Channel,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = "registry/publishers/verified.json")]
    publishers: PathBuf,
}

#[derive(Debug, Args)]
struct List {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
}

#[derive(Debug, Deserialize)]
struct VersionDescriptor {
    version: String,
    channel: String,
}

fn main() {
    let args = Cli::parse();
    if let Err(err) = run(args) {
        eprintln!("skill failed: {err}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Pack(cmd) => {
            safeagent_skill_registry::pack_skill(&cmd.input, &cmd.out)
                .map_err(|e| e.to_string())?;
            println!("pack ok: {}", cmd.out.display());
        }
        Command::Sign(cmd) => {
            safeagent_skill_registry::sign_skill(&cmd.package, &cmd.key)
                .map_err(|e| e.to_string())?;
            println!("sign ok");
        }
        Command::Verify(cmd) => {
            let result = safeagent_skill_registry::verify_skill(&cmd.package, &cmd.publishers)
                .map_err(|e| e.to_string())?;
            if result.passed {
                println!(
                    "verify ok: publisher={} signing_key={}",
                    result.publisher_id, result.signing_key_id
                );
            }
        }
        Command::Scan(cmd) => match safeagent_skill_registry::scan_skill(&cmd.package) {
            Ok(ScanResult { passed: true, .. }) => {
                println!("scan ok");
            }
            Ok(_) => return Err("scan failed".to_string()),
            Err(safeagent_skill_registry::RegistryError::Scan(reasons)) => {
                for reason in reasons {
                    eprintln!("scan deny: {reason}");
                }
                return Err("scan denied".to_string());
            }
            Err(err) => return Err(err.to_string()),
        },
        Command::PublisherAdd(cmd) => {
            safeagent_skill_registry::add_verified_publisher(
                &cmd.store,
                cmd.publisher_id,
                cmd.key_id,
                cmd.public_key,
            )
            .map_err(|e| e.to_string())?;
            println!("publisher add ok");
        }
        Command::Publish(cmd) => publish(cmd)?,
        Command::Pull(cmd) => pull(cmd)?,
        Command::List(cmd) => list(cmd)?,
    }
    Ok(())
}

fn list(cmd: List) -> Result<(), String> {
    let response = client()
        .get(format!("{}/skills", trim_url(&cmd.server)))
        .send()
        .map_err(|err| format!("request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("list failed: {}", response.status()));
    }
    let skills: Vec<String> = response
        .json()
        .map_err(|err| format!("failed parse list response: {err}"))?;
    for skill in skills {
        println!("{skill}");
    }
    Ok(())
}

fn publish(cmd: Publish) -> Result<(), String> {
    if !package_contains_required_files(&cmd.pkg) {
        return Err("package is incomplete: missing required files".to_string());
    }

    if !cmd.skip_local_checks {
        let publisher_file = cmd
            .publishers
            .unwrap_or_else(|| PathBuf::from("registry/publishers/verified.json"));
        safeagent_skill_registry::verify_skill(&cmd.pkg, &publisher_file)
            .map_err(|e| format!("local verify failed: {e}"))?;
        safeagent_skill_registry::scan_skill(&cmd.pkg)
            .map_err(|e| format!("local scan failed: {e}"))?;
    }

    let form = Form::new()
        .part(
            "manifest",
            make_part_file(cmd.pkg.join(safeagent_skill_registry::MANIFEST_FILE))?,
        )
        .part(
            "payload",
            make_part_file(cmd.pkg.join(safeagent_skill_registry::PAYLOAD_TAR_FILE))?,
        )
        .part(
            "signature",
            make_part_file(cmd.pkg.join(safeagent_skill_registry::SIGNATURE_FILE))?,
        )
        .part(
            "checksums",
            make_part_file(cmd.pkg.join(safeagent_skill_registry::CHECKSUM_FILE))?,
        )
        .text("channel", cmd.channel.to_string());

    let response = client()
        .post(format!("{}/publish", trim_url(&cmd.server)))
        .multipart(form)
        .send()
        .map_err(|err| format!("request failed: {err}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "publish failed: {} {}",
            response.status(),
            response
                .text()
                .unwrap_or_else(|_| "missing response body".to_string())
        ));
    }
    println!("publish ok");
    Ok(())
}

fn pull(cmd: Pull) -> Result<(), String> {
    let manifest_version = if let Some(version) = cmd.version {
        version
    } else {
        let versions = client()
            .get(format!(
                "{}/skills/{}/versions",
                trim_url(&cmd.server),
                cmd.id
            ))
            .send()
            .map_err(|err| format!("request failed: {err}"))?;
        if !versions.status().is_success() {
            return Err(format!("version query failed: {}", versions.status()));
        }

        let mut items: Vec<VersionDescriptor> = versions
            .json()
            .map_err(|err| format!("invalid versions response: {err}"))?;
        let channel = cmd.channel.to_string();
        items.retain(|item| item.channel == channel);
        items.sort_by(|a, b| a.version.cmp(&b.version));
        items
            .pop()
            .map(|item| item.version)
            .ok_or_else(|| format!("no matching version for channel: {channel}"))?
    };

    let response = client()
        .get(format!(
            "{}/skills/{}/{}/download",
            trim_url(&cmd.server),
            cmd.id,
            manifest_version
        ))
        .send()
        .map_err(|err| format!("download request failed: {err}"))?;
    if response.status() != StatusCode::OK {
        return Err(format!("pull failed: {}", response.status()));
    }

    let bytes = response
        .bytes()
        .map_err(|err| format!("download body read failed: {err}"))?;
    std::fs::write(&cmd.out, &bytes).map_err(|err| format!("write failed: {err}"))?;

    let temp = tempdir().map_err(|err| format!("tempdir create failed: {err}"))?;
    let pkg_dir = temp.path().join("pkg");
    extract_package(&cmd.out, &pkg_dir).map_err(|err| format!("extract failed: {err}"))?;
    scan_skill(&pkg_dir).map_err(|err| format!("scan failed: {err}"))?;
    let result =
        verify_skill(&pkg_dir, &cmd.publishers).map_err(|err| format!("verify failed: {err}"))?;
    if !result.passed {
        return Err("pulled package did not pass verify".to_string());
    }

    println!(
        "pull ok: {} {} {} (install-ready)",
        cmd.id,
        manifest_version,
        cmd.out.display()
    );
    Ok(())
}

fn extract_package(archive: &Path, out_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).map_err(|err| format!("create dir: {err}"))?;
    let archive = std::fs::File::open(archive).map_err(|err| format!("open archive: {err}"))?;
    let decoder = GzDecoder::new(archive);
    let mut archive = Archive::new(decoder);
    archive.unpack(out_dir).map_err(|err| err.to_string())?;

    let mut manifest = std::fs::File::open(out_dir.join(safeagent_skill_registry::MANIFEST_FILE))
        .map_err(|err| format!("manifest missing: {err}"))?;
    let mut payload = std::fs::File::open(out_dir.join(safeagent_skill_registry::PAYLOAD_TAR_FILE))
        .map_err(|err| format!("payload missing: {err}"))?;
    let mut signature = std::fs::File::open(out_dir.join(safeagent_skill_registry::SIGNATURE_FILE))
        .map_err(|err| format!("signature missing: {err}"))?;
    let mut checksums = std::fs::File::open(out_dir.join(safeagent_skill_registry::CHECKSUM_FILE))
        .map_err(|err| format!("checksums missing: {err}"))?;

    let mut buf = Vec::new();
    manifest
        .read_to_end(&mut buf)
        .map_err(|err| err.to_string())?;
    payload
        .read_to_end(&mut buf)
        .map_err(|err| err.to_string())?;
    signature
        .read_to_end(&mut buf)
        .map_err(|err| err.to_string())?;
    checksums
        .read_to_end(&mut buf)
        .map_err(|err| err.to_string())?;
    if buf.is_empty() {
        return Err("invalid package archive".to_string());
    }
    Ok(())
}

fn make_part_file(path: PathBuf) -> Result<Part, String> {
    Part::file(path).map_err(|err| err.to_string())
}

fn client() -> Client {
    Client::new()
}

fn trim_url(server: &str) -> String {
    server.trim_end_matches('/').to_string()
}
