//! Audit Log Hash-Chain Verifier
//!
//! Reads audit log entries and verifies the cryptographic hash chain.
//!
//! Usage:
//!   audit_verify <audit.jsonl>
//!   audit_verify --sqlite <audit.db>
//!
//! Exit codes:
//!   0 - PASS: All entries valid
//!   1 - FAIL: Chain integrity violation detected
//!   2 - ERROR: Could not read/parse file

use safeagent_audit_log::hashchain::{verify_chain, ChainedAuditEntry};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: audit_verify <audit.jsonl>");
        eprintln!("       audit_verify --sqlite <audit.db>");
        return ExitCode::from(2);
    }

    let result = if args.len() >= 3 && args[1] == "--sqlite" {
        verify_sqlite(&args[2])
    } else {
        verify_jsonl(&args[1])
    };

    match result {
        Ok(verification) => {
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║           AUDIT LOG HASH-CHAIN VERIFICATION                  ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
            println!();
            println!("Chain ID:       {}", verification.chain_id);
            println!("Total entries:  {}", verification.total_entries);
            println!("Valid entries:  {}", verification.valid_entries);
            println!();

            if verification.passed {
                println!("┌──────────────────────────────────────────────────────────────┐");
                println!("│                      ✓ PASS                                  │");
                println!("│         All entries verified successfully.                   │");
                println!("└──────────────────────────────────────────────────────────────┘");
                ExitCode::from(0)
            } else {
                println!("┌──────────────────────────────────────────────────────────────┐");
                println!("│                      ✗ FAIL                                  │");
                println!("│         Hash chain integrity violation detected!             │");
                println!("└──────────────────────────────────────────────────────────────┘");
                println!();
                println!(
                    "First invalid entry at seq: {}",
                    verification.first_invalid_seq.unwrap_or(0)
                );
                println!();
                println!("Errors:");
                for err in &verification.errors {
                    println!(
                        "  - seq {}: {}",
                        err.seq,
                        err.error.as_deref().unwrap_or("unknown")
                    );
                }
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            ExitCode::from(2)
        }
    }
}

fn verify_jsonl(path: &str) -> Result<safeagent_audit_log::hashchain::ChainVerification, String> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }

    let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let reader = BufReader::new(file);

    let mut entries: Vec<ChainedAuditEntry> = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("Failed to read line {}: {}", line_num + 1, e))?;

        if line.trim().is_empty() {
            continue;
        }

        let entry: ChainedAuditEntry = serde_json::from_str(&line)
            .map_err(|e| format!("Failed to parse line {}: {}", line_num + 1, e))?;

        entries.push(entry);
    }

    if entries.is_empty() {
        return Ok(safeagent_audit_log::hashchain::ChainVerification {
            chain_id: String::new(),
            total_entries: 0,
            valid_entries: 0,
            first_invalid_seq: None,
            errors: vec![],
            passed: true,
        });
    }

    // Sort by sequence number
    entries.sort_by_key(|e| e.seq);

    Ok(verify_chain(&entries))
}

fn verify_sqlite(_path: &str) -> Result<safeagent_audit_log::hashchain::ChainVerification, String> {
    // SQLite verification would read from the chained_audit_entries table
    // For now, return an error indicating this is not yet implemented
    Err("SQLite verification not yet implemented. Export to JSONL first.".to_string())
}
