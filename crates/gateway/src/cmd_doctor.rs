use anyhow::Result;
use safeagent_credential_vault::{CredentialVault, SensitiveString};
use std::io::{self, BufRead, Write};
use std::path::Path;

/// Run diagnostics to check SafeAgent setup.
pub async fn run_doctor(data_dir: &Path) -> Result<()> {
    println!();
    println!("  🩺 SafeAgent Doctor");
    println!("  ─────────────────────");
    println!();

    let mut passed = 0u32;
    let mut warned = 0u32;
    let mut failed = 0u32;

    // Check 1: Data directory
    print!("  [1/7] Data directory... ");
    io::stdout().flush()?;
    if data_dir.exists() {
        println!("✅ {}", data_dir.display());
        passed += 1;
    } else {
        println!("❌ Not found: {}", data_dir.display());
        println!("        Fix: Run `safeagent init`");
        failed += 1;
    }

    // Check 2: Vault exists
    let vault_path = data_dir.join("vault.db");
    print!("  [2/7] Vault database... ");
    io::stdout().flush()?;
    if vault_path.exists() {
        let size = std::fs::metadata(&vault_path).map(|m| m.len()).unwrap_or(0);
        println!("✅ {} ({} bytes)", vault_path.display(), size);
        passed += 1;
    } else {
        println!("❌ Not found");
        println!("        Fix: Run `safeagent init`");
        failed += 1;
    }

    // Check 3: Vault unlockable + credentials
    print!("  [3/7] Vault credentials... ");
    io::stdout().flush()?;
    if vault_path.exists() {
        match CredentialVault::new(vault_path.clone()) {
            Ok(vault) => {
                print!("\n  🔐 Vault password: ");
                io::stdout().flush()?;
                let mut pwd = String::new();
                io::stdin().lock().read_line(&mut pwd)?;
                let pwd = SensitiveString::new(pwd.trim().to_string());

                match vault.unlock(&pwd) {
                    Ok(()) => {
                        let creds = vault.list().unwrap_or_default();
                        let keys: Vec<&str> = creds.iter().map(|c| c.key.as_str()).collect();
                        println!("        ✅ Vault unlocked ({} credentials stored)", creds.len());

                        // Check each expected key
                        let expected = [
                            ("anthropic_key", true, "Required for LLM calls"),
                            ("telegram_token", false, "Required for Telegram bridge"),
                            ("telegram_chat_id", false, "Required for Telegram bridge"),
                            ("voyage_api_key", false, "Enables smart embedding routing"),
                        ];
                        for (key, required, desc) in &expected {
                            let found = keys.contains(key);
                            if found {
                                println!("        ✅ {} — found", key);
                            } else if *required {
                                println!("        ❌ {} — MISSING ({})", key, desc);
                                println!("           Fix: Run `safeagent init`");
                                failed += 1;
                            } else {
                                println!("        ⚠️  {} — not set ({})", key, desc);
                                warned += 1;
                            }
                        }
                        passed += 1;
                        vault.lock();
                    }
                    Err(_) => {
                        println!("        ❌ Wrong password");
                        println!("        Fix: Try again or delete vault.db and run `safeagent init`");
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                println!("❌ Cannot open vault: {}", e);
                failed += 1;
            }
        }
    } else {
        println!("⏭️  Skipped (no vault)");
    }

    // Check 4: Memory database
    let memory_path = data_dir.join("memory.db");
    print!("  [4/7] Memory database... ");
    io::stdout().flush()?;
    if memory_path.exists() {
        let size = std::fs::metadata(&memory_path).map(|m| m.len()).unwrap_or(0);
        println!("✅ {} ({} bytes)", memory_path.display(), size);
        passed += 1;
    } else {
        println!("⚠️  Not found (will be created on first run)");
        warned += 1;
    }

    // Check 5: Config file
    let config_path = data_dir.join("safeagent.toml");
    print!("  [5/7] Config file... ");
    io::stdout().flush()?;
    if config_path.exists() {
        println!("✅ {}", config_path.display());
        passed += 1;
    } else {
        println!("⚠️  Not found (using defaults)");
        println!("        Fix: Run `safeagent init` to generate one");
        warned += 1;
    }

    // Check 6: Network (Anthropic API)
    print!("  [6/7] Anthropic API reachable... ");
    io::stdout().flush()?;
    match check_network("https://api.anthropic.com").await {
        Ok(ms) => {
            println!("✅ ({}ms)", ms);
            passed += 1;
        }
        Err(e) => {
            println!("❌ {}", e);
            println!("        Fix: Check internet, DNS, firewall, proxy settings");
            failed += 1;
        }
    }

    // Check 7: Network (Telegram API)
    print!("  [7/7] Telegram API reachable... ");
    io::stdout().flush()?;
    match check_network("https://api.telegram.org").await {
        Ok(ms) => {
            println!("✅ ({}ms)", ms);
            passed += 1;
        }
        Err(e) => {
            println!("⚠️  {} (Telegram won't work)", e);
            warned += 1;
        }
    }

    // File permissions check
    println!();
    print!("  Checking file permissions... ");
    io::stdout().flush()?;
    let mut perm_issues = Vec::new();
    for (path, name) in &[(vault_path, "vault.db"), (memory_path, "memory.db")] {
        if path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)
                    .map(|m| m.permissions().mode() & 0o777)
                    .unwrap_or(0);
                if mode & 0o077 != 0 {
                    perm_issues.push(format!("{} is world/group readable (mode {:o})", name, mode));
                }
            }
        }
    }
    if perm_issues.is_empty() {
        println!("✅");
    } else {
        println!("⚠️");
        for issue in &perm_issues {
            println!("        {}", issue);
            warned += 1;
        }
        println!("        Fix: chmod 600 vault.db memory.db");
    }

    // Summary
    println!();
    println!("  ─────────────────────────");
    println!(
        "  Results: {} passed, {} warnings, {} failed",
        passed, warned, failed
    );

    if failed == 0 && warned == 0 {
        println!("  ✅ Everything looks good! Run `safeagent run` to start.");
    } else if failed == 0 {
        println!("  ⚠️  Working but some optional features missing.");
    } else {
        println!("  ❌ Some checks failed. Fix the issues above and re-run `safeagent doctor`.");
    }
    println!();

    Ok(())
}

async fn check_network(url: &str) -> Result<u64> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let start = std::time::Instant::now();
    let resp = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            anyhow::anyhow!("Timeout (>10s)")
        } else if e.is_connect() {
            anyhow::anyhow!("Connection refused — check DNS/firewall")
        } else {
            anyhow::anyhow!("{}", e)
        }
    })?;
    let ms = start.elapsed().as_millis() as u64;

    // Any response (even 404) means network works
    let _ = resp;
    Ok(ms)
}
