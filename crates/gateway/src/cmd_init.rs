use anyhow::Result;
use safeagent_credential_vault::{CredentialVault, SensitiveString};
use std::io::{self, BufRead, Write};
use std::path::Path;

/// Run the interactive init wizard.
/// Creates vault, validates API keys, optionally configures Telegram, generates config file.
pub async fn run_init(data_dir: &Path) -> Result<()> {
    println!();
    println!("  🛡️  SafeAgent Init Wizard");
    println!("  ─────────────────────────");
    println!();

    // Step 1: Vault password
    std::fs::create_dir_all(data_dir)?;
    let vault_path = data_dir.join("vault.db");
    let is_new_vault = !vault_path.exists();

    let vault = CredentialVault::new(vault_path)?;

    if is_new_vault {
        println!("  Step 1/4: Create vault password");
        println!("  This password encrypts all your API keys locally.");
        println!("  If you forget it, delete vault.db and re-run init.");
        println!();
        let pwd = prompt_secret("  🔐 Create vault password: ")?;
        if pwd.expose().len() < 4 {
            anyhow::bail!("SA-E001: Vault password too short (minimum 4 characters).\n  Fix: Run `safeagent init` again with a longer password.");
        }
        vault.unlock(&pwd)?;
        println!("  ✅ Vault created and unlocked.");
    } else {
        println!("  Step 1/4: Unlock existing vault");
        let pwd = prompt_secret("  🔐 Vault password: ")?;
        vault.unlock(&pwd).map_err(|_| {
            anyhow::anyhow!("SA-E002: Wrong vault password.\n  Fix: Try again, or delete vault.db to reset (you'll lose stored keys).")
        })?;
        println!("  ✅ Vault unlocked.");
    }
    println!();

    // Step 2: Anthropic API key
    println!("  Step 2/4: Anthropic API Key");
    let api_key = match vault.get("anthropic_key") {
        Ok(existing) => {
            println!("  ✅ Anthropic key already stored.");
            print!("  Replace it? [y/N]: ");
            io::stdout().flush()?;
            let mut answer = String::new();
            io::stdin().lock().read_line(&mut answer)?;
            if answer.trim().to_lowercase() == "y" {
                let key = prompt_and_store_key(&vault, "anthropic_key", "Anthropic API Key", "anthropic", "sk-ant-...")?;
                key
            } else {
                existing
            }
        }
        Err(_) => {
            prompt_and_store_key(&vault, "anthropic_key", "Anthropic API Key", "anthropic", "sk-ant-...")?
        }
    };

    // Validate Anthropic key
    print!("  Validating API key... ");
    io::stdout().flush()?;
    match validate_anthropic_key(&api_key).await {
        Ok(()) => println!("✅ Valid (Anthropic API accessible)"),
        Err(e) => {
            println!("❌ Failed");
            println!("  SA-E003: API key validation failed: {}", e);
            println!("  Fix: Check your key at https://console.anthropic.com/settings/keys");
            println!("  Continuing anyway — you can fix this later.");
        }
    }
    println!();

    // Step 3: Platform setup
    println!("  Step 3/4: Platform Setup");
    println!("  SafeAgent supports: CLI (always on), Telegram (optional)");
    println!();

    let setup_telegram = prompt_yes_no("  Configure Telegram bot? [y/N]: ")?;
    if setup_telegram {
        configure_telegram(&vault).await?;
    } else {
        println!("  ℹ️  Telegram skipped. CLI mode only.");
    }
    println!();

    // Step 4: Voyage AI (optional)
    println!("  Step 4/4: Voyage AI Key (optional)");
    println!("  Enables embedding-based smart routing for better cost savings.");
    println!("  Without it, SafeAgent uses rule-based routing (still works fine).");
    println!();

    match vault.get("voyage_api_key") {
        Ok(_) => {
            println!("  ✅ Voyage AI key already stored.");
        }
        Err(_) => {
            let setup_voyage = prompt_yes_no("  Add Voyage AI key? [y/N]: ")?;
            if setup_voyage {
                prompt_and_store_key(&vault, "voyage_api_key", "Voyage AI Key", "voyage", "pa-...")?;
                println!("  ✅ Voyage AI key stored. Smart routing enabled.");
            } else {
                println!("  ℹ️  Skipped. Rule-based routing will be used.");
            }
        }
    }

    // Generate example config
    let config_path = data_dir.join("safeagent.toml");
    if !config_path.exists() {
        generate_default_config(&config_path)?;
        println!();
        println!("  📄 Config written to: {}", config_path.display());
    }

    vault.lock();

    // Summary
    println!();
    println!("  ─────────────────────────");
    println!("  ✅ SafeAgent is ready!");
    println!();
    println!("  Start with:");
    println!("    safeagent run");
    println!();
    println!("  Check setup:");
    println!("    safeagent doctor");
    println!();

    Ok(())
}

async fn validate_anthropic_key(key: &SensitiveString) -> Result<()> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key.expose())
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 400 {
        // 400 = bad request but key is valid; 200 = success
        Ok(())
    } else if resp.status().as_u16() == 401 {
        anyhow::bail!("Invalid API key (401 Unauthorized)")
    } else if matches!(resp.status().as_u16(), 429 | 529 | 503) {
        // Rate limited / overloaded / unavailable — but key is valid
        Ok(())
    } else {
        let status = resp.status();
        let data: serde_json::Value = resp.json().await.unwrap_or_default();
        let msg = data["error"]["message"].as_str().unwrap_or("Unknown error");
        anyhow::bail!("API returned {}: {}", status, msg)
    }
}

async fn configure_telegram(vault: &CredentialVault) -> Result<()> {
    println!("  Get a token from @BotFather on Telegram: https://t.me/BotFather");
    println!();

    let token = prompt_and_store_key(vault, "telegram_token", "Telegram Bot Token", "telegram", "123456:ABC...")?;

    // Validate token
    print!("  Validating Telegram token... ");
    io::stdout().flush()?;
    let client = reqwest::Client::new();
    let url = format!("https://api.telegram.org/bot{}/getMe", token.expose());
    match client.get(&url).send().await {
        Ok(resp) => {
            let data: serde_json::Value = resp.json().await.unwrap_or_default();
            if data["ok"].as_bool() == Some(true) {
                let bot_name = data["result"]["first_name"].as_str().unwrap_or("unknown");
                let bot_username = data["result"]["username"].as_str().unwrap_or("unknown");
                println!("✅ Connected as @{} ({})", bot_username, bot_name);
            } else {
                println!("❌ Invalid token");
                println!("  SA-E004: Telegram token validation failed.");
                println!("  Fix: Get a new token from @BotFather.");
            }
        }
        Err(e) => {
            println!("❌ Network error: {}", e);
            println!("  SA-E005: Could not reach Telegram API.");
            println!("  Fix: Check your internet connection.");
        }
    }

    // Chat ID
    println!();
    println!("  To find your chat ID:");
    println!("  1. Send any message to your bot on Telegram");
    println!("  2. Open: https://api.telegram.org/bot<TOKEN>/getUpdates");
    println!("  3. Look for \"chat\":{{\"id\":XXXXXXX}}");
    println!();

    let chat_id = prompt_and_store_key(vault, "telegram_chat_id", "Telegram Chat ID", "telegram", "123456789")?;
    let _ = chat_id; // stored in vault

    Ok(())
}

fn generate_default_config(path: &Path) -> Result<()> {
    let config = r#"# SafeAgent Configuration
# Generated by `safeagent init`

[router]
# Routing mode: "balanced" (default), "economy", "performance"
mode = "balanced"

# Confidence preset for embedding router: "conservative", "balanced", "aggressive"
# Or set manual threshold: confidence_threshold = 0.012
confidence_preset = "balanced"

[cache]
# Enable prompt caching (recommended)
enabled = true

[policy]
# Daily spending limit in USD (0 = no limit)
daily_limit_usd = 10.0

# Monthly spending limit in USD (0 = no limit)
monthly_limit_usd = 100.0

[logging]
# Log level: "error", "warn", "info", "debug", "trace"
level = "info"

# Terminal color theme: "dark", "light", "soft"
theme = "dark"
"#;

    std::fs::write(path, config)?;
    Ok(())
}

fn prompt_secret(prompt: &str) -> Result<SensitiveString> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    Ok(SensitiveString::new(input.trim().to_string()))
}

fn prompt_and_store_key(
    vault: &CredentialVault,
    key: &str,
    label: &str,
    provider: &str,
    hint: &str,
) -> Result<SensitiveString> {
    print!("  Enter {} ({}): ", label, hint);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() {
        anyhow::bail!("SA-E006: {} cannot be empty.\n  Fix: Run `safeagent init` again.", label);
    }
    let val = SensitiveString::new(input.to_string());
    vault.store(key, label, provider, &val)?;
    println!("  ✅ {} stored in vault.", label);
    Ok(val)
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input)?;
    Ok(input.trim().to_lowercase() == "y")
}
