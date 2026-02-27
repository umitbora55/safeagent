//! SafeAgent Desktop — Tauri 2.0 backend
//! Embeds the full security stack (vault, memory, ledger, audit, guard, policy)
//! and exposes IPC commands to the frontend SPA.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use chrono::Utc;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tauri::{Emitter, Manager, State};
use uuid::Uuid;

// ── SafeAgent internal crates ─────────────────────────────────────────────────
use safeagent_audit_log::{AuditEntry, AuditLog};
use safeagent_bridge_common::{ChatId, MessageId, Platform, UserId};
use safeagent_cost_ledger::CostLedger;
use safeagent_credential_vault::{CredentialVault, SensitiveString};
use safeagent_memory::{MemoryStore, MessageEntry, Role};
use safeagent_policy_engine::{PolicyConfig, PolicyEngine};
use safeagent_prompt_guard::{ContentSource, PromptGuard};

// ── Data models ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub role: String, // "user" | "assistant" | "system"
    pub content: String,
    pub timestamp: String,
    pub model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    pub total_requests: u64,
    pub total_cost_usd: f64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub cache_tokens: u64,
    pub session_cost_usd: f64,
    pub model_breakdown: Vec<ModelStat>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModelStat {
    pub model: String,
    pub requests: u64,
    pub cost_usd: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntryDto {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub model: String,
    pub platform: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    pub latency_ms: u64,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigDto {
    pub router_mode: String,        // "economy" | "balanced" | "performance"
    pub daily_limit_usd: f64,
    pub monthly_limit_usd: f64,
    pub telegram_enabled: bool,
    pub autostart: bool,
    pub skills: SkillsConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SkillsConfig {
    pub web_search: bool,
    pub file_reader: bool,
    pub file_writer: bool,
    pub shell_executor: bool,
    pub email_sender: bool,
    pub calendar_writer: bool,
}

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            web_search: true,
            file_reader: true,
            file_writer: false,
            shell_executor: false,
            email_sender: false,
            calendar_writer: false,
        }
    }
}

impl Default for ConfigDto {
    fn default() -> Self {
        Self {
            router_mode: "balanced".to_string(),
            daily_limit_usd: 5.0,
            monthly_limit_usd: 50.0,
            telegram_enabled: false,
            autostart: false,
            skills: SkillsConfig::default(),
        }
    }
}

// ── Application state ─────────────────────────────────────────────────────────

pub struct AppState {
    pub data_dir: PathBuf,
    pub vault: Arc<CredentialVault>,
    pub memory: Arc<MemoryStore>,
    pub ledger: Arc<CostLedger>,
    pub audit: Arc<AuditLog>,
    pub guard: Arc<PromptGuard>,
    pub policy: Arc<PolicyEngine>,
    pub vault_unlocked: AtomicBool,
    pub conversation: Mutex<Vec<ChatMessage>>,
    pub api_key: Mutex<Option<String>>,
    pub config: Mutex<ConfigDto>,
    pub http: reqwest::Client,
    pub session_cost_microdollars: std::sync::atomic::AtomicU64,
}

// SAFETY: All fields are Send + Sync
unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

// ── Helper: data directory ────────────────────────────────────────────────────

fn get_data_dir() -> PathBuf {
    if let Some(proj) = ProjectDirs::from("com", "safeagent", "SafeAgent") {
        proj.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".safeagent")
    }
}

// ── IPC Commands ──────────────────────────────────────────────────────────────

/// Check whether this is the first time the app has been opened.
/// Returns true if vault is not set up or API key not configured.
#[tauri::command]
async fn is_first_run(state: State<'_, AppState>) -> Result<bool, String> {
    let vault_db = state.data_dir.join("vault.db");
    if !vault_db.exists() {
        return Ok(true);
    }
    Ok(!state.vault_unlocked.load(Ordering::SeqCst))
}

/// Check if vault is currently unlocked.
#[tauri::command]
async fn is_vault_unlocked(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.vault_unlocked.load(Ordering::SeqCst))
}

/// Attempt to unlock the vault with the given password.
/// Returns true on success, false on wrong password.
#[tauri::command]
async fn unlock_vault(password: String, state: State<'_, AppState>) -> Result<bool, String> {
    match state.vault.unlock(&SensitiveString::new(password)) {
        Ok(_) => {
            state.vault_unlocked.store(true, Ordering::SeqCst);
            // Load API key if already stored
            if let Ok(sensitive) = state.vault.get("anthropic_key") {
                let key = sensitive.expose().to_string();
                *state.api_key.lock().unwrap() = Some(key);
            }
            // Load saved config
            if let Ok(raw) = state.vault.get("app_config") {
                let raw_str = raw.expose().to_string();
                if let Ok(cfg) = serde_json::from_str::<ConfigDto>(&raw_str) {
                    *state.config.lock().unwrap() = cfg;
                }
            }
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Save the Anthropic API key into the vault.
#[tauri::command]
async fn save_api_key(key: String, state: State<'_, AppState>) -> Result<(), String> {
    if !state.vault_unlocked.load(Ordering::SeqCst) {
        return Err("Vault not unlocked".to_string());
    }
    state
        .vault
        .store(
            "anthropic_key",
            "Anthropic API Key",
            "anthropic",
            &SensitiveString::new(key.clone()),
        )
        .map_err(|e| e.to_string())?;
    *state.api_key.lock().unwrap() = Some(key);
    Ok(())
}

/// Validate that an Anthropic API key is well-formed (sk-ant-...).
#[tauri::command]
async fn validate_api_key(key: String) -> Result<bool, String> {
    Ok(key.starts_with("sk-ant-") && key.len() > 20)
}

/// Check whether an API key has been saved.
#[tauri::command]
async fn has_api_key(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.api_key.lock().unwrap().is_some())
}

/// Send a chat message to the LLM and return the assistant's response.
#[tauri::command]
async fn send_message(
    text: String,
    state: State<'_, AppState>,
    window: tauri::WebviewWindow,
) -> Result<ChatMessage, String> {
    if !state.vault_unlocked.load(Ordering::SeqCst) {
        return Err("Vault not unlocked".to_string());
    }

    let api_key = state
        .api_key
        .lock()
        .unwrap()
        .clone()
        .ok_or("API key not configured. Please complete onboarding.")?;

    // Prompt injection check
    let guard_result = state.guard.sanitize(&text, ContentSource::User);
    if guard_result.risk_score >= 0.5 {
        return Err(format!(
            "Message blocked by safety filter (risk score: {:.2}). Possible prompt injection detected.",
            guard_result.risk_score
        ));
    }
    // Use the sanitised text for the actual request
    let text = guard_result.clean_text;

    // Add user message to in-memory conversation
    let user_msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        role: "user".to_string(),
        content: text.clone(),
        timestamp: Utc::now().to_rfc3339(),
        model: None,
        input_tokens: None,
        output_tokens: None,
        cost_usd: None,
    };
    {
        let mut conv = state.conversation.lock().unwrap();
        conv.push(user_msg.clone());
    }

    // Save to persistent memory
    if let Err(e) = state.memory.add_message(&MessageEntry {
        id: MessageId(Uuid::new_v4().to_string()),
        chat_id: ChatId("desktop-default".to_string()),
        sender_id: UserId("local-user".to_string()),
        role: Role::User,
        content: text.clone(),
        platform: Platform::Cli,
        timestamp: Utc::now(),
        token_count: None,
    }) {
        tracing::warn!("Memory write failed: {}", e);
    }

    // Build messages array for API call
    let messages: Vec<serde_json::Value> = {
        let conv = state.conversation.lock().unwrap();
        conv.iter()
            .filter(|m| m.role == "user" || m.role == "assistant")
            .map(|m| {
                serde_json::json!({
                    "role": m.role,
                    "content": m.content
                })
            })
            .collect()
    };

    // Choose model based on config
    let model = choose_model(&state.config.lock().unwrap().router_mode, &text);

    // Call Anthropic Messages API
    let body = serde_json::json!({
        "model": model,
        "max_tokens": 4096,
        "system": "You are SafeAgent, a secure and helpful AI assistant. You help users safely and transparently. Always be honest about your capabilities and limitations.",
        "messages": messages
    });

    let resp = state
        .http
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_body = resp.text().await.unwrap_or_default();
        return Err(format!("API error {}: {}", status, err_body));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Response parse error: {}", e))?;

    let content = data["content"][0]["text"]
        .as_str()
        .unwrap_or("(empty response)")
        .to_string();

    let input_tokens = data["usage"]["input_tokens"].as_u64().unwrap_or(0);
    let output_tokens = data["usage"]["output_tokens"].as_u64().unwrap_or(0);
    let actual_model = data["model"]
        .as_str()
        .unwrap_or(&model)
        .to_string();

    // Cost calculation (Anthropic pricing, microdollars)
    let cost_usd = calculate_cost(&actual_model, input_tokens, output_tokens);

    // Track cost in ledger
    let cost_micro = (cost_usd * 1_000_000.0) as u64;
    state
        .session_cost_microdollars
        .fetch_add(cost_micro, Ordering::SeqCst);

    if let Err(e) = state.ledger.record(&safeagent_cost_ledger::CostEntry {
        timestamp: Utc::now(),
        model_name: actual_model.clone(),
        tier: model_to_tier(&actual_model).to_string(),
        platform: "desktop".to_string(),
        input_tokens: input_tokens as u32,
        output_tokens: output_tokens as u32,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        cost_microdollars: cost_micro,
        cache_status: "miss".to_string(),
        latency_ms: 0,
    }) {
        tracing::warn!("Ledger write failed: {}", e);
    }

    // Audit log
    let _ = state.audit.record(&AuditEntry {
        timestamp: Utc::now(),
        event_type: "llm_request".to_string(),
        model_name: actual_model.clone(),
        tier: model_to_tier(&actual_model).to_string(),
        platform: "desktop".to_string(),
        input_tokens: input_tokens as u32,
        output_tokens: output_tokens as u32,
        cost_microdollars: cost_micro,
        cache_status: "miss".to_string(),
        latency_ms: 0,
        success: true,
        error_message: None,
        metadata: "{}".to_string(),
    });

    let assistant_msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        role: "assistant".to_string(),
        content: content.clone(),
        timestamp: Utc::now().to_rfc3339(),
        model: Some(actual_model.clone()),
        input_tokens: Some(input_tokens),
        output_tokens: Some(output_tokens),
        cost_usd: Some(cost_usd),
    };

    // Persist to memory
    let _ = state.memory.add_message(&MessageEntry {
        id: MessageId(Uuid::new_v4().to_string()),
        chat_id: ChatId("desktop-default".to_string()),
        sender_id: UserId("assistant".to_string()),
        role: Role::Assistant,
        content: content.clone(),
        platform: Platform::Cli,
        timestamp: Utc::now(),
        token_count: Some(output_tokens as u32),
    });

    // Add to in-memory conversation
    {
        let mut conv = state.conversation.lock().unwrap();
        conv.push(assistant_msg.clone());
    }

    // Emit real-time cost update
    let _ = window.emit(
        "cost_update",
        serde_json::json!({
            "cost_usd": cost_usd,
            "model": actual_model,
            "tokens": input_tokens + output_tokens
        }),
    );

    Ok(assistant_msg)
}

/// Return the full conversation history.
#[tauri::command]
async fn get_history(
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<ChatMessage>, String> {
    let conv = state.conversation.lock().unwrap();
    let limit = limit.unwrap_or(100) as usize;
    let start = if conv.len() > limit {
        conv.len() - limit
    } else {
        0
    };
    Ok(conv[start..].to_vec())
}

/// Clear the conversation history (in-memory only; persistent memory is kept).
#[tauri::command]
async fn clear_history(state: State<'_, AppState>) -> Result<(), String> {
    state.conversation.lock().unwrap().clear();
    Ok(())
}

/// Return cost and usage statistics.
#[tauri::command]
async fn get_stats(state: State<'_, AppState>) -> Result<StatsResponse, String> {
    let session_cost = state
        .session_cost_microdollars
        .load(Ordering::SeqCst);

    match state.ledger.total_summary() {
        Ok(s) => {
            let breakdown = state
                .ledger
                .model_breakdown_since("2000-01-01")
                .unwrap_or_default()
                .into_iter()
                .map(|m| ModelStat {
                    model: m.model_name,
                    requests: m.request_count as u64,
                    cost_usd: m.total_cost_microdollars as f64 / 1_000_000.0,
                })
                .collect();

            Ok(StatsResponse {
                total_requests: s.total_requests as u64,
                total_cost_usd: s.total_cost_microdollars as f64 / 1_000_000.0,
                total_input_tokens: s.total_input_tokens as u64,
                total_output_tokens: s.total_output_tokens as u64,
                cache_tokens: (s.total_cache_read_tokens + s.total_cache_write_tokens) as u64,
                session_cost_usd: session_cost as f64 / 1_000_000.0,
                model_breakdown: breakdown,
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Return recent audit log entries.
#[tauri::command]
async fn get_audit_entries(
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<AuditEntryDto>, String> {
    let limit = limit.unwrap_or(50);
    match state.audit.recent_entries(limit) {
        Ok(entries) => {
            let dtos = entries
                .into_iter()
                .map(|e| AuditEntryDto {
                    id: Uuid::new_v4().to_string(),
                    timestamp: e.timestamp.to_rfc3339(),
                    event_type: e.event_type,
                    model: e.model_name,
                    platform: e.platform,
                    input_tokens: e.input_tokens as u64,
                    output_tokens: e.output_tokens as u64,
                    cost_usd: e.cost_microdollars as f64 / 1_000_000.0,
                    latency_ms: e.latency_ms as u64,
                    success: e.success,
                    error: e.error_message,
                })
                .collect();
            Ok(dtos)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Return current app configuration.
#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<ConfigDto, String> {
    Ok(state.config.lock().unwrap().clone())
}

/// Save app configuration to vault.
#[tauri::command]
async fn save_config(config: ConfigDto, state: State<'_, AppState>) -> Result<(), String> {
    if !state.vault_unlocked.load(Ordering::SeqCst) {
        return Err("Vault not unlocked".to_string());
    }
    let json = serde_json::to_string(&config).map_err(|e| e.to_string())?;
    state
        .vault
        .store("app_config", "App Config", "config", &SensitiveString::new(json))
        .map_err(|e| e.to_string())?;
    *state.config.lock().unwrap() = config;
    Ok(())
}

/// Return current vault/system health status.
#[tauri::command]
async fn get_system_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let vault_unlocked = state.vault_unlocked.load(Ordering::SeqCst);
    let has_key = state.api_key.lock().unwrap().is_some();
    let msg_count = state.conversation.lock().unwrap().len();

    Ok(serde_json::json!({
        "vault_unlocked": vault_unlocked,
        "api_key_configured": has_key,
        "message_count": msg_count,
        "security_stack": {
            "prompt_guard": true,
            "policy_engine": true,
            "audit_log": true,
            "credential_vault": true
        },
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Get version string.
#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn choose_model(router_mode: &str, text: &str) -> String {
    let words = text.split_whitespace().count();
    match router_mode {
        "economy" => "claude-haiku-4-5".to_string(),
        "performance" => "claude-opus-4-5".to_string(),
        _ => {
            // Balanced: route by complexity
            if words < 20 {
                "claude-haiku-4-5".to_string()
            } else if words < 100 {
                "claude-sonnet-4-5".to_string()
            } else {
                "claude-opus-4-5".to_string()
            }
        }
    }
}

fn model_to_tier(model: &str) -> &'static str {
    if model.contains("haiku") {
        "economy"
    } else if model.contains("sonnet") {
        "standard"
    } else {
        "premium"
    }
}

fn calculate_cost(model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    // Approximate Anthropic pricing (USD per million tokens)
    let (input_price, output_price) = if model.contains("haiku") {
        (0.25, 1.25)
    } else if model.contains("sonnet") {
        (3.0, 15.0)
    } else {
        // opus
        (15.0, 75.0)
    };

    (input_tokens as f64 * input_price + output_tokens as f64 * output_price) / 1_000_000.0
}

// ── System tray ───────────────────────────────────────────────────────────────

fn setup_system_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use tauri::menu::{MenuBuilder, MenuItemBuilder};

    let open_item = MenuItemBuilder::with_id("open", "Open SafeAgent").build(app)?;
    let separator = tauri::menu::PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

    let menu = MenuBuilder::new(app)
        .items(&[&open_item, &separator, &quit_item])
        .build()?;

    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(false)
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("SafeAgent — AI Assistant")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "quit" => {
                app.exit(0);
            }
            "open" => {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "safeagent_desktop=info".into()),
        )
        .with_target(false)
        .init();

    let data_dir = get_data_dir();
    std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");

    // Initialise components (fail gracefully)
    let vault = Arc::new(
        CredentialVault::new(data_dir.join("vault.db"))
            .expect("Failed to open credential vault"),
    );

    let memory = Arc::new(
        MemoryStore::new(data_dir.join("memory.db")).expect("Failed to open memory store"),
    );

    let ledger = Arc::new(
        CostLedger::new(data_dir.join("cost_ledger.db"))
            .map_err(|e| anyhow::anyhow!("{}", e))
            .expect("Failed to open cost ledger"),
    );

    let audit = Arc::new(
        AuditLog::new(data_dir.join("audit.db"), 30, 10_000)
            .map_err(|e| anyhow::anyhow!("{}", e))
            .expect("Failed to open audit log"),
    );

    let guard = Arc::new(PromptGuard::with_defaults());

    let policy = Arc::new(PolicyEngine::new(PolicyConfig {
        daily_spend_limit_microdollars: Some(5_000_000),    // $5
        monthly_spend_limit_microdollars: Some(50_000_000), // $50
        ..Default::default()
    }));

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .expect("Failed to create HTTP client");

    let state = AppState {
        data_dir,
        vault,
        memory,
        ledger,
        audit,
        guard,
        policy,
        vault_unlocked: AtomicBool::new(false),
        conversation: Mutex::new(Vec::new()),
        api_key: Mutex::new(None),
        config: Mutex::new(ConfigDto::default()),
        http,
        session_cost_microdollars: std::sync::atomic::AtomicU64::new(0),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .plugin(tauri_plugin_process::init())
        .manage(state)
        .setup(|app| {
            setup_system_tray(app).map_err(|e| Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Setup / auth
            is_first_run,
            is_vault_unlocked,
            unlock_vault,
            save_api_key,
            validate_api_key,
            has_api_key,
            // Chat
            send_message,
            get_history,
            clear_history,
            // Analytics
            get_stats,
            get_audit_entries,
            // Config
            get_config,
            save_config,
            // System
            get_system_status,
            get_version,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hide to tray instead of quitting
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running SafeAgent Desktop");
}
