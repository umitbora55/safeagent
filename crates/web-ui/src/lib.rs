use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use safeagent_audit_log::AuditLog;
use safeagent_cost_ledger::CostLedger;
use safeagent_memory::MemoryStore;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Shared application state for all handlers.
pub struct AppState {
    pub ledger: Option<CostLedger>,
    pub audit: Option<AuditLog>,
    pub memory: Option<MemoryStore>,
    pub version: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(dashboard_page))
        .route("/api/health", get(api_health))
        .route("/api/stats", get(api_stats))
        .route("/api/audit", get(api_audit))
        .route("/api/conversations", get(api_conversations))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn start_server(state: Arc<AppState>, port: u16) -> anyhow::Result<()> {
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Web UI running at http://localhost:{}", port);
    println!("  🌐 Web UI: http://localhost:{}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

// ─── API Handlers ───────────────────────────────────────

async fn api_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let uptime = chrono::Utc::now() - state.start_time;
    Json(serde_json::json!({
        "status": "ok",
        "version": state.version,
        "uptime_seconds": uptime.num_seconds(),
        "has_ledger": state.ledger.is_some(),
        "has_audit": state.audit.is_some(),
        "has_memory": state.memory.is_some(),
    }))
}

async fn api_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = match &state.ledger {
        Some(ledger) => {
            match ledger.total_summary() {
                Ok(s) => serde_json::json!({
                    "total_requests": s.total_requests,
                    "total_input_tokens": s.total_input_tokens,
                    "total_output_tokens": s.total_output_tokens,
                    "total_cost_usd": format!("{:.4}", s.total_cost_microdollars as f64 / 1_000_000.0),
                    "total_cost_microdollars": s.total_cost_microdollars,
                    "cache_read_tokens": s.total_cache_read_tokens,
                    "cache_write_tokens": s.total_cache_write_tokens,
                }),
                Err(e) => serde_json::json!({"error": format!("{}", e)}),
            }
        }
        None => serde_json::json!({"error": "Cost ledger not available"}),
    };

    let model_stats: Vec<serde_json::Value> = match &state.ledger {
        Some(ledger) => {
            match ledger.model_breakdown_since("2000-01-01") {
                Ok(models) => models.iter().map(|m| {
                    serde_json::json!({
                        "model": m.model_name,
                        "requests": m.request_count,
                        "input_tokens": m.total_input_tokens,
                        "output_tokens": m.total_output_tokens,
                        "cost_usd": format!("{:.4}", m.total_cost_microdollars as f64 / 1_000_000.0),
                    })
                }).collect(),
                Err(_) => vec![],
            }
        }
        None => vec![],
    };

    Json(serde_json::json!({
        "summary": stats,
        "per_model": model_stats,
    }))
}

async fn api_audit(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let entries = match &state.audit {
        Some(audit) => {
            match audit.recent_entries(50) {
                Ok(entries) => entries.iter().map(|e| {
                    serde_json::json!({
                        "timestamp": e.timestamp.to_rfc3339(),
                        "event_type": e.event_type,
                        "model": e.model_name,
                        "tier": e.tier,
                        "platform": e.platform,
                        "input_tokens": e.input_tokens,
                        "output_tokens": e.output_tokens,
                        "cost_usd": format!("{:.4}", e.cost_microdollars as f64 / 1_000_000.0),
                        "latency_ms": e.latency_ms,
                        "success": e.success,
                        "error": e.error_message,
                    })
                }).collect::<Vec<_>>(),
                Err(_) => vec![],
            }
        }
        None => vec![],
    };

    Json(serde_json::json!({"entries": entries, "count": entries.len()}))
}

async fn api_conversations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let messages = match &state.memory {
        Some(mem) => {
            let chat_id = safeagent_bridge_common::ChatId("cli_main".into());
            match mem.recent_messages(&chat_id, 50) {
                Ok(msgs) => msgs.iter().map(|m| {
                    serde_json::json!({
                        "role": m.role.as_str(),
                        "content": m.content,
                        "timestamp": m.timestamp.to_rfc3339(),
                    })
                }).collect::<Vec<_>>(),
                Err(_) => vec![],
            }
        }
        None => vec![],
    };

    Json(serde_json::json!({"messages": messages, "count": messages.len()}))
}

// ─── Dashboard HTML ─────────────────────────────────────

async fn dashboard_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Html(format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SafeAgent Dashboard</title>
    <script src="https://unpkg.com/htmx.org@2.0.4"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }}
        .header {{ background: linear-gradient(135deg, #1e293b, #334155); padding: 1.5rem 2rem; border-bottom: 1px solid #475569; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ font-size: 1.5rem; color: #38bdf8; }}
        .header .badge {{ background: #22c55e; color: #fff; padding: 0.25rem 0.75rem; border-radius: 99px; font-size: 0.75rem; font-weight: 600; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; }}
        .card h3 {{ color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; }}
        .card .value {{ font-size: 2rem; font-weight: 700; color: #f8fafc; }}
        .card .sub {{ font-size: 0.875rem; color: #64748b; margin-top: 0.25rem; }}
        .section {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .section h2 {{ font-size: 1.125rem; color: #e2e8f0; margin-bottom: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid #334155; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; padding: 0.75rem; color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; border-bottom: 1px solid #334155; }}
        td {{ padding: 0.75rem; border-bottom: 1px solid #1e293b; font-size: 0.875rem; }}
        tr:hover {{ background: #334155; }}
        .success {{ color: #22c55e; }}
        .error {{ color: #ef4444; }}
        .chat {{ max-height: 400px; overflow-y: auto; }}
        .msg {{ padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 8px; }}
        .msg-user {{ background: #1e3a5f; border-left: 3px solid #38bdf8; }}
        .msg-assistant {{ background: #1a2e1a; border-left: 3px solid #22c55e; }}
        .msg-role {{ font-size: 0.7rem; color: #94a3b8; margin-bottom: 0.25rem; text-transform: uppercase; }}
        .tabs {{ display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }}
        .tab {{ padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; background: #334155; color: #94a3b8; border: none; font-size: 0.875rem; }}
        .tab.active {{ background: #38bdf8; color: #0f172a; font-weight: 600; }}
        .refresh {{ background: #475569; color: #e2e8f0; border: none; padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; font-size: 0.875rem; }}
        .refresh:hover {{ background: #64748b; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SafeAgent Dashboard</h1>
        <div>
            <span class="badge">v{version}</span>
            <button class="refresh" onclick="refreshAll()" style="margin-left: 1rem;">↻ Refresh</button>
        </div>
    </div>

    <div class="container">
        <!-- Stats Cards -->
        <div id="stats-cards" class="grid">
            <div class="card"><h3>Loading...</h3><div class="value">—</div></div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('models')">📊 Models</button>
            <button class="tab" onclick="showTab('audit')">📋 Audit Log</button>
            <button class="tab" onclick="showTab('chat')">💬 Conversations</button>
        </div>

        <!-- Models Table -->
        <div id="tab-models" class="section">
            <h2>Model Usage</h2>
            <div id="models-table">Loading...</div>
        </div>

        <!-- Audit Log -->
        <div id="tab-audit" class="section" style="display:none;">
            <h2>Recent Audit Log</h2>
            <div id="audit-table">Loading...</div>
        </div>

        <!-- Chat History -->
        <div id="tab-chat" class="section" style="display:none;">
            <h2>Recent Conversations</h2>
            <div id="chat-history" class="chat">Loading...</div>
        </div>
    </div>

    <script>
        function showTab(tab) {{
            document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById('tab-' + tab).style.display = 'block';
            event.target.classList.add('active');
        }}

        async function refreshAll() {{
            await Promise.all([loadStats(), loadAudit(), loadChat()]);
        }}

        async function loadStats() {{
            try {{
                const r = await fetch('/api/stats');
                const d = await r.json();
                const s = d.summary;
                document.getElementById('stats-cards').innerHTML = `
                    <div class="card"><h3>Total Requests</h3><div class="value">${{s.total_requests || 0}}</div></div>
                    <div class="card"><h3>Total Cost</h3><div class="value">${{s.total_cost_usd || '0.0000'}}</div><div class="sub">USD</div></div>
                    <div class="card"><h3>Input Tokens</h3><div class="value">${{(s.total_input_tokens || 0).toLocaleString()}}</div></div>
                    <div class="card"><h3>Output Tokens</h3><div class="value">${{(s.total_output_tokens || 0).toLocaleString()}}</div></div>
                    <div class="card"><h3>Cache Read</h3><div class="value">${{(s.cache_read_tokens || 0).toLocaleString()}}</div><div class="sub">tokens</div></div>
                    <div class="card"><h3>Cache Write</h3><div class="value">${{(s.cache_write_tokens || 0).toLocaleString()}}</div><div class="sub">tokens</div></div>
                `;

                let mt = '<table><tr><th>Model</th><th>Requests</th><th>Input</th><th>Output</th><th>Cost</th></tr>';
                (d.per_model || []).forEach(m => {{
                    mt += `<tr><td>${{m.model}}</td><td>${{m.requests}}</td><td>${{m.total_input_tokens.toLocaleString()}}</td><td>${{m.total_output_tokens.toLocaleString()}}</td><td>${{m.cost_usd}}</td></tr>`;
                }});
                mt += '</table>';
                document.getElementById('models-table').innerHTML = mt;
            }} catch(e) {{
                document.getElementById('stats-cards').innerHTML = '<div class="card"><h3>Error</h3><div class="value">—</div></div>';
            }}
        }}

        async function loadAudit() {{
            try {{
                const r = await fetch('/api/audit');
                const d = await r.json();
                let t = '<table><tr><th>Time</th><th>Event</th><th>Model</th><th>Platform</th><th>Tokens</th><th>Cost</th><th>Latency</th><th>Status</th></tr>';
                (d.entries || []).forEach(e => {{
                    const time = new Date(e.timestamp).toLocaleTimeString();
                    const status = e.success ? '<span class="success">✅</span>' : '<span class="error">❌</span>';
                    t += `<tr><td>${{time}}</td><td>${{e.event_type}}</td><td>${{e.model}}</td><td>${{e.platform}}</td><td>${{e.input_tokens}}/${{e.output_tokens}}</td><td>${{e.cost_usd}}</td><td>${{e.latency_ms}}ms</td><td>${{status}}</td></tr>`;
                }});
                t += '</table>';
                document.getElementById('audit-table').innerHTML = t;
            }} catch(e) {{
                document.getElementById('audit-table').innerHTML = 'Failed to load.';
            }}
        }}

        async function loadChat() {{
            try {{
                const r = await fetch('/api/conversations');
                const d = await r.json();
                let html = '';
                (d.messages || []).forEach(m => {{
                    const cls = m.role === 'user' ? 'msg-user' : 'msg-assistant';
                    const icon = m.role === 'user' ? '👤' : '🤖';
                    html += `<div class="msg ${{cls}}"><div class="msg-role">${{icon}} ${{m.role}}</div>${{m.content}}</div>`;
                }});
                document.getElementById('chat-history').innerHTML = html || '<p style="color:#64748b">No messages yet.</p>';
            }} catch(e) {{
                document.getElementById('chat-history').innerHTML = 'Failed to load.';
            }}
        }}

        refreshAll();
        setInterval(refreshAll, 15000);
    </script>
</body>
</html>"##, version = state.version))
}
