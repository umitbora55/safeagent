use axum::response::IntoResponse;
use axum::Json;

#[derive(Debug, serde::Serialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, serde::Deserialize)]
pub struct McpToolCallRequest {
    pub method: String,
    pub params: Option<McpToolCallParams>,
}

#[derive(Debug, serde::Deserialize)]
pub struct McpToolCallParams {
    pub name: Option<String>,
    pub arguments: Option<serde_json::Value>,
}

pub async fn mcp_list_tools() -> impl IntoResponse {
    let tools = vec![
        McpTool { name: "web_search".into(), description: "Search the web".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}) },
        McpTool { name: "url_fetch".into(), description: "Fetch a web page".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}) },
        McpTool { name: "file_read".into(), description: "Read a file".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}) },
        McpTool { name: "file_write".into(), description: "Write a file".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}) },
        McpTool { name: "calendar_read".into(), description: "Read Google Calendar events".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}) },
        McpTool { name: "calendar_write".into(), description: "Create a calendar event".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"title":{"type":"string"},"date":{"type":"string"},"start":{"type":"string"},"end":{"type":"string"}},"required":["title","date","start","end"]}) },
        McpTool { name: "email_read".into(), description: "Read Gmail emails".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}) },
        McpTool { name: "email_send".into(), description: "Send email via Gmail".into(),
            input_schema: serde_json::json!({"type":"object","properties":{"to":{"type":"string"},"subject":{"type":"string"},"body":{"type":"string"}},"required":["to","subject","body"]}) },
    ];

    Json(serde_json::json!({"jsonrpc":"2.0","result":{"tools": tools}}))
}

pub async fn mcp_handle(Json(request): Json<McpToolCallRequest>) -> impl IntoResponse {
    match request.method.as_str() {
        "initialize" => Json(serde_json::json!({
            "jsonrpc":"2.0",
            "result":{
                "protocolVersion":"2024-11-05",
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"safeagent-mcp","version":env!("CARGO_PKG_VERSION")}
            }
        })).into_response(),
        "tools/list" => mcp_list_tools().await.into_response(),
        "tools/call" => {
            let params = match request.params {
                Some(p) => p,
                None => return Json(mcp_error(-32602, "Missing params")).into_response(),
            };
            let tool_name = match params.name {
                Some(n) => n,
                None => return Json(mcp_error(-32602, "Missing tool name")).into_response(),
            };
            let args = params.arguments.unwrap_or(serde_json::json!({}));
            Json(serde_json::json!({
                "jsonrpc":"2.0",
                "result":{"content":[{"type":"text","text":format!("Tool '{}' called with: {}", tool_name, args)}],"isError":false}
            })).into_response()
        }
        _ => Json(mcp_error(-32601, &format!("Method not found: {}", request.method))).into_response(),
    }
}

fn mcp_error(code: i32, message: &str) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","error":{"code":code,"message":message}})
}
