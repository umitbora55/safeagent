#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]


#[tauri::command]
fn get_version() -> String {
    "0.1.0".to_string()
}

#[tauri::command]
fn get_health() -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "version": "0.1.0",
        "uptime": "running"
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_version, get_health])
        .run(tauri::generate_context!())
        .expect("error while running SafeAgent Desktop");
}
