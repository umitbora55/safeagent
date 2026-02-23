use anyhow::Result;
use safeagent_memory::MemoryStore;
use std::path::Path;

pub fn run_export(data_dir: &Path) -> Result<()> {
    let memory_path = data_dir.join("memory.db");
    if !memory_path.exists() {
        println!();
        println!("  📝 No conversation data to export.");
        println!("  Run `safeagent run` and chat first.");
        println!();
        return Ok(());
    }

    let memory = MemoryStore::new(memory_path)?;
    let messages = memory.recent_messages(
        &safeagent_bridge_common::ChatId("cli_main".into()), 1000
    ).unwrap_or_default();

    if messages.is_empty() {
        println!();
        println!("  📝 No messages found.");
        println!();
        return Ok(());
    }

    let facts = memory.get_facts().unwrap_or_default();

    // Export as Markdown
    let md_path = data_dir.join("export_conversation.md");
    let mut md = String::new();
    md.push_str("# SafeAgent Conversation Export\n\n");
    md.push_str(&format!("Exported: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")));
    md.push_str(&format!("Messages: {}\n\n", messages.len()));
    md.push_str("---\n\n");

    if !facts.is_empty() {
        md.push_str("## Known Facts\n\n");
        for f in &facts {
            md.push_str(&format!("- **{}**: {}\n", f.key, f.value));
        }
        md.push_str("\n---\n\n");
    }

    md.push_str("## Conversation\n\n");
    for msg in &messages {
        let role_icon = match msg.role {
            safeagent_memory::Role::User => "👤 **You**",
            safeagent_memory::Role::Assistant => "🤖 **SafeAgent**",
            safeagent_memory::Role::System => "⚙️ **System**",
        };
        let time = msg.timestamp.format("%H:%M:%S");
        md.push_str(&format!("### {} ({})\n\n{}\n\n", role_icon, time, msg.content));
    }

    std::fs::write(&md_path, &md)?;

    // Export as JSON
    let json_path = data_dir.join("export_conversation.json");
    let json_messages: Vec<serde_json::Value> = messages.iter().map(|m| {
        serde_json::json!({
            "id": m.id.0,
            "role": m.role.as_str(),
            "content": m.content,
            "platform": format!("{:?}", m.platform),
            "timestamp": m.timestamp.to_rfc3339(),
            "token_count": m.token_count,
        })
    }).collect();

    let json_export = serde_json::json!({
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "message_count": messages.len(),
        "facts": facts.iter().map(|f| serde_json::json!({"key": f.key, "value": f.value})).collect::<Vec<_>>(),
        "messages": json_messages,
    });

    std::fs::write(&json_path, serde_json::to_string_pretty(&json_export)?)?;

    println!();
    println!("  📝 Conversation exported ({} messages)", messages.len());
    println!("  Markdown: {}", md_path.display());
    println!("  JSON:     {}", json_path.display());
    println!();

    Ok(())
}
