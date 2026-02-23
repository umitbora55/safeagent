use chrono::{DateTime, Utc};
use safeagent_bridge_common::{ChatId, MessageId, Platform, UserId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Message Entry — stored conversation turn
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEntry {
    pub id: MessageId,
    pub chat_id: ChatId,
    pub sender_id: UserId,
    pub role: Role,
    pub content: String,
    pub platform: Platform,
    pub timestamp: DateTime<Utc>,
    pub token_count: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    System,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::System => "system",
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  User Fact — extracted knowledge about the user
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFact {
    pub key: String,
    pub value: String,
    pub confidence: f32,
    pub source: String,
    pub updated_at: DateTime<Utc>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Memory Store — thread-safe via Mutex
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct MemoryStore {
    db: Mutex<rusqlite::Connection>,
}

impl MemoryStore {
    pub fn new(db_path: PathBuf) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(&db_path)?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;

             CREATE TABLE IF NOT EXISTS messages (
                 id TEXT PRIMARY KEY,
                 chat_id TEXT NOT NULL,
                 sender_id TEXT NOT NULL,
                 role TEXT NOT NULL,
                 content TEXT NOT NULL,
                 platform TEXT NOT NULL,
                 timestamp TEXT NOT NULL,
                 token_count INTEGER
             );

             CREATE INDEX IF NOT EXISTS idx_messages_chat_time
                 ON messages(chat_id, timestamp);

             CREATE TABLE IF NOT EXISTS user_facts (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL,
                 confidence REAL NOT NULL DEFAULT 1.0,
                 source TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );

             CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts
                 USING fts5(content, chat_id, content='messages', content_rowid='rowid');"
        )?;

        info!("🧠 Memory store initialized at {:?}", db_path);
        Ok(Self { db: Mutex::new(conn) })
    }

    /// Store a message
    pub fn add_message(&self, entry: &MessageEntry) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT OR REPLACE INTO messages (id, chat_id, sender_id, role, content, platform, timestamp, token_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                entry.id.0,
                entry.chat_id.0,
                entry.sender_id.0,
                entry.role.as_str(),
                entry.content,
                entry.platform.to_string(),
                entry.timestamp.to_rfc3339(),
                entry.token_count,
            ],
        )?;

        // Update FTS index
        let _ = db.execute(
            "INSERT INTO messages_fts(rowid, content, chat_id)
             SELECT rowid, content, chat_id FROM messages WHERE id = ?1",
            [&entry.id.0],
        );

        Ok(())
    }

    /// Get recent messages for a chat (for LLM context window)
    pub fn recent_messages(&self, chat_id: &ChatId, limit: usize) -> anyhow::Result<Vec<MessageEntry>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, chat_id, sender_id, role, content, platform, timestamp, token_count
             FROM messages
             WHERE chat_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2"
        )?;

        let mut entries: Vec<MessageEntry> = stmt
            .query_map(rusqlite::params![chat_id.0, limit], |row| {
                Ok(MessageEntry {
                    id: MessageId(row.get(0)?),
                    chat_id: ChatId(row.get(1)?),
                    sender_id: UserId(row.get(2)?),
                    role: match row.get::<_, String>(3)?.as_str() {
                        "user" => Role::User,
                        "assistant" => Role::Assistant,
                        _ => Role::System,
                    },
                    content: row.get(4)?,
                    platform: match row.get::<_, String>(5)?.as_str() {
                        "telegram" => Platform::Telegram,
                        "whatsapp" => Platform::WhatsApp,
                        "discord" => Platform::Discord,
                        "signal" => Platform::Signal,
                        _ => Platform::Cli,
                    },
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    token_count: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        // Return chronological order
        entries.reverse();
        Ok(entries)
    }

    /// Get oldest messages for a chat (stable prefix for caching)
    pub fn oldest_messages(&self, chat_id: &ChatId, limit: usize) -> anyhow::Result<Vec<MessageEntry>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, chat_id, sender_id, role, content, platform, timestamp, token_count
             FROM messages
             WHERE chat_id = ?1
             ORDER BY timestamp ASC
             LIMIT ?2"
        )?;

        let entries: Vec<MessageEntry> = stmt
            .query_map(rusqlite::params![chat_id.0, limit], |row| {
                Ok(MessageEntry {
                    id: MessageId(row.get(0)?),
                    chat_id: ChatId(row.get(1)?),
                    sender_id: UserId(row.get(2)?),
                    role: match row.get::<_, String>(3)?.as_str() {
                        "user" => Role::User,
                        "assistant" => Role::Assistant,
                        _ => Role::System,
                    },
                    content: row.get(4)?,
                    platform: match row.get::<_, String>(5)?.as_str() {
                        "telegram" => Platform::Telegram,
                        "whatsapp" => Platform::WhatsApp,
                        "discord" => Platform::Discord,
                        "signal" => Platform::Signal,
                        _ => Platform::Cli,
                    },
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    token_count: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Full-text search across all messages
    pub fn search(&self, query: &str, limit: usize) -> anyhow::Result<Vec<MessageEntry>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT m.id, m.chat_id, m.sender_id, m.role, m.content, m.platform, m.timestamp, m.token_count
             FROM messages m
             JOIN messages_fts fts ON m.rowid = fts.rowid
             WHERE messages_fts MATCH ?1
             ORDER BY rank
             LIMIT ?2"
        )?;

        let entries = stmt
            .query_map(rusqlite::params![query, limit], |row| {
                Ok(MessageEntry {
                    id: MessageId(row.get(0)?),
                    chat_id: ChatId(row.get(1)?),
                    sender_id: UserId(row.get(2)?),
                    role: match row.get::<_, String>(3)?.as_str() {
                        "user" => Role::User,
                        "assistant" => Role::Assistant,
                        _ => Role::System,
                    },
                    content: row.get(4)?,
                    platform: match row.get::<_, String>(5)?.as_str() {
                        "telegram" => Platform::Telegram,
                        "whatsapp" => Platform::WhatsApp,
                        "discord" => Platform::Discord,
                        "signal" => Platform::Signal,
                        _ => Platform::Cli,
                    },
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    token_count: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Store or update a user fact
    pub fn set_fact(&self, fact: &UserFact) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT OR REPLACE INTO user_facts (key, value, confidence, source, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                fact.key,
                fact.value,
                fact.confidence,
                fact.source,
                fact.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Get all user facts
    pub fn get_facts(&self) -> anyhow::Result<Vec<UserFact>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT key, value, confidence, source, updated_at FROM user_facts ORDER BY key"
        )?;

        let facts = stmt
            .query_map([], |row| {
                Ok(UserFact {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    confidence: row.get(2)?,
                    source: row.get(3)?,
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(facts)
    }

    /// Get a specific fact
    pub fn get_fact(&self, key: &str) -> anyhow::Result<Option<UserFact>> {
        let db = self.db.lock().unwrap();
        let result = db.query_row(
            "SELECT key, value, confidence, source, updated_at FROM user_facts WHERE key = ?1",
            [key],
            |row| {
                Ok(UserFact {
                    key: row.get(0)?,
                    value: row.get(1)?,
                    confidence: row.get(2)?,
                    source: row.get(3)?,
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                })
            },
        );

        match result {
            Ok(fact) => Ok(Some(fact)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a fact
    pub fn delete_fact(&self, key: &str) -> anyhow::Result<bool> {
        let db = self.db.lock().unwrap();
        let deleted = db.execute("DELETE FROM user_facts WHERE key = ?1", [key])?;
        Ok(deleted > 0)
    }

    /// Total message count
    pub fn message_count(&self) -> anyhow::Result<u64> {
        let db = self.db.lock().unwrap();
        let count: u64 = db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Message count for a specific chat
    pub fn chat_message_count(&self, chat_id: &ChatId) -> anyhow::Result<u64> {
        let db = self.db.lock().unwrap();
        let count: u64 = db.query_row(
            "SELECT COUNT(*) FROM messages WHERE chat_id = ?1",
            [&chat_id.0],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Estimate total tokens for a chat (for context window budgeting)
    pub fn chat_token_estimate(&self, chat_id: &ChatId) -> anyhow::Result<u64> {
        let db = self.db.lock().unwrap();
        let total: u64 = db.query_row(
            "SELECT COALESCE(SUM(token_count), 0) FROM messages WHERE chat_id = ?1",
            [&chat_id.0],
            |row| row.get(0),
        )?;
        Ok(total)
    }

    /// Check if conversation is long enough to need summarization.
    pub fn should_summarize(&self, chat_id: &ChatId, threshold: usize) -> bool {
        let count = self.message_count_for_chat(chat_id).unwrap_or(0);
        count > threshold
    }

    /// Get message count for a specific chat.
    pub fn message_count_for_chat(&self, chat_id: &ChatId) -> anyhow::Result<usize> {
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM messages WHERE chat_id = ?1",
            rusqlite::params![chat_id.0],
            |row: &rusqlite::Row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Build a summarization context: oldest messages that should be compressed.
    pub fn messages_to_summarize(&self, chat_id: &ChatId, keep_recent: usize) -> anyhow::Result<Vec<MessageEntry>> {
        let all = self.oldest_messages(chat_id, 1000)?;
        if all.len() <= keep_recent {
            return Ok(vec![]);
        }
        let cutoff = all.len() - keep_recent;
        Ok(all[..cutoff].to_vec())
    }

    /// Store a summary as a system message, then delete the summarized messages.
    pub fn store_summary_and_prune(&self, chat_id: &ChatId, summary: &str, pruned_ids: &[String]) -> anyhow::Result<()> {
        let summary_entry = MessageEntry {
            id: MessageId(uuid::Uuid::new_v4().to_string()),
            chat_id: chat_id.clone(),
            sender_id: UserId("system".into()),
            role: Role::System,
            content: format!("[Conversation Summary]\n{}", summary),
            platform: safeagent_bridge_common::Platform::Cli,
            timestamp: chrono::Utc::now(),
            token_count: None,
        };
        self.add_message(&summary_entry)?;
        let db = self.db.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        for id in pruned_ids {
            db.execute("DELETE FROM messages WHERE id = ?1", rusqlite::params![id])?;
        }
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> MemoryStore {
        let path = std::env::temp_dir().join(format!("safeagent_mem_test_{}.db", uuid::Uuid::new_v4()));
        MemoryStore::new(path).unwrap()
    }

    fn make_msg(chat: &str, role: Role, content: &str) -> MessageEntry {
        MessageEntry {
            id: MessageId(uuid::Uuid::new_v4().to_string()),
            chat_id: ChatId(chat.into()),
            sender_id: UserId("user1".into()),
            role,
            content: content.into(),
            platform: Platform::Telegram,
            timestamp: Utc::now(),
            token_count: Some(content.split_whitespace().count() as u32),
        }
    }

    #[test]
    fn test_add_and_retrieve() {
        let store = temp_store();
        let msg = make_msg("chat1", Role::User, "Hello agent");
        store.add_message(&msg).unwrap();

        let chat_id = ChatId("chat1".into());
        let msgs = store.recent_messages(&chat_id, 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, "Hello agent");
        assert_eq!(msgs[0].role, Role::User);
    }

    #[test]
    fn test_recent_messages_order() {
        let store = temp_store();
        let chat = ChatId("chat1".into());

        for i in 0..5 {
            let mut msg = make_msg("chat1", Role::User, &format!("Message {}", i));
            msg.timestamp = Utc::now() + chrono::Duration::seconds(i as i64);
            store.add_message(&msg).unwrap();
        }

        let msgs = store.recent_messages(&chat, 3).unwrap();
        assert_eq!(msgs.len(), 3);
        // Should be chronological (oldest first of the last 3)
        assert!(msgs[0].content.contains("2"));
        assert!(msgs[1].content.contains("3"));
        assert!(msgs[2].content.contains("4"));
    }

    #[test]
    fn test_chat_isolation() {
        let store = temp_store();
        store.add_message(&make_msg("chat_a", Role::User, "For chat A")).unwrap();
        store.add_message(&make_msg("chat_b", Role::User, "For chat B")).unwrap();

        let a_msgs = store.recent_messages(&ChatId("chat_a".into()), 10).unwrap();
        let b_msgs = store.recent_messages(&ChatId("chat_b".into()), 10).unwrap();

        assert_eq!(a_msgs.len(), 1);
        assert_eq!(b_msgs.len(), 1);
        assert_eq!(a_msgs[0].content, "For chat A");
        assert_eq!(b_msgs[0].content, "For chat B");
    }

    #[test]
    fn test_full_text_search() {
        let store = temp_store();
        store.add_message(&make_msg("c1", Role::User, "I love Rust programming")).unwrap();
        store.add_message(&make_msg("c1", Role::User, "Python is great too")).unwrap();
        store.add_message(&make_msg("c1", Role::User, "Rust is memory safe")).unwrap();

        let results = store.search("Rust", 10).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_user_facts_crud() {
        let store = temp_store();

        // Create
        let fact = UserFact {
            key: "name".into(),
            value: "Umit".into(),
            confidence: 1.0,
            source: "user_message".into(),
            updated_at: Utc::now(),
        };
        store.set_fact(&fact).unwrap();

        // Read
        let retrieved = store.get_fact("name").unwrap().unwrap();
        assert_eq!(retrieved.value, "Umit");

        // Update
        let updated = UserFact { value: "Ümit Bora".into(), ..fact };
        store.set_fact(&updated).unwrap();
        let retrieved = store.get_fact("name").unwrap().unwrap();
        assert_eq!(retrieved.value, "Ümit Bora");

        // List
        let facts = store.get_facts().unwrap();
        assert_eq!(facts.len(), 1);

        // Delete
        assert!(store.delete_fact("name").unwrap());
        assert!(store.get_fact("name").unwrap().is_none());
        assert!(!store.delete_fact("nonexistent").unwrap());
    }

    #[test]
    fn test_message_count() {
        let store = temp_store();
        let chat = ChatId("chat1".into());

        assert_eq!(store.message_count().unwrap(), 0);
        assert_eq!(store.chat_message_count(&chat).unwrap(), 0);

        store.add_message(&make_msg("chat1", Role::User, "One")).unwrap();
        store.add_message(&make_msg("chat1", Role::Assistant, "Two")).unwrap();
        store.add_message(&make_msg("chat2", Role::User, "Three")).unwrap();

        assert_eq!(store.message_count().unwrap(), 3);
        assert_eq!(store.chat_message_count(&chat).unwrap(), 2);
    }

    #[test]
    fn test_token_estimate() {
        let store = temp_store();
        let chat = ChatId("chat1".into());

        let mut msg1 = make_msg("chat1", Role::User, "one two three");
        msg1.token_count = Some(3);
        let mut msg2 = make_msg("chat1", Role::Assistant, "four five");
        msg2.token_count = Some(2);

        store.add_message(&msg1).unwrap();
        store.add_message(&msg2).unwrap();

        assert_eq!(store.chat_token_estimate(&chat).unwrap(), 5);
    }

    #[test]
    fn test_empty_chat_returns_empty() {
        let store = temp_store();
        let msgs = store.recent_messages(&ChatId("nonexistent".into()), 10).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_concurrent_writes() {
        use std::sync::Arc;

        let store = Arc::new(temp_store());
        let mut handles = vec![];

        for i in 0..10 {
            let s = store.clone();
            handles.push(std::thread::spawn(move || {
                let msg = make_msg("shared", Role::User, &format!("Concurrent msg {}", i));
                s.add_message(&msg).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(store.chat_message_count(&ChatId("shared".into())).unwrap(), 10);
    }
}
