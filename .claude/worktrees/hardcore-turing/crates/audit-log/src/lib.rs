pub mod eu_ai_act;
pub mod hashchain;
pub mod merkle;
/// W15: Enterprise Compliance Suite
pub mod compliance;

use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub model_name: String,
    pub tier: String,
    pub platform: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cost_microdollars: u64,
    pub cache_status: String,
    pub latency_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: String,
}

pub struct AuditLog {
    pool: Pool<SqliteConnectionManager>,
    max_size_mb: u64,
    retention_days: u32,
}

#[derive(Debug)]
pub enum AuditError {
    Database(String),
    Lock(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Database(msg) => write!(f, "Audit DB error: {}", msg),
            AuditError::Lock(msg) => write!(f, "Audit lock error: {}", msg),
        }
    }
}

impl std::error::Error for AuditError {}

/// Redact sensitive values from a string.
/// Masks API keys, tokens, passwords.
pub fn redact_secrets(input: &str) -> String {
    let patterns = [
        (r"sk-ant-[a-zA-Z0-9\-_]{10,}", "sk-ant-****"),
        (r"pa-[a-zA-Z0-9\-_]{10,}", "pa-****"),
        (r"\b\d{6,10}:[A-Za-z0-9_\-]{20,}", "****:****"),
        (
            r"(?i)(password|pwd|secret|token|key)\s*[:=]\s*\S+",
            "$1=****",
        ),
    ];

    let mut result = input.to_string();
    for (pattern, replacement) in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            result = re.replace_all(&result, *replacement).to_string();
        }
    }
    result
}

impl AuditLog {
    pub fn new(path: PathBuf, retention_days: u32, max_size_mb: u64) -> Result<Self, AuditError> {
        let manager = SqliteConnectionManager::file(&path);
        let pool = Pool::builder()
            .max_size(10)
            .build(manager)
            .map_err(|e| AuditError::Database(format!("Pool: {}", e)))?;
        let db = pool
            .get()
            .map_err(|e| AuditError::Database(e.to_string()))?;
        db.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| AuditError::Database(e.to_string()))?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                model_name TEXT NOT NULL DEFAULT '',
                tier TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                cost_microdollars INTEGER NOT NULL DEFAULT 0,
                cache_status TEXT NOT NULL DEFAULT '',
                latency_ms INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 1,
                error_message TEXT,
                metadata TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_entries(event_type);",
        )
        .map_err(|e| AuditError::Database(e.to_string()))?;

        tracing::info!("Audit log initialized at {:?}", path);

        Ok(Self {
            pool,
            max_size_mb,
            retention_days,
        })
    }

    pub fn record(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let db = self
            .pool
            .get()
            .map_err(|e| AuditError::Lock(e.to_string()))?;

        let error_msg = entry.error_message.as_deref().map(redact_secrets);
        let metadata = redact_secrets(&entry.metadata);

        db.execute(
            "INSERT INTO audit_entries (timestamp, event_type, model_name, tier, platform,
             input_tokens, output_tokens, cost_microdollars, cache_status, latency_ms,
             success, error_message, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                entry.timestamp.to_rfc3339(),
                entry.event_type,
                entry.model_name,
                entry.tier,
                entry.platform,
                entry.input_tokens,
                entry.output_tokens,
                entry.cost_microdollars,
                entry.cache_status,
                entry.latency_ms,
                entry.success as i32,
                error_msg,
                metadata,
            ],
        )
        .map_err(|e| AuditError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get recent audit entries, most recent first.
    pub fn recent_entries(&self, limit: u32) -> Result<Vec<AuditEntry>, AuditError> {
        let db = self
            .pool
            .get()
            .map_err(|e| AuditError::Lock(e.to_string()))?;
        let mut stmt = db
            .prepare(
                "SELECT timestamp, event_type, model_name, tier, platform,
                    input_tokens, output_tokens, cost_microdollars, cache_status,
                    latency_ms, success, error_message, metadata
             FROM audit_entries ORDER BY timestamp DESC LIMIT ?1",
            )
            .map_err(|e| AuditError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(AuditEntry {
                    timestamp: row
                        .get::<_, String>(0)
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|d| d.with_timezone(&Utc))
                                .unwrap_or_else(|_| Utc::now())
                        })
                        .unwrap_or_else(|_| Utc::now()),
                    event_type: row.get(1)?,
                    model_name: row.get(2)?,
                    tier: row.get(3)?,
                    platform: row.get(4)?,
                    input_tokens: row.get::<_, i32>(5)? as u32,
                    output_tokens: row.get::<_, i32>(6)? as u32,
                    cost_microdollars: row.get::<_, i64>(7)? as u64,
                    cache_status: row.get(8)?,
                    latency_ms: row.get::<_, i64>(9)? as u64,
                    success: row.get::<_, i32>(10)? != 0,
                    error_message: row.get(11)?,
                    metadata: row.get(12)?,
                })
            })
            .map_err(|e| AuditError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| AuditError::Database(e.to_string()))?);
        }
        Ok(results)
    }

    /// Filter entries by date range.
    pub fn entries_between(
        &self,
        from: &str,
        to: &str,
        limit: u32,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let db = self
            .pool
            .get()
            .map_err(|e| AuditError::Lock(e.to_string()))?;
        let mut stmt = db
            .prepare(
                "SELECT timestamp, event_type, model_name, tier, platform,
                    input_tokens, output_tokens, cost_microdollars, cache_status,
                    latency_ms, success, error_message, metadata
             FROM audit_entries WHERE timestamp >= ?1 AND timestamp <= ?2
             ORDER BY timestamp DESC LIMIT ?3",
            )
            .map_err(|e| AuditError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![from, to, limit], |row| {
                Ok(AuditEntry {
                    timestamp: row
                        .get::<_, String>(0)
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|d| d.with_timezone(&Utc))
                                .unwrap_or_else(|_| Utc::now())
                        })
                        .unwrap_or_else(|_| Utc::now()),
                    event_type: row.get(1)?,
                    model_name: row.get(2)?,
                    tier: row.get(3)?,
                    platform: row.get(4)?,
                    input_tokens: row.get::<_, i32>(5)? as u32,
                    output_tokens: row.get::<_, i32>(6)? as u32,
                    cost_microdollars: row.get::<_, i64>(7)? as u64,
                    cache_status: row.get(8)?,
                    latency_ms: row.get::<_, i64>(9)? as u64,
                    success: row.get::<_, i32>(10)? != 0,
                    error_message: row.get(11)?,
                    metadata: row.get(12)?,
                })
            })
            .map_err(|e| AuditError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| AuditError::Database(e.to_string()))?);
        }
        Ok(results)
    }

    /// Prune old entries beyond retention period and size limit.
    pub fn prune(&self) -> Result<u64, AuditError> {
        let db = self
            .pool
            .get()
            .map_err(|e| AuditError::Lock(e.to_string()))?;

        // Prune by retention days
        let cutoff = Utc::now() - chrono::Duration::days(self.retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let deleted: usize = db
            .execute(
                "DELETE FROM audit_entries WHERE timestamp < ?1",
                params![cutoff_str],
            )
            .map_err(|e| AuditError::Database(e.to_string()))?;

        // Prune by size (approximate — check page_count * page_size)
        let page_count: i64 = db
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap_or(0);
        let page_size: i64 = db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .unwrap_or(4096);
        let size_mb = (page_count * page_size) as u64 / (1024 * 1024);

        let mut extra_deleted = 0usize;
        if size_mb > self.max_size_mb {
            extra_deleted = db
                .execute(
                    "DELETE FROM audit_entries WHERE id IN (
                    SELECT id FROM audit_entries ORDER BY timestamp ASC LIMIT 1000
                )",
                    [],
                )
                .map_err(|e| AuditError::Database(e.to_string()))?;
        }

        if deleted + extra_deleted > 0 {
            let _ = db.execute_batch("VACUUM;");
        }

        Ok((deleted + extra_deleted) as u64)
    }

    pub fn entry_count(&self) -> Result<u64, AuditError> {
        let db = self
            .pool
            .get()
            .map_err(|e| AuditError::Lock(e.to_string()))?;
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |r| r.get(0))
            .map_err(|e| AuditError::Database(e.to_string()))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_audit() -> AuditLog {
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("safeagent_audit_test_{}_{}.db", nanos, id));
        AuditLog::new(path, 30, 200).unwrap()
    }

    fn sample_entry(event: &str, success: bool) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now(),
            event_type: event.to_string(),
            model_name: "claude-haiku-4-5-20251001".to_string(),
            tier: "economy".to_string(),
            platform: "cli".to_string(),
            input_tokens: 500,
            output_tokens: 200,
            cost_microdollars: 1000,
            cache_status: "hit".to_string(),
            latency_ms: 300,
            success,
            error_message: None,
            metadata: "{}".to_string(),
        }
    }

    #[test]
    fn test_record_and_count() {
        let log = temp_audit();
        assert_eq!(log.entry_count().unwrap(), 0);
        log.record(&sample_entry("llm_request", true)).unwrap();
        log.record(&sample_entry("llm_request", true)).unwrap();
        assert_eq!(log.entry_count().unwrap(), 2);
    }

    #[test]
    fn test_recent_entries() {
        let log = temp_audit();
        log.record(&sample_entry("llm_request", true)).unwrap();
        log.record(&sample_entry("llm_error", false)).unwrap();

        let entries = log.recent_entries(10).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event_type, "llm_error");
    }

    #[test]
    fn test_secret_redaction() {
        assert_eq!(
            redact_secrets("key is sk-ant-abc123def456ghi789"),
            "key is sk-ant-****"
        );
        assert_eq!(
            redact_secrets("voyage pa-abcdef1234567890xyz"),
            "voyage pa-****"
        );
        // Telegram token pattern
        let redacted = redact_secrets("bot 123456789:ABCdefGHI_jklMNO12345");
        assert!(redacted.contains("****"));
        assert!(!redacted.contains("ABCdefGHI"));
    }

    #[test]
    fn test_error_message_redacted() {
        let log = temp_audit();
        let mut entry = sample_entry("llm_error", false);
        entry.error_message = Some("API error with key sk-ant-secret1234567890abc".to_string());
        log.record(&entry).unwrap();

        let entries = log.recent_entries(1).unwrap();
        let stored = &entries[0];
        assert!(stored
            .error_message
            .as_ref()
            .unwrap()
            .contains("sk-ant-****"));
        assert!(!stored
            .error_message
            .as_ref()
            .unwrap()
            .contains("secret1234567890abc"));
    }

    #[test]
    fn test_prune_empty() {
        let log = temp_audit();
        let pruned = log.prune().unwrap();
        assert_eq!(pruned, 0);
    }

    #[test]
    fn test_entries_between() {
        let log = temp_audit();
        log.record(&sample_entry("llm_request", true)).unwrap();

        let from = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let to = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let entries = log.entries_between(&from, &to, 100).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_concurrent_writes() {
        let log = std::sync::Arc::new(temp_audit());
        let mut handles = vec![];

        for _ in 0..20 {
            let l = log.clone();
            handles.push(std::thread::spawn(move || {
                l.record(&sample_entry("llm_request", true)).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(log.entry_count().unwrap(), 20);
    }
}
