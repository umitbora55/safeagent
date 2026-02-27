use chrono::{DateTime, Datelike, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEntry {
    pub timestamp: DateTime<Utc>,
    pub model_name: String,
    pub tier: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_read_tokens: u32,
    pub cache_write_tokens: u32,
    pub cost_microdollars: u64,
    pub cache_status: String,
    pub platform: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CostSummary {
    pub total_requests: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_microdollars: u64,
    pub total_cache_read_tokens: u64,
    pub total_cache_write_tokens: u64,
}

impl CostSummary {
    pub fn cost_usd(&self) -> f64 {
        self.total_cost_microdollars as f64 / 1_000_000.0
    }
}

#[derive(Debug, Clone)]
pub struct ModelCostBreakdown {
    pub model_name: String,
    pub request_count: u64,
    pub total_cost_microdollars: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
}

impl ModelCostBreakdown {
    pub fn cost_usd(&self) -> f64 {
        self.total_cost_microdollars as f64 / 1_000_000.0
    }
}

#[derive(Debug, Clone)]
pub struct DailyCost {
    pub date: String,
    pub request_count: u64,
    pub total_cost_microdollars: u64,
}

impl DailyCost {
    pub fn cost_usd(&self) -> f64 {
        self.total_cost_microdollars as f64 / 1_000_000.0
    }
}

pub struct CostLedger {
    pool: Pool<SqliteConnectionManager>,
}

#[derive(Debug)]
pub enum LedgerError {
    Database(String),
    Lock(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Database(msg) => write!(f, "Ledger DB error: {}", msg),
            LedgerError::Lock(msg) => write!(f, "Ledger lock error: {}", msg),
        }
    }
}

impl std::error::Error for LedgerError {}

impl CostLedger {
    pub fn new(path: PathBuf) -> Result<Self, LedgerError> {
        let manager = SqliteConnectionManager::file(&path);
        let pool = Pool::builder()
            .max_size(10)
            .build(manager)
            .map_err(|e| LedgerError::Database(format!("Pool: {}", e)))?;
        let db = pool
            .get()
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        db.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS cost_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                model_name TEXT NOT NULL,
                tier TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cache_read_tokens INTEGER NOT NULL DEFAULT 0,
                cache_write_tokens INTEGER NOT NULL DEFAULT 0,
                cost_microdollars INTEGER NOT NULL,
                cache_status TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL DEFAULT 'cli',
                latency_ms INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_cost_timestamp ON cost_entries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_cost_model ON cost_entries(model_name);",
        )
        .map_err(|e| LedgerError::Database(e.to_string()))?;

        tracing::info!("Cost ledger initialized at {:?}", path);

        Ok(Self { pool })
    }

    pub fn record(&self, entry: &CostEntry) -> Result<(), LedgerError> {
        let db = self
            .pool
            .get()
            .map_err(|e| LedgerError::Lock(e.to_string()))?;
        db.execute(
            "INSERT INTO cost_entries (timestamp, model_name, tier, input_tokens, output_tokens,
             cache_read_tokens, cache_write_tokens, cost_microdollars, cache_status, platform, latency_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                entry.timestamp.to_rfc3339(),
                entry.model_name,
                entry.tier,
                entry.input_tokens,
                entry.output_tokens,
                entry.cache_read_tokens,
                entry.cache_write_tokens,
                entry.cost_microdollars,
                entry.cache_status,
                entry.platform,
                entry.latency_ms,
            ],
        ).map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn today_summary(&self) -> Result<CostSummary, LedgerError> {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        self.summary_since(&format!("{}T00:00:00", today))
    }

    pub fn week_summary(&self) -> Result<CostSummary, LedgerError> {
        let now = Utc::now().naive_utc().date();
        let weekday = now.weekday().num_days_from_monday();
        let monday = now - chrono::Duration::days(weekday as i64);
        self.summary_since(&format!("{}T00:00:00", monday))
    }

    pub fn month_summary(&self) -> Result<CostSummary, LedgerError> {
        let now = Utc::now();
        let first = format!("{}-{:02}-01T00:00:00", now.format("%Y"), now.format("%m"));
        self.summary_since(&first)
    }

    pub fn total_summary(&self) -> Result<CostSummary, LedgerError> {
        self.summary_since("1970-01-01T00:00:00")
    }

    fn summary_since(&self, since: &str) -> Result<CostSummary, LedgerError> {
        let db = self
            .pool
            .get()
            .map_err(|e| LedgerError::Lock(e.to_string()))?;
        let mut stmt = db
            .prepare(
                "SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
                    COALESCE(SUM(cost_microdollars),0), COALESCE(SUM(cache_read_tokens),0),
                    COALESCE(SUM(cache_write_tokens),0)
             FROM cost_entries WHERE timestamp >= ?1",
            )
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let summary = stmt
            .query_row(params![since], |row| {
                Ok(CostSummary {
                    total_requests: row.get::<_, i64>(0)? as u64,
                    total_input_tokens: row.get::<_, i64>(1)? as u64,
                    total_output_tokens: row.get::<_, i64>(2)? as u64,
                    total_cost_microdollars: row.get::<_, i64>(3)? as u64,
                    total_cache_read_tokens: row.get::<_, i64>(4)? as u64,
                    total_cache_write_tokens: row.get::<_, i64>(5)? as u64,
                })
            })
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        Ok(summary)
    }

    pub fn model_breakdown_since(
        &self,
        since: &str,
    ) -> Result<Vec<ModelCostBreakdown>, LedgerError> {
        let db = self
            .pool
            .get()
            .map_err(|e| LedgerError::Lock(e.to_string()))?;
        let mut stmt = db
            .prepare(
                "SELECT model_name, COUNT(*), COALESCE(SUM(cost_microdollars),0),
                    COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)
             FROM cost_entries WHERE timestamp >= ?1
             GROUP BY model_name ORDER BY SUM(cost_microdollars) DESC",
            )
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![since], |row| {
                Ok(ModelCostBreakdown {
                    model_name: row.get(0)?,
                    request_count: row.get::<_, i64>(1)? as u64,
                    total_cost_microdollars: row.get::<_, i64>(2)? as u64,
                    total_input_tokens: row.get::<_, i64>(3)? as u64,
                    total_output_tokens: row.get::<_, i64>(4)? as u64,
                })
            })
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| LedgerError::Database(e.to_string()))?);
        }
        Ok(results)
    }

    pub fn daily_costs(&self, days: u32) -> Result<Vec<DailyCost>, LedgerError> {
        let since = Utc::now() - chrono::Duration::days(days as i64);
        let since_str = since.format("%Y-%m-%dT00:00:00").to_string();

        let db = self
            .pool
            .get()
            .map_err(|e| LedgerError::Lock(e.to_string()))?;
        let mut stmt = db
            .prepare(
                "SELECT DATE(timestamp) as day, COUNT(*), COALESCE(SUM(cost_microdollars),0)
             FROM cost_entries WHERE timestamp >= ?1
             GROUP BY day ORDER BY day ASC",
            )
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![since_str], |row| {
                Ok(DailyCost {
                    date: row.get(0)?,
                    request_count: row.get::<_, i64>(1)? as u64,
                    total_cost_microdollars: row.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| LedgerError::Database(e.to_string()))?);
        }
        Ok(results)
    }

    pub fn entry_count(&self) -> Result<u64, LedgerError> {
        let db = self
            .pool
            .get()
            .map_err(|e| LedgerError::Lock(e.to_string()))?;
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM cost_entries", [], |row| row.get(0))
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_ledger() -> CostLedger {
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("safeagent_ledger_test_{}_{}.db", nanos, id));
        CostLedger::new(path).unwrap()
    }

    fn sample_entry(model: &str, cost: u64) -> CostEntry {
        CostEntry {
            timestamp: Utc::now(),
            model_name: model.to_string(),
            tier: "standard".to_string(),
            input_tokens: 500,
            output_tokens: 200,
            cache_read_tokens: 100,
            cache_write_tokens: 0,
            cost_microdollars: cost,
            cache_status: "hit".to_string(),
            platform: "cli".to_string(),
            latency_ms: 450,
        }
    }

    #[test]
    fn test_record_and_count() {
        let ledger = temp_ledger();
        assert_eq!(ledger.entry_count().unwrap(), 0);
        ledger.record(&sample_entry("haiku", 1000)).unwrap();
        ledger.record(&sample_entry("sonnet", 5000)).unwrap();
        assert_eq!(ledger.entry_count().unwrap(), 2);
    }

    #[test]
    fn test_today_summary() {
        let ledger = temp_ledger();
        ledger.record(&sample_entry("haiku", 1000)).unwrap();
        ledger.record(&sample_entry("sonnet", 5000)).unwrap();
        ledger.record(&sample_entry("haiku", 2000)).unwrap();

        let summary = ledger.today_summary().unwrap();
        assert_eq!(summary.total_requests, 3);
        assert_eq!(summary.total_cost_microdollars, 8000);
        assert_eq!(summary.total_input_tokens, 1500);
        assert_eq!(summary.total_output_tokens, 600);
    }

    #[test]
    fn test_total_summary() {
        let ledger = temp_ledger();
        ledger.record(&sample_entry("opus", 15000)).unwrap();

        let summary = ledger.total_summary().unwrap();
        assert_eq!(summary.total_requests, 1);
        assert_eq!(summary.total_cost_microdollars, 15000);
        assert_eq!(summary.cost_usd(), 0.015);
    }

    #[test]
    fn test_model_breakdown() {
        let ledger = temp_ledger();
        ledger.record(&sample_entry("haiku", 1000)).unwrap();
        ledger.record(&sample_entry("haiku", 2000)).unwrap();
        ledger.record(&sample_entry("sonnet", 5000)).unwrap();

        let breakdown = ledger.model_breakdown_since("1970-01-01T00:00:00").unwrap();
        assert_eq!(breakdown.len(), 2);
        assert_eq!(breakdown[0].model_name, "sonnet");
        assert_eq!(breakdown[0].request_count, 1);
        assert_eq!(breakdown[1].model_name, "haiku");
        assert_eq!(breakdown[1].request_count, 2);
        assert_eq!(breakdown[1].total_cost_microdollars, 3000);
    }

    #[test]
    fn test_daily_costs() {
        let ledger = temp_ledger();
        ledger.record(&sample_entry("haiku", 1000)).unwrap();
        ledger.record(&sample_entry("sonnet", 5000)).unwrap();

        let daily = ledger.daily_costs(7).unwrap();
        assert_eq!(daily.len(), 1);
        assert_eq!(daily[0].request_count, 2);
        assert_eq!(daily[0].total_cost_microdollars, 6000);
    }

    #[test]
    fn test_empty_ledger() {
        let ledger = temp_ledger();
        let summary = ledger.today_summary().unwrap();
        assert_eq!(summary.total_requests, 0);
        assert_eq!(summary.total_cost_microdollars, 0);
    }

    #[test]
    fn test_week_and_month_summary() {
        let ledger = temp_ledger();
        ledger.record(&sample_entry("haiku", 3000)).unwrap();

        let week = ledger.week_summary().unwrap();
        assert_eq!(week.total_requests, 1);

        let month = ledger.month_summary().unwrap();
        assert_eq!(month.total_requests, 1);
    }

    #[test]
    fn test_cache_tokens_tracked() {
        let ledger = temp_ledger();
        let mut entry = sample_entry("sonnet", 4000);
        entry.cache_read_tokens = 300;
        entry.cache_write_tokens = 150;
        ledger.record(&entry).unwrap();

        let summary = ledger.today_summary().unwrap();
        assert_eq!(summary.total_cache_read_tokens, 300);
        assert_eq!(summary.total_cache_write_tokens, 150);
    }

    #[test]
    fn test_concurrent_writes() {
        let ledger = std::sync::Arc::new(temp_ledger());
        let mut handles = vec![];

        for i in 0..20 {
            let l = ledger.clone();
            handles.push(std::thread::spawn(move || {
                l.record(&sample_entry("haiku", (i + 1) * 100)).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(ledger.entry_count().unwrap(), 20);
        let summary = ledger.total_summary().unwrap();
        assert_eq!(summary.total_cost_microdollars, 21000);
    }
}
