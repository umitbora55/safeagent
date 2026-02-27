use serde::{Deserialize, Serialize};
use std::path::Path;

/// Root configuration — parsed from safeagent.toml
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SafeAgentConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub router: RouterConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub platforms: PlatformsConfig,
    #[serde(default)]
    pub skills: SkillsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub log_level: String,
    pub data_dir: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            data_dir: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    pub mode: String,
    pub confidence_preset: String,
    pub confidence_threshold: Option<f64>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            mode: "balanced".into(),
            confidence_preset: "balanced".into(),
            confidence_threshold: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LimitsConfig {
    /// Daily spend limit in USD (e.g. 5.0 = $5)
    pub daily_spend_usd: Option<f64>,
    /// Monthly spend limit in USD
    pub monthly_spend_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformsConfig {
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    #[serde(default)]
    pub discord: Option<DiscordConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    pub enabled: bool,
}

/// Skills configuration — each skill has its own section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SkillsConfig {
    #[serde(default)]
    pub web_search: Option<SkillEntry>,
    #[serde(default)]
    pub url_fetcher: Option<SkillEntry>,
    #[serde(default)]
    pub file_reader: Option<FileReaderEntry>,
    #[serde(default)]
    pub file_writer: Option<FileWriterEntry>,
    #[serde(default)]
    pub calendar_reader: Option<SkillEntry>,
    #[serde(default)]
    pub calendar_writer: Option<CalendarWriterEntry>,
    #[serde(default)]
    pub email_reader: Option<SkillEntry>,
    #[serde(default)]
    pub email_sender: Option<EmailSenderEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillEntry {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_max_response")]
    pub max_response_bytes: usize,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl Default for SkillEntry {
    fn default() -> Self {
        Self {
            enabled: false,
            permissions: vec![],
            rate_limit_per_minute: 10,
            max_response_bytes: 1_048_576,
            timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReaderEntry {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_dirs: Vec<String>,
    #[serde(default = "default_max_response")]
    pub max_response_bytes: usize,
}

impl Default for FileReaderEntry {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_dirs: vec![],
            max_response_bytes: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWriterEntry {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_dirs: Vec<String>,
    #[serde(default = "default_false")]
    pub allow_overwrite: bool,
    #[serde(default = "default_max_response")]
    pub max_response_bytes: usize,
}

impl Default for FileWriterEntry {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_dirs: vec![],
            allow_overwrite: false,
            max_response_bytes: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarWriterEntry {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_daily_limit_10")]
    pub daily_limit: u32,
}

impl Default for CalendarWriterEntry {
    fn default() -> Self {
        Self {
            enabled: false,
            daily_limit: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSenderEntry {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_recipients: Vec<String>,
    #[serde(default = "default_daily_limit_20")]
    pub daily_limit: u32,
    #[serde(default = "default_true")]
    pub require_confirmation: bool,
}

impl Default for EmailSenderEntry {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_recipients: vec![],
            daily_limit: 20,
            require_confirmation: true,
        }
    }
}

fn default_false() -> bool {
    false
}
fn default_true() -> bool {
    true
}
fn default_rate_limit() -> u32 {
    10
}
fn default_max_response() -> usize {
    1_048_576
}
fn default_timeout() -> u64 {
    30
}
fn default_daily_limit_10() -> u32 {
    10
}
fn default_daily_limit_20() -> u32 {
    20
}

impl SafeAgentConfig {
    /// Load config from a TOML file. Returns default config if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        toml::from_str(&content).map_err(|e| format!("Failed to parse config file: {}", e))
    }

    /// Save config to a TOML file.
    #[allow(dead_code)]
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        std::fs::write(path, content).map_err(|e| format!("Failed to write config file: {}", e))
    }

    /// Generate a default config file with comments.
    #[allow(dead_code)]
    pub fn generate_default_toml() -> String {
        r#"# SafeAgent Configuration
# See docs/troubleshooting.md for help

[general]
log_level = "info"
# data_dir = "~/.local/share/safeagent"

[router]
mode = "balanced"             # economy | balanced | performance
confidence_preset = "balanced" # conservative | balanced | aggressive
# confidence_threshold = 0.012  # manual override

[limits]
# daily_spend_usd = 5.0
# monthly_spend_usd = 50.0

[platforms.telegram]
enabled = true

# [platforms.discord]
# enabled = false

# ─── Read-Only Skills ───────────────────────

[skills.web_search]
enabled = true
rate_limit_per_minute = 10

[skills.url_fetcher]
enabled = true
max_response_bytes = 1048576  # 1MB

[skills.file_reader]
enabled = false
allowed_dirs = []             # e.g. ["/home/user/documents"]

[skills.calendar_reader]
enabled = false               # requires Google OAuth setup

[skills.email_reader]
enabled = false               # requires Google OAuth setup

# ─── Write Skills (deny-all by default) ─────

[skills.file_writer]
enabled = false
allowed_dirs = []
allow_overwrite = false       # create-only mode

[skills.calendar_writer]
enabled = false
daily_limit = 10

[skills.email_sender]
enabled = false
allowed_recipients = []       # e.g. ["*@yourcompany.com", "friend@gmail.com"]
daily_limit = 20
require_confirmation = true
"#
        .to_string()
    }

    /// Convert limits to microdollars for policy engine.
    pub fn daily_spend_limit_microdollars(&self) -> Option<u64> {
        self.limits
            .daily_spend_usd
            .map(|usd| (usd * 1_000_000.0) as u64)
    }

    pub fn monthly_spend_limit_microdollars(&self) -> Option<u64> {
        self.limits
            .monthly_spend_usd
            .map(|usd| (usd * 1_000_000.0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SafeAgentConfig::default();
        assert_eq!(config.general.log_level, "info");
        assert_eq!(config.router.mode, "balanced");
        assert!(config.limits.daily_spend_usd.is_none());
        assert!(config.skills.web_search.is_none());
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml_str = r#"
[general]
log_level = "debug"

[limits]
daily_spend_usd = 5.0
"#;
        let config: SafeAgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.general.log_level, "debug");
        assert_eq!(config.limits.daily_spend_usd, Some(5.0));
    }

    #[test]
    fn test_parse_skills_config() {
        let toml_str = r#"
[skills.web_search]
enabled = true
rate_limit_per_minute = 20

[skills.file_writer]
enabled = true
allowed_dirs = ["/tmp/safe"]
allow_overwrite = false

[skills.email_sender]
enabled = true
allowed_recipients = ["*@company.com", "boss@other.com"]
daily_limit = 10
require_confirmation = true
"#;
        let config: SafeAgentConfig = toml::from_str(toml_str).unwrap();

        let ws = config.skills.web_search.unwrap();
        assert!(ws.enabled);
        assert_eq!(ws.rate_limit_per_minute, 20);

        let fw = config.skills.file_writer.unwrap();
        assert!(fw.enabled);
        assert_eq!(fw.allowed_dirs, vec!["/tmp/safe"]);
        assert!(!fw.allow_overwrite);

        let es = config.skills.email_sender.unwrap();
        assert!(es.enabled);
        assert_eq!(es.allowed_recipients.len(), 2);
        assert_eq!(es.daily_limit, 10);
    }

    #[test]
    fn test_microdollar_conversion() {
        let config = SafeAgentConfig {
            limits: LimitsConfig {
                daily_spend_usd: Some(5.0),
                monthly_spend_usd: Some(50.0),
            },
            ..Default::default()
        };
        assert_eq!(config.daily_spend_limit_microdollars(), Some(5_000_000));
        assert_eq!(config.monthly_spend_limit_microdollars(), Some(50_000_000));
    }

    #[test]
    fn test_generate_default_toml() {
        let toml = SafeAgentConfig::generate_default_toml();
        assert!(toml.contains("[general]"));
        assert!(toml.contains("[skills.web_search]"));
        assert!(toml.contains("[skills.email_sender]"));
        assert!(toml.contains("deny-all"));
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = SafeAgentConfig::load(Path::new("/nonexistent/safeagent.toml")).unwrap();
        assert_eq!(config.general.log_level, "info");
    }

    #[test]
    fn test_save_and_load() {
        let dir = std::env::temp_dir().join(format!(
            "safeagent_config_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("safeagent.toml");

        let mut config = SafeAgentConfig::default();
        config.limits.daily_spend_usd = Some(10.0);
        config.save(&path).unwrap();

        let loaded = SafeAgentConfig::load(&path).unwrap();
        assert_eq!(loaded.limits.daily_spend_usd, Some(10.0));

        std::fs::remove_dir_all(&dir).ok();
    }
}
