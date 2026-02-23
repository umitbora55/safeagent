use chrono::Datelike;
use crate::{Permission, Skill, SkillConfig, SkillResult};
use crate::google_oauth::{OAuthTokens, get_valid_token};
use async_trait::async_trait;

/// Read events from Google Calendar (read-only).
pub struct CalendarReaderSkill {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    tokens: tokio::sync::RwLock<Option<OAuthTokens>>,
    config: SkillConfig,
}

impl CalendarReaderSkill {
    pub fn new(client_id: String, client_secret: String, tokens: Option<OAuthTokens>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            client_id,
            client_secret,
            tokens: tokio::sync::RwLock::new(tokens),
            config: SkillConfig::default(),
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    /// Update stored tokens (after refresh or initial auth).
    pub async fn set_tokens(&self, tokens: OAuthTokens) {
        let mut t = self.tokens.write().await;
        *t = Some(tokens);
    }

    /// Get current tokens.
    pub async fn get_tokens(&self) -> Option<OAuthTokens> {
        self.tokens.read().await.clone()
    }

    async fn get_access_token(&self) -> Result<String, String> {
        let current = self.tokens.read().await.clone();
        let current = current.ok_or("Google Calendar not authorized. Run `safeagent init` to connect.")?;

        let refreshed = get_valid_token(&self.client_id, &self.client_secret, &current).await?;
        let access_token = refreshed.access_token.clone();

        // Update stored tokens if refreshed
        if refreshed.expires_at != current.expires_at {
            let mut t = self.tokens.write().await;
            *t = Some(refreshed);
        }

        Ok(access_token)
    }
}

#[async_trait]
impl Skill for CalendarReaderSkill {
    fn id(&self) -> &str { "calendar_reader" }
    fn name(&self) -> &str { "Google Calendar Reader" }
    fn description(&self) -> &str {
        "Read events from Google Calendar. Input: 'today', 'tomorrow', 'this week', or a date like '2025-03-15'. Returns: list of events with time, title, and location."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission::read_calendar()] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err("Calendar reader skill is disabled".into());
        }

        let query = input.trim().to_lowercase();
        if query.is_empty() {
            return SkillResult::err("Empty query. Try: 'today', 'tomorrow', 'this week', or a date.".into());
        }

        let access_token = match self.get_access_token().await {
            Ok(t) => t,
            Err(e) => return SkillResult::err(e),
        };

        let (time_min, time_max) = parse_time_range(&query);

        let url = format!(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events?timeMin={}&timeMax={}&singleEvents=true&orderBy=startTime&maxResults=20",
            time_min, time_max
        );

        let resp = match self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SkillResult::err(format!("Calendar API request failed: {}", e)),
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return SkillResult::err(format!("Calendar API error {}: {}", status, body));
        }

        let data: serde_json::Value = match resp.json().await {
            Ok(d) => d,
            Err(e) => return SkillResult::err(format!("Failed to parse calendar response: {}", e)),
        };

        let events = data["items"].as_array();
        let output = match events {
            Some(items) if !items.is_empty() => {
                let mut text = format!("📅 {} event(s) found:\n\n", items.len());
                for item in items {
                    let summary = item["summary"].as_str().unwrap_or("(No title)");
                    let location = item["location"].as_str().unwrap_or("");
                    let start = item["start"]["dateTime"].as_str()
                        .or_else(|| item["start"]["date"].as_str())
                        .unwrap_or("?");
                    let end = item["end"]["dateTime"].as_str()
                        .or_else(|| item["end"]["date"].as_str())
                        .unwrap_or("?");
                    let status = item["status"].as_str().unwrap_or("");

                    let start_display = format_datetime(start);
                    let end_display = format_datetime(end);

                    text.push_str(&format!("• {} — {}\n", start_display, summary));
                    if !location.is_empty() {
                        text.push_str(&format!("  📍 {}\n", location));
                    }
                    if end != start {
                        text.push_str(&format!("  🕐 {} → {}\n", start_display, end_display));
                    }
                    if status == "cancelled" {
                        text.push_str("  ❌ Cancelled\n");
                    }
                    text.push('\n');
                }
                text
            }
            _ => "No events found for this period.".into(),
        };

        let count = events.map(|e| e.len()).unwrap_or(0);
        SkillResult::ok(output)
            .with_meta("query", &query)
            .with_meta("event_count", &count.to_string())
    }
}

/// Parse a natural language time query into RFC3339 time range.
fn parse_time_range(query: &str) -> (String, String) {
    let now = chrono::Utc::now();
    let today = now.date_naive();

    let (start_date, end_date) = match query {
        "today" | "bugun" | "bugün" => (today, today),
        "tomorrow" | "yarin" | "yarın" => {
            let tmrw = today + chrono::Duration::days(1);
            (tmrw, tmrw)
        }
        "this week" | "bu hafta" => {
            let weekday = today.weekday().num_days_from_monday();
            let monday = today - chrono::Duration::days(weekday as i64);
            let sunday = monday + chrono::Duration::days(6);
            (monday, sunday)
        }
        "next week" | "gelecek hafta" | "haftaya" => {
            let weekday = today.weekday().num_days_from_monday();
            let next_monday = today + chrono::Duration::days((7 - weekday) as i64);
            let next_sunday = next_monday + chrono::Duration::days(6);
            (next_monday, next_sunday)
        }
        _ => {
            // Try parsing as date
            if let Ok(date) = chrono::NaiveDate::parse_from_str(query, "%Y-%m-%d") {
                (date, date)
            } else {
                // Default to next 7 days
                (today, today + chrono::Duration::days(7))
            }
        }
    };

    let time_min = format!("{}T00:00:00Z", start_date);
    let time_max = format!("{}T23:59:59Z", end_date);
    (time_min, time_max)
}

/// Format an RFC3339 or date string into a readable format.
fn format_datetime(dt: &str) -> String {
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(dt) {
        parsed.format("%H:%M").to_string()
    } else if dt.len() == 10 {
        // All-day event (just a date)
        "All day".to_string()
    } else {
        dt.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_today() {
        let (min, max) = parse_time_range("today");
        assert!(min.contains("T00:00:00Z"));
        assert!(max.contains("T23:59:59Z"));
    }

    #[test]
    fn test_parse_tomorrow() {
        let (min, max) = parse_time_range("tomorrow");
        assert!(min.contains("T00:00:00Z"));
        assert!(max.contains("T23:59:59Z"));
        assert_ne!(min, parse_time_range("today").0);
    }

    #[test]
    fn test_parse_this_week() {
        let (min, max) = parse_time_range("this week");
        assert!(min < max);
    }

    #[test]
    fn test_parse_specific_date() {
        let (min, max) = parse_time_range("2025-06-15");
        assert!(min.contains("2025-06-15"));
        assert!(max.contains("2025-06-15"));
    }

    #[test]
    fn test_parse_turkish() {
        let (min, _) = parse_time_range("bugün");
        let (min2, _) = parse_time_range("today");
        assert_eq!(min, min2);
    }

    #[test]
    fn test_format_datetime() {
        assert_eq!(format_datetime("2025-03-15T14:30:00+03:00"), "14:30");
        assert_eq!(format_datetime("2025-03-15"), "All day");
    }

    #[test]
    fn test_no_tokens() {
        let skill = CalendarReaderSkill::new("id".into(), "secret".into(), None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("today"));
        assert!(!result.success);
        assert!(result.output.contains("not authorized"));
    }

    #[test]
    fn test_disabled() {
        let config = SkillConfig { enabled: false, ..Default::default() };
        let skill = CalendarReaderSkill::new("id".into(), "secret".into(), None).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("today"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_empty_query() {
        let skill = CalendarReaderSkill::new("id".into(), "secret".into(), None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }
}
