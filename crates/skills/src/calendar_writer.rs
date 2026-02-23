// chrono::Datelike not needed here
use crate::{Permission, Skill, SkillConfig, SkillResult};
use crate::google_oauth::{OAuthTokens, get_valid_token};
use async_trait::async_trait;

/// Create events in Google Calendar.
/// Requires confirmation + daily limit.
pub struct CalendarWriterSkill {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    tokens: tokio::sync::RwLock<Option<OAuthTokens>>,
    daily_limit: u32,
    events_created_today: std::sync::atomic::AtomicU32,
    config: SkillConfig,
}

impl CalendarWriterSkill {
    pub fn new(client_id: String, client_secret: String, tokens: Option<OAuthTokens>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            client_id,
            client_secret,
            tokens: tokio::sync::RwLock::new(tokens),
            daily_limit: 10,
            events_created_today: std::sync::atomic::AtomicU32::new(0),
            config: SkillConfig { enabled: false, ..Default::default() }, // disabled by default
        }
    }

    pub fn with_daily_limit(mut self, limit: u32) -> Self {
        self.daily_limit = limit;
        self
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    pub async fn set_tokens(&self, tokens: OAuthTokens) {
        let mut t = self.tokens.write().await;
        *t = Some(tokens);
    }

    async fn get_access_token(&self) -> Result<String, String> {
        let current = self.tokens.read().await.clone();
        let current = current.ok_or("Google Calendar not authorized. Run `safeagent init` to connect.")?;

        let refreshed = get_valid_token(&self.client_id, &self.client_secret, &current).await?;
        let access_token = refreshed.access_token.clone();

        if refreshed.expires_at != current.expires_at {
            let mut t = self.tokens.write().await;
            *t = Some(refreshed);
        }

        Ok(access_token)
    }
}

#[async_trait]
impl Skill for CalendarWriterSkill {
    fn id(&self) -> &str { "calendar_writer" }
    fn name(&self) -> &str { "Google Calendar Writer" }
    fn description(&self) -> &str {
        "Create an event in Google Calendar. Input format:\n\
         title: Meeting with Bob\n\
         date: 2025-03-20\n\
         start: 14:00\n\
         end: 15:00\n\
         location: Office (optional)\n\
         description: Discuss Q1 results (optional)"
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission("write:calendar".into())] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err(
                "Calendar writer is disabled by default. Enable in safeagent.toml:\n\
                 [skills.calendar_writer]\n\
                 enabled = true".into()
            );
        }

        // Check daily limit
        let count = self.events_created_today.load(std::sync::atomic::Ordering::Relaxed);
        if count >= self.daily_limit {
            return SkillResult::err(format!(
                "Daily event creation limit reached ({}/{}). Resets at midnight.",
                count, self.daily_limit
            ));
        }

        // Parse input
        let event = match parse_event_input(input) {
            Ok(e) => e,
            Err(e) => return SkillResult::err(e),
        };

        let access_token = match self.get_access_token().await {
            Ok(t) => t,
            Err(e) => return SkillResult::err(e),
        };

        // Build Google Calendar event body
        let body = serde_json::json!({
            "summary": event.title,
            "location": event.location.unwrap_or_default(),
            "description": event.description.unwrap_or_default(),
            "start": {
                "dateTime": format!("{}T{}:00", event.date, event.start_time),
                "timeZone": "UTC"
            },
            "end": {
                "dateTime": format!("{}T{}:00", event.date, event.end_time),
                "timeZone": "UTC"
            }
        });

        let resp = match self.client
            .post("https://www.googleapis.com/calendar/v3/calendars/primary/events")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json")
            .json(&body)
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
            Err(e) => return SkillResult::err(format!("Failed to parse response: {}", e)),
        };

        self.events_created_today.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let event_link = data["htmlLink"].as_str().unwrap_or("");
        SkillResult::ok(format!(
            "✅ Event created: {} on {} {}-{}\n📎 {}",
            event.title, event.date, event.start_time, event.end_time, event_link
        ))
        .with_meta("event_id", data["id"].as_str().unwrap_or(""))
        .with_meta("link", event_link)
    }
}

#[derive(Debug)]
struct ParsedEvent {
    title: String,
    date: String,
    start_time: String,
    end_time: String,
    location: Option<String>,
    description: Option<String>,
}

fn parse_event_input(input: &str) -> Result<ParsedEvent, String> {
    let mut title = None;
    let mut date = None;
    let mut start = None;
    let mut end = None;
    let mut location = None;
    let mut description = None;

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();

            match key.as_str() {
                "title" | "baslik" | "başlık" => title = Some(value),
                "date" | "tarih" => date = Some(value),
                "start" | "baslangic" | "başlangıç" => start = Some(value),
                "end" | "bitis" | "bitiş" => end = Some(value),
                "location" | "konum" | "yer" => location = Some(value),
                "description" | "aciklama" | "açıklama" => description = Some(value),
                _ => {}
            }
        }
    }

    let title = title.ok_or("Missing 'title' field")?;
    let date = date.ok_or("Missing 'date' field (format: YYYY-MM-DD)")?;
    let start_time = start.ok_or("Missing 'start' field (format: HH:MM)")?;
    let end_time = end.ok_or("Missing 'end' field (format: HH:MM)")?;

    // Validate date format
    if chrono::NaiveDate::parse_from_str(&date, "%Y-%m-%d").is_err() {
        return Err(format!("Invalid date '{}'. Expected format: YYYY-MM-DD", date));
    }

    // Validate time format
    if chrono::NaiveTime::parse_from_str(&start_time, "%H:%M").is_err() {
        return Err(format!("Invalid start time '{}'. Expected format: HH:MM", start_time));
    }
    if chrono::NaiveTime::parse_from_str(&end_time, "%H:%M").is_err() {
        return Err(format!("Invalid end time '{}'. Expected format: HH:MM", end_time));
    }

    Ok(ParsedEvent { title, date, start_time, end_time, location, description })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_event_valid() {
        let input = "title: Team Meeting\ndate: 2025-03-20\nstart: 14:00\nend: 15:30\nlocation: Room A";
        let event = parse_event_input(input).unwrap();
        assert_eq!(event.title, "Team Meeting");
        assert_eq!(event.date, "2025-03-20");
        assert_eq!(event.start_time, "14:00");
        assert_eq!(event.end_time, "15:30");
        assert_eq!(event.location.unwrap(), "Room A");
    }

    #[test]
    fn test_parse_event_turkish() {
        let input = "başlık: Toplantı\ntarih: 2025-04-01\nbaşlangıç: 09:00\nbitiş: 10:00\nkonum: Ofis";
        let event = parse_event_input(input).unwrap();
        assert_eq!(event.title, "Toplantı");
        assert_eq!(event.location.unwrap(), "Ofis");
    }

    #[test]
    fn test_parse_event_missing_title() {
        let input = "date: 2025-03-20\nstart: 14:00\nend: 15:00";
        let result = parse_event_input(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("title"));
    }

    #[test]
    fn test_parse_event_invalid_date() {
        let input = "title: Test\ndate: not-a-date\nstart: 14:00\nend: 15:00";
        let result = parse_event_input(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid date"));
    }

    #[test]
    fn test_parse_event_invalid_time() {
        let input = "title: Test\ndate: 2025-03-20\nstart: 25:00\nend: 15:00";
        let result = parse_event_input(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid start time"));
    }

    #[test]
    fn test_disabled_by_default() {
        let skill = CalendarWriterSkill::new("id".into(), "secret".into(), None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("title: Test\ndate: 2025-03-20\nstart: 14:00\nend: 15:00"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_daily_limit() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = CalendarWriterSkill::new("id".into(), "secret".into(), None)
            .with_daily_limit(2)
            .with_config(config);

        // Simulate hitting the limit
        skill.events_created_today.store(2, std::sync::atomic::Ordering::Relaxed);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("title: Test\ndate: 2025-03-20\nstart: 14:00\nend: 15:00"));
        assert!(!result.success);
        assert!(result.output.contains("limit reached"));
    }
}
