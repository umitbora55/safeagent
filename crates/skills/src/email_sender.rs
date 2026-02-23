use crate::{Permission, Skill, SkillConfig, SkillResult};
use crate::google_oauth::{OAuthTokens, get_valid_token};
use async_trait::async_trait;
use base64::Engine;

/// Send emails via Gmail API.
/// Requires confirmation + recipient allowlist.
pub struct EmailSenderSkill {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    tokens: tokio::sync::RwLock<Option<OAuthTokens>>,
    allowed_recipients: Vec<String>,
    daily_limit: u32,
    emails_sent_today: std::sync::atomic::AtomicU32,
    config: SkillConfig,
}

impl EmailSenderSkill {
    pub fn new(client_id: String, client_secret: String, tokens: Option<OAuthTokens>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            client_id,
            client_secret,
            tokens: tokio::sync::RwLock::new(tokens),
            allowed_recipients: vec![], // deny-all by default
            daily_limit: 20,
            emails_sent_today: std::sync::atomic::AtomicU32::new(0),
            config: SkillConfig { enabled: false, ..Default::default() }, // disabled by default
        }
    }

    pub fn with_allowed_recipients(mut self, recipients: Vec<String>) -> Self {
        self.allowed_recipients = recipients;
        self
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
        let current = current.ok_or("Gmail not authorized. Run `safeagent init` to connect.")?;

        let refreshed = get_valid_token(&self.client_id, &self.client_secret, &current).await?;
        let access_token = refreshed.access_token.clone();

        if refreshed.expires_at != current.expires_at {
            let mut t = self.tokens.write().await;
            *t = Some(refreshed);
        }

        Ok(access_token)
    }

    /// Check if recipient is in allowlist. Supports exact email or domain wildcard.
    fn is_recipient_allowed(&self, email: &str) -> bool {
        if self.allowed_recipients.is_empty() {
            return false; // deny-all when empty
        }

        let email_lower = email.to_lowercase();

        for allowed in &self.allowed_recipients {
            let allowed_lower = allowed.to_lowercase();

            // Exact match
            if email_lower == allowed_lower {
                return true;
            }

            // Domain wildcard: "*@domain.com"
            if allowed_lower.starts_with("*@") {
                let domain = &allowed_lower[1..]; // "@domain.com"
                if email_lower.ends_with(domain) {
                    return true;
                }
            }
        }

        false
    }
}

#[async_trait]
impl Skill for EmailSenderSkill {
    fn id(&self) -> &str { "email_sender" }
    fn name(&self) -> &str { "Gmail Sender" }
    fn description(&self) -> &str {
        "Send an email via Gmail. Input format:\n\
         to: recipient@example.com\n\
         subject: Hello\n\
         ---\n\
         Email body here."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission::write_email()] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err(
                "Email sender is disabled by default. Enable in safeagent.toml:\n\
                 [skills.email_sender]\n\
                 enabled = true\n\
                 allowed_recipients = [\"*@yourdomain.com\"]".into()
            );
        }

        // Check daily limit
        let count = self.emails_sent_today.load(std::sync::atomic::Ordering::Relaxed);
        if count >= self.daily_limit {
            return SkillResult::err(format!(
                "Daily email limit reached ({}/{}). Resets at midnight.",
                count, self.daily_limit
            ));
        }

        // Parse input
        let email = match parse_email_input(input) {
            Ok(e) => e,
            Err(e) => return SkillResult::err(e),
        };

        // Check recipient allowlist
        if !self.is_recipient_allowed(&email.to) {
            return SkillResult::err(format!(
                "Recipient '{}' is not in the allowlist. Configure allowed_recipients in safeagent.toml.\n\
                 Current allowlist: {:?}",
                email.to, self.allowed_recipients
            ));
        }

        let access_token = match self.get_access_token().await {
            Ok(t) => t,
            Err(e) => return SkillResult::err(e),
        };

        // Build RFC 2822 message
        let raw_message = format!(
            "To: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
            email.to, email.subject, email.body
        );

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_message.as_bytes());

        let body = serde_json::json!({ "raw": encoded });

        let resp = match self.client
            .post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SkillResult::err(format!("Gmail API request failed: {}", e)),
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return SkillResult::err(format!("Gmail API error {}: {}", status, body));
        }

        self.emails_sent_today.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let sent_count = self.emails_sent_today.load(std::sync::atomic::Ordering::Relaxed);
        SkillResult::ok(format!(
            "✅ Email sent to {} — \"{}\" ({}/{}  daily limit)",
            email.to, email.subject, sent_count, self.daily_limit
        ))
        .with_meta("to", &email.to)
        .with_meta("subject", &email.subject)
    }
}

#[derive(Debug)]
struct ParsedEmail {
    to: String,
    subject: String,
    body: String,
}

fn parse_email_input(input: &str) -> Result<ParsedEmail, String> {
    let parts: Vec<&str> = input.splitn(2, "\n---\n").collect();
    if parts.len() != 2 {
        return Err(
            "Invalid format. Expected:\nto: recipient@email.com\nsubject: Subject line\n---\nBody text".into()
        );
    }

    let headers = parts[0];
    let body = parts[1].trim().to_string();

    if body.is_empty() {
        return Err("Email body is empty".into());
    }

    let mut to = None;
    let mut subject = None;

    for line in headers.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();

            match key.as_str() {
                "to" | "kime" => to = Some(value),
                "subject" | "konu" => subject = Some(value),
                _ => {}
            }
        }
    }

    let to = to.ok_or("Missing 'to' field")?;
    let subject = subject.ok_or("Missing 'subject' field")?;

    // Basic email validation
    if !to.contains('@') || !to.contains('.') {
        return Err(format!("Invalid email address: {}", to));
    }

    Ok(ParsedEmail { to, subject, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_email_valid() {
        let input = "to: alice@example.com\nsubject: Hello\n---\nHi Alice!";
        let email = parse_email_input(input).unwrap();
        assert_eq!(email.to, "alice@example.com");
        assert_eq!(email.subject, "Hello");
        assert_eq!(email.body, "Hi Alice!");
    }

    #[test]
    fn test_parse_email_turkish() {
        let input = "kime: test@test.com\nkonu: Merhaba\n---\nNasılsınız?";
        let email = parse_email_input(input).unwrap();
        assert_eq!(email.to, "test@test.com");
        assert_eq!(email.subject, "Merhaba");
    }

    #[test]
    fn test_parse_email_missing_to() {
        let input = "subject: Hello\n---\nBody";
        assert!(parse_email_input(input).is_err());
    }

    #[test]
    fn test_parse_email_invalid_address() {
        let input = "to: notanemail\nsubject: Test\n---\nBody";
        let result = parse_email_input(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid email"));
    }

    #[test]
    fn test_parse_email_no_separator() {
        let input = "to: test@test.com\nsubject: Hi\nno separator here";
        assert!(parse_email_input(input).is_err());
    }

    #[test]
    fn test_recipient_allowlist_exact() {
        let skill = EmailSenderSkill::new("id".into(), "secret".into(), None)
            .with_allowed_recipients(vec!["alice@example.com".into()]);
        assert!(skill.is_recipient_allowed("alice@example.com"));
        assert!(skill.is_recipient_allowed("Alice@Example.com")); // case insensitive
        assert!(!skill.is_recipient_allowed("bob@example.com"));
    }

    #[test]
    fn test_recipient_allowlist_domain() {
        let skill = EmailSenderSkill::new("id".into(), "secret".into(), None)
            .with_allowed_recipients(vec!["*@company.com".into()]);
        assert!(skill.is_recipient_allowed("anyone@company.com"));
        assert!(skill.is_recipient_allowed("CEO@Company.com"));
        assert!(!skill.is_recipient_allowed("someone@other.com"));
    }

    #[test]
    fn test_recipient_empty_allowlist_denies_all() {
        let skill = EmailSenderSkill::new("id".into(), "secret".into(), None);
        assert!(!skill.is_recipient_allowed("anyone@anywhere.com"));
    }

    #[test]
    fn test_disabled_by_default() {
        let skill = EmailSenderSkill::new("id".into(), "secret".into(), None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("to: test@test.com\nsubject: Hi\n---\nBody"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_daily_limit() {
        let config = SkillConfig { enabled: true, ..Default::default() };
        let skill = EmailSenderSkill::new("id".into(), "secret".into(), None)
            .with_allowed_recipients(vec!["*@test.com".into()])
            .with_daily_limit(5)
            .with_config(config);

        skill.emails_sent_today.store(5, std::sync::atomic::Ordering::Relaxed);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("to: x@test.com\nsubject: Hi\n---\nBody"));
        assert!(!result.success);
        assert!(result.output.contains("limit reached"));
    }
}
