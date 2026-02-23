use crate::{Permission, Skill, SkillConfig, SkillResult};
use crate::google_oauth::{OAuthTokens, get_valid_token};
use async_trait::async_trait;

/// Read emails from Gmail (read-only).
pub struct EmailReaderSkill {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    tokens: tokio::sync::RwLock<Option<OAuthTokens>>,
    config: SkillConfig,
}

impl EmailReaderSkill {
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

    pub async fn set_tokens(&self, tokens: OAuthTokens) {
        let mut t = self.tokens.write().await;
        *t = Some(tokens);
    }

    pub async fn get_tokens(&self) -> Option<OAuthTokens> {
        self.tokens.read().await.clone()
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
}

#[async_trait]
impl Skill for EmailReaderSkill {
    fn id(&self) -> &str { "email_reader" }
    fn name(&self) -> &str { "Gmail Reader" }
    fn description(&self) -> &str {
        "Read emails from Gmail. Input: 'inbox', 'unread', a search query like 'from:boss@company.com', or 'latest 5'. Returns: email subjects, senders, dates, and snippets."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission::read_email()] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err("Email reader skill is disabled".into());
        }

        let query = input.trim();
        if query.is_empty() {
            return SkillResult::err("Empty query. Try: 'inbox', 'unread', 'from:someone@email.com', or 'latest 5'.".into());
        }

        let access_token = match self.get_access_token().await {
            Ok(t) => t,
            Err(e) => return SkillResult::err(e),
        };

        // Parse max results
        let (gmail_query, max_results) = parse_email_query(query);

        // List messages
        let list_url = format!(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages?q={}&maxResults={}",
            crate::web_search::urlencoding_pub(&gmail_query),
            max_results
        );

        let list_resp = match self.client
            .get(&list_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SkillResult::err(format!("Gmail API request failed: {}", e)),
        };

        if !list_resp.status().is_success() {
            let status = list_resp.status();
            let body = list_resp.text().await.unwrap_or_default();
            return SkillResult::err(format!("Gmail API error {}: {}", status, body));
        }

        let list_data: serde_json::Value = match list_resp.json().await {
            Ok(d) => d,
            Err(e) => return SkillResult::err(format!("Failed to parse Gmail response: {}", e)),
        };

        let messages = list_data["messages"].as_array();
        let msg_ids: Vec<&str> = match messages {
            Some(msgs) => msgs.iter()
                .filter_map(|m| m["id"].as_str())
                .collect(),
            None => return SkillResult::ok("No emails found.".into())
                .with_meta("query", query),
        };

        if msg_ids.is_empty() {
            return SkillResult::ok("No emails found.".into())
                .with_meta("query", query);
        }

        // Fetch each message metadata
        let mut output = format!("📧 {} email(s) found:\n\n", msg_ids.len());

        for (i, msg_id) in msg_ids.iter().enumerate() {
            let msg_url = format!(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date",
                msg_id
            );

            let msg_resp = match self.client
                .get(&msg_url)
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            if !msg_resp.status().is_success() { continue; }

            let msg_data: serde_json::Value = match msg_resp.json().await {
                Ok(d) => d,
                Err(_) => continue,
            };

            let headers = msg_data["payload"]["headers"].as_array();
            let mut from = String::new();
            let mut subject = String::new();
            let mut date = String::new();

            if let Some(hdrs) = headers {
                for h in hdrs {
                    let name = h["name"].as_str().unwrap_or("").to_lowercase();
                    let value = h["value"].as_str().unwrap_or("");
                    match name.as_str() {
                        "from" => from = value.to_string(),
                        "subject" => subject = value.to_string(),
                        "date" => date = format_email_date(value),
                        _ => {}
                    }
                }
            }

            let snippet = msg_data["snippet"].as_str().unwrap_or("");
            let labels = msg_data["labelIds"].as_array()
                .map(|l| l.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();

            let unread = labels.contains("UNREAD");
            let unread_marker = if unread { "🔵 " } else { "" };

            output.push_str(&format!(
                "{}{}. {}\n   From: {}\n   Date: {}\n   {}\n\n",
                unread_marker, i + 1, subject, from, date, snippet
            ));
        }

        SkillResult::ok(output)
            .with_meta("query", query)
            .with_meta("email_count", &msg_ids.len().to_string())
    }
}

/// Parse email query input into Gmail search query and max results.
fn parse_email_query(input: &str) -> (String, u32) {
    let lower = input.to_lowercase();

    // "latest N" or "son N"
    if lower.starts_with("latest ") || lower.starts_with("son ") {
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(n) = parts[1].parse::<u32>() {
                return ("in:inbox".to_string(), n.min(20));
            }
        }
    }

    match lower.as_str() {
        "inbox" | "gelen kutusu" => ("in:inbox".to_string(), 10),
        "unread" | "okunmamis" | "okunmamış" => ("is:unread".to_string(), 10),
        "sent" | "gonderilen" | "gönderilen" => ("in:sent".to_string(), 10),
        "starred" | "yildizli" | "yıldızlı" => ("is:starred".to_string(), 10),
        _ => (input.to_string(), 10),
    }
}

/// Format email date to a more readable form.
fn format_email_date(date_str: &str) -> String {
    // Email dates are complex (RFC 2822). Just take the first meaningful part.
    let trimmed = date_str.trim();
    if trimmed.len() > 25 {
        trimmed[..25].to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_inbox() {
        let (q, n) = parse_email_query("inbox");
        assert_eq!(q, "in:inbox");
        assert_eq!(n, 10);
    }

    #[test]
    fn test_parse_unread() {
        let (q, _) = parse_email_query("unread");
        assert_eq!(q, "is:unread");
    }

    #[test]
    fn test_parse_latest_n() {
        let (q, n) = parse_email_query("latest 5");
        assert_eq!(q, "in:inbox");
        assert_eq!(n, 5);
    }

    #[test]
    fn test_parse_custom_query() {
        let (q, n) = parse_email_query("from:boss@company.com");
        assert_eq!(q, "from:boss@company.com");
        assert_eq!(n, 10);
    }

    #[test]
    fn test_parse_turkish() {
        let (q, _) = parse_email_query("okunmamış");
        assert_eq!(q, "is:unread");
        let (q, _) = parse_email_query("gelen kutusu");
        assert_eq!(q, "in:inbox");
    }

    #[test]
    fn test_no_tokens() {
        let skill = EmailReaderSkill::new("id".into(), "secret".into(), None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("inbox"));
        assert!(!result.success);
        assert!(result.output.contains("not authorized"));
    }

    #[test]
    fn test_disabled() {
        let config = SkillConfig { enabled: false, ..Default::default() };
        let skill = EmailReaderSkill::new("id".into(), "secret".into(), None).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("inbox"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_empty_query() {
        let skill = EmailReaderSkill::new("id".into(), "secret".into(), None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }
}
