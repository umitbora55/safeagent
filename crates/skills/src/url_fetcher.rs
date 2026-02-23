use crate::{Permission, Skill, SkillConfig, SkillResult, validate_url};
use async_trait::async_trait;

/// Fetch and summarize web pages.
pub struct UrlFetcherSkill {
    client: reqwest::Client,
    config: SkillConfig,
}

impl UrlFetcherSkill {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::limited(3))
                .build()
                .unwrap_or_default(),
            config: SkillConfig::default(),
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }
}

#[async_trait]
impl Skill for UrlFetcherSkill {
    fn id(&self) -> &str { "url_fetcher" }
    fn name(&self) -> &str { "URL Fetcher" }
    fn description(&self) -> &str {
        "Fetch a web page and extract its text content. Input: a URL. Returns: extracted text from the page, truncated to max response size."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission::read_web()] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err("URL fetcher skill is disabled".into());
        }

        let url = input.trim();
        if url.is_empty() {
            return SkillResult::err("Empty URL".into());
        }

        // SSRF protection
        if let Err(e) = validate_url(url) {
            return SkillResult::err(format!("URL blocked: {}", e));
        }

        let resp = match self.client
            .get(url)
            .header("User-Agent", "SafeAgent/0.1 (URL Fetcher)")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SkillResult::err(format!("Fetch failed: {}", e)),
        };

        let status = resp.status();
        if !status.is_success() {
            return SkillResult::err(format!("HTTP {}", status));
        }

        // Check content type
        let content_type = resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        let allowed_types = ["text/html", "text/plain", "application/json", "text/xml", "application/xml"];
        if !allowed_types.iter().any(|t| content_type.contains(t)) {
            return SkillResult::err(format!(
                "Content type '{}' not allowed. Only text/html, text/plain, application/json supported.", content_type
            ));
        }

        // Read body with size limit
        let body = match resp.text().await {
            Ok(t) => t,
            Err(e) => return SkillResult::err(format!("Failed to read response: {}", e)),
        };

        if body.len() > self.config.max_response_bytes {
            let truncated = &body[..self.config.max_response_bytes];
            let text = extract_text(truncated);
            return SkillResult::ok(format!("{}\n\n[Truncated — original size: {} bytes]", text, body.len()))
                .with_meta("url", url)
                .with_meta("truncated", "true");
        }

        let text = extract_text(&body);
        if text.trim().is_empty() {
            return SkillResult::ok("[Page returned no readable text content]".into())
                .with_meta("url", url);
        }

        SkillResult::ok(text)
            .with_meta("url", url)
            .with_meta("content_type", &content_type)
            .with_meta("size_bytes", &body.len().to_string())
    }
}

/// Simple HTML to text extraction — strips tags and normalizes whitespace.
fn extract_text(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let mut last_was_space = false;

    let lower = html.to_lowercase();
    let chars: Vec<char> = html.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    let mut i = 0;
    while i < chars.len() {
        if !in_tag && i + 7 < lower_chars.len() && lower_chars[i..i+7].iter().collect::<String>() == "<script" {
            in_script = true;
            in_tag = true;
            i += 1;
            continue;
        }
        if in_script && i + 9 <= lower_chars.len() && lower_chars[i..i+9].iter().collect::<String>() == "</script>" {
            in_script = false;
            in_tag = false;
            i += 9;
            continue;
        }
        if !in_tag && i + 6 < lower_chars.len() && lower_chars[i..i+6].iter().collect::<String>() == "<style" {
            in_style = true;
            in_tag = true;
            i += 1;
            continue;
        }
        if in_style && i + 8 <= lower_chars.len() && lower_chars[i..i+8].iter().collect::<String>() == "</style>" {
            in_style = false;
            in_tag = false;
            i += 8;
            continue;
        }

        if in_script || in_style {
            i += 1;
            continue;
        }

        let ch = chars[i];
        if ch == '<' {
            in_tag = true;
            // Add space for block elements
            if !last_was_space {
                text.push(' ');
                last_was_space = true;
            }
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            if ch.is_whitespace() {
                if !last_was_space {
                    text.push(' ');
                    last_was_space = true;
                }
            } else {
                text.push(ch);
                last_was_space = false;
            }
        }
        i += 1;
    }

    // Decode common HTML entities
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_text_simple() {
        let html = "<p>Hello <b>world</b></p>";
        let text = extract_text(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("world"));
        assert!(!text.contains("<p>"));
    }

    #[test]
    fn test_extract_text_strips_script() {
        let html = "<p>before</p><script>var x = 1;</script><p>after</p>";
        let text = extract_text(html);
        assert!(text.contains("before"));
        assert!(text.contains("after"));
        assert!(!text.contains("var x"));
    }

    #[test]
    fn test_extract_text_strips_style() {
        let html = "<style>.x{color:red}</style><p>content</p>";
        let text = extract_text(html);
        assert!(text.contains("content"));
        assert!(!text.contains("color"));
    }

    #[test]
    fn test_extract_text_entities() {
        let html = "A &amp; B &lt; C &gt; D";
        let text = extract_text(html);
        assert!(text.contains("A & B < C > D"));
    }

    #[test]
    fn test_ssrf_blocked() {
        let skill = UrlFetcherSkill::new();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(skill.execute("http://127.0.0.1/admin"));
        assert!(!result.success);
        assert!(result.output.contains("blocked"));

        let result = rt.block_on(skill.execute("http://169.254.169.254/latest"));
        assert!(!result.success);
        assert!(result.output.contains("blocked"));
    }

    #[test]
    fn test_empty_url() {
        let skill = UrlFetcherSkill::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }

    #[test]
    fn test_invalid_scheme() {
        let skill = UrlFetcherSkill::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("ftp://server.com/file"));
        assert!(!result.success);
        assert!(result.output.contains("blocked"));
    }

    #[test]
    fn test_disabled() {
        let config = SkillConfig { enabled: false, ..Default::default() };
        let skill = UrlFetcherSkill::new().with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("https://example.com"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }
}
