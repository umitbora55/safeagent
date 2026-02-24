use crate::{validate_url, Permission, Skill, SkillConfig, SkillResult};
use async_trait::async_trait;

/// Headless browser control with domain allowlist.
/// No form submission by default. Sandboxed.
pub struct BrowserControlSkill {
    client: reqwest::Client,
    allowed_domains: Vec<String>,
    allow_form_submission: bool,
    config: SkillConfig,
}

impl BrowserControlSkill {
    pub fn new(allowed_domains: Vec<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::limited(3))
                .user_agent("SafeAgent-Browser/0.1 (Headless)")
                .build()
                .unwrap_or_default(),
            allowed_domains,
            allow_form_submission: false,
            config: SkillConfig {
                enabled: false,
                ..Default::default()
            },
        }
    }

    pub fn with_form_submission(mut self, allow: bool) -> Self {
        self.allow_form_submission = allow;
        self
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }

    fn is_domain_allowed(&self, url: &str) -> Result<(), String> {
        // SSRF check first
        validate_url(url)?;

        if self.allowed_domains.is_empty() {
            return Err(
                "No domains allowlisted. Configure [skills.browser_control] allowed_domains."
                    .into(),
            );
        }

        let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
        let host = parsed.host_str().ok_or("No host in URL")?;

        let domain_ok = self.allowed_domains.iter().any(|d| {
            let d_lower = d.to_lowercase();
            let host_lower = host.to_lowercase();
            // Exact match or subdomain match
            host_lower == d_lower || host_lower.ends_with(&format!(".{}", d_lower))
        });

        if !domain_ok {
            return Err(format!(
                "Domain '{}' not in allowlist. Allowed: {:?}",
                host, self.allowed_domains
            ));
        }

        Ok(())
    }
}

/// Supported browser actions
#[derive(Debug)]
enum BrowserAction {
    Navigate {
        url: String,
    },
    Screenshot {
        url: String,
    },
    ExtractText {
        url: String,
    },
    ExtractLinks {
        url: String,
    },
    SubmitForm {
        url: String,
        data: Vec<(String, String)>,
    },
}

fn parse_browser_input(input: &str) -> Result<BrowserAction, String> {
    let lines: Vec<&str> = input.lines().collect();
    if lines.is_empty() {
        return Err("Empty input. Supported actions: navigate, screenshot, extract_text, extract_links, submit_form".into());
    }

    let first = lines[0].trim().to_lowercase();

    if first.starts_with("navigate ") || first.starts_with("goto ") || first.starts_with("git ") {
        let url = first
            .split_once(' ')
            .map(|(_, rest)| rest.trim())
            .unwrap_or("")
            .to_string();
        Ok(BrowserAction::Navigate { url })
    } else if first.starts_with("screenshot ") {
        let url = first
            .split_once(' ')
            .map(|(_, rest)| rest.trim())
            .unwrap_or("")
            .to_string();
        Ok(BrowserAction::Screenshot { url })
    } else if first.starts_with("extract_text ") || first.starts_with("text ") {
        let url = first
            .split_once(' ')
            .map(|(_, rest)| rest.trim())
            .unwrap_or("")
            .to_string();
        Ok(BrowserAction::ExtractText { url })
    } else if first.starts_with("extract_links ") || first.starts_with("links ") {
        let url = first
            .split_once(' ')
            .map(|(_, rest)| rest.trim())
            .unwrap_or("")
            .to_string();
        Ok(BrowserAction::ExtractLinks { url })
    } else if first.starts_with("submit_form ") {
        let url = first
            .split_once(' ')
            .map(|(_, rest)| rest.trim())
            .unwrap_or("")
            .to_string();
        let mut data = Vec::new();
        for line in &lines[1..] {
            if let Some((k, v)) = line.split_once('=') {
                data.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        Ok(BrowserAction::SubmitForm { url, data })
    } else if first.starts_with("http://") || first.starts_with("https://") {
        // Default: navigate to URL
        Ok(BrowserAction::Navigate { url: first })
    } else {
        Err("Unknown action. Supported: navigate <url>, extract_text <url>, extract_links <url>, submit_form <url>".to_string())
    }
}

/// Simple HTML text extraction (reuse from url_fetcher)
fn extract_text_from_html(html: &str) -> String {
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
        if !in_tag
            && i + 7 < lower_chars.len()
            && lower_chars[i..i + 7].iter().collect::<String>() == "<script"
        {
            in_script = true;
            in_tag = true;
            i += 1;
            continue;
        }
        if in_script
            && i + 9 <= lower_chars.len()
            && lower_chars[i..i + 9].iter().collect::<String>() == "</script>"
        {
            in_script = false;
            in_tag = false;
            i += 9;
            continue;
        }
        if !in_tag
            && i + 6 < lower_chars.len()
            && lower_chars[i..i + 6].iter().collect::<String>() == "<style"
        {
            in_style = true;
            in_tag = true;
            i += 1;
            continue;
        }
        if in_style
            && i + 8 <= lower_chars.len()
            && lower_chars[i..i + 8].iter().collect::<String>() == "</style>"
        {
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

    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

/// Extract all links from HTML
fn extract_links_from_html(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    let lower = html.to_lowercase();
    let mut pos = 0;

    while let Some(href_pos) = lower[pos..].find("href=\"") {
        let start = pos + href_pos + 6;
        if let Some(end_pos) = html[start..].find('"') {
            let link = &html[start..start + end_pos];
            if link.starts_with("http://") || link.starts_with("https://") {
                links.push(link.to_string());
            } else if link.starts_with('/') {
                if let Ok(base) = url::Url::parse(base_url) {
                    if let Ok(full) = base.join(link) {
                        links.push(full.to_string());
                    }
                }
            }
            pos = start + end_pos;
        } else {
            break;
        }
    }

    links.sort();
    links.dedup();
    links
}

#[async_trait]
impl Skill for BrowserControlSkill {
    fn id(&self) -> &str {
        "browser_control"
    }
    fn name(&self) -> &str {
        "Browser Control"
    }
    fn description(&self) -> &str {
        "Headless browser with domain allowlist. Actions: navigate <url>, extract_text <url>, extract_links <url>, submit_form <url>"
    }
    fn permissions(&self) -> Vec<Permission> {
        vec![Permission("execute:browser".into())]
    }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err(
                "Browser control is disabled. Enable in safeagent.toml:\n\
                 [skills.browser_control]\n\
                 enabled = true\n\
                 allowed_domains = [\"example.com\"]"
                    .into(),
            );
        }

        let action = match parse_browser_input(input) {
            Ok(a) => a,
            Err(e) => return SkillResult::err(e),
        };

        match action {
            BrowserAction::Navigate { url } | BrowserAction::ExtractText { url } => {
                if let Err(e) = self.is_domain_allowed(&url) {
                    return SkillResult::err(e);
                }

                let resp = match self.client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => return SkillResult::err(format!("Request failed: {}", e)),
                };
                if !resp.status().is_success() {
                    return SkillResult::err(format!("HTTP {}", resp.status()));
                }
                let body = resp.text().await.unwrap_or_default();
                let text = extract_text_from_html(&body);
                let truncated = if text.len() > self.config.max_response_bytes {
                    format!(
                        "{}...\n[Truncated]",
                        &text[..self.config.max_response_bytes]
                    )
                } else {
                    text
                };

                SkillResult::ok(truncated)
                    .with_meta("url", &url)
                    .with_meta("action", "extract_text")
            }
            BrowserAction::Screenshot { url } => {
                if let Err(e) = self.is_domain_allowed(&url) {
                    return SkillResult::err(e);
                }
                // Without a real headless browser, return page title + metadata
                let resp = match self.client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => return SkillResult::err(format!("Request failed: {}", e)),
                };
                let body = resp.text().await.unwrap_or_default();
                let title = extract_title(&body);
                SkillResult::ok(format!(
                    "📸 Page: {}\nURL: {}\n[Screenshot requires chromium runtime]",
                    title, url
                ))
                .with_meta("url", &url)
                .with_meta("action", "screenshot")
            }
            BrowserAction::ExtractLinks { url } => {
                if let Err(e) = self.is_domain_allowed(&url) {
                    return SkillResult::err(e);
                }
                let resp = match self.client.get(&url).send().await {
                    Ok(r) => r,
                    Err(e) => return SkillResult::err(format!("Request failed: {}", e)),
                };
                let body = resp.text().await.unwrap_or_default();
                let links = extract_links_from_html(&body, &url);
                let output = format!("🔗 {} links found:\n\n{}", links.len(), links.join("\n"));
                SkillResult::ok(output)
                    .with_meta("url", &url)
                    .with_meta("link_count", &links.len().to_string())
            }
            BrowserAction::SubmitForm { url, data } => {
                if !self.allow_form_submission {
                    return SkillResult::err(
                        "Form submission is disabled by default. Enable with allow_form_submission = true".into()
                    );
                }
                if let Err(e) = self.is_domain_allowed(&url) {
                    return SkillResult::err(e);
                }
                let resp = match self.client.post(&url).form(&data).send().await {
                    Ok(r) => r,
                    Err(e) => return SkillResult::err(format!("Form submit failed: {}", e)),
                };
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let text = extract_text_from_html(&body);
                let truncated = if text.len() > 2000 {
                    format!("{}...", &text[..2000])
                } else {
                    text
                };
                SkillResult::ok(format!("Form submitted (HTTP {})\n\n{}", status, truncated))
                    .with_meta("url", &url)
                    .with_meta("action", "submit_form")
            }
        }
    }
}

fn extract_title(html: &str) -> String {
    let lower = html.to_lowercase();
    if let Some(start) = lower.find("<title>") {
        let s = start + 7;
        if let Some(end) = lower[s..].find("</title>") {
            return html[s..s + end].trim().to_string();
        }
    }
    "(No title)".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_by_default() {
        let skill = BrowserControlSkill::new(vec!["example.com".into()]);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("navigate https://example.com"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_domain_not_allowed() {
        let config = SkillConfig {
            enabled: true,
            ..Default::default()
        };
        let skill = BrowserControlSkill::new(vec!["example.com".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("navigate https://evil.com"));
        assert!(!result.success);
        assert!(result.output.contains("not in allowlist"));
    }

    #[test]
    fn test_empty_allowlist() {
        let config = SkillConfig {
            enabled: true,
            ..Default::default()
        };
        let skill = BrowserControlSkill::new(vec![]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("navigate https://example.com"));
        assert!(!result.success);
        assert!(result.output.contains("No domains"));
    }

    #[test]
    fn test_form_submission_blocked() {
        let config = SkillConfig {
            enabled: true,
            ..Default::default()
        };
        let skill = BrowserControlSkill::new(vec!["example.com".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("submit_form https://example.com/form\nname=test"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }

    #[test]
    fn test_ssrf_blocked() {
        let config = SkillConfig {
            enabled: true,
            ..Default::default()
        };
        let skill = BrowserControlSkill::new(vec!["*".into()]).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("navigate http://169.254.169.254/latest"));
        assert!(!result.success);
    }

    #[test]
    fn test_parse_navigate() {
        let action = parse_browser_input("navigate https://example.com").unwrap();
        assert!(matches!(action, BrowserAction::Navigate { .. }));
    }

    #[test]
    fn test_parse_extract_links() {
        let action = parse_browser_input("extract_links https://example.com").unwrap();
        assert!(matches!(action, BrowserAction::ExtractLinks { .. }));
    }

    #[test]
    fn test_parse_bare_url() {
        let action = parse_browser_input("https://example.com").unwrap();
        assert!(matches!(action, BrowserAction::Navigate { .. }));
    }

    #[test]
    fn test_extract_links_html() {
        let html = r#"<a href="https://a.com">A</a><a href="/page">B</a>"#;
        let links = extract_links_from_html(html, "https://base.com");
        assert!(links.contains(&"https://a.com".to_string()));
        assert!(links.contains(&"https://base.com/page".to_string()));
    }

    #[test]
    fn test_extract_title() {
        assert_eq!(extract_title("<title>Hello World</title>"), "Hello World");
        assert_eq!(extract_title("<html>no title</html>"), "(No title)");
    }
}
