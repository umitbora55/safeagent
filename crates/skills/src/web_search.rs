use crate::{Permission, Skill, SkillConfig, SkillResult, validate_url};
use async_trait::async_trait;

/// Web search skill using Brave Search API.
pub struct WebSearchSkill {
    client: reqwest::Client,
    api_key: Option<String>,
    config: SkillConfig,
}

impl WebSearchSkill {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            api_key,
            config: SkillConfig::default(),
        }
    }

    pub fn with_config(mut self, config: SkillConfig) -> Self {
        self.config = config;
        self
    }
}

#[async_trait]
impl Skill for WebSearchSkill {
    fn id(&self) -> &str { "web_search" }
    fn name(&self) -> &str { "Web Search" }
    fn description(&self) -> &str {
        "Search the web using Brave Search API. Input: search query string. Returns: top results with title, URL, and snippet."
    }
    fn permissions(&self) -> Vec<Permission> { vec![Permission::read_web()] }

    async fn execute(&self, input: &str) -> SkillResult {
        if !self.config.enabled {
            return SkillResult::err("Web search skill is disabled".into());
        }

        let query = input.trim();
        if query.is_empty() {
            return SkillResult::err("Empty search query".into());
        }

        let api_key = match &self.api_key {
            Some(k) => k.clone(),
            None => return SkillResult::err(
                "Brave Search API key not configured. Get one at https://brave.com/search/api/".into()
            ),
        };

        let url = format!(
            "https://api.search.brave.com/res/v1/web/search?q={}&count=5",
            urlencoding(query)
        );

        let resp = match self.client
            .get(&url)
            .header("X-Subscription-Token", &api_key)
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return SkillResult::err(format!("Search request failed: {}", e)),
        };

        if !resp.status().is_success() {
            return SkillResult::err(format!("Search API error: {}", resp.status()));
        }

        let data: serde_json::Value = match resp.json().await {
            Ok(d) => d,
            Err(e) => return SkillResult::err(format!("Failed to parse response: {}", e)),
        };

        let results = data["web"]["results"].as_array();
        let output = match results {
            Some(items) if !items.is_empty() => {
                let mut text = String::new();
                for (i, item) in items.iter().enumerate().take(5) {
                    let title = item["title"].as_str().unwrap_or("No title");
                    let url = item["url"].as_str().unwrap_or("");
                    let desc = item["description"].as_str().unwrap_or("No description");
                    text.push_str(&format!("{}. {}\n   {}\n   {}\n\n", i + 1, title, url, desc));
                }
                text
            }
            _ => "No results found.".into(),
        };

        SkillResult::ok(output)
            .with_meta("query", query)
            .with_meta("result_count", &results.map(|r| r.len()).unwrap_or(0).to_string())
    }
}

/// Simple URL encoding for query parameters.
fn urlencoding(input: &str) -> String {
    let mut encoded = String::new();
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            b' ' => encoded.push_str("%20"),
            _ => encoded.push_str(&format!("%{:02X}", b)),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding("hello world"), "hello%20world");
        assert_eq!(urlencoding("rust+lang"), "rust%2Blang");
        assert_eq!(urlencoding("test"), "test");
    }

    #[test]
    fn test_no_api_key() {
        let skill = WebSearchSkill::new(None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("test query"));
        assert!(!result.success);
        assert!(result.output.contains("API key not configured"));
    }

    #[test]
    fn test_empty_query() {
        let skill = WebSearchSkill::new(Some("fake-key".into()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute(""));
        assert!(!result.success);
        assert!(result.output.contains("Empty"));
    }

    #[test]
    fn test_disabled_skill() {
        let config = SkillConfig { enabled: false, ..Default::default() };
        let skill = WebSearchSkill::new(Some("key".into())).with_config(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(skill.execute("test"));
        assert!(!result.success);
        assert!(result.output.contains("disabled"));
    }
}
