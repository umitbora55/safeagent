use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

/// Run the full OAuth2 authorization code flow for Google APIs.
/// Opens a browser for consent, starts a local server to receive the callback.
pub async fn authorize(
    client_id: &str,
    client_secret: &str,
    scopes: &[&str],
) -> Result<OAuthTokens, String> {
    let redirect_uri = "http://localhost:18790";
    let scope_str = scopes.join(" ");

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent",
        urlencoding(client_id),
        urlencoding(redirect_uri),
        urlencoding(&scope_str),
    );

    println!();
    println!("  🌐 Open this URL in your browser to authorize SafeAgent:");
    println!();
    println!("  {}", auth_url);
    println!();
    println!("  Waiting for authorization...");

    // Try to open browser automatically
    let _ = open_browser(&auth_url);

    // Start local server to receive callback
    let code = receive_auth_code().await?;

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| format!("Token exchange failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Token exchange error: {}", body));
    }

    let token_resp: TokenResponse = resp.json().await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    let expires_at = chrono::Utc::now().timestamp() + token_resp.expires_in as i64;

    Ok(OAuthTokens {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token.unwrap_or_default(),
        expires_at,
    })
}

/// Refresh an expired access token.
pub async fn refresh_token(
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<OAuthTokens, String> {
    let client = reqwest::Client::new();
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|e| format!("Token refresh failed: {}", e))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Token refresh error: {}", body));
    }

    let token_resp: TokenResponse = resp.json().await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    let expires_at = chrono::Utc::now().timestamp() + token_resp.expires_in as i64;

    Ok(OAuthTokens {
        access_token: token_resp.access_token,
        refresh_token: if token_resp.refresh_token.is_some() {
            token_resp.refresh_token.unwrap()
        } else {
            refresh_token.to_string()
        },
        expires_at,
    })
}

/// Get a valid access token, refreshing if expired.
pub async fn get_valid_token(
    client_id: &str,
    client_secret: &str,
    tokens: &OAuthTokens,
) -> Result<OAuthTokens, String> {
    let now = chrono::Utc::now().timestamp();
    if now < tokens.expires_at - 60 {
        // Still valid (with 60s buffer)
        return Ok(tokens.clone());
    }

    if tokens.refresh_token.is_empty() {
        return Err("Token expired and no refresh token available. Run `safeagent init` to re-authorize.".into());
    }

    refresh_token(client_id, client_secret, &tokens.refresh_token).await
}

/// Start a minimal HTTP server on localhost:18790 to receive the OAuth callback.
async fn receive_auth_code() -> Result<String, String> {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:18790").await
        .map_err(|e| format!("Cannot bind to port 18790: {}", e))?;

    let (mut stream, _) = listener.accept().await
        .map_err(|e| format!("Failed to accept connection: {}", e))?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await
        .map_err(|e| format!("Failed to read request: {}", e))?;

    let request = String::from_utf8_lossy(&buf[..n]);

    // Extract code from GET /?code=XXX&scope=...
    let code = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|path| {
            path.split('?')
                .nth(1)
                .and_then(|query| {
                    query.split('&')
                        .find(|p| p.starts_with("code="))
                        .map(|p| p.trim_start_matches("code=").to_string())
                })
        })
        .ok_or_else(|| "No authorization code received".to_string())?;

    // Send success response
    let html = "<!DOCTYPE html><html><body><h2>✅ SafeAgent authorized!</h2><p>You can close this tab.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        html.len(), html
    );
    let _ = stream.write_all(response.as_bytes()).await;

    Ok(code)
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()
            .map_err(|e| format!("Failed to open browser: {}", e))?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()
            .map_err(|e| format!("Failed to open browser: {}", e))?;
    }
    Ok(())
}

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
        assert_eq!(urlencoding("a@b.com"), "a%40b.com");
        assert_eq!(urlencoding("scope1 scope2"), "scope1%20scope2");
    }

    #[test]
    fn test_oauth_tokens_serialize() {
        let tokens = OAuthTokens {
            access_token: "test_access".into(),
            refresh_token: "test_refresh".into(),
            expires_at: 1234567890,
        };
        let json = serde_json::to_string(&tokens).unwrap();
        let parsed: OAuthTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.access_token, "test_access");
        assert_eq!(parsed.refresh_token, "test_refresh");
        assert_eq!(parsed.expires_at, 1234567890);
    }
}
