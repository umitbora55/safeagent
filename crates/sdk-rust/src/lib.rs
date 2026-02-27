//! SafeAgent control-plane SDK (public client API).

use safeagent_shared_identity::TenantId;
use safeagent_shared_proto::{
    ApprovalDecisionRequest, ApprovalDecisionResponse, ApprovalRequest, ApprovalStatusResponse,
    ControlPlaneExecuteRequest, ExecuteRequest, ExecuteResponse, IssueTokenRequest,
    IssueTokenResponse, Jwks, WorkerRegisterRequest, WorkerRegisterResponse,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::time::{sleep, Duration};
use url::Url;

use reqwest::{Certificate, Identity, Method, Response, StatusCode};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(120),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MtlsConfig {
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug, Clone, Default)]
pub struct SafeAgentClientConfig {
    pub base_url: String,
    pub timeout: Option<Duration>,
    pub retries: RetryPolicy,
    pub mtls: Option<MtlsConfig>,
    pub token: Option<String>,
}

impl SafeAgentClientConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Self::default()
        }
    }

    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn retries(mut self, max_retries: u32, base_delay: Duration) -> Self {
        self.retries = RetryPolicy {
            max_retries,
            base_delay,
        };
        self
    }

    pub fn mtls(
        mut self,
        ca_pem: impl Into<String>,
        cert_pem: impl Into<String>,
        key_pem: impl Into<String>,
    ) -> Self {
        self.mtls = Some(MtlsConfig {
            ca_pem: ca_pem.into(),
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
        });
        self
    }

    pub fn build(self) -> Result<SafeAgentClient> {
        let base_url = normalize_base_url(self.base_url);
        let mut builder = reqwest::Client::builder();

        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }

        if let Some(mtls) = self.mtls {
            let ca_bytes = std::fs::read(&mtls.ca_pem)
                .map_err(|err| SafeAgentError::Config(format!("read ca failed: {err}")))?;
            let cert_bytes = std::fs::read(&mtls.cert_pem)
                .map_err(|err| SafeAgentError::Config(format!("read cert failed: {err}")))?;
            let key_bytes = std::fs::read(&mtls.key_pem)
                .map_err(|err| SafeAgentError::Config(format!("read key failed: {err}")))?;

            let ca = Certificate::from_pem(&ca_bytes)
                .map_err(|err| SafeAgentError::Config(format!("invalid ca pem: {err}")))?;
            builder = builder.add_root_certificate(ca);
            let identity =
                Identity::from_pem([cert_bytes, b"\n".to_vec(), key_bytes].concat().as_slice())
                    .map_err(|err| {
                        SafeAgentError::Config(format!("invalid mtls identity: {err}"))
                    })?;
            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .map_err(|err| SafeAgentError::Config(format!("client build failed: {err}")))?;

        Ok(SafeAgentClient {
            base_url,
            client,
            token: self.token,
            retries: self.retries,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SafeAgentClient {
    base_url: String,
    client: reqwest::Client,
    token: Option<String>,
    retries: RetryPolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum SafeAgentError {
    #[error("http error: {0}")]
    Http(String),
    #[error("api error {0}: {1}")]
    Api(StatusCode, String),
    #[error("invalid response: {0}")]
    Decode(String),
    #[error("client config invalid: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, SafeAgentError>;

impl SafeAgentClient {
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn set_token(&mut self, token: impl Into<String>) {
        self.token = Some(token.into());
    }

    pub fn clear_token(&mut self) {
        self.token = None;
    }

    pub async fn register_worker(
        &self,
        request: WorkerRegisterRequest,
    ) -> Result<WorkerRegisterResponse> {
        self.request_json(Method::POST, "/register", Some(&request), None::<&str>)
            .await
    }

    pub async fn issue_token(
        &self,
        subject: impl Into<String>,
        scopes: Vec<String>,
        ttl_secs: u64,
    ) -> Result<IssueTokenResponse> {
        let request = IssueTokenRequest {
            subject: subject.into(),
            scopes,
            ttl_secs,
        };
        self.request_json(Method::POST, "/issue-token", Some(&request), None::<&str>)
            .await
    }

    pub async fn execute(
        &self,
        tenant_id: impl Into<String>,
        skill_id: impl Into<String>,
        input: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<ExecuteResponse> {
        let token = self
            .token
            .as_deref()
            .ok_or_else(|| SafeAgentError::Config("missing bearer token".to_string()))?;
        self.execute_with_token(token, tenant_id, skill_id, input, request_id)
            .await
    }

    pub async fn execute_with_token(
        &self,
        token: impl Into<String>,
        tenant_id: impl Into<String>,
        skill_id: impl Into<String>,
        input: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<ExecuteResponse> {
        let request = ExecuteRequest {
            token: token.into(),
            tenant_id: TenantId(tenant_id.into()),
            skill_id: skill_id.into(),
            input: input.into(),
            request_id: request_id.into(),
        };
        self.request_json(Method::POST, "/execute", Some(&request), None::<&str>)
            .await
    }

    pub async fn execute_without_token(
        &self,
        request: ControlPlaneExecuteRequest,
    ) -> Result<ExecuteResponse> {
        self.request_json(Method::POST, "/execute", Some(&request), None::<&str>)
            .await
    }

    pub async fn get_pending_approvals(&self) -> Result<Vec<ApprovalRequest>> {
        self.request_json(
            Method::GET,
            "/approval/pending",
            Option::<&()>::None,
            None::<&str>,
        )
        .await
    }

    pub async fn get_approval_status(
        &self,
        approval_id: impl Into<String>,
    ) -> Result<ApprovalStatusResponse> {
        let approval_id = approval_id.into();
        let path = format!("/approval/status?approval_id={}", approval_id);
        self.request_json(Method::GET, &path, None::<&()>, None::<&str>)
            .await
    }

    pub async fn approve(
        &self,
        approval_id: impl Into<String>,
        decided_by: impl Into<String>,
        reason: Option<impl Into<String>>,
    ) -> Result<ApprovalDecisionResponse> {
        let req = ApprovalDecisionRequest {
            approval_id: approval_id.into(),
            decision: "approved".to_string(),
            decided_by: decided_by.into(),
            reason: reason.map(Into::into),
        };
        self.decide_approval(req).await
    }

    pub async fn deny(
        &self,
        approval_id: impl Into<String>,
        decided_by: impl Into<String>,
        reason: Option<impl Into<String>>,
    ) -> Result<ApprovalDecisionResponse> {
        let req = ApprovalDecisionRequest {
            approval_id: approval_id.into(),
            decision: "denied".to_string(),
            decided_by: decided_by.into(),
            reason: reason.map(Into::into),
        };
        self.decide_approval(req).await
    }

    pub async fn decide_approval(
        &self,
        request: ApprovalDecisionRequest,
    ) -> Result<ApprovalDecisionResponse> {
        self.request_json(
            Method::POST,
            "/approval/decide",
            Some(&request),
            None::<&str>,
        )
        .await
    }

    pub async fn fetch_jwks(&self) -> Result<Jwks> {
        self.request_json(Method::GET, "/jwks", None::<&()>, None::<&str>)
            .await
    }

    async fn request_json<TReq, TResp>(
        &self,
        method: Method,
        path_or_url: &str,
        body: Option<&TReq>,
        token: Option<&str>,
    ) -> Result<TResp>
    where
        TReq: Serialize + ?Sized,
        TResp: DeserializeOwned,
    {
        let mut retries_left = self.retries.max_retries;
        let url = build_url(&self.base_url, path_or_url)?;
        let mut last_error = None;
        let auth = token.or(self.token.as_deref());

        loop {
            let mut request = self.client.request(
                method.clone(),
                Url::parse(&url)
                    .map_err(|err| SafeAgentError::Config(format!("invalid url '{url}': {err}")))?,
            );

            if let Some(auth) = auth {
                if !auth.is_empty() {
                    request = request.bearer_auth(auth);
                }
            }

            if let Some(body) = body {
                request = request.json(body);
            }

            match request.send().await {
                Ok(response) => {
                    if response.status().is_server_error() && retries_left > 0 {
                        retries_left = retries_left.saturating_sub(1);
                        let status = response.status();
                        let body = response
                            .text()
                            .await
                            .unwrap_or_else(|_| "<unreadable>".to_string());
                        last_error = Some(format!("status {status}: {body}"));
                        let delay =
                            self.retries.base_delay.saturating_mul(2_u32.saturating_pow(
                                self.retries.max_retries.saturating_sub(retries_left),
                            ));
                        sleep(delay).await;
                        continue;
                    }
                    return handle_response(response).await;
                }
                Err(err) if retries_left > 0 => {
                    retries_left = retries_left.saturating_sub(1);
                    last_error = Some(err.to_string());
                    let delay = self.retries.base_delay.saturating_mul(
                        2_u32.saturating_pow(self.retries.max_retries.saturating_sub(retries_left)),
                    );
                    sleep(delay).await;
                }
                Err(err) => {
                    return Err(SafeAgentError::Http(
                        last_error.unwrap_or_else(|| err.to_string()),
                    ));
                }
            }
        }
    }
}

async fn handle_response<T>(response: Response) -> Result<T>
where
    T: DeserializeOwned,
{
    let status = response.status();
    if status.is_success() {
        response
            .json::<T>()
            .await
            .map_err(|err| SafeAgentError::Decode(err.to_string()))
    } else {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
        Err(SafeAgentError::Api(status, body))
    }
}

fn build_url(base_url: &str, path_or_url: &str) -> Result<String> {
    if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
        return Ok(path_or_url.to_string());
    }
    if Url::parse(base_url).is_err() {
        return Err(SafeAgentError::Config("invalid base url".to_string()));
    }
    let trimmed = base_url.trim_end_matches('/');
    let suffix = path_or_url.trim_start_matches('/');
    Ok(format!("{trimmed}/{suffix}"))
}

fn normalize_base_url(base_url: String) -> String {
    match Url::parse(&base_url) {
        Ok(mut parsed) => {
            let path = parsed.path().trim_end_matches('/').to_string();
            parsed.set_path(&path);
            parsed.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => base_url.trim_end_matches('/').to_string(),
    }
}

pub fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_normalizes_path() {
        let url = build_url("https://example.invalid/api/", "/jwks").expect("url");
        assert_eq!(url, "https://example.invalid/api/jwks");
    }

    #[test]
    fn request_without_token_fails() {
        let client = SafeAgentClientConfig::new("https://example.invalid")
            .build()
            .expect("client");
        tokio::runtime::Runtime::new()
            .expect("tokio")
            .block_on(async {
                let err = client
                    .execute("tenant-1", "skill", "input", "req-1")
                    .await
                    .unwrap_err();
                let text = err.to_string();
                assert!(text.contains("missing bearer token"));
            });
    }

    #[test]
    fn new_request_id_is_uuid_like() {
        let id = new_request_id();
        assert!(id.split('-').count() >= 4);
    }
}
