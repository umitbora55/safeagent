use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use safeagent_shared_identity::Claims;
use safeagent_shared_proto::{
    ApprovalRequest, ApprovalRequestResponse, ApprovalStatusResponse, ExecuteRequest,
};

mod sandbox;

#[derive(Clone)]
pub struct WorkerState {
    pub verifier: Arc<dyn TokenVerifier + Send + Sync>,
    pub used_nonces: Arc<DashMap<String, u64>>,
    pub control_plane_url: Option<String>,
    pub control_plane_client: Option<Arc<rustls::ClientConfig>>,
    pub approval_timeout_secs: u64,
}

impl WorkerState {
    pub fn new(verifier: Arc<dyn TokenVerifier + Send + Sync>) -> Self {
        Self {
            verifier,
            used_nonces: Arc::new(DashMap::new()),
            control_plane_url: None,
            control_plane_client: None,
            approval_timeout_secs: DEFAULT_APPROVAL_TIMEOUT_SECONDS,
        }
    }

    pub fn with_control_plane(
        verifier: Arc<dyn TokenVerifier + Send + Sync>,
        control_plane_url: String,
        control_plane_client: rustls::ClientConfig,
        approval_timeout_secs: u64,
    ) -> Self {
        Self {
            verifier,
            used_nonces: Arc::new(DashMap::new()),
            control_plane_url: Some(control_plane_url),
            control_plane_client: Some(Arc::new(control_plane_client)),
            approval_timeout_secs,
        }
    }
}

const DEFAULT_APPROVAL_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_APPROVAL_POLL_INTERVAL_MILLIS: u64 = 250;

pub trait TokenVerifier {
    fn verify(&self, token: &str, required_scope: &str) -> Result<Claims, String>;
}

#[derive(Clone)]
pub struct Ed25519TokenVerifier {
    public_key: VerifyingKey,
}

impl Ed25519TokenVerifier {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read public key {}: {}", path, e))?;
        let bytes = hex::decode(data.trim())
            .map_err(|e| format!("Invalid public key hex {}: {}", path, e))?;
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err("Public key must be 32 bytes".to_string());
        }
        let public_key = VerifyingKey::from_bytes(
            &bytes
                .try_into()
                .map_err(|_| "Invalid public key length".to_string())?,
        )
        .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;
        Ok(Self { public_key })
    }
}

impl TokenVerifier for Ed25519TokenVerifier {
    fn verify(&self, token: &str, required_scope: &str) -> Result<Claims, String> {
        let (payload, signature) = parse_token(token)?;
        self.public_key
            .verify(&payload, &signature)
            .map_err(|_| "invalid signature".to_string())?;
        let claims: Claims =
            serde_json::from_slice(&payload).map_err(|_| "invalid token payload".to_string())?;
        let now = now_unix_secs()?;

        if claims.exp == 0 {
            return Err("token missing exp".to_string());
        }
        if claims.exp < now {
            return Err("token expired".to_string());
        }
        if claims.nbf > now {
            return Err("token not yet valid".to_string());
        }
        if claims.nonce.is_empty() {
            return Err("token missing nonce".to_string());
        }
        if !scope_allows(&claims.scopes, required_scope) {
            return Err("missing required scope".to_string());
        }
        Ok(claims)
    }
}

fn scope_allows(scopes: &[String], required_scope: &str) -> bool {
    scopes
        .iter()
        .any(|scope| scope == "*" || scope == required_scope)
}

pub async fn record_and_reject_replays(state: &WorkerState, claims: &Claims) -> Result<(), String> {
    let now = now_unix_secs()?;
    if let Some(existing) = state.used_nonces.get(&claims.nonce) {
        if *existing > now {
            return Err("token replay detected".to_string());
        }
        let _ = state.used_nonces.remove(&claims.nonce);
    }
    state.used_nonces.insert(claims.nonce.clone(), claims.exp);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub ok: bool,
    pub output: String,
    pub error: Option<String>,
    pub audit_id: Option<String>,
}

pub fn build_router(state: WorkerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/execute", post(execute))
        .with_state(state)
}

enum ActionLevel {
    Green,
    Red,
}

fn classify_skill(skill_id: &str) -> ActionLevel {
    match skill_id {
        "admin_op" => ActionLevel::Red,
        _ => ActionLevel::Green,
    }
}

fn build_control_plane_client(
    state: &WorkerState,
) -> Option<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
> {
    let config = state.control_plane_client.as_ref()?;
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((**config).clone())
        .https_only()
        .enable_http1()
        .build();
    Some(Client::builder(TokioExecutor::new()).build(https))
}

async fn execute(
    State(state): State<WorkerState>,
    Json(req): Json<ExecuteRequest>,
) -> (StatusCode, Json<ExecuteResponse>) {
    if req.token.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ExecuteResponse {
                ok: false,
                output: String::new(),
                error: Some("missing token".to_string()),
                audit_id: None,
            }),
        );
    }

    let required_scope = format!("skill:{}", req.skill_id);
    let claims = match state.verifier.verify(&req.token, &required_scope) {
        Ok(claims) => claims,
        Err(err) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ExecuteResponse {
                    ok: false,
                    output: String::new(),
                    error: Some(err),
                    audit_id: None,
                }),
            );
        }
    };

    if let Err(err) = record_and_reject_replays(&state, &claims).await {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                ok: false,
                output: String::new(),
                error: Some(err),
                audit_id: None,
            }),
        );
    }

    if let ActionLevel::Red = classify_skill(&req.skill_id) {
        if let Err(err) = await_approval(&state, &req, &claims).await {
            return (
                StatusCode::FORBIDDEN,
                Json(ExecuteResponse {
                    ok: false,
                    output: String::new(),
                    error: Some(err),
                    audit_id: None,
                }),
            );
        }
    }

    let output = match sandbox::run_sandboxed_skill(&req.skill_id, &req.input, &req.request_id) {
        Ok(output) => output,
        Err(err) => {
            let status = if err == "unknown skill" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (
                status,
                Json(ExecuteResponse {
                    ok: false,
                    output: String::new(),
                    error: Some(err),
                    audit_id: None,
                }),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ExecuteResponse {
            ok: true,
            output,
            error: None,
            audit_id: Some(req.request_id),
        }),
    )
}

fn approval_timeout(state: &WorkerState) -> Duration {
    Duration::from_secs(state.approval_timeout_secs)
}

fn approval_summary(input: &str) -> String {
    let max = 64;
    if input.len() <= max {
        return input.to_string();
    }
    let mut end = max;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut value = input[..end].to_string();
    value.push_str("...");
    value
}

fn build_approval_request(
    state: &WorkerState,
    req: &ExecuteRequest,
    claims: &Claims,
) -> Result<ApprovalRequest, String> {
    let now = i64::try_from(now_unix_secs()?).map_err(|_| "time overflow".to_string())?;
    let timeout_secs = state.approval_timeout_secs.max(1);
    let expires_at = now
        .checked_add(i64::try_from(timeout_secs).map_err(|_| "invalid timeout".to_string())?)
        .ok_or_else(|| "timeout overflow".to_string())?;
    Ok(ApprovalRequest {
        approval_id: Uuid::new_v4().to_string(),
        request_id: req.request_id.clone(),
        node_id: claims.sub.clone(),
        skill_id: req.skill_id.clone(),
        input_summary: approval_summary(&req.input),
        reason: "red action requires human approval".to_string(),
        created_at: now,
        expires_at,
    })
}

async fn await_approval(
    state: &WorkerState,
    req: &ExecuteRequest,
    claims: &Claims,
) -> Result<(), String> {
    let control_plane_url = state
        .control_plane_url
        .as_ref()
        .ok_or_else(|| "approval unavailable".to_string())?;
    let client =
        build_control_plane_client(state).ok_or_else(|| "approval unavailable".to_string())?;

    let approval_request = build_approval_request(state, req, claims)?;
    let body = serde_json::to_vec(&approval_request)
        .map_err(|_| "failed to build approval request".to_string())?;
    let request = Request::builder()
        .method("POST")
        .uri(format!("{}/approval/request", control_plane_url))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| "failed to build approval request".to_string())?;
    let response = client
        .request(request)
        .await
        .map_err(|_| "approval request failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!("approval request rejected: {}", response.status()));
    }
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|_| "failed to read approval response".to_string())?
        .to_bytes();
    let approval_resp: ApprovalRequestResponse =
        serde_json::from_slice(&body).map_err(|_| "invalid approval response".to_string())?;
    let approval_id = approval_resp.approval_id;

    let deadline = std::time::Instant::now() + approval_timeout(state);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("approval timeout".to_string());
        }
        let status = Request::builder()
            .method("GET")
            .uri(format!(
                "{}/approval/status?approval_id={}",
                control_plane_url, approval_id
            ))
            .body(Full::new(Bytes::new()))
            .map_err(|_| "failed to build status request".to_string())?;
        let status_resp = client
            .request(status)
            .await
            .map_err(|_| "approval status request failed".to_string())?;
        if !status_resp.status().is_success() {
            return Err(format!(
                "approval status rejected: {}",
                status_resp.status()
            ));
        }
        let status_body = status_resp
            .into_body()
            .collect()
            .await
            .map_err(|_| "failed to read approval status".to_string())?
            .to_bytes();
        let status: ApprovalStatusResponse = serde_json::from_slice(&status_body)
            .map_err(|_| "invalid approval status response".to_string())?;
        match status.status.as_str() {
            "approved" => return Ok(()),
            "denied" => return Err("approval denied".to_string()),
            "timeout" => return Err("approval timeout".to_string()),
            _ => {}
        }
        sleep(Duration::from_millis(DEFAULT_APPROVAL_POLL_INTERVAL_MILLIS)).await;
    }
}

pub fn parse_token(token: &str) -> Result<(Vec<u8>, Signature), String> {
    let (payload_b64, signature_b64) = token
        .split_once('.')
        .ok_or_else(|| "malformed token".to_string())?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "invalid token payload encoding".to_string())?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| "invalid token signature encoding".to_string())?;
    let signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| "token signature must be 64 bytes".to_string())?,
    );
    Ok((payload, signature))
}

pub fn build_server_config(
    ca_certs: Vec<CertificateDer<'static>>,
    server_certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, String> {
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert)
            .map_err(|e| format!("Failed to add CA cert: {:?}", e))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("Failed to build client verifier: {:?}", e))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, key)
        .map_err(|e| format!("Failed to build TLS config: {:?}", e))
}

pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read cert {}: {}", path, e))?;
    let mut reader = BufReader::new(&data[..]);
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse certs: {:?}", e))
}

pub fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read key {}: {}", path, e))?;
    let mut reader = BufReader::new(&data[..]);
    let mut keys = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse PKCS8 key: {:?}", e))?;
    if let Some(key) = keys.pop() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }
    let mut reader = BufReader::new(&data[..]);
    let mut keys = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse RSA key: {:?}", e))?;
    keys.pop()
        .map(PrivateKeyDer::Pkcs1)
        .ok_or_else(|| "No private key found".to_string())
}

pub async fn serve(
    listener: TcpListener,
    tls_config: ServerConfig,
    app: Router,
) -> Result<(), String> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("Accept error: {}", e))?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            if let Ok(tls_stream) = acceptor.accept(stream).await {
                let service = app.clone().into_service();
                let service = TowerToHyperService::new(service);
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            }
        });
    }
}

async fn health() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({ "ok": true }))
}

fn now_unix_secs() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use safeagent_shared_identity::{TenantId, UserId};

    fn test_signing_pair() -> (SigningKey, [u8; 32]) {
        let seed = [9u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        (signing_key.clone(), signing_key.verifying_key().to_bytes())
    }

    fn issue_token(signing_key: &SigningKey, claims: &Claims) -> String {
        let payload = serde_json::to_vec(claims).expect("encode claims");
        let signature = signing_key.sign(&payload);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn make_claims(
        subject: &str,
        scope: Option<&str>,
        ttl_secs: i64,
        nonce_suffix: &str,
    ) -> Claims {
        let now = now_unix_secs().expect("time");
        let exp = ((now as i128 + ttl_secs as i128).max(0)) as u64;
        let scopes = scope.map(|s| vec![s.to_string()]).unwrap_or_default();
        Claims {
            sub: subject.to_string(),
            tenant_id: TenantId("tenant".to_string()),
            user_id: UserId("user".to_string()),
            scopes,
            exp,
            nbf: now,
            nonce: format!("{}-{}", subject, nonce_suffix),
        }
    }

    fn new_state(public_key: [u8; 32]) -> WorkerState {
        let verifier = Ed25519TokenVerifier {
            public_key: ed25519_dalek::VerifyingKey::from_bytes(&public_key).expect("public key"),
        };
        WorkerState::new(std::sync::Arc::new(verifier))
    }

    #[tokio::test]
    async fn execute_with_invalid_signature_fails() {
        let (signing_key, public_key) = test_signing_pair();
        let state = new_state(public_key);
        let claims = make_claims("unit", Some("skill:echo"), 60, "invalid-signature");
        let mut token = issue_token(&signing_key, &claims);
        token.push('A');

        let output = state.verifier.verify(&token, "skill:echo");
        assert!(output.is_err());
    }

    #[tokio::test]
    async fn execute_with_expired_token_fails() {
        let (signing_key, public_key) = test_signing_pair();
        let state = new_state(public_key);
        let claims = make_claims("unit", Some("skill:echo"), -1, "expired");
        let token = issue_token(&signing_key, &claims);

        let output = state.verifier.verify(&token, "skill:echo");
        assert_eq!(output.err().as_deref(), Some("token expired"));
    }

    #[tokio::test]
    async fn execute_with_replay_token_fails() {
        let (signing_key, public_key) = test_signing_pair();
        let state = new_state(public_key);
        let claims = make_claims("unit", Some("skill:echo"), 60, "replay");
        let token = issue_token(&signing_key, &claims);

        let claims = state
            .verifier
            .verify(&token, "skill:echo")
            .expect("first verify");
        assert!(record_and_reject_replays(&state, &claims).await.is_ok());
        let claims = state
            .verifier
            .verify(&token, "skill:echo")
            .expect("second verify");
        assert_eq!(
            record_and_reject_replays(&state, &claims)
                .await
                .err()
                .as_deref(),
            Some("token replay detected")
        );
    }

    #[tokio::test]
    async fn execute_with_missing_scope_fails() {
        let (signing_key, public_key) = test_signing_pair();
        let state = new_state(public_key);
        let claims = make_claims("unit", Some("skill:read"), 60, "missing-scope");
        let token = issue_token(&signing_key, &claims);

        let output = state.verifier.verify(&token, "skill:echo");
        assert_eq!(output.err().as_deref(), Some("missing required scope"));
    }

    #[tokio::test]
    async fn execute_with_valid_token_succeeds() {
        let (signing_key, public_key) = test_signing_pair();
        let state = new_state(public_key);
        let claims = make_claims("unit", Some("skill:echo"), 60, "valid");
        let token = issue_token(&signing_key, &claims);
        let req = ExecuteRequest {
            token,
            skill_id: "echo".to_string(),
            input: "hello".to_string(),
            request_id: "req1".to_string(),
        };

        let claims = state
            .verifier
            .verify(&req.token, &format!("skill:{}", req.skill_id))
            .expect("token verified");
        assert!(record_and_reject_replays(&state, &claims).await.is_ok());
    }

    #[cfg(target_os = "linux")]
    mod linux_sandbox_tests {
        use super::*;
        use std::fs;

        #[test]
        fn test_no_new_privs_set() {
            sandbox::apply_no_new_privs().expect("apply_no_new_privs");
            assert!(sandbox::is_no_new_privs_set().expect("read_no_new_privs"));
        }

        #[test]
        fn test_capabilities_dropped() {
            sandbox::drop_capabilities().expect("drop_capabilities");

            let status = fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
            let cap_eff_line = status
                .lines()
                .find(|line| line.starts_with("CapEff:"))
                .expect("CapEff line exists");
            let hex = cap_eff_line.split_whitespace().nth(1).expect("cap field");
            let value: u128 = u128::from_str_radix(hex, 16).expect("parse CapEff");

            assert_eq!(value, 0);
        }

        #[test]
        fn test_rlimit_enforced() {
            sandbox::apply_rlimits().expect("apply_rlimits");

            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe {
                assert!(libc::getrlimit(libc::RLIMIT_CPU, &mut limit) == 0);
                assert_eq!(limit.rlim_cur, 2);
                assert_eq!(limit.rlim_max, 2);

                assert!(libc::getrlimit(libc::RLIMIT_AS, &mut limit) == 0);
                assert_eq!(limit.rlim_cur, 256 * 1024 * 1024);
                assert_eq!(limit.rlim_max, 256 * 1024 * 1024);

                assert!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) == 0);
                assert_eq!(limit.rlim_cur, 10 * 1024 * 1024);
                assert_eq!(limit.rlim_max, 10 * 1024 * 1024);
            }
        }

        #[test]
        fn test_seccomp_blocks_disallowed_syscall() {
            let result = sandbox::run_probe_task(|| {
                let rc = unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) };
                if rc >= 0 {
                    return Err("ptrace unexpectedly allowed".to_string());
                }

                Err(format!(
                    "ptrace blocked with os err: {}",
                    std::io::Error::last_os_error().to_string()
                ))
            })
            .expect_err("ptrace should fail under seccomp");

            assert!(result.contains("Operation not permitted"));
        }

        #[test]
        fn test_skill_exec_under_sandbox() {
            let output = sandbox::run_sandboxed_skill("echo", "sandboxed", "req-1")
                .expect("sandboxed execution");
            assert_eq!(output, "sandboxed");
        }
    }
}
