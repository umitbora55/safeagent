use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use dashmap::DashMap;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

use safeagent_shared_identity::{
    cert_fingerprint_sha256, node_id_from_cert, Claims, NodeId, TenantId, UserId,
};
use safeagent_shared_proto::{
    ApprovalDecisionRequest, ApprovalDecisionResponse, ApprovalRequest, ApprovalRequestResponse,
    ApprovalStatusResponse, ControlPlaneExecuteRequest, ExecuteRequest, ExecuteResponse,
    IssueTokenRequest, IssueTokenResponse, Jwks, RotateKeysResponse, WorkerRegisterRequest,
    WorkerRegisterResponse,
};
use std::sync::Mutex;
use uuid::Uuid;

pub use keys::{KeyRecord, KeyStatus, KeyStore};
pub use rate_limiter::{
    RateLimitError, RateLimitErrorBody, TenantRateLimitConfig, TenantRateLimiter,
};

mod keys;
mod rate_limiter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub ok: bool,
}

#[derive(Clone)]
pub struct WorkerInfo {
    pub node_id: NodeId,
    pub addr: String,
    pub last_seen: i64,
    pub cert_fingerprint: String,
    pub version: String,
}

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<DashMap<NodeId, WorkerInfo>>,
    pub token_issuer: Arc<dyn TokenIssuer + Send + Sync>,
    pub key_store: Arc<Mutex<KeyStore>>,
    pub worker_client: Arc<ClientConfig>,
    pub approvals: Arc<DashMap<String, ApprovalRecord>>,
    pub approval_timeout_secs: u64,
    pub rate_limiter: Arc<TenantRateLimiter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub request: ApprovalRequest,
    pub status: ApprovalStatus,
    pub decided_by: Option<String>,
    pub decided_at: Option<i64>,
    pub reason: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalStatusQuery {
    pub approval_id: String,
}

#[derive(Clone)]
pub struct PeerCert {
    pub der: Option<Vec<u8>>,
}

pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 60;
pub const MAX_TOKEN_TTL_SECONDS: u64 = 300;
pub const DEFAULT_APPROVAL_TIMEOUT_SECONDS: u64 = 30;
pub const DEFAULT_TENANT_CONCURRENT_LIMIT: usize = 1000;
pub const DEFAULT_TENANT_QUEUE_LIMIT: usize = 1000;
pub const DEFAULT_TENANT_TOKEN_BUCKET_CAPACITY: u64 = 10_000;
pub const DEFAULT_TENANT_TOKEN_BUCKET_REFILL_PER_SECOND: u64 = 10_000;
pub const DEFAULT_TENANT_COST_BUDGET: u64 = 1_000_000;

fn ensure_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub trait TokenIssuer {
    fn issue(
        &self,
        subject: &str,
        tenant_id: TenantId,
        scopes: Vec<String>,
        ttl_secs: u64,
    ) -> Result<String, String>;
}

pub struct RotatingTokenIssuer {
    key_store: Arc<Mutex<KeyStore>>,
    default_ttl: u64,
    max_ttl: u64,
}

impl RotatingTokenIssuer {
    pub fn new(key_store: Arc<Mutex<KeyStore>>, default_ttl: u64, max_ttl: u64) -> Self {
        Self {
            key_store,
            default_ttl,
            max_ttl,
        }
    }
}

impl TokenIssuer for RotatingTokenIssuer {
    fn issue(
        &self,
        subject: &str,
        tenant_id: TenantId,
        scopes: Vec<String>,
        ttl_secs: u64,
    ) -> Result<String, String> {
        let ttl = if ttl_secs == 0 {
            self.default_ttl
        } else {
            ttl_secs
        };
        if ttl > self.max_ttl {
            return Err(format!("ttl exceeds max limit of {} seconds", self.max_ttl));
        }
        if scopes.is_empty() {
            return Err("missing scopes".to_string());
        }

        let now = now_unix_secs()?;
        let mut store = self
            .key_store
            .lock()
            .map_err(|_| "key store lock poisoned".to_string())?;
        let (active_kid, private_key) = store.active_signing_key()?;
        let private_key = SigningKey::from_bytes(&private_key);
        let claims = Claims {
            sub: subject.to_string(),
            tenant_id,
            user_id: UserId("default".to_string()),
            scopes,
            kid: active_kid.clone(),
            exp: now + ttl,
            nbf: now,
            iat: now,
            nonce: format!("{}:{}:{}", subject, now, Uuid::new_v4()),
        };

        let header = serde_json::json!({"alg":"EdDSA","kid":active_kid});
        let header = serde_json::to_vec(&header)
            .map_err(|e| format!("Failed to encode token header: {e}"))?;
        let header = URL_SAFE_NO_PAD.encode(header);
        let payload =
            serde_json::to_vec(&claims).map_err(|e| format!("Failed to encode claims: {e}"))?;
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signature = private_key.sign(payload.as_bytes());
        Ok(format!(
            "{}.{}.{}",
            header,
            payload,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

#[derive(Clone)]
pub struct Ed25519TokenIssuer {
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519TokenIssuer {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let bytes = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read token issuer key {}: {}", path, e))?;
        let seed = hex::decode(bytes.trim())
            .map_err(|e| format!("Invalid token issuer key {}: {}", path, e))?;
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| "Token issuer key must be 32 bytes".to_string())?;
        Ok(Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        })
    }
}

impl TokenIssuer for Ed25519TokenIssuer {
    fn issue(
        &self,
        subject: &str,
        tenant_id: TenantId,
        scopes: Vec<String>,
        ttl_secs: u64,
    ) -> Result<String, String> {
        let ttl = if ttl_secs == 0 {
            DEFAULT_TOKEN_TTL_SECONDS
        } else {
            ttl_secs
        };
        if ttl > MAX_TOKEN_TTL_SECONDS {
            return Err(format!(
                "ttl exceeds max limit of {} seconds",
                MAX_TOKEN_TTL_SECONDS
            ));
        }
        if scopes.is_empty() {
            return Err("missing scopes".to_string());
        }

        let now = now_unix_secs()?;
        let claims = Claims {
            sub: subject.to_string(),
            tenant_id,
            user_id: UserId("default".to_string()),
            scopes,
            kid: String::new(),
            exp: now + ttl,
            nbf: now,
            iat: now,
            nonce: format!("{}:{}:{}", subject, now, Uuid::new_v4()),
        };

        let payload =
            serde_json::to_vec(&claims).map_err(|e| format!("Failed to encode claims: {}", e))?;
        let header = serde_json::json!({"alg":"EdDSA","kid":""});
        let header = serde_json::to_vec(&header)
            .map_err(|e| format!("Failed to encode token header: {}", e))?;
        let header = URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let signature = self.signing_key.sign(payload_b64.as_bytes());
        Ok(format!(
            "{}.{}.{}",
            header,
            payload_b64,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/issue-token", post(issue_token))
        .route("/jwks", get(jwks))
        .route("/admin/rotate-keys", post(rotate_keys))
        .route("/execute", post(execute))
        .route("/approval/request", post(request_approval))
        .route("/approval/pending", get(list_pending_approvals))
        .route("/approval/decide", post(decide_approval))
        .route("/approval/status", get(approval_status))
        .with_state(state)
}

pub fn build_server_config(
    ca_certs: Vec<CertificateDer<'static>>,
    server_certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, String> {
    ensure_default_crypto_provider();

    use rustls::server::WebPkiClientVerifier;

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
        .map_err(|e| format!("Failed to build server config: {:?}", e))
}

pub fn build_client_config(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<ClientConfig, String> {
    ensure_default_crypto_provider();

    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        roots
            .add(cert)
            .map_err(|e| format!("Failed to add CA cert: {:?}", e))?;
    }
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|e| format!("Failed to build client config: {:?}", e))
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
                let peer = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(|c| c.as_ref().to_vec());

                let service = app
                    .clone()
                    .layer(Extension(PeerCert { der: peer }))
                    .into_service();
                let service = TowerToHyperService::new(service);
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            }
        });
    }
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

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn register(
    State(state): State<AppState>,
    Extension(peer): Extension<PeerCert>,
    Json(req): Json<WorkerRegisterRequest>,
) -> Result<Json<WorkerRegisterResponse>, StatusCode> {
    let der = peer.der.ok_or(StatusCode::UNAUTHORIZED)?;
    let node_id = node_id_from_cert(&der).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let fingerprint = cert_fingerprint_sha256(&der);
    let now = now_unix_secs().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? as i64;
    let info = WorkerInfo {
        node_id: node_id.clone(),
        addr: req.addr,
        last_seen: now,
        cert_fingerprint: fingerprint,
        version: req.version.clone(),
    };
    state.registry.insert(node_id.clone(), info);
    Ok(Json(WorkerRegisterResponse {
        node_id: node_id.0,
        registered_at: now,
        worker_version: req.version,
    }))
}

async fn issue_token(
    State(state): State<AppState>,
    Json(req): Json<IssueTokenRequest>,
) -> Result<Json<IssueTokenResponse>, StatusCode> {
    let ttl = if req.ttl_secs == 0 {
        DEFAULT_TOKEN_TTL_SECONDS
    } else {
        req.ttl_secs
    };
    let token = state
        .token_issuer
        .issue(
            &req.subject,
            TenantId("default".to_string()),
            req.scopes,
            ttl,
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(IssueTokenResponse { token }))
}

fn rate_limit_to_response(error: RateLimitError) -> Response {
    let status = error.status;
    let body = error.into_body();
    (status, Json(body)).into_response()
}

async fn jwks(State(state): State<AppState>) -> (StatusCode, Json<Jwks>) {
    let mut store = match state.key_store.lock() {
        Ok(store) => store,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Jwks { keys: Vec::new() }),
            )
        }
    };
    match store.public_jwks() {
        Ok(jwks) => (StatusCode::OK, Json(jwks)),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Jwks { keys: Vec::new() }),
        ),
    }
}

async fn rotate_keys(
    Extension(peer): Extension<PeerCert>,
    State(state): State<AppState>,
) -> (StatusCode, Json<RotateKeysResponse>) {
    if !is_rotation_authorized(&peer) {
        return (
            StatusCode::FORBIDDEN,
            Json(RotateKeysResponse {
                active_kid: String::new(),
                rotated_kid: String::new(),
            }),
        );
    }

    let (active_kid, rotated_kid) = match state.key_store.lock() {
        Ok(mut store) => {
            let previous_active: String = store.active_key_kid().unwrap_or_default();
            match store.rotate() {
                Ok(_) => {
                    let active_kid = store.active_key_kid().unwrap_or_default();
                    let rotated_kid = if previous_active.is_empty() {
                        active_kid.clone()
                    } else {
                        previous_active
                    };
                    (active_kid, rotated_kid)
                }
                Err(_) => (String::new(), String::new()),
            }
        }
        Err(_) => (String::new(), String::new()),
    };
    if active_kid.is_empty() || rotated_kid.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RotateKeysResponse {
                active_kid: String::new(),
                rotated_kid: String::new(),
            }),
        );
    }
    (
        StatusCode::OK,
        Json(RotateKeysResponse {
            active_kid,
            rotated_kid,
        }),
    )
}

fn is_rotation_authorized(peer: &PeerCert) -> bool {
    let allow_all =
        std::env::var("CONTROL_PLANE_ROTATE_KEYS_ALLOW_ALL").unwrap_or_else(|_| "1".to_string());
    if allow_all == "0" {
        return peer.der.is_some();
    }
    peer.der.is_some()
}

fn decision_to_status(decision: &str) -> Option<ApprovalStatus> {
    match decision {
        "approved" => Some(ApprovalStatus::Approved),
        "denied" => Some(ApprovalStatus::Denied),
        "timeout" => Some(ApprovalStatus::Timeout),
        _ => None,
    }
}

fn status_to_text(status: &ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Timeout => "timeout",
    }
}

fn log_approval_audit(event: &str, approval_id: &str, request_id: &str, status: &str) {
    println!(
        "{{\"event_type\":\"{}\",\"approval_id\":\"{}\",\"request_id\":\"{}\",\"status\":\"{}\"}}",
        event, approval_id, request_id, status
    );
}

fn now_i64() -> Result<i64, String> {
    i64::try_from(now_unix_secs()?).map_err(|_| "time overflow".to_string())
}

pub fn create_approval(state: &AppState, mut request: ApprovalRequest) -> ApprovalRequestResponse {
    if request.approval_id.is_empty() {
        request.approval_id = Uuid::new_v4().to_string();
    }
    let created_at = now_i64().unwrap_or_default();
    request.created_at = created_at;
    request.expires_at = created_at.saturating_add(
        i64::try_from(state.approval_timeout_secs).unwrap_or(
            i64::try_from(DEFAULT_APPROVAL_TIMEOUT_SECONDS)
                .unwrap_or(DEFAULT_APPROVAL_TIMEOUT_SECONDS as i64),
        ),
    );
    let approval_id = request.approval_id.clone();
    if let Some(existing) = state.approvals.get(&approval_id) {
        if let ApprovalStatus::Approved | ApprovalStatus::Denied = existing.status {
            return ApprovalRequestResponse {
                approval_id: existing.request.approval_id.clone(),
            };
        }
    }

    let record = ApprovalRecord {
        request,
        status: ApprovalStatus::Pending,
        decided_by: None,
        decided_at: None,
        reason: None,
        updated_at: created_at,
    };
    let approval_id = record.request.approval_id.clone();
    state.approvals.insert(approval_id.clone(), record);
    ApprovalRequestResponse { approval_id }
}

async fn request_approval(
    State(state): State<AppState>,
    Json(req): Json<ApprovalRequest>,
) -> (StatusCode, Json<ApprovalRequestResponse>) {
    let response = create_approval(&state, req);
    log_approval_audit(
        "approval.requested",
        &response.approval_id,
        "request",
        "pending",
    );
    (StatusCode::OK, Json(response))
}

async fn list_pending_approvals(State(state): State<AppState>) -> Json<Vec<ApprovalRequest>> {
    let now = now_i64().unwrap_or_default();
    let mut pending = Vec::new();
    for item in state.approvals.iter() {
        if matches!(item.status, ApprovalStatus::Pending) && item.request.expires_at > now {
            pending.push(item.request.clone());
        }
    }
    Json(pending)
}

async fn decide_approval(
    State(state): State<AppState>,
    Json(req): Json<ApprovalDecisionRequest>,
) -> (StatusCode, Json<ApprovalDecisionResponse>) {
    let decision = match decision_to_status(&req.decision.to_lowercase()) {
        Some(decision) => decision,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApprovalDecisionResponse {
                    status: "invalid_decision".to_string(),
                }),
            );
        }
    };

    let now = now_i64().unwrap_or_default();
    match state.approvals.get_mut(&req.approval_id) {
        Some(mut entry) => {
            if matches!(
                entry.status,
                ApprovalStatus::Approved | ApprovalStatus::Denied
            ) {
                return (
                    StatusCode::OK,
                    Json(ApprovalDecisionResponse {
                        status: status_to_text(&entry.status).to_string(),
                    }),
                );
            }
            entry.status = decision.clone();
            entry.decided_by = Some(req.decided_by);
            entry.decided_at = Some(now);
            entry.reason = req.reason;
            entry.updated_at = now;
            log_approval_audit(
                "approval.decided",
                &entry.request.approval_id,
                &entry.request.request_id,
                status_to_text(&entry.status),
            );
            (
                StatusCode::OK,
                Json(ApprovalDecisionResponse {
                    status: status_to_text(&entry.status).to_string(),
                }),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ApprovalDecisionResponse {
                status: "not_found".to_string(),
            }),
        ),
    }
}

async fn approval_status(
    State(state): State<AppState>,
    Query(query): Query<ApprovalStatusQuery>,
) -> (StatusCode, Json<ApprovalStatusResponse>) {
    match state.approvals.get(&query.approval_id) {
        Some(entry) => (
            StatusCode::OK,
            Json(ApprovalStatusResponse {
                approval_id: entry.request.approval_id.clone(),
                status: status_to_text(&entry.status).to_string(),
                request: entry.request.clone(),
                decided_by: entry.decided_by.clone(),
                decided_at: entry.decided_at,
                reason: entry.reason.clone(),
            }),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(ApprovalStatusResponse {
                approval_id: query.approval_id,
                status: "not_found".to_string(),
                request: ApprovalRequest {
                    approval_id: String::new(),
                    request_id: String::new(),
                    node_id: String::new(),
                    skill_id: String::new(),
                    input_summary: String::new(),
                    reason: String::new(),
                    created_at: 0,
                    expires_at: 0,
                },
                decided_by: None,
                decided_at: None,
                reason: None,
            }),
        ),
    }
}

pub fn mark_expired_approvals(state: &AppState) -> usize {
    let now = now_i64().unwrap_or_default();
    let mut timed_out = Vec::new();
    for entry in state.approvals.iter() {
        if let ApprovalStatus::Pending = entry.status {
            if entry.request.expires_at <= now {
                timed_out.push(entry.key().clone());
            }
        }
    }

    for approval_id in &timed_out {
        if let Some(mut entry) = state.approvals.get_mut(approval_id) {
            entry.status = ApprovalStatus::Timeout;
            entry.decided_by = None;
            entry.decided_at = Some(now);
            entry.reason = Some("approval timeout".to_string());
            entry.updated_at = now;
            log_approval_audit(
                "approval.timeout",
                &entry.request.approval_id,
                &entry.request.request_id,
                "timeout",
            );
        }
    }
    let retain_after = now.saturating_sub(60);
    state
        .approvals
        .retain(|_, item| item.updated_at >= retain_after);
    timed_out.len()
}

pub fn spawn_approval_maintenance(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        loop {
            mark_expired_approvals(&state);
            sleep(Duration::from_secs(1)).await;
        }
    });
}

async fn execute(
    State(state): State<AppState>,
    Extension(peer): Extension<PeerCert>,
    Json(req): Json<ControlPlaneExecuteRequest>,
) -> Response {
    let _ = peer;
    let worker = match state.registry.iter().next() {
        Some(entry) => entry.value().clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ExecuteResponse {
                    ok: false,
                    output: String::new(),
                    error: Some("no worker registered".to_string()),
                    audit_id: None,
                }),
            )
                .into_response();
        }
    };

    let permit = match state.rate_limiter.allow_request(&req.tenant_id) {
        Ok(permit) => permit,
        Err(err) => return rate_limit_to_response(err),
    };
    if let Err(err) = state.rate_limiter.charge_cost(&req.tenant_id, 1) {
        drop(permit);
        return rate_limit_to_response(err);
    }

    let scope = format!("skill:{}", req.skill_id);
    let token = match state.token_issuer.issue(
        &req.subject,
        req.tenant_id.clone(),
        vec![scope],
        DEFAULT_TOKEN_TTL_SECONDS,
    ) {
        Ok(token) => token,
        Err(err) => {
            drop(permit);
            return (
                StatusCode::BAD_REQUEST,
                Json(ExecuteResponse {
                    ok: false,
                    output: String::new(),
                    error: Some(err),
                    audit_id: None,
                }),
            )
                .into_response();
        }
    };

    let execute_req = ExecuteRequest {
        token,
        tenant_id: req.tenant_id,
        skill_id: req.skill_id,
        input: req.input,
        request_id: req.request_id,
    };
    let payload = match serde_json::to_vec(&execute_req) {
        Ok(v) => v,
        Err(err) => {
            drop(permit);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecuteResponse {
                    ok: false,
                    output: String::new(),
                    error: Some(format!("serialize worker request: {}", err)),
                    audit_id: None,
                }),
            )
                .into_response();
        }
    };

    match forward_to_worker(&worker.addr, payload, state.worker_client.as_ref()).await {
        Ok((status, body)) => {
            let worker_resp = match serde_json::from_slice::<ExecuteResponse>(&body) {
                Ok(resp) => resp,
                Err(_) => ExecuteResponse {
                    ok: false,
                    output: String::new(),
                    error: Some("invalid worker response".to_string()),
                    audit_id: None,
                },
            };
            if status.is_success() {
                drop(permit);
                (StatusCode::OK, Json(worker_resp)).into_response()
            } else {
                drop(permit);
                (status, Json(worker_resp)).into_response()
            }
        }
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(ExecuteResponse {
                ok: false,
                output: String::new(),
                error: Some(err),
                audit_id: None,
            }),
        )
            .into_response(),
    }
}

async fn forward_to_worker(
    addr: &str,
    payload: Vec<u8>,
    client_cfg: &ClientConfig,
) -> Result<(StatusCode, Vec<u8>), String> {
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(client_cfg.clone())
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let url = format!("https://{}/execute", addr);
    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(payload)))
        .map_err(|e| format!("build worker request: {}", e))?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| format!("worker request failed: {}", e))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read worker response: {}", e))?
        .to_bytes();
    Ok((status, bytes.to_vec()))
}

fn now_unix_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())
        .map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::Json;
    use safeagent_shared_secrets::FileSecretStore;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestTokenIssuer;

    impl TokenIssuer for TestTokenIssuer {
        fn issue(
            &self,
            _: &str,
            tenant_id: TenantId,
            _: Vec<String>,
            _: u64,
        ) -> Result<String, String> {
            let _ = tenant_id;
            Ok("token".to_string())
        }
    }

    fn test_state(approval_timeout_secs: u64) -> AppState {
        let secret_store_dir = std::env::temp_dir().join(format!(
            "safeagent-control-plane-test-secrets-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&secret_store_dir);
        let key_store_dir = std::env::temp_dir().join(format!(
            "safeagent-control-plane-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&key_store_dir);
        let key_store = Arc::new(std::sync::Mutex::new(
            KeyStore::new(
                key_store_dir,
                std::sync::Arc::new(
                    FileSecretStore::new(&secret_store_dir, "test-password")
                        .expect("test secret store"),
                ),
                60 * 60,
            )
            .expect("test key store"),
        ));
        AppState {
            registry: Arc::new(DashMap::new()),
            token_issuer: Arc::new(TestTokenIssuer),
            key_store,
            worker_client: Arc::new(build_fake_client_config()),
            approvals: Arc::new(DashMap::new()),
            approval_timeout_secs,
            rate_limiter: Arc::new(TenantRateLimiter::new(TenantRateLimitConfig::default())),
        }
    }

    fn build_fake_client_config() -> ClientConfig {
        use rustls::RootCertStore;
        let roots = RootCertStore::empty();
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn approval_request() -> ApprovalRequest {
        let now = i64::try_from(now_unix_secs().unwrap_or_default()).unwrap_or_default();
        ApprovalRequest {
            approval_id: "approval".to_string(),
            request_id: "request".to_string(),
            node_id: "worker-001".to_string(),
            skill_id: "admin_op".to_string(),
            input_summary: "admin action".to_string(),
            reason: "test".to_string(),
            created_at: now,
            expires_at: now + 30,
        }
    }

    #[tokio::test]
    async fn approval_store_created_to_approved() {
        let state = test_state(30);
        let response = create_approval(&state, approval_request());
        let decision_request = ApprovalDecisionRequest {
            approval_id: response.approval_id,
            decision: "approved".to_string(),
            decided_by: "operator".to_string(),
            reason: None,
        };
        let (_, response) = decide_approval(State(state.clone()), Json(decision_request)).await;
        assert_eq!(response.0.status, "approved");
        let entry = state.approvals.get("approval").unwrap();
        assert!(matches!(entry.status, ApprovalStatus::Approved));
    }

    #[tokio::test]
    async fn approval_store_created_to_denied() {
        let state = test_state(30);
        let response = create_approval(&state, approval_request());
        let decision_request = ApprovalDecisionRequest {
            approval_id: response.approval_id,
            decision: "denied".to_string(),
            decided_by: "operator".to_string(),
            reason: None,
        };
        let (_, response) = decide_approval(State(state.clone()), Json(decision_request)).await;
        assert_eq!(response.0.status, "denied");
        let entry = state.approvals.get("approval").unwrap();
        assert!(matches!(entry.status, ApprovalStatus::Denied));
    }

    #[tokio::test]
    async fn approval_store_created_to_timeout() {
        let state = test_state(30);
        let mut request = approval_request();
        request.created_at = 1;
        request.expires_at = 2;
        state.approvals.insert(
            request.approval_id.clone(),
            ApprovalRecord {
                request,
                status: ApprovalStatus::Pending,
                decided_by: None,
                decided_at: None,
                reason: None,
                updated_at: 1,
            },
        );
        mark_expired_approvals(&state);
        let entry = state.approvals.get("approval").unwrap();
        assert!(matches!(entry.status, ApprovalStatus::Timeout));
    }

    #[tokio::test]
    async fn approval_store_double_approve_is_idempotent() {
        let state = test_state(30);
        let response = create_approval(&state, approval_request());
        let approval_id = response.approval_id;

        let first = ApprovalDecisionRequest {
            approval_id: approval_id.clone(),
            decision: "approved".to_string(),
            decided_by: "operator".to_string(),
            reason: None,
        };
        let (_, first_response) = decide_approval(State(state.clone()), Json(first)).await;
        assert_eq!(first_response.0.status, "approved");

        let second = ApprovalDecisionRequest {
            approval_id,
            decision: "denied".to_string(),
            decided_by: "operator".to_string(),
            reason: None,
        };
        let (_, second_response) = decide_approval(State(state.clone()), Json(second)).await;
        assert_eq!(second_response.0.status, "approved");
        let entry = state.approvals.get("approval").unwrap();
        assert!(matches!(entry.status, ApprovalStatus::Approved));
    }
}
