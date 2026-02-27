use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::Router;
use dashmap::DashMap;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout, Duration};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use safeagent_control_plane::{
    build_client_config, build_router, build_server_config, AppState, KeyStore,
    RotatingTokenIssuer, TenantRateLimitConfig,
};
use safeagent_shared_identity::{Claims as IdentityClaims, TenantId};
use safeagent_shared_proto::{
    ApprovalDecisionRequest, ApprovalRequest, ApprovalStatusResponse, ControlPlaneExecuteRequest,
    ExecuteRequest, ExecuteResponse, IssueTokenRequest, IssueTokenResponse, Jwks,
    WorkerRegisterRequest, WorkerRegisterResponse,
};
use safeagent_shared_secrets::FileSecretStore;
use safeagent_worker::{
    build_router as build_worker_router, build_server_config as build_worker_server_config,
};
use safeagent_worker::{JwksTokenVerifier, WorkerState};

type TestHttpClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

fn pki_path(file: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("pki")
        .join(file)
}

fn load_certs(path: &std::path::Path) -> Vec<CertificateDer<'static>> {
    let data = std::fs::read(path).expect("read cert");
    let mut reader = std::io::BufReader::new(&data[..]);
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certs")
}

fn load_key(path: &std::path::Path) -> PrivateKeyDer<'static> {
    let data = std::fs::read(path).expect("read key");
    let mut reader = std::io::BufReader::new(&data[..]);
    let mut keys = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse pkcs8");
    if let Some(key) = keys.pop() {
        return PrivateKeyDer::Pkcs8(key);
    }
    let mut reader = std::io::BufReader::new(&data[..]);
    let mut keys = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("parse rsa");
    keys.pop().map(PrivateKeyDer::Pkcs1).expect("no key")
}

async fn start_server() -> SocketAddr {
    start_server_with_timeout(30).await
}

async fn start_server_with_timeout(approval_timeout_secs: u64) -> SocketAddr {
    start_server_with_state(approval_timeout_secs, TenantRateLimitConfig::default())
        .await
        .0
}

async fn start_server_with_state(
    approval_timeout_secs: u64,
    rate_limit_config: TenantRateLimitConfig,
) -> (SocketAddr, std::path::PathBuf) {
    let ca = load_certs(&pki_path("ca.crt"));
    let certs = load_certs(&pki_path("control-plane.crt"));
    let key = load_key(&pki_path("control-plane.key"));
    let tls_config = build_server_config(ca, certs, key).expect("tls config");
    let keys_dir = std::env::temp_dir().join(format!(
        "safeagent-cp-test-keys-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let key_store = std::sync::Arc::new(std::sync::Mutex::new(
        KeyStore::new(
            &keys_dir,
            std::sync::Arc::new(
                FileSecretStore::new(
                    std::env::temp_dir().join(format!(
                        "safeagent-cp-secret-test-{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .expect("time")
                            .as_nanos()
                    )),
                    "test-password",
                )
                .expect("secret store"),
            ),
            24 * 60 * 60,
        )
        .expect("key store"),
    ));
    let token_issuer = RotatingTokenIssuer::new(std::sync::Arc::clone(&key_store), 60, 300);
    let worker_client = build_client_config(
        pki_path("ca.crt").to_str().expect("ca path"),
        pki_path("worker.crt").to_str().expect("worker cert path"),
        pki_path("worker.key").to_str().expect("worker key path"),
    )
    .expect("worker client config");

    let state = AppState {
        registry: Arc::new(DashMap::new()),
        token_issuer: Arc::new(token_issuer),
        key_store,
        worker_client: Arc::new(worker_client),
        approvals: Arc::new(DashMap::new()),
        approval_timeout_secs,
        rate_limiter: std::sync::Arc::new(safeagent_control_plane::TenantRateLimiter::new(
            rate_limit_config,
        )),
    };
    let app: Router = build_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = safeagent_control_plane::serve(listener, tls_config, app).await;
    });
    (addr, keys_dir)
}

async fn start_worker_server(control_plane_url: &str) -> SocketAddr {
    start_worker_server_with_approval_timeout(control_plane_url, 30).await
}

async fn start_worker_server_with_approval_timeout(
    control_plane_url: &str,
    approval_timeout_secs: u64,
) -> SocketAddr {
    let ca = load_certs(&pki_path("ca.crt"));
    let certs = load_certs(&pki_path("worker.crt"));
    let key = load_key(&pki_path("worker.key"));
    let tls_config = build_worker_server_config(ca, certs, key).expect("worker tls config");
    let worker_client_config = build_client_config(
        pki_path("ca.crt").to_str().expect("ca path"),
        pki_path("worker.crt").to_str().expect("worker cert path"),
        pki_path("worker.key").to_str().expect("worker key path"),
    )
    .expect("worker client config");
    let verifier = JwksTokenVerifier::new(
        control_plane_url.to_string(),
        std::sync::Arc::new(worker_client_config.clone()),
        60,
    );
    let state = WorkerState::with_control_plane(
        Arc::new(verifier),
        control_plane_url.to_string(),
        worker_client_config,
        approval_timeout_secs,
    );
    let app = build_worker_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = safeagent_worker::serve(listener, tls_config, app).await;
    });
    addr
}

fn now_unix_secs() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    now.try_into().expect("time")
}

fn build_client(
    server_ca: &[CertificateDer<'static>],
    client_certs: Option<Vec<CertificateDer<'static>>>,
    client_key: Option<PrivateKeyDer<'static>>,
) -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
> {
    let mut roots = RootCertStore::empty();
    for cert in server_ca.iter().cloned() {
        roots.add(cert).expect("add root");
    }

    let config = if let (Some(certs), Some(key)) = (client_certs, client_key) {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .expect("client config")
    } else {
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(https)
}

#[tokio::test]
async fn register_with_valid_cert_passes() {
    let addr = start_server().await;
    let ca = load_certs(&pki_path("ca.crt"));
    let client_certs = load_certs(&pki_path("worker.crt"));
    let client_key = load_key(&pki_path("worker.key"));
    let client = build_client(&ca, Some(client_certs), Some(client_key));

    let body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: "127.0.0.1:8280".to_string(),
        version: "test".to_string(),
    })
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri(format!("https://{}/register", addr))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert!(resp.status().is_success());
}

#[tokio::test]
async fn register_without_client_cert_fails() {
    let addr = start_server().await;
    let ca = load_certs(&pki_path("ca.crt"));
    let client = build_client(&ca, None, None);

    let body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: "127.0.0.1:8280".to_string(),
        version: "test".to_string(),
    })
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri(format!("https://{}/register", addr))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();

    let resp = client.request(req).await;
    assert!(resp.is_err());
}

#[tokio::test]
async fn register_with_wrong_ca_fails() {
    let addr = start_server().await;
    let ca = load_certs(&pki_path("ca.crt"));

    let mut ca_params = CertificateParams::new(vec!["bad-ca".to_string()]).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "bad-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut client_params = CertificateParams::new(vec![]).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "worker-bad");
    client_params
        .subject_alt_names
        .push(SanType::URI("safeagent://node/worker-bad".parse().unwrap()));
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    let client = build_client(
        &ca,
        Some(vec![client_cert.der().clone()]),
        Some(PrivateKeyDer::Pkcs8(client_key.serialize_der().into())),
    );

    let body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: "127.0.0.1:8280".to_string(),
        version: "test".to_string(),
    })
    .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri(format!("https://{}/register", addr))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();

    let resp = client.request(req).await;
    assert!(resp.is_err());
}

#[tokio::test]
async fn execute_via_control_plane_passes() {
    let control_plane_addr = start_server().await;
    let control_plane_url = format!("https://{}", control_plane_addr);
    let worker_addr = start_worker_server(&control_plane_url).await;

    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );

    let health_request = Request::builder()
        .method("GET")
        .uri(format!("https://{}/health", worker_addr))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let health_resp = cp_client.request(health_request).await.unwrap();
    assert!(health_resp.status().is_success());

    let register_body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: worker_addr.to_string(),
        version: "v1".to_string(),
    })
    .unwrap();
    let register = Request::builder()
        .method("POST")
        .uri(format!("https://{}/register", control_plane_addr))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(register_body)))
        .unwrap();
    let register_resp = cp_client.request(register).await.unwrap();
    assert_eq!(register_resp.status(), 200);

    let parsed = register_resp
        .into_body()
        .collect()
        .await
        .expect("register response");
    let _resp: WorkerRegisterResponse =
        serde_json::from_slice(&parsed.to_bytes()).expect("register response body");

    let execute = serde_json::to_vec(&ControlPlaneExecuteRequest {
        subject: "safeagent://node/worker-001".to_string(),
        tenant_id: TenantId("tenant-1".to_string()),
        skill_id: "echo".to_string(),
        input: "hello".to_string(),
        request_id: "req-1".to_string(),
    })
    .unwrap();
    let execute_request = Request::builder()
        .method("POST")
        .uri(format!("https://{}/execute", control_plane_addr))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(execute)))
        .unwrap();
    let execute_resp = cp_client.request(execute_request).await.unwrap();
    let status = execute_resp.status();
    let execute_body = execute_resp
        .into_body()
        .collect()
        .await
        .expect("execute response");
    let execute_body = execute_body.to_bytes();
    let execute_resp: ExecuteResponse =
        serde_json::from_slice(&execute_body).expect("execute response body");
    assert_eq!(
        status,
        200,
        "execute failed: status={}, body={}",
        status,
        String::from_utf8_lossy(&execute_body)
    );
    assert!(execute_resp.ok);
    assert_eq!(execute_resp.output, "hello");
}

#[tokio::test]
async fn rate_limit_parallel_requests_enforce_tenant_concurrency_limit() {
    let control_plane_addr = start_server_with_state(
        1,
        TenantRateLimitConfig {
            concurrent_limit: 5,
            queue_limit: 5,
            token_bucket_capacity: 1000,
            token_bucket_refill_per_second: 1000,
            cost_budget: 1000,
        },
    )
    .await
    .0;

    let control_plane_url = format!("https://{}", control_plane_addr);
    let worker_addr = start_worker_server(&control_plane_url).await;
    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );

    let register_body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: worker_addr.to_string(),
        version: "v1".to_string(),
    })
    .unwrap();
    let register = Request::builder()
        .method("POST")
        .uri(format!("https://{}/register", control_plane_addr))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(register_body)))
        .unwrap();
    let register_resp = cp_client.request(register).await.unwrap();
    assert_eq!(register_resp.status(), 200);

    let mut handles = Vec::new();
    for i in 0..10 {
        let execute_client = cp_client.clone();
        let request_id = format!("rl-{}", i);
        let execute = serde_json::to_vec(&ControlPlaneExecuteRequest {
            subject: "safeagent://node/worker-001".to_string(),
            tenant_id: TenantId("tenant-rl".to_string()),
            skill_id: "echo".to_string(),
            input: "hello".to_string(),
            request_id,
        })
        .unwrap();
        let handle = tokio::spawn(async move {
            execute_client
                .request(
                    Request::builder()
                        .method("POST")
                        .uri(format!("https://{}/execute", control_plane_addr))
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(execute)))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        });
        handles.push(handle);
    }

    let mut denied = 0u32;
    let mut accepted = 0u32;
    for handle in handles {
        let status = handle.await.unwrap();
        if status == StatusCode::TOO_MANY_REQUESTS {
            denied += 1;
        } else {
            accepted += 1;
        }
    }

    assert_eq!(accepted, 5);
    assert_eq!(denied, 5);
}

#[test]
fn rate_limit_queue_limit_returns_service_unavailable_when_queue_exhausted() {
    let limiter = safeagent_control_plane::TenantRateLimiter::new(TenantRateLimitConfig {
        concurrent_limit: 1,
        queue_limit: 0,
        token_bucket_capacity: 10,
        token_bucket_refill_per_second: 10,
        cost_budget: 10,
    });
    let tenant = TenantId("tenant-queue".to_string());
    let _first = limiter
        .allow_request(&tenant)
        .expect("first request enters");
    let denied = limiter
        .allow_request(&tenant)
        .expect_err("queue should be exhausted");

    assert_eq!(denied.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(denied.code, "queue_limit_exceeded");
}

#[test]
fn rate_limit_cost_limit_returns_payment_required() {
    let limiter = safeagent_control_plane::TenantRateLimiter::new(TenantRateLimitConfig {
        concurrent_limit: 10,
        queue_limit: 10,
        token_bucket_capacity: 10,
        token_bucket_refill_per_second: 10,
        cost_budget: 1,
    });
    let tenant = TenantId("tenant-cost".to_string());
    let permit = limiter
        .allow_request(&tenant)
        .expect("first request allowed");
    limiter
        .charge_cost(permit.tenant_id(), 1)
        .expect("cost under budget");
    drop(permit);
    let denied = limiter
        .charge_cost(&tenant, 1)
        .expect_err("second cost charge denied");

    assert_eq!(denied.status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(denied.code, "cost_limit_exceeded");
}

#[tokio::test]
async fn approval_request_and_pending_list_and_decide() {
    let control_plane_addr = start_server().await;
    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );

    let now = now_unix_secs();
    let request = ApprovalRequest {
        approval_id: "phase-1-4-1".to_string(),
        request_id: "req-red-1".to_string(),
        node_id: "worker-001".to_string(),
        skill_id: "admin_op".to_string(),
        input_summary: "admin action".to_string(),
        reason: "human approval required".to_string(),
        created_at: now,
        expires_at: now + 30,
    };

    let request_body = serde_json::to_vec(&request).unwrap();
    let request_resp = cp_client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/approval/request", control_plane_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(request_body)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(request_resp.status(), 200);

    let pending_body = cp_client
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("https://{}/approval/pending", control_plane_addr))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let pending: Vec<ApprovalRequest> =
        serde_json::from_slice(&pending_body).expect("pending approvals");
    let found = pending
        .iter()
        .any(|entry| entry.approval_id == "phase-1-4-1");
    assert!(found);

    let decision_body = serde_json::to_vec(&ApprovalDecisionRequest {
        approval_id: "phase-1-4-1".to_string(),
        decision: "approved".to_string(),
        decided_by: "operator".to_string(),
        reason: Some("allowed".to_string()),
    })
    .unwrap();
    let decision_resp = cp_client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/approval/decide", control_plane_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(decision_body)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decision_resp.status(), 200);

    let status_body = cp_client
        .request(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "https://{}/approval/status?approval_id=phase-1-4-1",
                    control_plane_addr
                ))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let status: ApprovalStatusResponse =
        serde_json::from_slice(&status_body).expect("approval status");
    assert_eq!(status.status, "approved");
    assert_eq!(status.decided_by.as_deref(), Some("operator"));
}

#[tokio::test]
async fn red_action_waits_for_approval_then_executes() {
    let control_plane_addr = start_server_with_timeout(2).await;
    let control_plane_url = format!("https://{}", control_plane_addr);
    let worker_addr = start_worker_server_with_approval_timeout(&control_plane_url, 2).await;
    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );

    let register_body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: worker_addr.to_string(),
        version: "v1".to_string(),
    })
    .unwrap();
    let register = cp_client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/register", control_plane_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(register_body)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(register.status(), 200);

    let execute_body = serde_json::to_vec(&ControlPlaneExecuteRequest {
        subject: "safeagent://node/worker-001".to_string(),
        tenant_id: TenantId("tenant-1".to_string()),
        skill_id: "admin_op".to_string(),
        input: "rotate-key".to_string(),
        request_id: "req-admin-approve".to_string(),
    })
    .unwrap();
    let execute_client = cp_client.clone();
    let execute_handle = tokio::spawn(async move {
        let response = execute_client
            .request(
                Request::builder()
                    .method("POST")
                    .uri(format!("https://{}/execute", control_plane_addr))
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(execute_body)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("execute response")
            .to_bytes();
        let parsed =
            serde_json::from_slice::<ExecuteResponse>(&body).expect("execute response body");
        (status, parsed, body)
    });

    let mut approval_id = None;
    for _ in 0..20 {
        let pending = cp_client
            .request(
                Request::builder()
                    .method("GET")
                    .uri(format!("https://{}/approval/pending", control_plane_addr))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .expect("pending endpoint");
        let pending_body = pending
            .into_body()
            .collect()
            .await
            .expect("pending response")
            .to_bytes();
        let pending: Vec<ApprovalRequest> =
            serde_json::from_slice(&pending_body).expect("pending body");
        if let Some(entry) = pending
            .into_iter()
            .find(|entry| entry.request_id == "req-admin-approve")
        {
            approval_id = Some(entry.approval_id);
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    assert!(approval_id.is_some());

    let approve = serde_json::to_vec(&ApprovalDecisionRequest {
        approval_id: approval_id.clone().expect("approval id"),
        decision: "approved".to_string(),
        decided_by: "operator".to_string(),
        reason: Some("approved for test".to_string()),
    })
    .unwrap();
    let decide = cp_client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/approval/decide", control_plane_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(approve)))
                .unwrap(),
        )
        .await
        .expect("decide");
    assert_eq!(decide.status(), 200);

    let (status, response, raw) = execute_handle.await.unwrap();
    assert_eq!(status, 200);
    assert!(
        response.ok,
        "status={}, body={}",
        status,
        String::from_utf8_lossy(&raw)
    );
    assert_eq!(response.output, "admin-op:req-admin-approve:approved");
}

#[tokio::test]
async fn red_action_timeout_is_rejected() {
    let control_plane_addr = start_server_with_timeout(1).await;
    let control_plane_url = format!("https://{}", control_plane_addr);
    let worker_addr = start_worker_server_with_approval_timeout(&control_plane_url, 1).await;
    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );

    let register_body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: worker_addr.to_string(),
        version: "v1".to_string(),
    })
    .unwrap();
    cp_client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/register", control_plane_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(register_body)))
                .unwrap(),
        )
        .await
        .unwrap();

    let execute_body = serde_json::to_vec(&ControlPlaneExecuteRequest {
        subject: "safeagent://node/worker-001".to_string(),
        tenant_id: TenantId("tenant-1".to_string()),
        skill_id: "admin_op".to_string(),
        input: "rotate-key-timeout".to_string(),
        request_id: "req-admin-timeout".to_string(),
    })
    .unwrap();
    let execute_handle = tokio::spawn(async move {
        let cp_timeout_client = {
            let ca = load_certs(&pki_path("ca.crt"));
            build_client(
                &ca,
                Some(load_certs(&pki_path("worker.crt"))),
                Some(load_key(&pki_path("worker.key"))),
            )
        };
        let response = cp_timeout_client
            .request(
                Request::builder()
                    .method("POST")
                    .uri(format!("https://{}/execute", control_plane_addr))
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(execute_body)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("execute response")
            .to_bytes();
        let parsed =
            serde_json::from_slice::<ExecuteResponse>(&body).expect("execute response body");
        (status, parsed, body)
    });

    let output = timeout(Duration::from_secs(6), execute_handle)
        .await
        .expect("execute did not complete")
        .expect("join ok");
    assert_eq!(output.0, StatusCode::FORBIDDEN);
    let message = output
        .1
        .error
        .unwrap_or_else(|| String::from("missing error"));
    assert_eq!(message, "approval timeout");
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

fn decode_token_parts(token: &str) -> (Option<JwtHeader>, IdentityClaims) {
    let mut parts = token.split('.').collect::<Vec<_>>();
    assert!((2..=3).contains(&parts.len()));
    let (header, payload) = if parts.len() == 3 {
        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("decode token header");
        (
            Some(
                serde_json::from_slice::<JwtHeader>(&header_json)
                    .expect("decode token header json"),
            ),
            parts[1],
        )
    } else {
        (None, parts.remove(0))
    };
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("decode token payload");
    let claims = serde_json::from_slice::<IdentityClaims>(&payload).expect("decode token claims");
    (header, claims)
}

async fn fetch_jwks(cp_addr: &SocketAddr, client: &TestHttpClient) -> Jwks {
    let response = client
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("https://{}/jwks", cp_addr))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .expect("jwks request");
    assert!(response.status().is_success());
    serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("jwks body")
            .to_bytes(),
    )
    .expect("jwks decode")
}

async fn issue_token(cp_addr: &SocketAddr, client: &TestHttpClient, subject: &str) -> String {
    let req = serde_json::to_vec(&IssueTokenRequest {
        subject: subject.to_string(),
        scopes: vec!["skill:echo".to_string()],
        ttl_secs: 120,
    })
    .unwrap();
    let response = client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/issue-token", cp_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(req)))
                .unwrap(),
        )
        .await
        .expect("issue-token request");
    assert!(response.status().is_success());
    let response = serde_json::from_slice::<IssueTokenResponse>(
        &response
            .into_body()
            .collect()
            .await
            .expect("issue-token body")
            .to_bytes(),
    )
    .expect("issue-token decode");
    response.token
}

async fn execute_with_token(
    worker_addr: &SocketAddr,
    client: &TestHttpClient,
    token: String,
    request_id: &str,
) -> ExecuteResponse {
    let request = ExecuteRequest {
        token,
        tenant_id: TenantId("tenant-1".to_string()),
        skill_id: "echo".to_string(),
        input: "hello".to_string(),
        request_id: request_id.to_string(),
    };
    let body = serde_json::to_vec(&request).unwrap();
    let response = client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/execute", worker_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
        )
        .await
        .expect("worker execute request");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("worker execute body")
        .to_bytes();
    assert!(status.is_success(), "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice::<ExecuteResponse>(&body).expect("worker execute decode")
}

#[tokio::test]
async fn key_rotation_rotate_and_jwks_contains_retired_key() {
    let control_plane_addr = start_server().await;
    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );
    let jwks_before = fetch_jwks(&control_plane_addr, &cp_client).await;
    let rotate = {
        let response = cp_client
            .request(
                Request::builder()
                    .method("POST")
                    .uri(format!("https://{}/admin/rotate-keys", control_plane_addr))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .expect("rotate keys");
        assert!(response.status().is_success());
        let body = response
            .into_body()
            .collect()
            .await
            .expect("rotate body")
            .to_bytes();
        serde_json::from_slice::<serde_json::Value>(&body).expect("rotate response")
    };
    let before_kids: std::collections::HashSet<_> = jwks_before
        .keys
        .into_iter()
        .map(|entry| entry.kid)
        .collect();
    let rotated_kid = rotate["rotated_kid"].as_str().expect("rotated_kid");
    let active_kid = rotate["active_kid"].as_str().expect("active_kid");
    assert_ne!(rotated_kid, active_kid);
    let jwks_after = fetch_jwks(&control_plane_addr, &cp_client).await;
    let after_kids: std::collections::HashSet<_> =
        jwks_after.keys.into_iter().map(|entry| entry.kid).collect();
    assert!(after_kids.contains(active_kid));
    assert!(after_kids.contains(rotated_kid));
    assert!(before_kids.contains(active_kid) || before_kids.contains(rotated_kid));
}

#[tokio::test]
async fn key_rotation_issue_token_includes_kid() {
    let control_plane_addr = start_server().await;
    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );
    let token = issue_token(
        &control_plane_addr,
        &cp_client,
        "safeagent://node/worker-001",
    )
    .await;
    let (header, claims) = decode_token_parts(&token);
    assert!(!claims.kid.is_empty());
    assert!(header.is_some());
    let header = header.expect("header");
    assert_eq!(header.alg, "EdDSA");
    assert_eq!(header.kid, Some(claims.kid.clone()));
}

#[tokio::test]
async fn key_rotation_e2e() {
    let control_plane_addr = start_server().await;
    let control_plane_url = format!("https://{}", control_plane_addr);
    let worker_addr = start_worker_server_with_approval_timeout(&control_plane_url, 30).await;
    let cp_ca = load_certs(&pki_path("ca.crt"));
    let cp_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );
    let worker_client = build_client(
        &cp_ca,
        Some(load_certs(&pki_path("worker.crt"))),
        Some(load_key(&pki_path("worker.key"))),
    );

    let register_body = serde_json::to_vec(&WorkerRegisterRequest {
        addr: worker_addr.to_string(),
        version: "v1".to_string(),
    })
    .unwrap();
    let register = cp_client
        .request(
            Request::builder()
                .method("POST")
                .uri(format!("https://{}/register", control_plane_addr))
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(register_body)))
                .unwrap(),
        )
        .await
        .expect("register worker");
    assert!(register.status().is_success());

    let token_v1 = issue_token(
        &control_plane_addr,
        &cp_client,
        "safeagent://node/worker-001",
    )
    .await;
    let (_header, _claims_v1) = decode_token_parts(&token_v1);

    let rotate = {
        let response = cp_client
            .request(
                Request::builder()
                    .method("POST")
                    .uri(format!("https://{}/admin/rotate-keys", control_plane_addr))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .expect("rotate keys");
        serde_json::from_slice::<serde_json::Value>(
            &response
                .into_body()
                .collect()
                .await
                .expect("rotate body")
                .to_bytes(),
        )
        .expect("rotate body decode")
    };
    assert!(rotate
        .get("rotated_kid")
        .and_then(|value| value.as_str())
        .is_some());

    let response =
        execute_with_token(&worker_addr, &worker_client, token_v1.clone(), "req-v1").await;
    assert!(response.ok);
    assert_eq!(response.output, "hello");

    let token_v2 = issue_token(
        &control_plane_addr,
        &cp_client,
        "safeagent://node/worker-001",
    )
    .await;
    let (_header, _claims_v2) = decode_token_parts(&token_v2);
    let response = execute_with_token(&worker_addr, &worker_client, token_v2, "req-v2").await;
    assert!(response.ok);
    assert_eq!(response.output, "hello");
}
