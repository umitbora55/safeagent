use std::env;

use tokio::net::TcpListener;

use safeagent_control_plane::{
    build_client_config, build_router, build_server_config, load_certs, load_key,
    Ed25519TokenIssuer,
};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8443";

struct ControlPlaneConfig {
    listen_addr: String,
    mtls_ca: String,
    mtls_cert: String,
    mtls_key: String,
    token_issuer_key: String,
    approval_timeout_secs: u64,
}

impl ControlPlaneConfig {
    fn from_env() -> Self {
        Self {
            listen_addr: env::var("CONTROL_PLANE_LISTEN_ADDR")
                .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string()),
            mtls_ca: env::var("MTLS_CA").unwrap_or_else(|_| "platform/pki/ca.crt".to_string()),
            mtls_cert: env::var("MTLS_CERT")
                .unwrap_or_else(|_| "platform/pki/control-plane.crt".to_string()),
            mtls_key: env::var("MTLS_KEY")
                .unwrap_or_else(|_| "platform/pki/control-plane.key".to_string()),
            token_issuer_key: env::var("TOKEN_ISSUER_KEY")
                .unwrap_or_else(|_| "platform/pki/token_issuer.key".to_string()),
            approval_timeout_secs: env::var("APPROVAL_TIMEOUT_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(safeagent_control_plane::DEFAULT_APPROVAL_TIMEOUT_SECONDS),
        }
    }
}

#[tokio::main]
async fn main() {
    let config = ControlPlaneConfig::from_env();

    let ca = load_certs(&config.mtls_ca).expect("Failed to load CA cert");
    let certs = load_certs(&config.mtls_cert).expect("Failed to load cert");
    let key = load_key(&config.mtls_key).expect("Failed to load key");
    let token_issuer = Ed25519TokenIssuer::from_file(&config.token_issuer_key)
        .expect("Failed to load token issuer key");
    let worker_client = build_client_config(&config.mtls_ca, &config.mtls_cert, &config.mtls_key)
        .expect("Failed to build worker client");

    let tls_config = build_server_config(ca, certs, key).expect("Failed to build TLS config");
    let state = safeagent_control_plane::AppState {
        registry: std::sync::Arc::new(dashmap::DashMap::new()),
        token_issuer: std::sync::Arc::new(token_issuer),
        worker_client: std::sync::Arc::new(worker_client),
        approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        approval_timeout_secs: config.approval_timeout_secs,
    };
    safeagent_control_plane::spawn_approval_maintenance(&state);
    let app = build_router(state);

    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind {}: {}", config.listen_addr, e));

    println!(
        "[control-plane] listen={} ca={} cert={} key={}",
        config.listen_addr, config.mtls_ca, config.mtls_cert, config.mtls_key
    );

    safeagent_control_plane::serve(listener, tls_config, app)
        .await
        .expect("Control plane failed");
}
