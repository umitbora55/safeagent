use std::env;
use std::sync::Arc;

use safeagent_shared_secrets::{FileSecretStore, SecretStore, VaultSecretStore};
use tokio::net::TcpListener;

use safeagent_control_plane::{
    build_client_config, build_server_config, load_certs, load_key, KeyStore, RotatingTokenIssuer,
};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8443";

struct ControlPlaneConfig {
    listen_addr: String,
    mtls_ca: String,
    mtls_cert: String,
    mtls_key: String,
    token_keys_dir: String,
    secret_store_dir: String,
    secret_backend: String,
    secret_password: String,
    vault_addr: String,
    vault_token: String,
    vault_mount: String,
    approval_timeout_secs: u64,
    rotation_grace_seconds: u64,
    tenant_concurrent_limit: usize,
    tenant_queue_limit: usize,
    tenant_token_bucket_capacity: u64,
    tenant_token_bucket_refill_per_second: u64,
    tenant_cost_budget: u64,
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
            approval_timeout_secs: env::var("APPROVAL_TIMEOUT_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(safeagent_control_plane::DEFAULT_APPROVAL_TIMEOUT_SECONDS),
            token_keys_dir: env::var("CONTROL_PLANE_KEYS_DIR")
                .unwrap_or_else(|_| "platform/control-plane/.keys".to_string()),
            secret_store_dir: env::var("CONTROL_PLANE_SECRET_DIR")
                .unwrap_or_else(|_| "platform/control-plane/.secrets".to_string()),
            secret_backend: env::var("CONTROL_PLANE_SECRET_BACKEND")
                .unwrap_or_else(|_| "file".to_string()),
            secret_password: env::var("SAFEAGENT_SECRET_PASSWORD")
                .unwrap_or_else(|_| "dev-change-me".to_string()),
            vault_addr: env::var("VAULT_ADDR").unwrap_or_default(),
            vault_token: env::var("VAULT_TOKEN").unwrap_or_default(),
            vault_mount: env::var("VAULT_MOUNT").unwrap_or_else(|_| "kv".to_string()),
            rotation_grace_seconds: env::var("CONTROL_PLANE_KEY_ROTATION_GRACE_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(24 * 60 * 60),
            tenant_concurrent_limit: env::var("CONTROL_PLANE_TENANT_CONCURRENT_LIMIT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(safeagent_control_plane::DEFAULT_TENANT_CONCURRENT_LIMIT),
            tenant_queue_limit: env::var("CONTROL_PLANE_TENANT_QUEUE_LIMIT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(safeagent_control_plane::DEFAULT_TENANT_QUEUE_LIMIT),
            tenant_token_bucket_capacity: env::var("CONTROL_PLANE_TENANT_TOKEN_BUCKET_CAPACITY")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(safeagent_control_plane::DEFAULT_TENANT_TOKEN_BUCKET_CAPACITY),
            tenant_token_bucket_refill_per_second: env::var(
                "CONTROL_PLANE_TENANT_TOKEN_BUCKET_REFILL_PER_SECOND",
            )
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(safeagent_control_plane::DEFAULT_TENANT_TOKEN_BUCKET_REFILL_PER_SECOND),
            tenant_cost_budget: env::var("CONTROL_PLANE_TENANT_COST_BUDGET")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(safeagent_control_plane::DEFAULT_TENANT_COST_BUDGET),
        }
    }
}

fn ensure_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_secret_store(config: &ControlPlaneConfig) -> Arc<dyn SecretStore> {
    match config.secret_backend.as_str() {
        "vault" => Arc::new(VaultSecretStore::new(
            &config.vault_addr,
            &config.vault_token,
            &config.vault_mount,
        )),
        _ => Arc::new(
            FileSecretStore::new(&config.secret_store_dir, &config.secret_password)
                .expect("failed to initialize file secret store"),
        ),
    }
}

#[tokio::main]
async fn main() {
    ensure_default_crypto_provider();

    let config = ControlPlaneConfig::from_env();
    let secret_store = build_secret_store(&config);

    let ca = load_certs(&config.mtls_ca).expect("Failed to load CA cert");
    let certs = load_certs(&config.mtls_cert).expect("Failed to load cert");
    let key = load_key(&config.mtls_key).expect("Failed to load key");
    let key_store = std::sync::Arc::new(std::sync::Mutex::new(
        KeyStore::new(
            &config.token_keys_dir,
            std::sync::Arc::clone(&secret_store),
            config.rotation_grace_seconds,
        )
        .unwrap_or_else(|err| {
            panic!(
                "Failed to initialize key store in {}: {}",
                config.token_keys_dir, err
            )
        }),
    ));
    let token_issuer = RotatingTokenIssuer::new(
        std::sync::Arc::clone(&key_store),
        safeagent_control_plane::DEFAULT_TOKEN_TTL_SECONDS,
        safeagent_control_plane::MAX_TOKEN_TTL_SECONDS,
    );
    let worker_client = build_client_config(&config.mtls_ca, &config.mtls_cert, &config.mtls_key)
        .expect("Failed to build worker client");

    let tls_config = build_server_config(ca, certs, key).expect("Failed to build TLS config");
    let state = safeagent_control_plane::AppState {
        registry: std::sync::Arc::new(dashmap::DashMap::new()),
        token_issuer: std::sync::Arc::new(token_issuer),
        key_store,
        worker_client: std::sync::Arc::new(worker_client),
        approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        approval_timeout_secs: config.approval_timeout_secs,
        rate_limiter: std::sync::Arc::new(safeagent_control_plane::TenantRateLimiter::new(
            safeagent_control_plane::TenantRateLimitConfig {
                token_bucket_capacity: config.tenant_token_bucket_capacity,
                token_bucket_refill_per_second: config.tenant_token_bucket_refill_per_second,
                concurrent_limit: config.tenant_concurrent_limit,
                queue_limit: config.tenant_queue_limit,
                cost_budget: config.tenant_cost_budget,
            },
        )),
    };
    safeagent_control_plane::spawn_approval_maintenance(&state);
    let app = safeagent_control_plane::build_router(state);

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
