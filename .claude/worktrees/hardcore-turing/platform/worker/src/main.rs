use std::env;
use std::io::BufReader;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::PrivateKeyDer;
use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys};
use serde_json::to_vec;
use tokio::net::TcpListener;
use tokio::time::sleep;

use safeagent_shared_proto::{WorkerRegisterRequest, WorkerRegisterResponse};
use safeagent_worker::{
    build_router, build_server_config, load_certs, load_key, serve, Ed25519TokenVerifier,
    WorkerState,
};

const DEFAULT_CONTROL_PLANE_URL: &str = "https://127.0.0.1:8443";
const DEFAULT_TOKEN_PUBLIC_KEY: &str = "platform/pki/token_issuer.pub";

struct WorkerConfig {
    control_plane_url: String,
    mtls_ca: String,
    mtls_cert: String,
    mtls_key: String,
    worker_addr: String,
    worker_version: String,
    token_public_key: String,
    oneshot: bool,
    approval_timeout_secs: u64,
}

impl WorkerConfig {
    fn from_env() -> Self {
        Self {
            control_plane_url: env::var("CONTROL_PLANE_URL")
                .unwrap_or_else(|_| DEFAULT_CONTROL_PLANE_URL.to_string()),
            mtls_ca: env::var("MTLS_CA").unwrap_or_else(|_| "platform/pki/ca.crt".to_string()),
            mtls_cert: env::var("MTLS_CERT")
                .unwrap_or_else(|_| "platform/pki/worker.crt".to_string()),
            mtls_key: env::var("MTLS_KEY")
                .unwrap_or_else(|_| "platform/pki/worker.key".to_string()),
            worker_addr: env::var("WORKER_ADDR").unwrap_or_else(|_| "127.0.0.1:8280".to_string()),
            worker_version: env::var("WORKER_VERSION").unwrap_or_else(|_| "v1".to_string()),
            token_public_key: env::var("TOKEN_PUBLIC_KEY")
                .unwrap_or_else(|_| DEFAULT_TOKEN_PUBLIC_KEY.to_string()),
            oneshot: env::var("WORKER_ONESHOT").unwrap_or_default() == "1",
            approval_timeout_secs: env::var("APPROVAL_TIMEOUT_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(30),
        }
    }
}

fn build_client_config(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<rustls::ClientConfig, String> {
    use rustls::ClientConfig;
    use rustls::RootCertStore;

    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        roots
            .add(cert)
            .map_err(|e| format!("Failed to add CA cert: {:?}", e))?;
    }

    let certs = load_certs(cert_path)?;
    let data = std::fs::read(key_path).map_err(|e| format!("read key {}: {}", key_path, e))?;
    let mut reader = BufReader::new(&data[..]);
    let mut keys = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse PKCS8 key: {:?}", e))?;
    if let Some(key) = keys.pop() {
        return ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, PrivateKeyDer::Pkcs8(key))
            .map_err(|e| format!("Failed to build client config: {:?}", e));
    }

    let mut reader = BufReader::new(&data[..]);
    let mut keys = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse RSA key: {:?}", e))?;
    let key = keys
        .pop()
        .ok_or_else(|| "No private key found".to_string())?;

    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, PrivateKeyDer::Pkcs1(key))
        .map_err(|e| format!("Failed to build client config: {:?}", e))
}

#[tokio::main]
async fn main() {
    let config = WorkerConfig::from_env();
    println!(
        "[worker] control_plane={} ca={} cert={} key={} addr={}",
        config.control_plane_url,
        config.mtls_ca,
        config.mtls_cert,
        config.mtls_key,
        config.worker_addr
    );

    let verifier = Ed25519TokenVerifier::from_file(&config.token_public_key)
        .expect("failed to load token public key");
    let state = WorkerState::with_control_plane(
        std::sync::Arc::new(verifier),
        config.control_plane_url.clone(),
        build_client_config(&config.mtls_ca, &config.mtls_cert, &config.mtls_key).unwrap_or_else(
            |e| panic!("Failed to build worker control plane client config: {}", e),
        ),
        config.approval_timeout_secs,
    );

    let ca = load_certs(&config.mtls_ca).unwrap_or_else(|e| panic!("Failed to load CA: {}", e));
    let certs = load_certs(&config.mtls_cert)
        .unwrap_or_else(|e| panic!("Failed to load worker cert: {}", e));
    let key =
        load_key(&config.mtls_key).unwrap_or_else(|e| panic!("Failed to load worker key: {}", e));
    let server_tls = build_server_config(ca, certs, key)
        .unwrap_or_else(|e| panic!("Failed to build worker TLS config: {}", e));

    let listener = TcpListener::bind(&config.worker_addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind {}: {}", config.worker_addr, e));
    let app = build_router(state);
    tokio::spawn(async move {
        let _ = serve(listener, server_tls, app).await;
    });

    let client_cfg = build_client_config(&config.mtls_ca, &config.mtls_cert, &config.mtls_key)
        .unwrap_or_else(|e| panic!("Failed to build worker client config: {}", e));
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(client_cfg)
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    for _ in 0..5 {
        let health_url = format!("{}/health", config.control_plane_url);
        if let Ok(response) = client
            .request(
                Request::builder()
                    .method("GET")
                    .uri(&health_url)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
        {
            if response.status().is_success() {
                break;
            }
        }
        sleep(Duration::from_millis(200)).await;
    }

    let register_url = format!("{}/register", config.control_plane_url);
    let register_body = to_vec(&WorkerRegisterRequest {
        addr: config.worker_addr.clone(),
        version: config.worker_version.clone(),
    })
    .expect("serialize register request");
    if let Ok(response) = client
        .request(
            Request::builder()
                .method("POST")
                .uri(register_url)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(register_body)))
                .unwrap(),
        )
        .await
    {
        let bytes = response
            .into_body()
            .collect()
            .await
            .map(|body| body.to_bytes())
            .unwrap_or_default();
        if let Ok(resp) = serde_json::from_slice::<WorkerRegisterResponse>(&bytes) {
            println!("[worker] registered node_id={}", resp.node_id);
        } else {
            println!(
                "[worker] register response={}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }

    if config.oneshot {
        return;
    }

    loop {
        sleep(Duration::from_secs(3600)).await;
    }
}
