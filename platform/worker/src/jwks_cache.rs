use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Verifier, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use tokio::sync::RwLock;

use safeagent_shared_identity::Claims;
use safeagent_shared_proto::Jwks;

use crate::{now_unix_secs, parse_token, scope_allows, ParsedToken, TokenVerifier};

#[derive(Default)]
struct JwksCacheState {
    keys: HashMap<String, VerifyingKey>,
    refreshed_at: Option<Instant>,
}

pub struct JwksTokenVerifier {
    control_plane_url: String,
    client_config: Arc<ClientConfig>,
    refresh_ttl: Duration,
    cache: RwLock<JwksCacheState>,
}

impl JwksTokenVerifier {
    pub fn new(
        control_plane_url: String,
        client_config: Arc<ClientConfig>,
        refresh_ttl_secs: u64,
    ) -> Self {
        Self {
            control_plane_url,
            client_config,
            refresh_ttl: Duration::from_secs(refresh_ttl_secs),
            cache: RwLock::new(JwksCacheState::default()),
        }
    }

    fn jwks_url(&self) -> String {
        let base = self.control_plane_url.trim_end_matches('/');
        format!("{base}/jwks")
    }

    fn has_fresh_cache(cache: &JwksCacheState, ttl: Duration) -> bool {
        if let Some(refreshed_at) = cache.refreshed_at {
            return refreshed_at.elapsed() < ttl;
        }
        false
    }

    async fn ensure_cache(&self, force_refresh: bool) -> Result<(), String> {
        {
            let cache = self.cache.read().await;
            if !force_refresh && Self::has_fresh_cache(&cache, self.refresh_ttl) {
                return Ok(());
            }
        }
        let keys = self.fetch_keys().await?;
        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.refreshed_at = Some(Instant::now());
        Ok(())
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, VerifyingKey>, String> {
        let https = HttpsConnectorBuilder::new()
            .with_tls_config((*self.client_config).clone())
            .https_only()
            .enable_http1()
            .build();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);
        let request = Request::builder()
            .method("GET")
            .uri(self.jwks_url())
            .body(Full::new(Bytes::new()))
            .map_err(|e| format!("failed to build jwks request: {e}"))?;
        let response = client
            .request(request)
            .await
            .map_err(|e| format!("failed to fetch jwks: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("jwks request failed: {}", response.status()));
        }
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("failed to read jwks: {e}"))?
            .to_bytes();
        let jwks: Jwks =
            serde_json::from_slice(&body).map_err(|e| format!("invalid jwks json: {e}"))?;
        jwks.keys
            .into_iter()
            .try_fold(HashMap::new(), |mut keys, key| {
                let public_bytes = URL_SAFE_NO_PAD
                    .decode(key.x)
                    .map_err(|_| "invalid jwks key encoding")?;
                if public_bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
                    return Err("invalid jwks key length".to_string());
                }
                let verifying_key = VerifyingKey::from_bytes(
                    &public_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid jwks key length")?,
                )
                .map_err(|_| "invalid jwks key".to_string())?;
                keys.insert(key.kid, verifying_key);
                Ok(keys)
            })
    }

    fn parse_kid(parsed: &ParsedToken) -> Result<String, String> {
        if let Some(header) = &parsed.header {
            if !header.kid.trim().is_empty() {
                return Ok(header.kid.clone());
            }
        }
        let claims: Claims = serde_json::from_slice(&parsed.payload)
            .map_err(|_| "invalid token payload".to_string())?;
        if claims.kid.trim().is_empty() {
            return Err("missing token kid".to_string());
        }
        Ok(claims.kid)
    }
}

#[async_trait]
impl TokenVerifier for JwksTokenVerifier {
    async fn verify(&self, token: &str, required_scope: &str) -> Result<Claims, String> {
        self.ensure_cache(false).await?;
        let parsed = parse_token(token)?;
        let expected_kid = Self::parse_kid(&parsed)?;
        let mut key = {
            let cache = self.cache.read().await;
            cache.keys.get(&expected_kid).cloned()
        };
        if key.is_none() {
            self.ensure_cache(true).await?;
            let cache = self.cache.read().await;
            key = cache.keys.get(&expected_kid).cloned();
        }
        let key = key.ok_or_else(|| "unknown token kid".to_string())?;

        key.verify(&parsed.signed_payload, &parsed.signature)
            .map_err(|_| "invalid signature".to_string())?;
        let claims: Claims = serde_json::from_slice(&parsed.payload)
            .map_err(|_| "invalid token payload".to_string())?;
        if let Some(header) = &parsed.header {
            if header.alg != "EdDSA" {
                return Err("unsupported token algorithm".to_string());
            }
            if !header.kid.is_empty() && !claims.kid.is_empty() && header.kid != claims.kid {
                return Err("token kid mismatch".to_string());
            }
        }
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
        if claims.iat != 0 && claims.iat > now {
            return Err("token issued in future".to_string());
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
