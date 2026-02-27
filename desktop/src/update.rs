use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, VerifyingKey, Verifier};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const FALLBACK_PRIVATE_KEY: [u8; 32] = [0x42; 32];
const FALLBACK_VERSION: &str = "0.1.0";
const VERSION_FILE: &str = include_str!("../../VERSION");

fn fallback_public_key_bytes() -> Vec<u8> {
    let key = ed25519_dalek::SigningKey::from_bytes(&FALLBACK_PRIVATE_KEY);
    key.verifying_key().to_bytes().to_vec()
}

pub const UPDATE_JSON_NAME: &str = "update.json";
pub const UPDATE_SIGNATURE_NAME: &str = "update.sig";

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub notes: Vec<String>,
    pub published_at: String,
}

#[derive(Serialize, Clone)]
pub struct UpdateCheckResult {
    pub manifest_present: bool,
    pub manifest_valid: bool,
    pub signature_valid: bool,
    pub update_available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub notes: Vec<String>,
    pub published_at: Option<String>,
    pub asset_url: String,
    pub asset_sha256_ok: bool,
    pub safe: bool,
    pub message: Option<String>,
}

impl Default for UpdateCheckResult {
    fn default() -> Self {
        Self {
            manifest_present: false,
            manifest_valid: false,
            signature_valid: false,
            update_available: false,
            current_version: current_version().to_string(),
            latest_version: current_version().to_string(),
            notes: Vec::new(),
            published_at: None,
            asset_url: String::new(),
            asset_sha256_ok: false,
            safe: false,
            message: None,
        }
    }
}

pub fn current_version() -> &'static str {
    VERSION_FILE
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .unwrap_or(FALLBACK_VERSION)
}

fn fallback_public_key_b64() -> String {
    STANDARD.encode(fallback_public_key_bytes())
}

pub fn parse_update_manifest(content: &str) -> Result<UpdateManifest, String> {
    serde_json::from_str(content).map_err(|e| format!("invalid update manifest: {e}"))
}

pub fn canonical_manifest_json(manifest: &UpdateManifest) -> Result<String, String> {
    serde_json::to_string(manifest).map_err(|e| format!("canonicalize manifest: {e}"))
}

pub fn signature_payload(manifest: &UpdateManifest) -> Result<Vec<u8>, String> {
    let canonical = canonical_manifest_json(manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let mut payload = canonical.into_bytes();
    payload.extend_from_slice(digest.as_bytes());
    Ok(payload)
}

pub fn verify_signature(
    manifest: &UpdateManifest,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<bool, String> {
    let key_buf = STANDARD
        .decode(public_key_b64)
        .map_err(|_| "invalid public key base64".to_string())?;
    if key_buf.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
        return Ok(false);
    }
    let key_arr: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = key_buf
        .as_slice()
        .try_into()
        .map_err(|_| "invalid public key length".to_string())?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_arr).map_err(|_| "invalid public key".to_string())?;
    let raw_sig = STANDARD
        .decode(signature_b64)
        .map_err(|_| "invalid signature base64".to_string())?;
    if raw_sig.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Ok(false);
    }
    let signature = Signature::from_bytes(
        &raw_sig
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signature length".to_string())?,
    );
    let payload = signature_payload(manifest)?;
    Ok(verifying_key.verify(&payload, &signature).is_ok())
}

pub fn verify_manifest_signature(
    manifest: &UpdateManifest,
    signature_b64: &str,
    public_key_b64: Option<String>,
) -> Result<bool, String> {
    let public_key = public_key_b64.unwrap_or_else(fallback_public_key_b64);
    verify_signature(manifest, signature_b64, &public_key)
}

pub fn file_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn verify_asset_sha256(manifest: &UpdateManifest, bytes: &[u8]) -> bool {
    let manifest_sha = manifest.sha256.trim();
    if manifest_sha.is_empty() {
        return true;
    }
    file_sha256_hex(bytes).eq_ignore_ascii_case(manifest_sha)
}

pub fn parse_update_signature(content: &str) -> String {
    content.trim().to_string()
}

pub fn manifest_signature_path(manifest_path: &str) -> String {
    let normalized = manifest_path.trim_end_matches('/');
    let normalized = if let Some(stripped) = normalized.strip_prefix("file://") {
        stripped
    } else {
        normalized
    };
    if normalized.ends_with(format!("/{UPDATE_JSON_NAME}").as_str()) {
        let path = PathBuf::from(normalized);
        if let Some(parent) = path.parent() {
            return parent.join(UPDATE_SIGNATURE_NAME).to_string_lossy().to_string();
        }
    }
    format!("{normalized}.sig")
}

pub async fn fetch_text(url: &str) -> Result<String, String> {
    if std::path::Path::new(url).exists() {
        return std::fs::read_to_string(url).map_err(|e| format!("read local manifest {url}: {e}"));
    }
    let client = Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetch manifest failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("manifest fetch failed with status {}", response.status()));
    }
    response
        .text()
        .await
        .map_err(|e| format!("read manifest body failed: {e}"))
}

pub async fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    if std::path::Path::new(url).exists() {
        return std::fs::read(url).map_err(|e| format!("read local asset {url}: {e}"));
    }
    let client = Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("asset fetch failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("asset fetch failed with status {}", response.status()));
    }
    response
        .bytes()
        .await
        .map_err(|e| format!("read asset body failed: {e}"))
        .map(|bytes| bytes.to_vec())
}

fn parse_version_tuple(version: &str) -> (u64, u64, u64) {
    let mut parts = version.split('.').map(|part| part.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

pub fn version_is_newer(current: &str, candidate: &str) -> bool {
    let current = parse_version_tuple(current);
    let candidate = parse_version_tuple(candidate);
    candidate > current
}

pub async fn collect_remote_signature(path: &str) -> Result<String, String> {
    if path.starts_with("file://") {
        let local = path.trim_start_matches("file://");
        return std::fs::read_to_string(local).map_err(|e| format!("read local signature: {e}"));
    }
    if std::path::Path::new(path).exists() {
        return std::fs::read_to_string(path).map_err(|e| format!("read local signature: {e}"));
    }
    fetch_text(path).await
}

pub async fn verify_remote_update(
    manifest_url: &str,
    signature_url: &str,
    expected_asset_path: Option<String>,
    public_key: Option<String>,
) -> Result<UpdateCheckResult, String> {
    let manifest_text = if manifest_url.starts_with("file://") {
        std::fs::read_to_string(manifest_url.trim_start_matches("file://"))
            .map_err(|e| format!("read manifest: {e}"))?
    } else {
        fetch_text(manifest_url).await?
    };
    let manifest = parse_update_manifest(&manifest_text)?;
    let signature_text = collect_remote_signature(signature_url).await?;
    let signature = parse_update_signature(&signature_text);
    let signature_valid = verify_manifest_signature(&manifest, &signature, public_key)?;

    let asset_sha256_ok = if let Some(asset_path) = expected_asset_path {
        let bytes = if asset_path.starts_with("file://") {
            std::fs::read(asset_path.trim_start_matches("file://"))
                .map_err(|e| format!("read asset: {e}"))?
        } else {
            fetch_bytes(&asset_path).await?
        };
        verify_asset_sha256(&manifest, &bytes)
    } else if manifest.url.starts_with("file://") {
        let asset_data = std::fs::read(manifest.url.trim_start_matches("file://"))
            .unwrap_or_else(|_| Vec::new());
        if manifest.sha256.is_empty() {
            true
        } else {
            verify_asset_sha256(&manifest, &asset_data)
        }
    } else {
        true
    };

    let latest_version = manifest.version.clone();
    let manifest_valid = true;
    let update_available = version_is_newer(current_version(), &latest_version)
        && signature_valid
        && asset_sha256_ok;
    let safe = manifest_valid && signature_valid && asset_sha256_ok;
    Ok(UpdateCheckResult {
        manifest_present: true,
        manifest_valid,
        signature_valid,
        update_available,
        current_version: current_version().to_string(),
        latest_version: latest_version.clone(),
        notes: manifest.notes.clone(),
        published_at: Some(manifest.published_at),
        asset_url: manifest.url.clone(),
        asset_sha256_ok,
        safe,
        message: if !signature_valid {
            Some("Update manifest signature verification failed".to_string())
        } else if !asset_sha256_ok {
            Some("Asset hash verification failed".to_string())
        } else if !version_is_newer(current_version(), &latest_version) {
            Some("Update already at latest or rollback rejected".to_string())
        } else {
            None
        },
    })
}

pub fn offline_signature_for_tests(manifest: &UpdateManifest) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&FALLBACK_PRIVATE_KEY);
    let payload = signature_payload(manifest).expect("payload");
    STANDARD.encode(key.sign(&payload).to_bytes())
}

pub fn public_key_for_tests() -> String {
    fallback_public_key_b64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_manifest() -> UpdateManifest {
        UpdateManifest {
            version: "0.2.0".to_string(),
            url: "file:///tmp/safeagent-desktop-update.bin".to_string(),
            sha256: "placeholder".to_string(),
            notes: vec!["seed".to_string()],
            published_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn verify_valid_signature_passes() {
        let manifest = fixture_manifest();
        let signature = offline_signature_for_tests(&manifest);
        assert!(verify_signature(
            &manifest,
            &signature,
            &public_key_for_tests()
        )
        .expect("valid sig"));
    }

    #[test]
    fn verify_tampered_manifest_fails() {
        let manifest = fixture_manifest();
        let signature = offline_signature_for_tests(&manifest);
        let mut changed = fixture_manifest();
        changed.version = "9.9.9".to_string();
        assert!(!verify_signature(
            &changed,
            &signature,
            &public_key_for_tests()
        )
        .expect("tampered sig"));
    }

    #[test]
    fn verify_wrong_signature_fails() {
        let mut manifest = fixture_manifest();
        let mut bad_sig = offline_signature_for_tests(&manifest).into_bytes();
        if !bad_sig.is_empty() {
            bad_sig[0] = if bad_sig[0] == b'A' { b'B' } else { b'A' };
        }
        manifest.notes.push("tampered signature".to_string());
        assert!(!verify_signature(
            &manifest,
            &String::from_utf8_lossy(&bad_sig),
            &public_key_for_tests()
        )
        .expect("wrong sig"));
    }
}
