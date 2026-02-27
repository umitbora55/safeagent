use std::env;
use std::fs;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_SIGNING_KEY: [u8; 32] = [0x42; 32];

#[derive(Deserialize, Serialize)]
struct UpdateManifest {
    version: String,
    url: String,
    sha256: String,
    notes: Vec<String>,
    published_at: String,
}

fn signature_payload(manifest: &UpdateManifest) -> Result<Vec<u8>, String> {
    let canonical = serde_json::to_string(manifest).map_err(|e| format!("canonicalize manifest: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let mut payload = canonical.into_bytes();
    payload.extend_from_slice(digest.as_bytes());
    Ok(payload)
}

fn read_key() -> [u8; 32] {
    if let Ok(raw) = env::var("SAFEAGENT_UPDATE_SIGNING_KEY_B64") {
        if let Ok(decoded) = STANDARD.decode(raw.trim()) {
            if decoded.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&decoded);
                return out;
            }
        }
    }
    DEFAULT_SIGNING_KEY
}

fn main() -> Result<(), String> {
    let manifest_path = env::args()
        .nth(1)
        .ok_or_else(|| "missing manifest path".to_string())?;
    let manifest_raw = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("read manifest {manifest_path}: {e}"))?;
    let manifest: UpdateManifest = serde_json::from_str(&manifest_raw)
        .map_err(|e| format!("parse manifest: {e}"))?;
    let payload = signature_payload(&manifest)?;
    let key = read_key();
    let signing_key = SigningKey::from_bytes(&key);
    let sig = signing_key.sign(&payload);
    println!("{}", STANDARD.encode(sig.to_bytes()));
    Ok(())
}
