use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use safeagent_shared_proto::Jwks;
use safeagent_shared_secrets::SecretStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub kid: String,
    pub created_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Retired,
}

const SECRET_KEY_PREFIX: &str = "token-keys/";

pub struct KeyStore {
    keys_dir: PathBuf,
    secret_store: Arc<dyn SecretStore>,
    grace_period_seconds: u64,
    records: Vec<KeyRecord>,
    private_keys: HashMap<String, [u8; 32]>,
    public_keys: HashMap<String, [u8; 32]>,
}

impl KeyStore {
    pub fn new<P: AsRef<Path>>(
        keys_dir: P,
        secret_store: Arc<dyn SecretStore>,
        grace_period_seconds: u64,
    ) -> Result<Self, String> {
        let keys_dir = keys_dir.as_ref().to_path_buf();
        fs::create_dir_all(&keys_dir)
            .map_err(|e| format!("failed to create keys dir {keys_dir:?}: {e}"))?;

        let mut store = Self {
            keys_dir,
            secret_store,
            grace_period_seconds,
            records: Vec::new(),
            private_keys: HashMap::new(),
            public_keys: HashMap::new(),
        };
        store.load_or_init()?;
        Ok(store)
    }

    pub fn active_key_kid(&mut self) -> Result<String, String> {
        self.cleanup_retired();
        self.ensure_active()?;
        self.active_record()
            .map(|record| record.kid.clone())
            .ok_or_else(|| "no active key".to_string())
    }

    pub fn active_signing_key(&mut self) -> Result<(String, [u8; 32]), String> {
        let kid = self.active_key_kid()?;
        let private_key = self
            .private_keys
            .get(&kid)
            .copied()
            .ok_or_else(|| format!("private key missing: {kid}"))?;
        Ok((kid, private_key))
    }

    pub fn active_public_keys(&mut self) -> Result<HashMap<String, [u8; 32]>, String> {
        self.cleanup_retired();
        self.ensure_active()?;
        let now = now_unix_secs()?;
        let keys: HashMap<String, [u8; 32]> = self
            .records
            .iter()
            .filter_map(|record| {
                if !matches!(record.status, KeyStatus::Active | KeyStatus::Retired) {
                    return None;
                }
                if record.status == KeyStatus::Retired
                    && record.expires_at > 0
                    && record.expires_at <= now
                {
                    return None;
                }
                self.public_keys
                    .get(&record.kid)
                    .map(|public| (record.kid.clone(), *public))
            })
            .collect();
        Ok(keys)
    }

    pub fn rotate(&mut self) -> Result<String, String> {
        self.cleanup_retired();

        if let Some(active_kid) = self.active_record().map(|record| record.kid.clone()) {
            self.mark_retired(&active_kid)?;
        }

        let now = now_unix_secs()?;
        let new_kid = format!("key-{}", Uuid::new_v4());
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let private_key = signing_key.to_bytes();
        let public_key = signing_key.verifying_key().to_bytes();

        self.secret_store
            .put(&self.private_secret_name(&new_kid), &private_key)
            .map_err(|e| format!("failed to store private key in secret store: {e}"))?;
        fs::write(
            self.keys_dir.join(format!("{new_kid}.pub")),
            hex::encode(public_key),
        )
        .map_err(|e| format!("failed to write public key file: {e}"))?;

        self.private_keys.insert(new_kid.clone(), private_key);
        self.public_keys.insert(new_kid.clone(), public_key);
        self.records.push(KeyRecord {
            kid: new_kid.clone(),
            created_at: now,
            not_before: now,
            expires_at: 0,
            status: KeyStatus::Active,
        });
        self.persist()?;
        Ok(new_kid)
    }

    pub fn public_jwks(&mut self) -> Result<Jwks, String> {
        let keys = self
            .active_public_keys()?
            .into_iter()
            .map(|(kid, public_key)| {
                let x = URL_SAFE_NO_PAD.encode(public_key);
                safeagent_shared_proto::Jwk {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x,
                    kid,
                    alg: "EdDSA".to_string(),
                    r#use: "sig".to_string(),
                }
            })
            .collect();
        Ok(Jwks { keys })
    }

    pub fn record_by_kid(&self, kid: &str) -> Option<&KeyRecord> {
        self.records.iter().find(|record| record.kid == kid)
    }

    pub fn retire_expired_public_keys(&mut self) {
        self.cleanup_retired();
        self.retain_key_materials();
    }

    fn private_secret_name(&self, kid: &str) -> String {
        format!("{SECRET_KEY_PREFIX}{kid}")
    }

    fn mark_retired(&mut self, kid: &str) -> Result<(), String> {
        let now = now_unix_secs()?;
        let grace = i64::try_from(self.grace_period_seconds)
            .map_err(|_| "invalid grace period".to_string())?;
        for record in &mut self.records {
            if record.kid == kid {
                record.status = KeyStatus::Retired;
                record.not_before = now;
                record.expires_at = now.saturating_add(grace);
            }
        }
        self.persist()
    }

    fn active_record(&self) -> Option<&KeyRecord> {
        self.records
            .iter()
            .filter(|record| matches!(record.status, KeyStatus::Active))
            .max_by_key(|record| record.created_at)
    }

    fn ensure_active(&mut self) -> Result<(), String> {
        if self.active_record().is_none() {
            let _ = self.rotate()?;
        }
        Ok(())
    }

    fn cleanup_retired(&mut self) {
        if let Ok(now) = now_unix_secs() {
            self.records.retain(|record| {
                if matches!(record.status, KeyStatus::Retired) && record.expires_at > 0 {
                    return record.expires_at > now;
                }
                true
            });
        }
    }

    fn retain_key_materials(&mut self) {
        let alive: HashSet<String> = self
            .records
            .iter()
            .map(|record| record.kid.clone())
            .collect();
        for secret_name in self
            .secret_store
            .list(SECRET_KEY_PREFIX)
            .unwrap_or_default()
        {
            let stem = secret_name
                .strip_prefix(SECRET_KEY_PREFIX)
                .unwrap_or(&secret_name)
                .to_string();
            if !alive.contains(&stem) {
                let _ = self.secret_store.delete(&secret_name);
            }
        }

        if let Ok(entries) = fs::read_dir(&self.keys_dir) {
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().to_string();
                let stem = file_name.strip_suffix(".pub");
                let stem = if let Some(stem) = stem {
                    stem
                } else {
                    continue;
                };
                if !alive.contains(stem) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    fn load_or_init(&mut self) -> Result<(), String> {
        self.records = self
            .read_metadata()
            .unwrap_or_default()
            .into_iter()
            .filter(|record| {
                if record.status == KeyStatus::Retired && record.expires_at > 0 {
                    if let Ok(now) = now_unix_secs() {
                        return record.expires_at > now;
                    }
                }
                true
            })
            .collect();

        self.private_keys.clear();
        self.public_keys.clear();

        let mut valid_records = Vec::with_capacity(self.records.len());
        let records = std::mem::take(&mut self.records);
        for record in records {
            let private_secret_name = self.private_secret_name(&record.kid);
            let private = match self.secret_store.get(&private_secret_name) {
                Ok(private) => private,
                Err(_) => {
                    let _ = self.secret_store.delete(&private_secret_name).is_err();
                    continue;
                }
            };
            let public_path = self.keys_dir.join(format!("{}.pub", record.kid));
            if !public_path.exists() {
                continue;
            }
            let private = private
                .as_slice()
                .try_into()
                .map_err(|_| format!("invalid private key length for {}", record.kid))?;
            let public = self.read_hex_key(&public_path)?;
            self.private_keys.insert(record.kid.clone(), private);
            self.public_keys.insert(record.kid.clone(), public);
            valid_records.push(record);
        }
        self.records = valid_records;

        self.cleanup_retired();
        self.persist()?;
        if self.active_record().is_none() {
            let _ = self.rotate()?;
        }
        Ok(())
    }

    fn read_hex_key(&self, path: &Path) -> Result<[u8; 32], String> {
        let data = fs::read_to_string(path)
            .map_err(|e| format!("failed to read key file {:?}: {e}", path))?;
        let bytes = hex::decode(data.trim())
            .map_err(|e| format!("failed to decode key file {:?}: {e}", path))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("invalid key file length {:?}: expected 32 bytes", path))
    }

    fn read_metadata(&self) -> Result<Vec<KeyRecord>, String> {
        let path = self.keys_dir.join("keys.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read metadata file {:?}: {e}", path))?;
        serde_json::from_str(&data).map_err(|e| format!("failed to parse metadata {:?}: {e}", path))
    }

    fn persist(&self) -> Result<(), String> {
        let payload = serde_json::to_vec_pretty(&self.records)
            .map_err(|e| format!("failed to encode metadata: {e}"))?;
        fs::write(self.keys_dir.join("keys.json"), payload)
            .map_err(|e| format!("failed to write metadata: {e}"))?;
        Ok(())
    }
}

fn now_unix_secs() -> Result<i64, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock failure: {e}"))?
        .as_secs();
    i64::try_from(now).map_err(|_| "timestamp overflow".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeagent_shared_secrets::FileSecretStore;
    use std::fs;

    #[test]
    fn rotate_keeps_retired_keys_for_grace() {
        let dir = std::env::temp_dir().join(format!("safeagent-keys-test-{}", std::process::id()));
        let secret_dir =
            std::env::temp_dir().join(format!("safeagent-secrets-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&secret_dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&secret_dir).unwrap();
        let secret_store = Arc::new(
            FileSecretStore::new(&secret_dir, "test-password-3").expect("new secret store"),
        );

        let mut store = KeyStore::new(&dir, secret_store, 10).expect("new key store");
        let first = store.active_key_kid().expect("active key");
        let rotated = store.rotate().expect("rotate");

        assert_ne!(first, rotated);
        let keys = store
            .public_jwks()
            .expect("jwks")
            .keys
            .into_iter()
            .map(|key| key.kid)
            .collect::<Vec<_>>();
        assert!(keys.contains(&first));
        assert!(keys.contains(&rotated));
        assert!(matches!(
            store.record_by_kid(&first).expect("first record").status,
            KeyStatus::Retired
        ));
        assert!(matches!(
            store
                .record_by_kid(&rotated)
                .expect("rotated record")
                .status,
            KeyStatus::Active
        ));

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&secret_dir);
    }
}
