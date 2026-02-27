pub mod keychain;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::info;
use zeroize::Zeroize;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Errors
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Vault is locked")]
    Locked,
    #[error("Invalid master password")]
    InvalidPassword,
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Already exists: {0}")]
    AlreadyExists(String),
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Credential metadata (value never exposed in listing)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMeta {
    pub key: String,
    pub label: String,
    pub provider: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Sensitive string that zeroizes on drop
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(s: String) -> Self {
        Self(s)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Credential Vault — AES-256-GCM encrypted storage
//
//  Thread-safe: all methods take &self via internal Mutex
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

struct VaultInner {
    cipher: Option<Aes256Gcm>,
    db: Connection,
}

pub struct CredentialVault {
    inner: Mutex<VaultInner>,
}

impl CredentialVault {
    /// Create and initialize the vault
    pub fn new(db_path: PathBuf) -> Result<Self, VaultError> {
        let conn = Connection::open(&db_path).map_err(|e| VaultError::Database(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS credentials (
                key TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                provider TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TEXT NOT NULL,
                last_used TEXT
            );
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )
        .map_err(|e| VaultError::Database(e.to_string()))?;

        info!("🔐 Vault initialized at {:?}", db_path);

        Ok(Self {
            inner: Mutex::new(VaultInner {
                cipher: None,
                db: conn,
            }),
        })
    }

    /// Is the vault currently unlocked?
    pub fn is_unlocked(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.cipher.is_some()
    }

    /// Unlock with master password
    pub fn unlock(&self, master_password: &SensitiveString) -> Result<(), VaultError> {
        let mut inner = self.inner.lock().unwrap();

        let salt = get_or_create_salt(&inner.db)?;

        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut hash = vec![0u8; 32];
        argon2
            .hash_password_into(master_password.expose().as_bytes(), &salt, &mut hash)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        // Verify password by checking stored verifier (if exists)
        if let Some(stored_verifier) = get_meta(&inner.db, "password_verifier")? {
            let verifier_nonce_bytes = get_meta(&inner.db, "verifier_nonce")?
                .ok_or(VaultError::Encryption("Missing verifier nonce".into()))?;

            let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&hash[..32]);
            let cipher = Aes256Gcm::new(cipher_key);
            let nonce = Nonce::from_slice(&verifier_nonce_bytes);

            cipher
                .decrypt(nonce, stored_verifier.as_slice())
                .map_err(|_| VaultError::InvalidPassword)?;

            inner.cipher = Some(cipher);
        } else {
            // First unlock — store verifier
            let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&hash[..32]);
            let cipher = Aes256Gcm::new(cipher_key);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let verifier = cipher
                .encrypt(nonce, b"safeagent_vault_v1".as_slice())
                .map_err(|e| VaultError::Encryption(e.to_string()))?;

            set_meta(&inner.db, "password_verifier", &verifier)?;
            set_meta(&inner.db, "verifier_nonce", &nonce_bytes)?;

            inner.cipher = Some(cipher);
        }

        info!("🔓 Vault unlocked");
        Ok(())
    }

    /// Lock the vault (clear cipher from memory)
    pub fn lock(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cipher = None;
        info!("🔒 Vault locked");
    }

    /// Store a credential
    pub fn store(
        &self,
        key: &str,
        label: &str,
        provider: &str,
        value: &SensitiveString,
    ) -> Result<(), VaultError> {
        let inner = self.inner.lock().unwrap();
        let cipher = inner.cipher.as_ref().ok_or(VaultError::Locked)?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, value.expose().as_bytes())
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        let now = Utc::now().to_rfc3339();

        inner.db.execute(
            "INSERT OR REPLACE INTO credentials (key, label, provider, encrypted_value, nonce, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![key, label, provider, encrypted, nonce_bytes.to_vec(), now],
        ).map_err(|e| VaultError::Database(e.to_string()))?;

        info!("🔑 Stored: {} ({})", label, provider);
        Ok(())
    }

    /// Retrieve a credential value
    pub fn get(&self, key: &str) -> Result<SensitiveString, VaultError> {
        let inner = self.inner.lock().unwrap();
        let cipher = inner.cipher.as_ref().ok_or(VaultError::Locked)?;

        let (encrypted, nonce_bytes): (Vec<u8>, Vec<u8>) = inner
            .db
            .query_row(
                "SELECT encrypted_value, nonce FROM credentials WHERE key = ?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| VaultError::KeyNotFound(key.to_string()))?;

        // Update last_used
        let _ = inner.db.execute(
            "UPDATE credentials SET last_used = ?1 WHERE key = ?2",
            rusqlite::params![Utc::now().to_rfc3339(), key],
        );

        let nonce = Nonce::from_slice(&nonce_bytes);
        let decrypted = cipher
            .decrypt(nonce, encrypted.as_slice())
            .map_err(|_| VaultError::InvalidPassword)?;

        let value =
            String::from_utf8(decrypted).map_err(|e| VaultError::Encryption(e.to_string()))?;

        Ok(SensitiveString::new(value))
    }

    /// List all stored credentials (values never exposed)
    pub fn list(&self) -> Result<Vec<CredentialMeta>, VaultError> {
        let inner = self.inner.lock().unwrap();

        let mut stmt = inner
            .db
            .prepare("SELECT key, label, provider, created_at, last_used FROM credentials")
            .map_err(|e| VaultError::Database(e.to_string()))?;

        let creds = stmt
            .query_map([], |row| {
                let created_str: String = row.get(3)?;
                let last_used_str: Option<String> = row.get(4)?;
                Ok(CredentialMeta {
                    key: row.get(0)?,
                    label: row.get(1)?,
                    provider: row.get(2)?,
                    created_at: DateTime::parse_from_rfc3339(&created_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    last_used: last_used_str.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&Utc))
                    }),
                })
            })
            .map_err(|e| VaultError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(creds)
    }

    /// Delete a credential
    pub fn delete(&self, key: &str) -> Result<(), VaultError> {
        let inner = self.inner.lock().unwrap();

        let deleted = inner
            .db
            .execute("DELETE FROM credentials WHERE key = ?1", [key])
            .map_err(|e| VaultError::Database(e.to_string()))?;

        if deleted == 0 {
            return Err(VaultError::KeyNotFound(key.to_string()));
        }

        info!("🗑️ Deleted credential: {}", key);
        Ok(())
    }

    /// Count stored credentials
    pub fn count(&self) -> Result<usize, VaultError> {
        let inner = self.inner.lock().unwrap();
        let count: usize = inner
            .db
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))
            .map_err(|e| VaultError::Database(e.to_string()))?;
        Ok(count)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Implement SecretResolver for integration with LLM Router
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[async_trait::async_trait]
impl safeagent_llm_router::SecretResolver for CredentialVault {
    async fn resolve(&self, key_ref: &str) -> anyhow::Result<String> {
        let sensitive = self.get(key_ref)?;
        Ok(sensitive.expose().to_string())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DB helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn get_or_create_salt(db: &Connection) -> Result<Vec<u8>, VaultError> {
    match get_meta(db, "salt")? {
        Some(salt) => Ok(salt),
        None => {
            let mut salt = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            set_meta(db, "salt", &salt)?;
            Ok(salt)
        }
    }
}

fn get_meta(db: &Connection, key: &str) -> Result<Option<Vec<u8>>, VaultError> {
    match db.query_row(
        "SELECT value FROM vault_meta WHERE key = ?1",
        [key],
        |row| row.get::<_, Vec<u8>>(0),
    ) {
        Ok(val) => Ok(Some(val)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(VaultError::Database(e.to_string())),
    }
}

fn set_meta(db: &Connection, key: &str, value: &[u8]) -> Result<(), VaultError> {
    db.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )
    .map_err(|e| VaultError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn temp_vault() -> CredentialVault {
        let path = std::env::temp_dir().join(format!("safeagent_test_{}.db", uuid::Uuid::new_v4()));
        CredentialVault::new(path).unwrap()
    }

    #[test]
    fn test_new_vault_is_locked() {
        let vault = temp_vault();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn test_unlock_lock_cycle() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("test_password_123".into());

        vault.unlock(&pwd).unwrap();
        assert!(vault.is_unlocked());

        vault.lock();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn test_wrong_password_fails() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("correct_password".into());
        vault.unlock(&pwd).unwrap();
        vault.lock();

        let wrong = SensitiveString::new("wrong_password".into());
        let result = vault.unlock(&wrong);
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn test_store_and_retrieve() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("master123".into());
        vault.unlock(&pwd).unwrap();

        let api_key = SensitiveString::new("sk-ant-abc123xyz".into());
        vault
            .store("anthropic_key", "Anthropic API Key", "anthropic", &api_key)
            .unwrap();

        let retrieved = vault.get("anthropic_key").unwrap();
        assert_eq!(retrieved.expose(), "sk-ant-abc123xyz");
    }

    #[test]
    fn test_get_while_locked_fails() {
        let vault = temp_vault();
        let result = vault.get("any_key");
        assert!(matches!(result, Err(VaultError::Locked)));
    }

    #[test]
    fn test_store_while_locked_fails() {
        let vault = temp_vault();
        let val = SensitiveString::new("test".into());
        let result = vault.store("key", "label", "provider", &val);
        assert!(matches!(result, Err(VaultError::Locked)));
    }

    #[test]
    fn test_get_nonexistent_key() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("master123".into());
        vault.unlock(&pwd).unwrap();

        let result = vault.get("nonexistent");
        assert!(matches!(result, Err(VaultError::KeyNotFound(_))));
    }

    #[test]
    fn test_list_credentials() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("master123".into());
        vault.unlock(&pwd).unwrap();

        vault
            .store(
                "key1",
                "Key One",
                "provider_a",
                &SensitiveString::new("val1".into()),
            )
            .unwrap();
        vault
            .store(
                "key2",
                "Key Two",
                "provider_b",
                &SensitiveString::new("val2".into()),
            )
            .unwrap();

        let list = vault.list().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|c| c.key == "key1" && c.label == "Key One"));
        assert!(list
            .iter()
            .any(|c| c.key == "key2" && c.provider == "provider_b"));
    }

    #[test]
    fn test_delete_credential() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("master123".into());
        vault.unlock(&pwd).unwrap();

        vault
            .store(
                "to_delete",
                "Delete Me",
                "test",
                &SensitiveString::new("val".into()),
            )
            .unwrap();
        assert_eq!(vault.count().unwrap(), 1);

        vault.delete("to_delete").unwrap();
        assert_eq!(vault.count().unwrap(), 0);
    }

    #[test]
    fn test_delete_nonexistent_fails() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("master123".into());
        vault.unlock(&pwd).unwrap();

        let result = vault.delete("ghost");
        assert!(matches!(result, Err(VaultError::KeyNotFound(_))));
    }

    #[test]
    fn test_overwrite_credential() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("master123".into());
        vault.unlock(&pwd).unwrap();

        vault
            .store(
                "key",
                "V1",
                "test",
                &SensitiveString::new("old_value".into()),
            )
            .unwrap();
        vault
            .store(
                "key",
                "V2",
                "test",
                &SensitiveString::new("new_value".into()),
            )
            .unwrap();

        let val = vault.get("key").unwrap();
        assert_eq!(val.expose(), "new_value");
        assert_eq!(vault.count().unwrap(), 1);
    }

    #[test]
    fn test_persist_across_lock_unlock() {
        let vault = temp_vault();
        let pwd = SensitiveString::new("master123".into());

        vault.unlock(&pwd).unwrap();
        vault
            .store(
                "persist",
                "Persist Test",
                "test",
                &SensitiveString::new("secret".into()),
            )
            .unwrap();
        vault.lock();

        vault.unlock(&pwd).unwrap();
        let val = vault.get("persist").unwrap();
        assert_eq!(val.expose(), "secret");
    }

    #[test]
    fn test_sensitive_string_debug_redacted() {
        let s = SensitiveString::new("super_secret".into());
        let debug = format!("{:?}", s);
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains("super_secret"));
    }

    #[test]
    fn test_concurrent_access() {
        let vault = Arc::new(temp_vault());
        let pwd = SensitiveString::new("master123".into());
        vault.unlock(&pwd).unwrap();

        let mut handles = vec![];
        for i in 0..10 {
            let v = vault.clone();
            handles.push(std::thread::spawn(move || {
                let key = format!("key_{}", i);
                let val = SensitiveString::new(format!("value_{}", i));
                v.store(&key, &format!("Label {}", i), "test", &val)
                    .unwrap();
                let retrieved = v.get(&key).unwrap();
                assert_eq!(retrieved.expose(), format!("value_{}", i));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(vault.count().unwrap(), 10);
    }
}
