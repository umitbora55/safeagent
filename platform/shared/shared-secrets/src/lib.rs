use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type SecretResult<T> = Result<T, SecretError>;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("invalid secret store name: {0}")]
    InvalidName(String),
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("vault error: {status}: {body}")]
    Vault { status: u16, body: String },
    #[error("vault request error: {0}")]
    Http(String),
}

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> SecretResult<Vec<u8>>;
    fn put(&self, name: &str, value: &[u8]) -> SecretResult<()>;
    fn delete(&self, name: &str) -> SecretResult<()>;
    fn list(&self, prefix: &str) -> SecretResult<Vec<String>>;
}

fn sanitize_name(name: &str) -> SecretResult<()> {
    if name.is_empty() {
        return Err(SecretError::InvalidName(
            "secret name must not be empty".to_string(),
        ));
    }
    if name.starts_with('/') || name.contains("..") {
        return Err(SecretError::InvalidName(format!(
            "unsafe secret name: {name}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct FileSecretStore {
    root: PathBuf,
    password: String,
}

impl FileSecretStore {
    pub const SECRET_DIR_PREFIX: &'static str = "token-keys/";

    pub fn new<P: AsRef<Path>>(root: P, password: impl AsRef<str>) -> SecretResult<Self> {
        let password = password.as_ref();
        if password.is_empty() {
            return Err(SecretError::InvalidName(
                "SAFEAGENT_SECRET_PASSWORD cannot be empty".to_string(),
            ));
        }
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            password: password.to_string(),
        })
    }

    fn path_for(&self, name: &str) -> SecretResult<PathBuf> {
        sanitize_name(name)?;
        Ok(self.root.join(name))
    }

    fn derive_key(&self, salt: &[u8]) -> SecretResult<[u8; 32]> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(self.password.as_bytes(), salt, &mut key)
            .map_err(|err| SecretError::Crypto(format!("argon2 derive key: {err}")))?;
        Ok(key)
    }

    fn read_secret_file(&self, path: &Path) -> SecretResult<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() < 16 + 12 {
            return Err(SecretError::Serialization(
                "secret file format invalid".to_string(),
            ));
        }

        let salt = &bytes[..16];
        let nonce = &bytes[16..28];
        let ciphertext = &bytes[28..];

        let key = self.derive_key(salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|err| SecretError::Crypto(format!("build cipher for decrypt: {err}")))?;
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|err| SecretError::Crypto(format!("decrypt: {err}")))
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, name: &str) -> SecretResult<Vec<u8>> {
        let path = self.path_for(name)?;
        if !path.exists() {
            return Err(SecretError::NotFound(name.to_string()));
        }
        self.read_secret_file(&path)
    }

    fn put(&self, name: &str, value: &[u8]) -> SecretResult<()> {
        let path = self.path_for(name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|err| SecretError::Crypto(format!("build cipher for encrypt: {err}")))?;
        let nonce = aes_gcm::Nonce::from_slice(&nonce);
        let encrypted = cipher
            .encrypt(nonce, value)
            .map_err(|err| SecretError::Crypto(format!("encrypt: {err}")))?;
        let mut out = Vec::with_capacity(28 + encrypted.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&encrypted);
        let mut file = File::create(path)?;
        file.write_all(&out)?;
        Ok(())
    }

    fn delete(&self, name: &str) -> SecretResult<()> {
        let path = self.path_for(name)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn list(&self, prefix: &str) -> SecretResult<Vec<String>> {
        sanitize_name(prefix)?;
        let prefix = prefix.trim_end_matches('/');
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                let meta = entry.metadata()?;
                if meta.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(&self.root)
                    .map_err(|err| {
                        SecretError::Serialization(format!("relative path error: {err}"))
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel.starts_with(prefix) {
                    out.push(rel);
                }
            }
        }
        Ok(out)
    }
}

#[derive(Clone)]
pub struct VaultSecretStore {
    base_url: String,
    token: String,
    mount: String,
    client: Client,
}

impl VaultSecretStore {
    pub fn new(base_url: impl AsRef<str>, token: impl AsRef<str>, mount: impl AsRef<str>) -> Self {
        Self {
            base_url: base_url.as_ref().trim_end_matches('/').to_string(),
            token: token.as_ref().to_string(),
            mount: mount.as_ref().trim_end_matches('/').to_string(),
            client: Client::builder()
                .build()
                .unwrap_or_else(|err| panic!("vault http client creation failed: {err}")),
        }
    }

    fn headers(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        request.header("X-Vault-Token", self.token.clone())
    }

    fn data_url(&self, name: &str) -> SecretResult<String> {
        sanitize_name(name)?;
        Ok(format!("{}/v1/{}/data/{}", self.base_url, self.mount, name))
    }

    fn metadata_url(&self, name: &str) -> SecretResult<String> {
        sanitize_name(name)?;
        Ok(format!(
            "{}/v1/{}/metadata/{}",
            self.base_url,
            self.mount,
            name.trim_end_matches('/')
        ))
    }
}

#[derive(Deserialize)]
struct VaultDataEnvelope {
    data: VaultData,
}

#[derive(Deserialize)]
struct VaultData {
    data: HashMap<String, String>,
}

#[derive(Serialize)]
struct VaultWritePayload {
    data: VaultWriteBody,
}

#[derive(Serialize)]
struct VaultWriteBody {
    data: HashMap<String, String>,
}

impl SecretStore for VaultSecretStore {
    fn get(&self, name: &str) -> SecretResult<Vec<u8>> {
        let url = self.data_url(name)?;
        let response = self
            .headers(self.client.get(url))
            .send()
            .map_err(|err| SecretError::Http(err.to_string()))?;
        let status = response.status().as_u16();
        if status == 404 {
            return Err(SecretError::NotFound(name.to_string()));
        }
        if !response.status().is_success() {
            let body = response.text().unwrap_or_else(|_| String::new());
            return Err(SecretError::Vault { status, body });
        }
        let resp = response
            .json::<VaultDataEnvelope>()
            .map_err(|err| SecretError::Serialization(err.to_string()))?;
        let encoded = resp
            .data
            .data
            .get("value")
            .ok_or_else(|| SecretError::Serialization("missing secret value".to_string()))?;
        STANDARD
            .decode(encoded)
            .map_err(|err| SecretError::Serialization(err.to_string()))
    }

    fn put(&self, name: &str, value: &[u8]) -> SecretResult<()> {
        let url = self.data_url(name)?;
        let encoded = STANDARD.encode(value);
        let mut data = HashMap::new();
        data.insert("value".to_string(), encoded);
        let payload = VaultWritePayload {
            data: VaultWriteBody { data },
        };
        let response = self
            .headers(self.client.put(url))
            .json(&payload)
            .send()
            .map_err(|err| SecretError::Http(err.to_string()))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_else(|_| String::new());
            return Err(SecretError::Vault { status, body });
        }
        Ok(())
    }

    fn delete(&self, name: &str) -> SecretResult<()> {
        let url = self.metadata_url(name)?;
        let response = self
            .headers(self.client.delete(url))
            .send()
            .map_err(|err| SecretError::Http(err.to_string()))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_else(|_| String::new());
            return Err(SecretError::Vault { status, body });
        }
        Ok(())
    }

    fn list(&self, prefix: &str) -> SecretResult<Vec<String>> {
        sanitize_name(prefix)?;
        let prefix_path = prefix.trim_end_matches('/');
        let request_path = if prefix_path.is_empty() {
            String::new()
        } else {
            prefix_path.to_string()
        };
        let mut url = format!(
            "{}/v1/{}/metadata/{}",
            self.base_url, self.mount, request_path
        );
        if !url.ends_with('/') {
            url.push('/');
        }
        let response = self
            .headers(self.client.get(url).query(&[("list", "true")]))
            .send()
            .map_err(|err| SecretError::Http(err.to_string()))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_else(|_| String::new());
            return Err(SecretError::Vault { status, body });
        }
        #[derive(Deserialize)]
        struct ListResponse {
            data: ListData,
        }
        #[derive(Deserialize)]
        struct ListData {
            keys: Vec<String>,
        }
        let response: ListResponse = response
            .json()
            .map_err(|err| SecretError::Serialization(err.to_string()))?;
        if request_path.is_empty() {
            Ok(response.data.keys)
        } else {
            Ok(response
                .data
                .keys
                .into_iter()
                .map(|entry| format!("{request_path}/{entry}"))
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use tempfile::tempdir;

    #[test]
    fn file_secret_roundtrip_and_tamper_detection() {
        let dir = tempdir().expect("tempdir");
        let store = FileSecretStore::new(dir.path(), "test-password-1").expect("create file store");
        let name = "token-keys/key-1";

        store.put(name, b"secret").expect("put");
        let roundtrip = store.get(name).expect("get");
        assert_eq!(roundtrip, b"secret");

        let wrong = FileSecretStore::new(dir.path(), "wrong-password").expect("create wrong");
        assert!(wrong.get(name).is_err());

        let path = dir.path().join(name);
        let mut bytes = std::fs::read(&path).expect("read secret file");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, bytes).expect("corrupt");
        assert!(store.get(name).is_err());
    }

    #[test]
    fn vault_secret_roundtrip_mocked() {
        let server = MockServer::start();
        let mount = "secret";
        let name = "token-keys/key-1";
        let encoded = STANDARD.encode(b"vault-secret");

        server.mock(|when, then| {
            when.method(httpmock::Method::PUT)
                .path(format!("/v1/{}/data/{}", mount, name));
            then.status(204);
        });

        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/v1/{}/data/{}", mount, name));
            then.status(200).json_body(serde_json::json!({
                "data": { "data": { "value": encoded.clone() } }
            }));
        });

        server.mock(|when, then| {
            when.method(httpmock::Method::DELETE)
                .path(format!("/v1/{}/metadata/{}", mount, name));
            then.status(204);
        });

        server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path(format!("/v1/{}/metadata/token-keys/", mount))
                .query_param("list", "true");
            then.status(200).json_body(serde_json::json!({
                "data": { "keys": ["key-2"] }
            }));
        });

        let store = VaultSecretStore::new(server.base_url(), "vault-token", mount);
        store.put(name, b"vault-secret").expect("vault put");
        let value = store.get(name).expect("vault get");
        assert_eq!(value, b"vault-secret");
        store.delete(name).expect("vault delete");
        let list = store.list("token-keys/").expect("vault list");
        assert!(list.contains(&"token-keys/key-2".to_string()));
    }
}
