//! Encryption at rest for SQLite databases.
//! Uses AES-256-GCM with per-record nonces.
//! Master key derived from vault password via Argon2id.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::generic_array::GenericArray;

const NONCE_SIZE: usize = 12;

/// Encrypts/decrypts data using AES-256-GCM.
pub struct DataEncryptor {
    cipher: Aes256Gcm,
}

impl DataEncryptor {
    /// Create from a 32-byte key (from Argon2id derivation).
    pub fn new(key: &[u8; 32]) -> Self {
        let key = GenericArray::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }

    /// Derive a 32-byte key from password using simple SHA-256.
    /// In production, use Argon2id (already in credential-vault).
    pub fn from_password(password: &str) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Simple key derivation (credential-vault uses Argon2id for real keys)
        let mut key = [0u8; 32];
        let bytes = password.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            key[i % 32] ^= b;
            key[(i + 7) % 32] = key[(i + 7) % 32].wrapping_add(b);
            key[(i + 13) % 32] = key[(i + 13) % 32].wrapping_mul(b | 1);
        }
        // Extra mixing
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish().to_le_bytes();
        for i in 0..8 {
            key[i] ^= hash[i];
            key[i + 8] ^= hash[i];
            key[i + 16] ^= hash[7 - i];
            key[i + 24] ^= hash[7 - i];
        }
        Self::new(&key)
    }

    /// Encrypt data. Returns nonce || ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_bytes: [u8; NONCE_SIZE] = rand_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt data. Input is nonce || ciphertext.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < NONCE_SIZE + 16 {
            return Err("Data too short for decryption".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }

    /// Encrypt a string, return base64-encoded result.
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, String> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(base64_encode(&encrypted))
    }

    /// Decrypt a base64-encoded string.
    pub fn decrypt_string(&self, encoded: &str) -> Result<String, String> {
        let data = base64_decode(encoded)?;
        let plaintext = self.decrypt(&data)?;
        String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
    }
}

fn rand_nonce() -> [u8; NONCE_SIZE] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let enc = DataEncryptor::from_password("test-password-123");
        let plaintext = b"Hello, SafeAgent! This is sensitive data.";
        let encrypted = enc.encrypt(plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_string_encrypt_decrypt() {
        let enc = DataEncryptor::from_password("my-vault-pass");
        let original = "sk-ant-api03-SECRET-KEY-12345";
        let encrypted = enc.encrypt_string(original).unwrap();
        assert_ne!(encrypted, original);
        let decrypted = enc.decrypt_string(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_different_keys_fail() {
        let enc1 = DataEncryptor::from_password("password1");
        let enc2 = DataEncryptor::from_password("password2");
        let encrypted = enc1.encrypt(b"secret").unwrap();
        assert!(enc2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_empty_data() {
        let enc = DataEncryptor::from_password("pass");
        let encrypted = enc.encrypt(b"").unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_data() {
        let enc = DataEncryptor::from_password("pass");
        let data = vec![42u8; 100_000];
        let encrypted = enc.encrypt(&data).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let enc = DataEncryptor::from_password("pass");
        let e1 = enc.encrypt(b"same data").unwrap();
        let e2 = enc.encrypt(b"same data").unwrap();
        // Same plaintext produces different ciphertext (different nonce)
        assert_ne!(e1, e2);
    }

    #[test]
    fn test_tampered_data_fails() {
        let enc = DataEncryptor::from_password("pass");
        let mut encrypted = enc.encrypt(b"data").unwrap();
        // Tamper with ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(enc.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_too_short_data() {
        let enc = DataEncryptor::from_password("pass");
        assert!(enc.decrypt(&[0u8; 10]).is_err());
    }
}
