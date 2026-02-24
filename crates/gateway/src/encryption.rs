//! Encryption at rest for SQLite databases.
//! Uses AES-256-GCM with per-record nonces.
//! Master key derived from vault password via Argon2id.

#![allow(dead_code)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};

const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;

// Argon2id parameters (matching credential-vault)
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallelism
const ARGON2_OUTPUT_LEN: usize = 32;

/// Encrypts/decrypts data using AES-256-GCM.
pub struct DataEncryptor {
    cipher: Aes256Gcm,
    salt: [u8; SALT_SIZE],
}

impl DataEncryptor {
    /// Create from a 32-byte key (from Argon2id derivation).
    pub fn new(key: &[u8; 32], salt: [u8; SALT_SIZE]) -> Self {
        let key = GenericArray::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
            salt,
        }
    }

    /// Derive a 32-byte key from password using Argon2id.
    /// Generates a new random salt.
    pub fn from_password(password: &str) -> Self {
        let salt = rand_salt();
        Self::from_password_with_salt(password, salt)
    }

    /// Derive key from password with a specific salt.
    /// Use this when loading existing encrypted data.
    pub fn from_password_with_salt(password: &str, salt: [u8; SALT_SIZE]) -> Self {
        let key = derive_key_argon2id(password, &salt);
        Self::new(&key, salt)
    }

    /// Get the salt used for key derivation.
    /// Store this alongside encrypted data to enable decryption.
    pub fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    /// Encrypt data. Returns nonce || ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_bytes: [u8; NONCE_SIZE] = rand_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
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

    /// Encrypt with salt prefix: salt || nonce || ciphertext (for storage).
    pub fn encrypt_with_salt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let encrypted = self.encrypt(plaintext)?;
        let mut output = Vec::with_capacity(SALT_SIZE + encrypted.len());
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }

    /// Decrypt data that includes salt prefix.
    /// Returns (salt, plaintext) for verification.
    pub fn decrypt_with_salt(password: &str, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < SALT_SIZE + NONCE_SIZE + 16 {
            return Err("Data too short (missing salt or ciphertext)".into());
        }

        let (salt_bytes, encrypted) = data.split_at(SALT_SIZE);
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(salt_bytes);

        let encryptor = Self::from_password_with_salt(password, salt);
        encryptor.decrypt(encrypted)
    }
}

/// Derive a 32-byte key using Argon2id.
fn derive_key_argon2id(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .expect("valid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2id hash should succeed");

    key
}

fn rand_nonce() -> [u8; NONCE_SIZE] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn rand_salt() -> [u8; SALT_SIZE] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
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
    fn test_same_password_different_salt_fail() {
        let enc1 = DataEncryptor::from_password("same-password");
        let enc2 = DataEncryptor::from_password("same-password");
        // Different random salts
        assert_ne!(enc1.salt(), enc2.salt());
        let encrypted = enc1.encrypt(b"secret").unwrap();
        // Cannot decrypt with different salt-derived key
        assert!(enc2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_same_password_same_salt_works() {
        let enc1 = DataEncryptor::from_password("test-password");
        let salt = *enc1.salt();
        let enc2 = DataEncryptor::from_password_with_salt("test-password", salt);
        let encrypted = enc1.encrypt(b"secret").unwrap();
        let decrypted = enc2.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"secret");
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

    #[test]
    fn test_encrypt_with_salt_roundtrip() {
        let password = "my-secure-password";
        let enc = DataEncryptor::from_password(password);
        let plaintext = b"API key: sk-ant-12345";

        // Encrypt with salt prefix
        let encrypted = enc.encrypt_with_salt(plaintext).unwrap();

        // Verify salt is prepended
        assert!(encrypted.len() > SALT_SIZE + NONCE_SIZE + 16);

        // Decrypt using static method (extracts salt from data)
        let decrypted = DataEncryptor::decrypt_with_salt(password, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_salt_wrong_password() {
        let enc = DataEncryptor::from_password("correct-password");
        let encrypted = enc.encrypt_with_salt(b"secret").unwrap();

        let result = DataEncryptor::decrypt_with_salt("wrong-password", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2id_key_derivation_deterministic() {
        let password = "test123";
        let salt = [1u8; SALT_SIZE];

        let key1 = derive_key_argon2id(password, &salt);
        let key2 = derive_key_argon2id(password, &salt);

        // Same password + same salt = same key
        assert_eq!(key1, key2);

        // Different salt = different key
        let salt2 = [2u8; SALT_SIZE];
        let key3 = derive_key_argon2id(password, &salt2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_salt_is_random() {
        let salt1 = rand_salt();
        let salt2 = rand_salt();
        // Extremely unlikely to be equal
        assert_ne!(salt1, salt2);
    }
}
