use anyhow::{Result, anyhow};
use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use rand::Rng;

#[derive(Clone)]
pub struct EncryptionService;

impl Default for EncryptionService {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionService {
    const KEY_LENGTH: usize = 32; // 256 bits for AES-256
    const NONCE_LENGTH: usize = 12; // 96 bits for GCM

    pub fn new() -> Self {
        Self
    }

    pub fn generate_key() -> String {
        let mut rng = rand::thread_rng();
        let key: [u8; Self::KEY_LENGTH] = rng.r#gen();
        base64.encode(key)
    }

    pub fn encrypt(&self, plaintext: &str, key: &str) -> Result<String> {
        let key_bytes = base64
            .decode(key)
            .map_err(|e| anyhow!("Base64 decode error: {e}"))?;

        if key_bytes.len() != Self::KEY_LENGTH {
            return Err(anyhow!(
                "Invalid key length: expected {}, get {}",
                Self::KEY_LENGTH,
                key_bytes.len()
            ));
        }

        // Create cipher instance
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {e}"))?;

        // Combine nonce + encrypted text
        let mut result = Vec::with_capacity(Self::NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(base64.encode(result))
    }

    pub fn decrypt(&self, ciphertext: &str, key: &str) -> Result<String> {
        let key_bytes = base64.decode(key)?;

        if key_bytes.len() != Self::KEY_LENGTH {
            return Err(anyhow!(
                "Invalid key length: expected {}, got {}",
                Self::KEY_LENGTH,
                key_bytes.len()
            ));
        }

        let data = base64.decode(ciphertext)?;

        if data.len() < Self::NONCE_LENGTH {
            return Err(anyhow!("encrypted text is too short"));
        }

        // Split nonce and ciphertext
        let nonce = Nonce::from_slice(&data[..Self::NONCE_LENGTH]);
        let ciphertext_bytes = &data[Self::NONCE_LENGTH..];

        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let plaintext_bytes = cipher
            .decrypt(nonce, ciphertext_bytes)
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        String::from_utf8(plaintext_bytes).map_err(|e| anyhow!("UTF-8 conversion failed: {e}"))
    }

    pub fn hash_passphrase(passphrase: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);

        let hash = Argon2::default()
            .hash_password(passphrase.as_bytes(), &salt)
            .map_err(|e| anyhow!("Argon2 hashing error: {}", e))?
            .to_string();
        Ok(hash)
    }

    pub fn verify_passphrase(passphrase: &str, hash: &str) -> Result<bool> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| anyhow!("Password hash parsing error: {}", e))?;

        let result = Argon2::default().verify_password(passphrase.as_bytes(), &parsed_hash);

        match result {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false), // Password doesn't match
            Err(e) => Err(anyhow!("Argon2 verification error: {}", e)), // Other errors
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_returns_base64_string() {
        let key = EncryptionService::generate_key();

        // Should be a valid base64 string
        assert!(base64.decode(&key).is_ok());

        // Decoded key should have correct length
        let key_bytes = base64.decode(&key).unwrap();
        assert_eq!(key_bytes.len(), EncryptionService::KEY_LENGTH);
    }

    #[test]
    fn test_generate_key_produces_unique_keys() {
        let key1 = EncryptionService::generate_key();
        let key2 = EncryptionService::generate_key();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_works() {
        let service = EncryptionService::new();
        let key = EncryptionService::generate_key();
        let plaintext = "Hello! This is a test message.";

        let ciphertext = service.encrypt(plaintext, &key).unwrap();
        let decrypted = service.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let service = EncryptionService::new();
        let key = EncryptionService::generate_key();
        let plaintext = "";

        let ciphertext = service.encrypt(plaintext, &key).unwrap();
        let decrypted = service.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_special_characters() {
        let service = EncryptionService::new();
        let key = EncryptionService::generate_key();
        let plaintext = "Special chars:ñáéíÑÑÑ";

        let ciphertext = service.encrypt(plaintext, &key).unwrap();
        let decrypted = service.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_with_invalid_key_length() {
        let service = EncryptionService::new();
        let invalid_key = base64.encode("too-short"); // Key that's too short

        let result = service.encrypt("test message", &invalid_key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid key length")
        );
    }

    #[test]
    fn test_encrypt_with_invalid_base64_key() {
        let service = EncryptionService::new();
        let invalid_key = "not-valid-base64!@#$";

        let result = service.encrypt("test message", invalid_key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Base64 decode error")
        );
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let service = EncryptionService::new();
        let key1 = EncryptionService::generate_key();
        let key2 = EncryptionService::generate_key();
        let plaintext = "Secret message";

        let ciphertext = service.encrypt(plaintext, &key1).unwrap();
        let result = service.decrypt(&ciphertext, &key2);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Decryption failed")
        );
    }

    #[test]
    fn test_decrypt_with_short_ciphertext() {
        let service = EncryptionService::new();
        let key = EncryptionService::generate_key();
        let short_ciphertext = base64.encode("short");

        let result = service.decrypt(&short_ciphertext, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_hash_passphrase_creates_valid_hash() {
        let passphrase = "my_secure_password123";

        let hash = EncryptionService::hash_passphrase(passphrase).unwrap();

        // Should be a valid password hash string
        assert!(PasswordHash::new(&hash).is_ok());
        // Should contain argon2 identifier
        assert!(hash.contains("$argon2"));
    }

    #[test]
    fn test_hash_passphrase_different_salts_produce_different_hashes() {
        let passphrase = "same_password";

        let hash1 = EncryptionService::hash_passphrase(passphrase).unwrap();
        let hash2 = EncryptionService::hash_passphrase(passphrase).unwrap();

        // Same password should produce different hashes due to different salts
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_passphrase_correct_password() {
        let passphrase = "correct_password";
        let hash = EncryptionService::hash_passphrase(passphrase).unwrap();

        let result = EncryptionService::verify_passphrase(passphrase, &hash).unwrap();

        assert!(result);
    }

    #[test]
    fn test_verify_passphrase_incorrect_password() {
        let passphrase = "correct_password";
        let wrong_passphrase = "wrong_password";
        let hash = EncryptionService::hash_passphrase(passphrase).unwrap();

        let result = EncryptionService::verify_passphrase(wrong_passphrase, &hash).unwrap();

        assert!(!result);
    }

    #[test]
    fn test_verify_passphrase_invalid_hash_format() {
        let passphrase = "some_password";
        let invalid_hash = "not_a_valid_argon2_hash";

        let result = EncryptionService::verify_passphrase(passphrase, invalid_hash);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Password hash parsing error")
        );
    }

    #[test]
    fn test_encrypt_decrypt_large_message() {
        let service = EncryptionService::new();
        let key = EncryptionService::generate_key();
        let plaintext = "A".repeat(10_000); // 10KB of data

        let ciphertext = service.encrypt(&plaintext, &key).unwrap();
        let decrypted = service.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
