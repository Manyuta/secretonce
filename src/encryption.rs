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
