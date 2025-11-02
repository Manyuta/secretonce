use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroizing;

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

    pub fn derive_key(passphrase: &str, context: &[u8]) -> Result<[u8; Self::KEY_LENGTH]> {
        let hk = Hkdf::<Sha256>::new(Some(context), passphrase.as_bytes());
        let mut key = [0u8; Self::KEY_LENGTH];
        hk.expand(&[], &mut key)
            .map_err(|e| anyhow!("HKDF key derivation failed: {e}"))?;

        Ok(key)
    }

    pub fn encrypt_with_passphrase(
        &self,
        plaintext: &str,
        passphrase: &str,
        secret_id: &uuid::Uuid,
    ) -> Result<String> {
        let context = secret_id.as_bytes();
        let key_bytes = Self::derive_key(passphrase, context)?;
        let key = Zeroizing::new(key_bytes); // Auto-zeroize in memory

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {e}"))?;

        // Combine nonce + ciphertext
        let mut result = Vec::with_capacity(Self::NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(base64.encode(result))
    }

    pub fn decrypt_with_passphrase(
        &self,
        ciphertext_b64: &str,
        passphrase: &str,
        secret_id: &uuid::Uuid,
    ) -> Result<String> {
        let context = secret_id.as_bytes();
        let key_bytes = Self::derive_key(passphrase, context)?;
        let key = Zeroizing::new(key_bytes);

        let data = base64
            .decode(ciphertext_b64)
            .map_err(|e| anyhow!("Base64 decode error: {e}"))?;

        if data.len() < Self::NONCE_LENGTH {
            return Err(anyhow!("Ciphertext too short"));
        }

        let nonce = Nonce::from_slice(&data[..Self::NONCE_LENGTH]);
        let ciphertext = &data[Self::NONCE_LENGTH..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        Ok(String::from_utf8(plaintext)?)
    }

    /// Generate ephemeral secret where user manages the key
    /// Returns (encrypted_data, decryption_key) - User stores the key
    pub fn encrypt_ephemeral(&self, plaintext: &str) -> Result<(String, Zeroizing<String>)> {
        let key_bytes: [u8; Self::KEY_LENGTH] = rand::thread_rng().r#gen();
        let key = Zeroizing::new(key_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {e}"))?;

        let mut result = Vec::with_capacity(Self::NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        let encrypted_data = base64.encode(result);
        let decryption_key = Zeroizing::new(base64.encode(key.as_ref()));

        Ok((encrypted_data, decryption_key))
    }

    /// Decrypt ephemeral secret with provided key from User
    pub fn decrypt_ephemeral(&self, ciphertext_b64: &str, key_b64: &str) -> Result<String> {
        let key_bytes = base64
            .decode(key_b64)
            .map_err(|e| anyhow!("Base64 key decode error: {e}"))?;

        if key_bytes.len() != Self::KEY_LENGTH {
            return Err(anyhow!("Invalid key length"));
        }

        let key_array: [u8; Self::KEY_LENGTH] = key_bytes
            .try_into()
            .map_err(|e| anyhow!("Failed to convert key to array: {:?}", e))?;

        let key = Zeroizing::new(key_array);

        let data = base64
            .decode(ciphertext_b64)
            .map_err(|e| anyhow!("Base64 ciphertext decode error: {e}"))?;

        if data.len() < Self::NONCE_LENGTH {
            return Err(anyhow!("Ciphertext too short"));
        }

        let nonce = Nonce::from_slice(&data[..Self::NONCE_LENGTH]);
        let ciphertext = &data[Self::NONCE_LENGTH..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        Ok(String::from_utf8(plaintext)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_encrypt_decrypt_passphrase_roundtrip() {
        let service = EncryptionService::new();
        let passphrase = "hunter2";
        let plaintext = "super secret message";
        let secret_id = Uuid::new_v4();

        let ciphertext = service
            .encrypt_with_passphrase(plaintext, passphrase, &secret_id)
            .unwrap();
        let decrypted = service
            .decrypt_with_passphrase(&ciphertext, passphrase, &secret_id)
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_ephemeral_roundtrip() {
        let service = EncryptionService::new();
        let plaintext = "super secret message";

        let (ciphertext, key) = service.encrypt_ephemeral(plaintext).unwrap();
        let decrypted = service.decrypt_ephemeral(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_secret_ids_produce_different_keys() {
        let service = EncryptionService::new();
        let passphrase = "hunter2";
        let plaintext = "super secret message";
        let secret_id1 = Uuid::new_v4();
        let secret_id2 = Uuid::new_v4();

        let ciphertext1 = service
            .encrypt_with_passphrase(plaintext, passphrase, &secret_id1)
            .unwrap();
        let ciphertext2 = service
            .encrypt_with_passphrase(plaintext, passphrase, &secret_id2)
            .unwrap();

        // Same plaintext and passphrase, but different secret IDs should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // Each should only decrypt with its own secret ID
        let decrypted1 = service
            .decrypt_with_passphrase(&ciphertext1, passphrase, &secret_id1)
            .unwrap();
        let decrypted2 = service
            .decrypt_with_passphrase(&ciphertext2, passphrase, &secret_id2)
            .unwrap();

        assert_eq!(plaintext, decrypted1);
        assert_eq!(plaintext, decrypted2);

        // Should fail if wrong secret ID is used
        assert!(
            service
                .decrypt_with_passphrase(&ciphertext1, passphrase, &secret_id2)
                .is_err()
        );
    }
}
