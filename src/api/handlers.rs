use secrecy::ExposeSecret;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    AppState, CreateSecretRequest, CreateSecretResponseApi, EncryptionType, RetrieveSecretRequest,
    RetrieveSecretResponse, Secret, dto::*,
};

pub struct ApiHandler;

impl ApiHandler {
    pub async fn create_secret(
        &self,
        request: CreateSecretRequest,
        state: AppState,
    ) -> anyhow::Result<CreateSecretResponseApi> {
        let secret_id = Uuid::new_v4();
        let (ciphertext, encryption_type, decryption_key) = match &request.passphrase {
            Some(passphrase) => {
                // Passphrase-based encryption
                let ciphertext = state.encryption.encrypt_with_passphrase(
                    &request.secret,
                    passphrase,
                    &secret_id,
                )?;
                (ciphertext, EncryptionType::Passphrase, None)
            }
            None => {
                // Ephemeral encryption - user manages the key
                let (ciphertext, key) = state.encryption.encrypt_ephemeral(&request.secret)?;
                (ciphertext, EncryptionType::Ephemeral, Some(key.to_string()))
            }
        };

        let secret = Secret {
            id: secret_id,
            ciphertext: ciphertext.into(),
            passphrase_required: request.passphrase.is_some(),
            access_count: 0,
            max_views: request.max_views.unwrap_or(1),
            ttl_minutes: request.ttl.unwrap_or(1440) as i64,
            created_at: OffsetDateTime::now_utc(),
        };

        state.storage.create_secret(secret).await?;

        Ok(CreateSecretResponseApi {
            secret_id: secret_id.to_string(),
            decryption_key, // Only Some for ephemeral secrets
            ttl: request.ttl.unwrap_or(1440),
            encryption_type,
            created_at: OffsetDateTime::now_utc(),
        })
    }

    pub async fn retrieve_secret(
        &self,
        secret_id: Uuid,
        request: RetrieveSecretRequest,
        state: AppState,
    ) -> anyhow::Result<RetrieveSecretResponse> {
        let secret = state
            .storage
            .get_secret(&secret_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Secret not found or expired"))?;

        // Check if secret has expired
        let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

        if expires_at < time::OffsetDateTime::now_utc() {
            state.storage.delete_secret(&secret_id).await?;

            return Err(anyhow::anyhow!("Secret not found"));
        }

        // Validate access limits
        if secret.access_count >= secret.max_views {
            return Err(anyhow::anyhow!("Secret has reached maximum view limit"));
        }

        // Check if max views reached
        if secret.access_count >= secret.max_views {
            state.storage.delete_secret(&secret_id).await?;

            return Err(anyhow::anyhow!("Secret not found"));
        }

        let plaintext = if secret.passphrase_required {
            // Passphrase-protected secret
            let passphrase = request
                .passphrase
                .ok_or_else(|| anyhow::anyhow!("Passphrase required for this secret"))?;

            state.encryption.decrypt_with_passphrase(
                &secret.ciphertext.expose_secret(),
                &passphrase,
                &secret_id,
            )?
        } else {
            // Ephemeral secret - requires decryption key
            let decryption_key = request
                .decryption_key
                .ok_or_else(|| anyhow::anyhow!("Decryption key required for this secret"))?;

            state
                .encryption
                .decrypt_ephemeral(&secret.ciphertext.expose_secret(), &decryption_key)?
        };

        // Update access count
        let mut updated_secret = secret.clone();
        updated_secret.access_count += 1;
        state.storage.update_secret(updated_secret).await?;

        let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

        // Calculate TTL remaining
        let ttl_remaining = self.calculate_ttl_remaining(expires_at)?;

        Ok(RetrieveSecretResponse {
            value: plaintext,
            encryption_type: if secret.passphrase_required {
                EncryptionType::Passphrase
            } else {
                EncryptionType::Ephemeral
            },
            views_remaining: secret.max_views.saturating_sub(secret.access_count + 1),
            ttl_remaining,
        })
    }

    pub async fn get_secret_metadata(
        &self,
        secret_id: Uuid,
        state: AppState,
    ) -> anyhow::Result<SecretMetadataResponse> {
        let secret = state
            .storage
            .get_secret(&secret_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Secret not found or expired"))?;

        let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

        let ttl_remaining = self.calculate_ttl_remaining(expires_at)?;

        if ttl_remaining <= 0 {
            state.storage.delete_secret(&secret_id).await?;
            return Err(anyhow::anyhow!("Secret not found"));
        }

        Ok(SecretMetadataResponse {
            encryption_type: if secret.passphrase_required {
                EncryptionType::Passphrase
            } else {
                EncryptionType::Ephemeral
            },
            passphrase_required: secret.passphrase_required,
            views_remaining: secret.max_views.saturating_sub(secret.access_count),
            ttl_remaining,
            max_views: secret.max_views,
            access_count: secret.access_count,
            created_at: secret.created_at,
        })
    }

    fn calculate_ttl_remaining(&self, expires_at: OffsetDateTime) -> anyhow::Result<i64> {
        let now = OffsetDateTime::now_utc();

        if now > expires_at {
            return Ok(0);
        }

        let remaining = (expires_at - now).whole_minutes();
        Ok(remaining)
    }
}
