use async_trait::async_trait;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

use uuid::Uuid;

use crate::error::ApiError;
use crate::models::{Secret, SecretFromRow};
use crate::storage::StorageResult;

#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> Result<Self, ApiError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        // Run migrations
        sqlx::migrate!().run(&pool).await?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl crate::storage::SecretStorage for PostgresStorage {
    async fn create_secret(&self, secret: Secret) -> StorageResult<()> {
        let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

        sqlx::query!(
            r#"
            INSERT INTO secrets (
                id, ciphertext, secret_key, passphrase, recipient, passphrase_required,
                burn_after_reading, access_count, max_views, ttl_minutes,
                created_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
            secret.id,
            secret.ciphertext,
            secret.secret_key,
            secret.passphrase,
            secret.metadata.recipient,
            secret.metadata.passphrase_required,
            secret.metadata.burn_after_reading,
            secret.access_count as i32,
            secret.max_views as i32,
            secret.ttl_minutes as i32,
            secret.created_at,
            expires_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_secret(&self, id: &Uuid) -> StorageResult<Option<Secret>> {
        let row = sqlx::query_as!(
            SecretFromRow,
            r#"
            SELECT 
                id, ciphertext, secret_key, passphrase, recipient, passphrase_required,
                burn_after_reading, access_count, max_views, ttl_minutes, created_at
            FROM secrets 
            WHERE id = $1 AND expires_at > NOW()
            "#,
            id
        )
        //.bind(id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let secret = Secret {
                id: row.id,
                ciphertext: row.ciphertext,
                secret_key: row.secret_key,
                passphrase: row.passphrase,
                metadata: crate::models::SecretMetadata {
                    recipient: row.recipient,
                    passphrase_required: row.passphrase_required,
                    burn_after_reading: row.burn_after_reading,
                },
                access_count: row.access_count as u32,
                max_views: row.max_views as u32,
                ttl_minutes: row.ttl_minutes as i64,
                created_at: row.created_at,
            };
            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }

    async fn update_secret(&self, secret: Secret) -> StorageResult<()> {
        let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

        sqlx::query!(
            r#"
        UPDATE secrets 
        SET 
            ciphertext = $2, secret_key = $3, passphrase = $4, recipient = $5, 
            passphrase_required = $6, burn_after_reading = $7,
            access_count = $8, max_views = $9, ttl_minutes = $10,
            created_at = $11, expires_at = $12, updated_at = NOW()
        WHERE id = $1
        "#,
            secret.id,
            secret.ciphertext,
            secret.secret_key,
            secret.passphrase,
            secret.metadata.recipient,
            secret.metadata.passphrase_required,
            secret.metadata.burn_after_reading,
            secret.access_count as i32,
            secret.max_views as i32,
            secret.ttl_minutes as i32,
            secret.created_at,
            expires_at
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_secret(&self, id: &Uuid) -> StorageResult<()> {
        sqlx::query!("DELETE FROM secrets WHERE id = $1", id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn cleanup_expired(&self) -> StorageResult<Vec<Uuid>> {
        let rows = sqlx::query!("DELETE FROM secrets WHERE expires_at <= NOW() RETURNING id")
            .fetch_all(&self.pool)
            .await?;

        let expired_ids: Vec<Uuid> = rows.into_iter().map(|row| row.id).collect();
        Ok(expired_ids)
    }
}
