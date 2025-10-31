use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};

use uuid::Uuid;

use crate::error::ApiError;
use crate::models::{Secret, SecretFromRow};
use crate::storage::{SecretStorage, StorageResult};

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
impl SecretStorage for PostgresStorage {
    async fn create_secret(&self, secret: Secret) -> StorageResult<()> {
        let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

        sqlx::query!(
            r#"
            INSERT INTO secrets (
                id, ciphertext, secret_key, passphrase, passphrase_required,
                access_count, max_views, ttl_minutes,
                created_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            secret.id,
            secret.ciphertext,
            secret.secret_key,
            secret.passphrase,
            secret.passphrase_required,
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
                id, ciphertext, secret_key, passphrase, passphrase_required,
                 access_count, max_views, ttl_minutes, created_at
            FROM secrets 
            WHERE id = $1 AND expires_at > NOW()
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let secret = Secret {
                id: row.id,
                ciphertext: row.ciphertext,
                secret_key: row.secret_key,
                passphrase: row.passphrase,
                passphrase_required: row.passphrase_required,
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
            ciphertext = $2, secret_key = $3, passphrase = $4,
            passphrase_required = $5,
            access_count = $6, max_views = $7, ttl_minutes = $8,
            created_at = $9, expires_at = $10, updated_at = NOW()
        WHERE id = $1
        "#,
            secret.id,
            secret.ciphertext,
            secret.secret_key,
            secret.passphrase,
            secret.passphrase_required,
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
