use crate::config::Config;
use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};

use uuid::Uuid;

use crate::ApiError;
use crate::models::{Secret, SecretFromRow};
use crate::storage::{SecretStorage, StorageResult};

#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(config: &Config) -> Result<Self, ApiError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect(&config.database.connection_string())
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
                id, ciphertext, passphrase_required,
                access_count, max_views, ttl_minutes,
                created_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            secret.id,
            secret.ciphertext,
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
                id, ciphertext, passphrase_required,
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
            ciphertext = $2, 
            passphrase_required = $3,
            access_count = $4, max_views = $5, ttl_minutes = $6,
            created_at = $7, expires_at = $8, updated_at = NOW()
        WHERE id = $1
        "#,
            secret.id,
            secret.ciphertext,
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
