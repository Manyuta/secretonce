mod postgres;

use async_trait::async_trait;
use uuid::Uuid;

use crate::ApiError;
use crate::models::Secret;

pub type StorageResult<T> = Result<T, ApiError>;

#[async_trait]
pub trait SecretStorage: Send + Sync {
    async fn create_secret(&self, secret: Secret) -> StorageResult<()>;
    async fn get_secret(&self, id: &Uuid) -> StorageResult<Option<Secret>>;
    async fn update_secret(&self, secret: Secret) -> StorageResult<()>;
    async fn delete_secret(&self, id: &Uuid) -> StorageResult<()>;
    async fn cleanup_expired(&self) -> StorageResult<Vec<Uuid>>;
}

pub use postgres::PostgresStorage;
