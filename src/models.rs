use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct Secret {
    pub id: Uuid,
    pub ciphertext: String,
    pub passphrase_required: bool,
    pub access_count: u32,
    pub max_views: u32,
    pub ttl_minutes: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct SecretFromRow {
    pub id: Uuid,
    pub ciphertext: String,
    pub passphrase_required: bool,
    pub access_count: i32,
    pub max_views: i32,
    pub ttl_minutes: i32,
    pub created_at: OffsetDateTime,
}
