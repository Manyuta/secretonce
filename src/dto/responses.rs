use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CreateSecretRequest {
    pub secret: String,
    pub passphrase: Option<String>,
    pub ttl: Option<u32>, // in minutes
    pub max_views: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretResponse {
    pub secret_key: String,
    pub decryption_key: Option<String>, // Only for ephemeral secrets
    pub metadata_key: String,
    pub secret_url: String,
    pub encryption_type: EncryptionType,
    pub ttl: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretResponseApi {
    pub secret_id: String,
    pub decryption_key: Option<String>, // Only for ephemeral secrets
    pub encryption_type: EncryptionType,
    pub ttl: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrieveSecretRequest {
    pub decryption_key: Option<String>, // Required for ephemeral secrets
    pub passphrase: Option<String>,     // Required for passphrase-protected secrets
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrieveSecretResponse {
    pub value: String,
    pub encryption_type: EncryptionType,
    pub views_remaining: u32,
    pub ttl_remaining: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum EncryptionType {
    Passphrase, // User provides passphrase, key derived from passphrase + secret_id
    Ephemeral,  // User receives decryption key, must provide it for retrieval
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretMetadataResponse {
    pub encryption_type: EncryptionType,
    pub passphrase_required: bool,
    pub views_remaining: u32,
    pub ttl_remaining: i64,
    pub max_views: u32,
    pub access_count: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(serde::Serialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub database: String,
    pub timestamp: time::OffsetDateTime,
    pub version: String,
}
