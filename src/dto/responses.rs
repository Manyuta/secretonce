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
    pub metadata_key: String,
    pub secret_url: String,
    pub ttl: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrieveSecretRequest {
    pub passphrase: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrieveSecretResponse {
    pub value: String,
    pub passphrase_required: bool,
    pub views_remaining: u32,
    pub ttl_remaining: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretMetadataResponse {
    pub passphrase_required: bool,
    pub views_remaining: u32,
    pub ttl_remaining: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
