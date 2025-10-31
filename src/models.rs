use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct Secret {
    pub id: Uuid,
    pub ciphertext: String,
    pub passphrase: Option<String>, // Hashed passphrase if provided
    pub passphrase_required: bool,
    pub access_count: u32,
    pub max_views: u32,
    pub ttl_minutes: i64,
    pub created_at: OffsetDateTime,
    pub secret_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, FromRow)]
pub struct SecretFromRow {
    pub id: Uuid,
    pub ciphertext: String,
    pub secret_key: String,
    pub passphrase: Option<String>,
    pub passphrase_required: bool,
    pub access_count: i32,
    pub max_views: i32,
    pub ttl_minutes: i32,
    pub created_at: OffsetDateTime,
}

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
    pub created_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{Token, assert_tokens};

    #[test]
    fn test_create_secret_request_serialization() {
        let request = CreateSecretRequest {
            secret: "my_secret".to_string(),
            passphrase: Some("pass123".to_string()),
            ttl: Some(60),
            max_views: Some(1),
        };

        assert_tokens(
            &request,
            &[
                Token::Struct {
                    name: "CreateSecretRequest",
                    len: 5,
                },
                Token::Str("secret"),
                Token::Str("my_secret"),
                Token::Str("passphrase"),
                Token::Some,
                Token::Str("pass123"),
                Token::Str("ttl"),
                Token::Some,
                Token::U32(60),
                Token::Str("recipient"),
                Token::Some,
                Token::Str("user@example.com"),
                Token::Str("max_views"),
                Token::Some,
                Token::U32(1),
                Token::StructEnd,
            ],
        );
    }
}
