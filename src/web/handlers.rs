use axum::{
    Json,
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};

use crate::{ApiError, dto::*, handlers::ApiHandler, state::AppState};

use uuid::Uuid;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(serde::Deserialize)]
pub struct VerifyPassphraseForm {
    pub secret_id: String,
    pub passphrase: String,
}

pub enum SecretResponse {
    Html(Html<String>),
    Redirect(Redirect),
}

impl IntoResponse for SecretResponse {
    fn into_response(self) -> Response {
        match self {
            SecretResponse::Html(html) => html.into_response(),
            SecretResponse::Redirect(redirect) => redirect.into_response(),
        }
    }
}

pub async fn create_secret(
    State(state): State<AppState>,
    Json(req): Json<CreateSecretRequest>,
) -> ApiResult<impl IntoResponse> {
    tracing::debug!(
        "Creating secret with TTL: {:?}, max_views: {:?}",
        req.ttl,
        req.max_views
    );

    // Validate TTL
    let ttl = req.ttl.unwrap_or(state.config.secrets.default_ttl);
    if ttl > state.config.secrets.max_ttl {
        return Err(ApiError::new(
            format!("TTL cannot exceed {} minutes", state.config.secrets.max_ttl),
            400,
        ));
    }

    // Validate max views
    let max_views = req
        .max_views
        .unwrap_or(state.config.secrets.default_max_views);
    if max_views > state.config.secrets.max_max_views {
        return Err(ApiError::new(
            format!(
                "Max views cannot exceed {}",
                state.config.secrets.max_max_views
            ),
            400,
        ));
    }

    // Generate keys
    let metadata_key = Uuid::new_v4().to_string();

    // Generate the secret URL
    let base_url = &state.config.secrets.base_url;

    let secret_url = format!("{}/secret/{}", base_url, metadata_key);

    tracing::debug!("Generated metadata_key: {}", metadata_key);

    // Encrypt the secret
    let secret_response = match ApiHandler.create_secret(req, state).await {
        Ok(response) => response,
        Err(e) => {
            return Err(ApiError::new(e.to_string(), 500));
        }
    };

    tracing::debug!("Storing secret with ID: {}", secret_response.secret_id);

    let response = CreateSecretResponse {
        encryption_type: secret_response.encryption_type,
        decryption_key: secret_response.decryption_key,
        secret_key: secret_response.secret_id,
        metadata_key,
        secret_url,
        ttl,
        created_at: time::OffsetDateTime::now_utc(),
    };

    tracing::debug!("Secret created successfully: {}", response.metadata_key);

    Ok((axum::http::StatusCode::CREATED, Json(response)))
}

pub async fn retrieve_secret(
    State(state): State<AppState>,
    Path(metadata_key): Path<String>,
    Json(req): Json<RetrieveSecretRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = Uuid::parse_str(&metadata_key).map_err(|_| ApiError::new("Invalid secret ID", 400))?;

    let response = match ApiHandler.retrieve_secret(id, req, state).await {
        Ok(response) => response,
        Err(e) => {
            return Err(ApiError::new(e.to_string(), 400));
        }
    };

    Ok(Json(response))
}

pub async fn get_secret_metadata(
    State(state): State<AppState>,
    Path(metadata_key): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = Uuid::parse_str(&metadata_key).map_err(|_| ApiError::new("Invalid secret ID", 400))?;

    let response = match ApiHandler.get_secret_metadata(id, state).await {
        Ok(response) => response,
        Err(e) => {
            return Err(ApiError::new(e.to_string(), 400));
        }
    };

    Ok(Json(response))
}

pub async fn delete_secret(
    State(state): State<AppState>,
    Path(metadata_key): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = Uuid::parse_str(&metadata_key).map_err(|_| ApiError::new("Invalid secret ID", 400))?;

    if let Err(e) = state.storage.delete_secret(&id).await {
        tracing::error!("Failed to delete a secret {e}");
    };

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// For internal database query
pub async fn get_secret(
    State(state): State<AppState>,
    Path(metadata_key): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = Uuid::parse_str(&metadata_key)?;
    // get secret from storage
    let secret = state.storage.get_secret(&id).await?;
    Ok(Json(secret))
}

#[derive(serde::Serialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub database: String,
    pub timestamp: time::OffsetDateTime,
    pub version: String,
}

pub async fn health_check(State(state): State<crate::state::AppState>) -> impl IntoResponse {
    let timestamp = time::OffsetDateTime::now_utc();

    // Test database connection
    let db_status = match state.storage.cleanup_expired().await {
        Ok(_) => "connected".to_string(),
        Err(e) => format!("disconnected: {}", e),
    };

    let health = HealthCheckResponse {
        status: "ok".to_string(),
        database: db_status,
        timestamp,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    Json(health)
}
