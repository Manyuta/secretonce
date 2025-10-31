use axum::{
    Json,
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};

use crate::{encryption::EncryptionService, error::ApiError, models::*, state::AppState};
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

// Templates
const SECRET_HTML: &str = include_str!("../templates/display_secret.html");
const PASSPHRASE_FORM_TEMPLATE: &str = include_str!("../templates/passphrase_input_form.html");

pub async fn verify_passphrase(
    State(state): State<AppState>,
    Form(form): Form<VerifyPassphraseForm>,
) -> SecretResponse {
    let id = match Uuid::parse_str(&form.secret_id) {
        Ok(id) => id,
        Err(_) => {
            return SecretResponse::Redirect(Redirect::to(&format!(
                "/secret?key={}&error=invalid_id",
                form.secret_id
            )));
        }
    };

    // Get the secret from storage
    let secret = match state.storage.get_secret(&id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return SecretResponse::Redirect(Redirect::to(&format!(
                "/secret?key={}&error=not_found",
                form.secret_id
            )));
        }
        Err(_) => {
            return SecretResponse::Redirect(Redirect::to(&format!(
                "/secret?key={}&error=storage_error",
                form.secret_id
            )));
        }
    };

    // Verify passphrase
    let is_valid = if let Some(stored_hash) = &secret.passphrase {
        EncryptionService::verify_passphrase(&form.passphrase, stored_hash).unwrap_or(false)
    } else {
        false
    };

    if !is_valid {
        return SecretResponse::Redirect(Redirect::to(&format!(
            "/secret?key={}&error=invalid_passphrase",
            form.secret_id
        )));
    }

    // Check if secret has expired
    let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

    let ttl_remaining = (expires_at - time::OffsetDateTime::now_utc())
        .whole_minutes()
        .max(0);

    if ttl_remaining <= 0 {
        if let Err(e) = state.storage.delete_secret(&id).await {
            tracing::error!("Failed to delete secret {}: {}", id, e);
        }

        return SecretResponse::Redirect(Redirect::to(&format!(
            "/secret?key={}&error=expired",
            form.secret_id
        )));
    }

    // Check if max views reached
    if secret.access_count >= secret.max_views {
        if let Err(e) = state.storage.delete_secret(&id).await {
            tracing::error!("Failed to delete a secret {}: {}", id, e);
        }

        return SecretResponse::Redirect(Redirect::to(&format!(
            "/secret?key={}&error=already_viewed",
            form.secret_id
        )));
    }

    // Decrypt the secret
    let decrypted_secret = match state
        .encryption
        .decrypt(&secret.ciphertext, &secret.secret_key)
    {
        Ok(value) => value,
        Err(_) => {
            return SecretResponse::Redirect(Redirect::to(&format!(
                "/secret?key={}&error=decryption_error",
                form.secret_id
            )));
        }
    };

    // Update access count
    let mut updated_secret = secret.clone();
    updated_secret.access_count += 1;

    if let Err(e) = state.storage.update_secret(updated_secret).await {
        tracing::error!("Failec to update secret {}: {}", id, e);

        return SecretResponse::Redirect(Redirect::to(&format!(
            "/secret?key={}&error=update_error",
            form.secret_id
        )));
    }

    let views_remaining = &secret.max_views.saturating_sub(secret.access_count);

    let html = SECRET_HTML
        .replace("{{SECRET_VALUE}}", &decrypted_secret)
        .replace("{{TTL_REMAINING}}", &ttl_remaining.to_string())
        .replace("{{VIEWS_REMAINING}}", &views_remaining.to_string());

    SecretResponse::Html(Html(html))
}

pub async fn view_secret_page(
    State(state): State<crate::state::AppState>,
    Path(metadata_key): Path<String>,
) -> impl IntoResponse {
    tracing::info!("View secret page requested for: {}", metadata_key);

    let id = match Uuid::parse_str(&metadata_key) {
        Ok(id) => id,
        Err(_) => {
            tracing::warn!("Invalid UUID format: {}", metadata_key);
            let html = SECRET_HTML
                .replace("{{SECRET_VALUE}}", "Invalid secret URL")
                .replace("{{TTL_REMAINING}}", "0")
                .replace("{{VIEWS_REMAINING}}", "0");
            return Html(html);
        }
    };

    // Get the secret from storage
    let secret = match state.storage.get_secret(&id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            tracing::warn!("Secret not found: {}", id);
            let html = SECRET_HTML
                .replace("{{SECRET_VALUE}}", "Secret not found or already viewed")
                .replace("{{TTL_REMAINING}}", "0")
                .replace("{{VIEWS_REMAINING}}", "0");
            return Html(html);
        }
        Err(e) => {
            tracing::error!("Storage error when getting secret {}: {}", id, e);
            let html = SECRET_HTML
                .replace("{{SECRET_VALUE}}", "Error retrieving secret")
                .replace("{{TTL_REMAINING}}", "0")
                .replace("{{VIEWS_REMAINING}}", "0");
            return Html(html);
        }
    };

    // Check if secret has expired
    let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);
    let ttl_remaining = (expires_at - time::OffsetDateTime::now_utc())
        .whole_minutes()
        .max(0);

    if ttl_remaining <= 0 {
        tracing::info!("Secret expired, deleting: {}", id);

        if let Err(e) = state.storage.delete_secret(&id).await {
            tracing::error!("Failed to delete a secret: {e}");
        }

        let html = SECRET_HTML
            .replace("{{SECRET_VALUE}}", "Secret has expired")
            .replace("{{TTL_REMAINING}}", "0")
            .replace("{{VIEWS_REMAINING}}", "0");
        return Html(html);
    }

    // Check if max views reached
    if secret.access_count >= secret.max_views {
        tracing::info!("Secret max views reached, deleting: {}", id);

        if let Err(e) = state.storage.delete_secret(&id).await {
            tracing::error!("Failed to delete a secret: {e}");
        }

        let html = SECRET_HTML
            .replace("{{SECRET_VALUE}}", "Secret has already been viewed")
            .replace("{{TTL_REMAINING}}", "0")
            .replace("{{VIEWS_REMAINING}}", "0");
        return Html(html);
    }

    // Check if passphrase is required
    if secret.passphrase_required {
        let html = PASSPHRASE_FORM_TEMPLATE
            .replace("{{SECRET_ID}}", &metadata_key)
            .replace("{{TTL_REMAINING}}", &ttl_remaining.to_string())
            .replace(
                "{{VIEWS_REMAINING}}",
                &secret
                    .max_views
                    .saturating_sub(secret.access_count)
                    .to_string(),
            );

        return Html(html);
    }

    // If no passphrase required, show the secret directly
    let decrypted_secret = match state
        .encryption
        .decrypt(&secret.ciphertext, &secret.secret_key)
    {
        Ok(value) => {
            tracing::info!("Successfully decrypted secret: {}", id);
            value
        }
        Err(e) => {
            tracing::error!("Failed to decrypt secret {}: {}", id, e);
            let html = SECRET_HTML
                .replace("{{SECRET_VALUE}}", "Error decrypting secret")
                .replace("{{TTL_REMAINING}}", "0")
                .replace("{{VIEWS_REMAINING}}", "0");
            return Html(html);
        }
    };

    // Update access count (this consumes one view)
    let mut updated_secret = secret.clone();
    updated_secret.access_count += 1;

    if let Err(e) = state.storage.update_secret(updated_secret).await {
        tracing::error!("Failed to update secret access count {}: {}", id, e);
    }

    let views_remaining = secret.max_views.saturating_sub(secret.access_count + 1);

    let html = SECRET_HTML
        .replace("{{SECRET_VALUE}}", &decrypted_secret)
        .replace("{{TTL_REMAINING}}", &ttl_remaining.to_string())
        .replace("{{VIEWS_REMAINING}}", &views_remaining.to_string());

    Html(html)
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
    let secret_key = EncryptionService::generate_key();
    let metadata_key = Uuid::new_v4().to_string();

    // Generate the secret URL
    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| {
        format!(
            "http://{}:{}",
            state.config.server.host, state.config.server.port
        )
    });
    let secret_url = format!("{}/secret/{}", base_url, metadata_key);

    tracing::debug!(
        "Generated keys - metadata_key: {}, secret_key: {}",
        metadata_key,
        secret_key
    );

    // Encrypt the secret
    let ciphertext = state
        .encryption
        .encrypt(&req.secret, &secret_key)
        .map_err(|e| {
            tracing::error!("Encryption failed: {}", e);
            ApiError::new(format!("Encryption failed: {}", e), 400)
        })?;

    // Hash passphrase if provided
    let hashed_passphrase = if let Some(passphrase) = &req.passphrase {
        Some(EncryptionService::hash_passphrase(passphrase).map_err(|e| {
            tracing::error!("Passphrase hashing failed: {}", e);
            ApiError::new(format!("Passphrase hashing failed: {}", e), 400)
        })?)
    } else {
        None
    };

    // Create secret
    let secret = Secret {
        id: Uuid::parse_str(&metadata_key).map_err(|e| {
            tracing::error!("Failed to parse generated UUID: {}", e);
            ApiError::new("Invalid UUID generation".to_string(), 400)
        })?,
        ciphertext,
        secret_key: secret_key.clone(),
        passphrase: hashed_passphrase,
        passphrase_required: req.passphrase.is_some(),
        access_count: 0,
        max_views,
        ttl_minutes: ttl as i64,
        created_at: time::OffsetDateTime::now_utc(),
    };

    tracing::debug!("Storing secret with ID: {}", secret.id);

    // Store secret
    state.storage.create_secret(secret).await?;

    let response = CreateSecretResponse {
        secret_key: secret_key.clone(),
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
    Json(req): Json<Option<RetrieveSecretRequest>>,
) -> ApiResult<impl IntoResponse> {
    let id = Uuid::parse_str(&metadata_key).map_err(|_| ApiError::new("Invalid secret ID", 400))?;

    let mut secret = state
        .storage
        .get_secret(&id)
        .await?
        .ok_or_else(|| ApiError::new("Secret not found", 404))?;

    // Check if secret has expired
    let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);

    if expires_at < time::OffsetDateTime::now_utc() {
        if let Err(e) = state.storage.delete_secret(&id).await {
            tracing::error!("Failed to delete secret {}: {}", id, e);
        }
        return Err(ApiError::new("Secret not found", 404));
    }

    // Check if max views reached
    if secret.access_count >= secret.max_views {
        if let Err(e) = state.storage.delete_secret(&id).await {
            tracing::error!("Failed to delete secret {}: {}", id, e);
        }
        return Err(ApiError::new("Secret not found", 404));
    }

    // Check passphrase if required
    if secret.passphrase_required {
        let passphrase = req
            .as_ref()
            .and_then(|r| r.passphrase.as_ref())
            .ok_or_else(|| ApiError::new("Passphrase required", 401))?;

        let stored_hash = secret
            .passphrase
            .as_ref()
            .ok_or_else(|| ApiError::new("Passphrase verification failed", 401))?;

        if !EncryptionService::verify_passphrase(passphrase, stored_hash)
            .map_err(|e| ApiError::new(format!("Passphrase verification error: {}", e), 500))?
        {
            return Err(ApiError::new("Invalid passphrase", 401));
        }
    }

    let decrypted_value = state
        .encryption
        .decrypt(&secret.ciphertext, &secret.secret_key)
        .map_err(|e| {
            tracing::error!("Failed to decrypt secret {}: {}", secret.id, e);
            ApiError::new(format!("Failed to decrypt secret: {}", e), 500)
        })?;

    secret.access_count += 1;
    state.storage.update_secret(secret.clone()).await?;

    let response = RetrieveSecretResponse {
        value: decrypted_value,
        passphrase_required: secret.passphrase_required,
        views_remaining: secret.max_views.saturating_sub(secret.access_count),
        ttl_remaining: (expires_at - time::OffsetDateTime::now_utc())
            .whole_minutes()
            .max(0),
    };

    Ok(Json(response))
}

pub async fn get_secret_metadata(
    State(state): State<AppState>,
    Path(metadata_key): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = Uuid::parse_str(&metadata_key).map_err(|_| ApiError::new("Invalid secret ID", 400))?;

    let secret = state
        .storage
        .get_secret(&id)
        .await?
        .ok_or_else(|| ApiError::new("Secret not found", 404))?;

    let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);
    let ttl_remaining = (expires_at - time::OffsetDateTime::now_utc())
        .whole_minutes()
        .max(0);

    if ttl_remaining <= 0 {
        if let Err(e) = state.storage.delete_secret(&id).await {
            tracing::error!("Failed to delete a secret: {e}");
        }
        return Err(ApiError::new("Secret not found", 404));
    }

    let response = SecretMetadataResponse {
        passphrase_required: secret.passphrase_required,
        views_remaining: secret.max_views.saturating_sub(secret.access_count),
        ttl_remaining,
        created_at: secret.created_at,
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
