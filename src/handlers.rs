use axum::{
    Json,
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};

use uuid::Uuid;

use crate::{encryption::EncryptionService, error::ApiError, models::*, state::AppState};

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

pub async fn verify_passphrase(
    State(state): State<crate::state::AppState>,
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
    let mut secret = match state.storage.get_secret(&id).await {
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
        let _ = state.storage.delete_secret(&id).await;
        return SecretResponse::Redirect(Redirect::to(&format!(
            "/secret?key={}&error=expired",
            form.secret_id
        )));
    }

    // Check if max views reached
    if secret.access_count >= secret.max_views {
        let _ = state.storage.delete_secret(&id).await;
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

    if let Err(_) = state.storage.update_secret(updated_secret).await {
        return SecretResponse::Redirect(Redirect::to(&format!(
            "/secret?key={}&error=update_error",
            form.secret_id
        )));
    }

    let recipient = "Anyone".to_string(); // TODO: get recipient from secret.metadata
    let views_remaining = &secret.max_views.saturating_sub(secret.access_count);

    let html = SECRET_HTML
        .replace("{{SECRET_VALUE}}", &decrypted_secret)
        .replace("{{RECIPIENT}}", &recipient)
        .replace("{{TTL_REMAINING}}", &ttl_remaining.to_string())
        .replace("{{VIEWS_REMAINING}}", &views_remaining.to_string());

    SecretResponse::Html(Html(html))
}

// HTML template for displaying the secret
const SECRET_HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <title>One-Time Secret</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .secret-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .secret-value {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #007bff;
            word-break: break-all;
            font-family: monospace;
            margin: 20px 0;
        }
        .warning {
            color: #856404;
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 10px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .btn {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="secret-container">
        <h1>🔒 One-Time Secret</h1>
        <div class="warning">
            ⚠️ This secret can only be viewed once and will be destroyed after reading.
        </div>
        <p><strong>Secret:</strong></p>
        <div class="secret-value">{{SECRET_VALUE}}</div>
        <p><strong>Recipient:</strong> {{RECIPIENT}}</p>
        <p><strong>Expires in:</strong> {{TTL_REMAINING}} minutes</p>
        <a href="/" class="btn">Create New Secret</a>
    </div>
</body>
</html>
"#;

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
                .replace("{{SECRET_VALUE}}", "❌ Invalid secret URL")
                .replace("{{RECIPIENT}}", "N/A")
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
                .replace("{{SECRET_VALUE}}", "❌ Secret not found or already viewed")
                .replace("{{RECIPIENT}}", "N/A")
                .replace("{{TTL_REMAINING}}", "0")
                .replace("{{VIEWS_REMAINING}}", "0");
            return Html(html);
        }
        Err(e) => {
            tracing::error!("Storage error when getting secret {}: {}", id, e);
            let html = SECRET_HTML
                .replace("{{SECRET_VALUE}}", "❌ Error retrieving secret")
                .replace("{{RECIPIENT}}", "N/A")
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
        let _ = state.storage.delete_secret(&id).await;
        let html = SECRET_HTML
            .replace("{{SECRET_VALUE}}", "❌ Secret has expired")
            .replace("{{RECIPIENT}}", "N/A")
            .replace("{{TTL_REMAINING}}", "0")
            .replace("{{VIEWS_REMAINING}}", "0");
        return Html(html);
    }

    // Check if max views reached
    if secret.access_count >= secret.max_views {
        tracing::info!("Secret max views reached, deleting: {}", id);
        let _ = state.storage.delete_secret(&id).await;
        let html = SECRET_HTML
            .replace("{{SECRET_VALUE}}", "❌ Secret has already been viewed")
            .replace("{{RECIPIENT}}", "N/A")
            .replace("{{TTL_REMAINING}}", "0")
            .replace("{{VIEWS_REMAINING}}", "0");
        return Html(html);
    }

    // Check if passphrase is required
    if secret.metadata.passphrase_required {
        // Show passphrase input form
        let passphrase_form = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>One-Time Secret - Passphrase Required</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                input {
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }
                button {
                    background: #007bff;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                }
                .warning {
                    color: #856404;
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 10px;
                    border-radius: 4px;
                    margin: 20px 0;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 One-Time Secret</h1>
                <div class="warning">
                    ⚠️ This secret is protected by a passphrase.
                </div>
                <p>Please enter the passphrase to view the secret:</p>
                <form method="POST" action="/secret/verify">
                    <input type="hidden" name="secret_id" value="{{SECRET_ID}}">
                    <input type="password" name="passphrase" placeholder="Enter passphrase" required>
                    <button type="submit">View Secret</button>
                </form>
                <p><strong>Expires in:</strong> {{TTL_REMAINING}} minutes</p>
                <p><strong>Views remaining:</strong> {{VIEWS_REMAINING}}</p>
            </div>
        </body>
        </html>
        "#;

        let html = passphrase_form
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
                .replace("{{SECRET_VALUE}}", "❌ Error decrypting secret")
                .replace("{{RECIPIENT}}", "N/A")
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

    let recipient = secret
        .metadata
        .recipient
        .unwrap_or_else(|| "Anyone".to_string());
    let views_remaining = secret.max_views.saturating_sub(secret.access_count + 1);

    let html = SECRET_HTML
        .replace("{{SECRET_VALUE}}", &decrypted_secret)
        .replace("{{RECIPIENT}}", &recipient)
        .replace("{{TTL_REMAINING}}", &ttl_remaining.to_string())
        .replace("{{VIEWS_REMAINING}}", &views_remaining.to_string());

    Html(html)
}

pub async fn _view_secret_page(
    State(state): State<AppState>,
    Path(metadata_key): Path<String>,
) -> impl IntoResponse {
    //let metadata_key = query.key;
    tracing::info!("metadata_key {}", metadata_key);

    let id = match Uuid::parse_str(&metadata_key) {
        Ok(id) => id,
        Err(_) => {
            return Html(
                SECRET_HTML
                    .replace("{{SECRET_VALUE}}", "❌ Invalid secret URL")
                    .replace("{{RECIPIENT}}", "N/A")
                    .replace("{{TTL_REMAINING}}", "0"),
            );
        }
    };

    // Try to retrieve the secret without passphrase first
    let result = state.storage.get_secret(&id).await;

    dbg!(&result);

    let secret = match result {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return Html(
                SECRET_HTML
                    .replace("{{SECRET_VALUE}}", "❌ Secret not found or already viewed")
                    .replace("{{RECIPIENT}}", "N/A")
                    .replace("{{TTL_REMAINING}}", "0"),
            );
        }
        Err(_) => {
            return Html(
                SECRET_HTML
                    .replace("{{SECRET_VALUE}}", "❌ Error retrieving secret")
                    .replace("{{RECIPIENT}}", "N/A")
                    .replace("{{TTL_REMAINING}}", "0"),
            );
        }
    };

    dbg!(&secret);

    // Check if secret has expired
    let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);
    let ttl_remaining = (expires_at - time::OffsetDateTime::now_utc())
        .whole_minutes()
        .max(0);

    if ttl_remaining <= 0 {
        let _ = state.storage.delete_secret(&id).await;
        return Html(
            SECRET_HTML
                .replace("{{SECRET_VALUE}}", "❌ Secret has expired")
                .replace("{{RECIPIENT}}", "N/A")
                .replace("{{TTL_REMAINING}}", "0"),
        );
    }

    // Check if max views reached
    if secret.access_count >= secret.max_views {
        let _ = state.storage.delete_secret(&id).await;
        return Html(
            SECRET_HTML
                .replace("{{SECRET_VALUE}}", "❌ Secret has already been viewed")
                .replace("{{RECIPIENT}}", "N/A")
                .replace("{{TTL_REMAINING}}", "0"),
        );
    }

    // Try to decrypt the secret
    let decrypted_secret = match state
        .encryption
        .decrypt(&secret.ciphertext, &secret.secret_key)
    {
        Ok(value) => value,
        Err(_) => {
            return Html(
                SECRET_HTML
                    .replace("{{SECRET_VALUE}}", "❌ Error decrypting secret")
                    .replace("{{RECIPIENT}}", "N/A")
                    .replace("{{TTL_REMAINING}}", "0"),
            );
        }
    };

    // Update access count (this consumes one view)
    let mut updated_secret = secret.clone();
    updated_secret.access_count += 1;
    let _ = state.storage.update_secret(updated_secret).await;

    let recipient = secret
        .metadata
        .recipient
        .unwrap_or_else(|| "Anyone".to_string());
    let views_remaining = secret.max_views.saturating_sub(secret.access_count + 1);

    let html = SECRET_HTML
        .replace("{{SECRET_VALUE}}", &decrypted_secret)
        .replace("{{RECIPIENT}}", &recipient)
        .replace("{{TTL_REMAINING}}", &ttl_remaining.to_string());

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
        metadata: SecretMetadata {
            recipient: req.recipient.clone(),
            passphrase_required: req.passphrase.is_some(),
            burn_after_reading: max_views == 1,
        },
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
        recipient: req.recipient.clone(),
    };

    tracing::debug!("Secret created successfully: {}", response.metadata_key);

    // Return 201 Created with the response
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
        let _ = state.storage.delete_secret(&id);
        return Err(ApiError::new("Secret not found", 404));
    }

    // Check if max views reached
    if secret.access_count >= secret.max_views {
        let _ = state.storage.delete_secret(&id);
        return Err(ApiError::new("Secret not found", 404));
    }

    // Check passphrase if required
    if secret.metadata.passphrase_required {
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

    // DECRYPT THE SECRET HERE
    let decrypted_value = state
        .encryption
        .decrypt(&secret.ciphertext, &secret.secret_key)
        .map_err(|e| {
            tracing::error!("Failed to decrypt secret {}: {}", secret.id, e);
            ApiError::new(format!("Failed to decrypt secret: {}", e), 500)
        })?;

    // Update access count
    secret.access_count += 1;
    state.storage.update_secret(secret.clone()).await?;
    let response = RetrieveSecretResponse {
        value: decrypted_value,
        recipient: secret.metadata.recipient.clone(),
        passphrase_required: secret.metadata.passphrase_required,
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
    dbg!(id);

    let secret = state
        .storage
        .get_secret(&id)
        .await?
        .ok_or_else(|| ApiError::new("Secret not found", 404))?;

    dbg!(&secret);

    let expires_at = secret.created_at + time::Duration::minutes(secret.ttl_minutes);
    let ttl_remaining = (expires_at - time::OffsetDateTime::now_utc())
        .whole_minutes()
        .max(0);

    if ttl_remaining <= 0 {
        let _ = state.storage.delete_secret(&id);
        return Err(ApiError::new("Secret not found", 404));
    }

    let response = SecretMetadataResponse {
        recipient: secret.metadata.recipient,
        passphrase_required: secret.metadata.passphrase_required,
        burn_after_reading: secret.metadata.burn_after_reading,
        views_remaining: secret.max_views.saturating_sub(secret.access_count),
        ttl_remaining,
        created_at: secret.created_at,
    };

    dbg!(&response);

    Ok(Json(response))
}

pub async fn delete_secret(
    State(state): State<AppState>,
    Path(metadata_key): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = Uuid::parse_str(&metadata_key).map_err(|_| ApiError::new("Invalid secret ID", 400))?;

    state.storage.delete_secret(&id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
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

    // Test database connection by doing a simple query
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
