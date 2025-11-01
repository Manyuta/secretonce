use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::{encryption::EncryptionService, state::AppState};

// Templates
const SECRET_HTML: &str = include_str!("../../templates/display_secret.html");
const PASSPHRASE_FORM_TEMPLATE: &str = include_str!("../../templates/passphrase_input_form.html");

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

#[derive(serde::Deserialize)]
pub struct VerifyPassphraseForm {
    pub secret_id: String,
    pub passphrase: String,
}

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
        .decrypt(&secret.ciphertext.expose_secret(), &secret.secret_key)
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
        tracing::error!("Failed to update secret {}: {}", id, e);

        return SecretResponse::Redirect(Redirect::to(&format!(
            "/secret?key={}&error=update_error",
            form.secret_id
        )));
    }

    let views_remaining = secret.max_views.saturating_sub(secret.access_count);

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
        .decrypt(&secret.ciphertext.expose_secret(), &secret.secret_key)
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
