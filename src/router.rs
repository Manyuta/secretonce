use crate::state::AppState;
use axum::{
    Router,
    response::Html,
    routing::{get, post},
};
use tower_http::cors::CorsLayer;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../templates/index.html")) }),
        )
        .route(
            "/secret/:metadata_key",
            get(crate::handlers::view_secret_page),
        )
        .route("/secret/verify", post(crate::handlers::verify_passphrase))
        .route("/health", get(crate::handlers::health_check))
        .route("/api/v1/secret", post(crate::handlers::create_secret))
        .route(
            "/api/v1/secret/:metadata_key",
            post(crate::handlers::retrieve_secret)
                .get(crate::handlers::get_secret_metadata)
                .delete(crate::handlers::delete_secret),
        )
        .route(
            "/api/v1/internal/secret/:metadata_key",
            get(crate::handlers::get_secret),
        )
        .layer(CorsLayer::permissive())
        .with_state(state)
}
