use crate::state::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

pub fn create_router(state: AppState) -> Router {
    // Serve static files from React build
    let static_files_service = ServeDir::new("frontend/build")
        .not_found_service(ServeDir::new("frontend/build/index.html"));

    Router::new()
        .route(
            "/secret/:metadata_key",
            get(crate::web::handlers::get_secret),
        )
        .route(
            "/secret/:metadata_key",
            post(crate::web::handlers::retrieve_secret),
        )
        .route("/secret", post(crate::web::handlers::create_secret))
        .route("/health", get(crate::web::handlers::health_check))
        .route("/api/v1/secret", post(crate::web::handlers::create_secret))
        .route(
            "/api/v1/secret/:metadata_key",
            post(crate::web::handlers::retrieve_secret)
                .get(crate::web::handlers::get_secret_metadata)
                .delete(crate::web::handlers::delete_secret),
        )
        .route(
            "/api/v1/internal/secret/:metadata_key",
            get(crate::web::handlers::get_secret),
        )
        .fallback_service(static_files_service)
        .layer(CorsLayer::permissive())
        .with_state(state)
}
