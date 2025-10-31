use secretonce::config::Config;

use secretonce::error::ApiError;
use secretonce::router;
use secretonce::state::AppState;
use tower_http::trace::TraceLayer;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env().expect("Failed to parse env config");

    let state = AppState::new(config.clone()).await?;

    // Start cleanup task
    let storage_clone = state.storage.clone();
    let config_clone = config.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
            config_clone.secrets.cleanup_interval_seconds,
        ));
        loop {
            interval.tick().await;
            match storage_clone.cleanup_expired().await {
                Ok(expired) => {
                    if !expired.is_empty() {
                        tracing::info!("Cleaned up {} expired secrets", expired.len());
                    }
                }
                Err(e) => {
                    tracing::error!("Cleanup error: {:?}", e);
                }
            }
        }
    });

    let app = router::create_router(state).layer(TraceLayer::new_for_http());

    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .await
            .map_err(|e| ApiError::new(format!("Failed to bind to address: {}", e), 500))?;

    tracing::info!(
        "Server running on http://{}:{}",
        config.server.host,
        config.server.port
    );

    axum::serve(listener, app)
        .await
        .map_err(|e| ApiError::new(format!("Server error: {}", e), 500))?;

    Ok(())
}
