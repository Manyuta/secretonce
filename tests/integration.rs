use std::net::SocketAddr;
use std::sync::Once;

use reqwest::Client;
use secretonce::config::Config;
use secretonce::router::create_router;
use secretonce::state::AppState;
use serde_json::json;

static INIT: Once = Once::new();

async fn spawn_app() -> (SocketAddr, AppState) {
    // Initialize logging only once
    INIT.call_once(|| {
        tracing_subscriber::fmt::init();
    });

    // Load config from env
    let config = Config::from_env().expect("Failed to parse config");

    let state = AppState::new(config.clone())
        .await
        .expect("Failed to initialize state");

    // Bind to a random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind random port");

    let addr = listener.local_addr().unwrap();

    // Spawn the server in a background task
    let app = create_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (addr, state)
}

#[tokio::test]
async fn test_create_and_retrieve_secret() {
    let (addr, _state) = spawn_app().await;
    let base_url = format!("http://{}", addr);
    let client = Client::new();

    // 1. Create a secret
    let secret_value = "my super secret";
    let create_resp = client
        .post(&format!("{}/api/v1/secret", base_url))
        .header("Content-Type", "application/json")
        .body(json!({ "secret": secret_value }).to_string())
        .send()
        .await
        .expect("Failed to send create request");

    assert_eq!(create_resp.status(), 201);

    let create_json: serde_json::Value = create_resp.json().await.unwrap();
    let metadata_key = create_json["metadata_key"].as_str().unwrap();
    let decryption_key = create_json["decryption_key"].as_str().unwrap();

    dbg!(decryption_key);

    // 2. Retrieve the secret
    let retrieve_resp = client
        .post(&format!("{}/api/v1/secret/{}", base_url, metadata_key))
        .header("Content-Type", "application/json")
        .body(json!({ "decryption_key": decryption_key }).to_string())
        .send()
        .await
        .expect("Failed to retrieve secret");

    assert_eq!(retrieve_resp.status(), 200);

    let retrieve_json: serde_json::Value = retrieve_resp.json().await.unwrap();

    assert_eq!(retrieve_json["value"], secret_value);
    assert_eq!(retrieve_json["views_remaining"].as_i64().unwrap(), 0);
}

#[tokio::test]
async fn test_health_check() {
    let (addr, _state) = spawn_app().await;
    let base_url = format!("http://{}", addr);
    let client = Client::new();

    let resp = client
        .get(&format!("{}/health", base_url))
        .send()
        .await
        .expect("Failed to send health check request");

    assert_eq!(resp.status(), 200);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["database"], "connected");
}
