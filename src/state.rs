use crate::ApiError;
use crate::encryption::EncryptionService;
use crate::storage::{PostgresStorage, SecretStorage};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn SecretStorage>,
    pub encryption: EncryptionService,
    pub config: crate::config::Config,
}

impl AppState {
    pub async fn new(config: crate::config::Config) -> Result<Self, ApiError> {
        let storage: Arc<dyn SecretStorage> = {
            let postgres_storage =
                PostgresStorage::new(&config.database.connection_string()).await?;
            Arc::new(postgres_storage)
        };

        Ok(Self {
            storage,
            encryption: EncryptionService::new(),
            config,
        })
    }
}
