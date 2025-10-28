use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub secrets: SecretsConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecretsConfig {
    pub default_ttl: u32,
    pub max_ttl: u32,
    pub default_max_views: u32,
    pub max_max_views: u32,
    pub cleanup_interval_seconds: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database_name: String,
    pub max_connections: u32,
}

impl DatabaseConfig {
    pub fn connection_string(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.database_name
        )
    }
}

pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} is not supported environment. \
                Use either `local`or `production`.",
                other
            )),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv().ok();

        let environment: Environment = std::env::var("APP_ENVIRONMENT")
            .unwrap_or_else(|_| "local".into())
            .try_into()
            .expect("Failed to parse APP_ENVIRONMENT");
        let environment_file = format!("{}.yaml", environment.as_str());

        let base_path = std::env::current_dir().expect("Failed to detect current directory.");
        let configuration_directory = base_path.join("configuration");
        let config: config::Config = config::Config::builder()
            .add_source(config::File::from(
                configuration_directory.join("base.yaml"),
            ))
            .add_source(config::File::from(
                configuration_directory.join(environment_file),
            ))
            .add_source(
                config::Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("_"),
            )
            .build()?;

        config.try_deserialize()
    }
}
