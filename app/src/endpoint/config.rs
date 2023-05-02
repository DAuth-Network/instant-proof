use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum Env {
    DEV,
    PROD,
}

impl Env {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dev" => Some(Self::DEV),
            "prod" => Some(Self::PROD),
            _ => None
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Api {
    pub env: String,
    pub port: u16,
    pub prefix: String,
    pub protocol: String,
    pub host: String,
    pub workers: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbConfig1 {
    pub host: String,
    pub name: String,
    pub password: String,
    pub port: u16,
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbConfig {
    pub host: String,
    pub name: String,
    pub password: String,
    pub port: u16,
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Email {
    pub account: String,
    pub password: String,
    pub sender: String,
    pub server: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuth {
    pub github: OAuthClient,
    pub google: OAuthClient,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Db {
    pub client: DbConfig,
    pub auth: DbConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DauthConfig {
    pub api: Api,
    pub db: Db,
    pub email: Email,
    pub oauth: OAuth,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TeeConfig {
    pub email: Email,
    pub oauth: OAuth,
    pub rsa_key: String,
    pub seal_key: String
}

impl DauthConfig {
    pub fn to_tee_config(&self, rsa_key: String, seal_key: String) -> TeeConfig {
        TeeConfig {
            email: self.email.clone(),
            oauth: self.oauth.clone(),
            rsa_key: rsa_key,
            seal_key: seal_key
        }
    }
}