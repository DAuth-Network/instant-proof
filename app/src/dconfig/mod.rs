use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Env {
    DEV,
    TEST,
    PROD,
}

impl Env {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "test" => Some(Self::TEST),
            "dev" => Some(Self::DEV),
            "prod" => Some(Self::PROD),
            _ => None
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Api {
    pub env: Env,
    pub port: u16,
    pub prefix: String,
    pub protocol: String,
    pub host: String,
    pub workers: u16,
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
pub struct Sms {
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
    pub sms: Sms,
    pub oauth: OAuth,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TeeConfig {
    pub email: Email,
    pub oauth: OAuth,
    pub sms: Sms,
    pub rsa_key: String,
    pub ecdsa_key: String,
    pub seal_key: String
}

impl DauthConfig {
    pub fn to_tee_config(
        &self, 
        rsa_key: String, 
        ecdsa_key: String,
        seal_key: String
    ) -> TeeConfig {
        TeeConfig {
            email: self.email.clone(),
            sms: self.sms.clone(),
            oauth: self.oauth.clone(),
            rsa_key: rsa_key,
            ecdsa_key: ecdsa_key,
            seal_key: seal_key,
        }
    }
}
