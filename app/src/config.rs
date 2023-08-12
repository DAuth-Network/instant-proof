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
            _ => None,
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
pub struct OtpChannelConf {
    pub account: String,
    pub password: String,
    pub sender: String,
    pub server: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OtpChannel {
    pub sms: OtpChannelConf,
    pub email: OtpChannelConf,
    pub email_api: OtpChannelConf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuth {
    pub github: OAuthConf,
    pub google: OAuthConf,
    pub apple: OAuthConf,
    pub twitter: OAuthConf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Db {
    pub client: DbConfig,
    pub auth: DbConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthConf {
    pub client_id: String,
    pub client_secret: String,
    pub kid: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignerConf {
    pub signer: String,
    pub signing_key: String, // set dummy in config file, read from env later
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signer {
    pub jwt: SignerConf,
    pub jwt_fb: SignerConf,
    pub proof: SignerConf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Attest {
    pub spid: String,
    pub api_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DauthConfig {
    pub api: Api,
    pub db: Db,
    pub otp: OtpChannel,
    pub oauth: OAuth,
    pub signer: Signer,
    pub ias: Attest,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TeeConfig {
    pub otp: OtpChannel,
    pub oauth: OAuth,
    pub seal_key: String,
    pub signer: Signer,
    pub ias: Attest,
}

impl DauthConfig {
    pub fn to_tee_config(&self, seal_key: String) -> TeeConfig {
        TeeConfig {
            otp: self.otp.clone(),
            oauth: self.oauth.clone(),
            signer: self.signer.clone(),
            seal_key,
            ias: self.ias.clone(),
        }
    }
}
