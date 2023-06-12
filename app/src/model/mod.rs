use crate::endpoint::utils;
use serde_derive::{Deserialize, Serialize};
use std::str::FromStr;
use time::PrimitiveDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub acc_hash: String,
    pub acc_seal: String,
    pub auth_type: AuthType,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignMode {
    Jwt,
    Proof,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Email,
    Sms,
    Github,
    Google,
    Apple,
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthType::Email => write!(f, "email"),
            AuthType::Sms => write!(f, "sms"),
            AuthType::Google => write!(f, "google"),
            AuthType::Github => write!(f, "github"),
            AuthType::Apple => write!(f, "apple"),
        }
    }
}
impl FromStr for AuthType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email" => Ok(AuthType::Email),
            "sms" => Ok(AuthType::Sms),
            "google" => Ok(AuthType::Google),
            "github" => Ok(AuthType::Github),
            "apple" => Ok(AuthType::Apple),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub acc_hash: String,
    pub auth_type: AuthType,
    pub auth_id: i32,
    pub auth_datetime: PrimitiveDateTime,
    pub auth_exp: u64,
    pub audience: String,
    pub request_id: String,
}

impl Auth {
    pub fn new(account: &Account, audience: &str, request_id: &str) -> Self {
        Self {
            acc_hash: account.acc_hash.clone(),
            auth_type: account.auth_type,
            auth_id: 0,
            auth_datetime: utils::now_datetime().unwrap(),
            auth_exp: 0,
            audience: audience.to_string(),
            request_id: request_id.to_string(),
        }
    }
}
