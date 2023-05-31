use crate::endpoint::utils;
use serde_derive::{Deserialize, Serialize};
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
    JWT = 0,
    PROOF = 1,
}

impl SignMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "jwt" => Some(Self::JWT),
            "proof" => Some(Self::PROOF),
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    Email = 0,
    Sms = 1,
    Google = 5,
    Twitter = 6,
    Discord = 7,
    Telegram = 8,
    Github = 9,
}

impl AuthType {
    pub const ALL: [Self; 7] = [
        Self::Email,
        Self::Sms,
        Self::Discord,
        Self::Google,
        Self::Github,
        Self::Telegram,
        Self::Twitter,
    ];

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "email" => Some(Self::Email),
            "sms" => Some(Self::Sms),
            "google" => Some(Self::Google),
            "twitter" => Some(Self::Twitter),
            "discord" => Some(Self::Discord),
            "telegram" => Some(Self::Telegram),
            "github" => Some(Self::Github),
            _ => None,
        }
    }

    pub fn from_int(i: i32) -> Option<Self> {
        match i {
            0 => Some(Self::Email),
            1 => Some(Self::Sms),
            5 => Some(Self::Google),
            6 => Some(Self::Twitter),
            7 => Some(Self::Discord),
            8 => Some(Self::Telegram),
            9 => Some(Self::Github),
            _ => None,
        }
    }
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthType::Email => write!(f, "email"),
            AuthType::Sms => write!(f, "sms"),
            AuthType::Google => write!(f, "google"),
            AuthType::Twitter => write!(f, "twitter"),
            AuthType::Discord => write!(f, "discord"),
            AuthType::Telegram => write!(f, "telegram"),
            AuthType::Github => write!(f, "github"),
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
            auth_type: account.auth_type.clone(),
            auth_id: 0,
            auth_datetime: utils::now_datetime().unwrap(),
            auth_exp: 0,
            audience: audience.to_string(),
            request_id: request_id.to_string(),
        }
    }
}
