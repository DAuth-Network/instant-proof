extern crate  serde;
use serde::{Deserialize, Serialize};
use std::string::*;
use std::fmt::*;
use std::vec::*;
use super::os_utils::*;

pub trait ToJsonBytes {
    fn to_json_bytes(&self) -> Vec<u8> where Self: Serialize {   
        serde_json::to_vec(&self).unwrap()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub acc_hash: String,
    pub acc_seal: String,
    pub auth_type: AuthType
}

impl ToJsonBytes for Account {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAuth {
    pub account: String,
    pub auth_type: AuthType,
    pub request_id: String,
}

impl DAuth {
    pub fn new(account: &Account, req_id: String) -> Self {
        Self {
            account: account.acc_hash.to_string(),
            auth_type: account.auth_type,
            request_id: req_id
        }
    }
    pub fn to_string(&self) -> String {
        format!("{}:{}:{}", self.auth_type.to_string(), self.account, self.request_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAuthEthSigned {
    pub auth: DAuth,
    pub signature: String
}

impl ToJsonBytes for DAuthEthSigned {}
impl DAuthEthSigned {
    pub fn new(dauth: DAuth, signed: &[u8]) -> Self {
        Self {
            auth: dauth,
            signature: encode_hex(&signed)
        }
    }
}

pub struct InnerAccount {
    pub account: String,
    pub auth_type: AuthType
}

impl InnerAccount {
    pub fn to_str(&self) -> String {
        format!("{}:{}", self.auth_type.to_string(), self.account)
    }
    pub fn from_str(some_str: &str) -> Option<Self> {
        match some_str.split_once(':') {
            Some((a, b)) => {
                let a_t = AuthType::from_str(a);
                if a_t.is_none() {
                    None
                } else {                
                    Some(Self {
                        account: b.to_string(),
                        auth_type: a_t.unwrap(),
                    })
                }
            },
            _ => None,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub const ALL: [Self;7] = [
        Self::Email,
        Self::Sms,
        Self::Discord,
        Self::Google,
        Self::Github,
        Self::Telegram,
        Self::Twitter
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
            _ => None
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
            _ => None
        }
    }

    pub fn to_string(self) -> String {
        match self {
            AuthType::Email => "email".to_string(),
            AuthType::Sms => "sms".to_string(),
            AuthType::Google => "google".to_string(),
            AuthType::Twitter => "twitter".to_string(),
            AuthType::Discord => "discord".to_string(),
            AuthType::Telegram => "telegram".to_string(),
            AuthType::Github => "github".to_string(),
        }
    }
}


