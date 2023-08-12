use crate::endpoint::utils;
use serde_derive::{Deserialize, Serialize};
use std::str::FromStr;
use time::PrimitiveDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub acc_hash: String,
    pub acc_and_type_hash: String,
    pub acc_seal: String,
    pub id_type: IdType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestReport {
    quote: String,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignMode {
    Jwt,
    Proof,
    JwtFb,
    Both,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdType {
    Mailto,
    Tel,
    Google,
    Apple,
    Github,
    Twitter,
}

impl std::fmt::Display for IdType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IdType::Mailto => write!(f, "mailto"),
            IdType::Tel => write!(f, "tel"),
            IdType::Apple => write!(f, "apple"),
            IdType::Github => write!(f, "github"),
            IdType::Google => write!(f, "google"),
            IdType::Twitter => write!(f, "twitter"),
        }
    }
}

impl FromStr for IdType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mailto" => Ok(IdType::Mailto),
            "tel" => Ok(IdType::Tel),
            "google" => Ok(IdType::Google),
            "apple" => Ok(IdType::Apple),
            "github" => Ok(IdType::Github),
            "twitter" => Ok(IdType::Twitter),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub acc_hash: String,
    pub acc_and_type_hash: String,
    pub id_type: IdType,
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
            acc_and_type_hash: account.acc_and_type_hash.clone(),
            id_type: account.id_type,
            auth_id: 0,
            auth_datetime: utils::now_datetime().unwrap(),
            auth_exp: 0,
            audience: audience.to_string(),
            request_id: request_id.to_string(),
        }
    }
}
