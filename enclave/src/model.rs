extern crate serde;
use crate::os_utils;

use super::err;
use super::log::*;
use super::os_utils::*;
use super::sgx_utils::*;
use super::signer;
use serde::{Deserialize, Serialize};
use std::fmt::*;
use std::result::Result;
use std::string::*;
use std::vec::*;

pub trait ToJsonBytes {
    fn to_json_bytes(&self) -> Vec<u8>
    where
        Self: Serialize,
    {
        serde_json::to_vec(&self).unwrap()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_name: String,
    pub client_id: String,
    pub client_origin: String,
    pub client_redirect_url: String,
    pub mail_subject: Option<String>,
    pub mail_text_template: Option<String>,
    pub mail_html_template: Option<String>,
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

impl ToJsonBytes for InnerAccount {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerAccount {
    #[serde(skip_serializing)]
    pub account: String,
    pub id_type: IdType,
    pub acc_hash: Option<String>,
    pub acc_and_type_hash: Option<String>,
    pub acc_seal: Option<String>,
}

impl InnerAccount {
    pub fn default() -> Self {
        Self {
            account: "".to_string(),
            id_type: IdType::Mailto,
            acc_hash: None,
            acc_and_type_hash: None,
            acc_seal: None,
        }
    }

    pub fn build(account: String, id_type: IdType) -> Self {
        Self {
            account: account,
            id_type: id_type,
            acc_hash: None,
            acc_and_type_hash: None,
            acc_seal: None,
        }
    }
    pub fn seal_and_hash(&mut self, seal_key: &str) -> Result<(), err::Error> {
        info(&format!("account is {:?}", &self.account));
        let sealed_r = i_seal(self.account.as_bytes(), seal_key);
        let sealed = match sealed_r {
            Ok(r) => r,
            Err(_) => {
                error("seal account failed");
                return Err(err::Error::new(err::ErrorKind::SgxError));
            }
        };
        self.acc_seal = Some(encode_hex(&sealed));
        let raw_hashed = signer::eth_hash(self.account.as_bytes());
        self.acc_hash = Some(encode_hex(&raw_hashed));
        let raw_hashed2 =
            signer::eth_hash(format!("{}:{}", self.id_type.to_string(), self.account).as_bytes());
        self.acc_and_type_hash = Some(encode_hex(&raw_hashed2));
        Ok(())
    }
}

pub struct AuthService {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIn {
    pub session_id: String,
    pub cipher_data: String,
    pub client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpData {
    pub account: String,
    pub id_type: IdType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthData {
    pub code: String,
    pub id_type: IdType, // default None, when None, compare with otp otherwise, call oauth
    pub id_key_salt: Option<i32>, // default Proof
    pub sign_msg: Option<String>, // default Proof
    pub sign_mode: SignMode, // default Proof
    pub account_plain: Option<bool>,
    pub user_key: Option<String>,
    pub user_key_signature: Option<String>,
}
