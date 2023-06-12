extern crate serde;
use super::os_utils::*;
use serde::{Deserialize, Serialize};
use std::fmt::*;
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
pub struct OtpIn {
    pub session_id: String,
    pub cipher_account: String,
    pub auth_type: AuthType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_name: String,
    pub client_id: String,
    pub client_origin: String,
    pub client_redirect_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthIn {
    pub session_id: String,
    pub request_id: String, // default None
    pub cipher_code: String,
    pub client: Client,
    pub iat: u64,
    pub auth_type: AuthType, // default None, when None, compare with otp otherwise, call oauth
    pub sign_mode: SignMode, // default Proof
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub acc_hash: String,
    pub acc_seal: String,
    pub auth_type: AuthType,
}

impl ToJsonBytes for Account {}

#[derive(Debug, Clone, Serialize)]
pub struct InnerAuth<'a> {
    pub account: &'a InnerAccount,
    pub auth_in: &'a AuthIn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthAuth {
    pub account: String,
    pub auth_type: AuthType,
    pub request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    alg: String,
    sub: String,
    iss: String,
    aud: String, // hard code to "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
    iat: u64,
    exp: u64,
    uid: String,
}

impl<'a> InnerAuth<'a> {
    pub fn to_eth_string(&self) -> String {
        format!(
            "{}:{}:{}",
            &self.account.auth_type.to_string(),
            &self.account.account,
            &self.auth_in.request_id
        )
    }
    pub fn to_eth_auth(&self) -> EthAuth {
        EthAuth {
            account: self.account.account.clone(),
            auth_type: self.account.auth_type,
            request_id: self.auth_in.request_id.clone(),
        }
    }
    pub fn to_jwt_claim(&self, issuer: &str) -> JwtClaims {
        JwtClaims {
            alg: "RS256".to_string(),
            sub: issuer.to_string(),
            iss: issuer.to_string(),
            aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
            iat: self.auth_in.iat,
            exp: self.auth_in.iat + 3600,
            uid: self.account.account.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthSigned {
    pub auth: EthAuth,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSigned {
    pub token: String,
}

impl ToJsonBytes for EthSigned {}
impl EthSigned {
    pub fn new(dauth: EthAuth, signed: &[u8]) -> Self {
        Self {
            auth: dauth,
            signature: encode_hex(&signed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerAccount {
    pub account: String,
    pub auth_type: AuthType,
}

impl InnerAccount {
    pub fn default() -> Self {
        Self {
            account: "".to_string(),
            auth_type: AuthType::Email,
        }
    }
}
