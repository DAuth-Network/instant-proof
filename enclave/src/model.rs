extern crate serde;
use crate::os_utils;

use super::os_utils::*;
use super::sgx_utils::*;
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
    pub client: Client,
    pub id_type: IdType,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthIn {
    pub session_id: String,
    pub request_id: String, // default None
    pub cipher_code: String,
    pub client: Client,
    pub id_type: IdType, // default None, when None, compare with otp otherwise, call oauth
    pub sign_mode: SignMode, // default Proof
    pub account_plain: Option<bool>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignMode {
    Jwt,
    Proof,
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

impl ToJsonBytes for Account {}

#[derive(Debug, Clone, Serialize)]
pub struct InnerAuth<'a> {
    pub account: &'a InnerAccount,
    pub auth_in: &'a AuthIn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthAuth {
    pub account: String,
    pub id_type: IdType,
    pub request_id: String,
    pub account_plain: Option<String>,
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
    pub fn to_eth_auth(&self) -> &'a EthAuth {
        match self.auth_in.account_plain {
            Some(true) => &EthAuth {
                account: self.account.account_hash,
                id_type: self.account.id_type,
                request_id: self.auth_in.request_id,
                account_plain: Some(self.account.account),
            },
            _ => &EthAuth {
                account: self.account.account_hash,
                id_type: self.account.id_type,
                request_id: self.auth_in.request_id,
                account_plain: None,
            },
        }
    }
    pub fn to_jwt_claim(&self, issuer: &str) -> JwtClaims {
        let iat = os_utils::system_time();
        match self.auth_in.account_plain {
            Some(true) => JwtClaims {
                alg: "RS256".to_string(),
                sub: issuer.to_string(),
                iss: issuer.to_string(),
                aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
                iat,
                exp: iat + 3600,
                uid: self.account.account.clone(),    
            },
            _ => JwtClaims {
                alg: "RS256".to_string(),
                sub: issuer.to_string(),
                iss: issuer.to_string(),
                aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
                iat,
                exp: iat + 3600,
                uid: self.account.account_hash.clone(),    
            },
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
    #[serde(skip_serializing)]
    pub account: String,
    pub id_type: IdType,
    pub account_hash: Option<String>,
    pub account_seal: Option<String>,
}

impl InnerAccount {
    pub fn build(account: String, id_type: IdType) -> Self {
        Self {
            account: account,
            id_type: id_type,
            account_hash: None,
            account_seal: None,
        }
    }
    pub fn seal_and_hash(&self, seal_key: &str) -> Result<(), Error> {
        info(&format!("account is {:?}", &self.account));
        let sealed_r = i_seal(self.account.as_bytes(), seal_key);
        let sealed = match sealed_r {
            Ok(r) => r,
            Err(_) => {
                error("seal account failed");
                return Error::new(ErrorKind::SgxError);
            }
        };
        self.account_seal = Some(encode_hex(&sealed));
        let raw_hashed = web3::eth_hash(self.account.as_bytes());
        self.account_hash = Some(encode_hex(&raw_hashed));
        Ok(())
    }
}
