extern crate serde;
use serde::{Deserialize, Serialize};
use std::fmt::*;
use std::string::*;

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
pub struct OAuthConf {
    pub client_id: String,
    pub client_secret: String,
    pub kid: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuth {
    pub github: OAuthConf,
    pub google: OAuthConf,
    pub apple: OAuthConf,
    pub twitter: OAuthConf,
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
pub struct TeeConfig {
    pub otp: OtpChannel,
    pub oauth: OAuth,
    pub signer: Signer,
    pub seal_key: String,
}

impl std::default::Default for TeeConfig {
    fn default() -> Self {
        Self {
            otp: OtpChannel {
                sms: OtpChannelConf::default(),
                email: OtpChannelConf::default(),
                email_api: OtpChannelConf::default(),
            },
            oauth: OAuth {
                github: OAuthConf::default(),
                google: OAuthConf::default(),
                apple: OAuthConf::default(),
                twitter: OAuthConf::default(),
            },
            seal_key: emp(),
            signer: Signer {
                jwt: SignerConf::default(),
                jwt_fb: SignerConf::default(),
                proof: SignerConf::default(),
            },
        }
    }
}

impl OAuthConf {
    fn default() -> Self {
        Self {
            client_id: emp(),
            client_secret: emp(),
            iss: None,
            kid: None,
            sub: None,
        }
    }
}

impl SignerConf {
    fn default() -> Self {
        Self {
            signer: emp(),
            signing_key: emp(),
        }
    }
}

impl OtpChannelConf {
    fn default() -> Self {
        Self {
            account: emp(),
            password: emp(),
            sender: emp(),
            server: emp(),
        }
    }
}

fn emp() -> String {
    "".to_string()
}

#[test]
fn test_oauth_client_creation() {
    let oauth_client = OAuthConf {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        iss: None,
        kid: None,
        sub: None,
    };
    assert_eq!(oauth_client.client_id, "client_id");
    assert_eq!(oauth_client.client_secret, "client_secret");
}

#[test]
fn test_oauth_creation() {
    let oauth = OAuth {
        github: OAuthConf::default(),
        google: OAuthConf::default(),
        apple: OAuthConf::default(),
        twitter: OAuthConf::default(),
    };
    assert_eq!(oauth.github.client_id, "");
    assert_eq!(oauth.github.client_secret, "");
}
