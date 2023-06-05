extern crate serde;
use serde::{Deserialize, Serialize};
use std::fmt::*;
use std::string::*;

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
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuth {
    pub github: OAuthClient,
    pub google: OAuthClient,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TeeConfig {
    pub email: Email,
    pub oauth: OAuth,
    pub sms: Sms,
    pub rsa_key: String,
    pub ecdsa_key: String,
    pub seal_key: String,
    pub proof_issuer: String,
    pub jwt_issuer: String,
}

impl TeeConfig {
    pub fn default() -> Self {
        Self {
            email: Email::default(),
            sms: Sms::default(),
            oauth: OAuth {
                github: OAuthClient::default(),
                google: OAuthClient::default(),
            },
            rsa_key: emp(),
            ecdsa_key: emp(),
            seal_key: emp(),
            proof_issuer: emp(),
            jwt_issuer: emp(),
        }
    }
}

impl OAuthClient {
    fn default() -> Self {
        Self {
            client_id: emp(),
            client_secret: emp(),
            redirect_url: emp(),
        }
    }
}

impl Email {
    fn default() -> Self {
        Self {
            account: emp(),
            password: emp(),
            sender: emp(),
            server: emp(),
        }
    }
}

impl Sms {
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
fn test_email_creation() {
    let email = Email {
        account: "example@example.com".to_string(),
        password: "password".to_string(),
        sender: "John Doe".to_string(),
        server: "localhost".to_string(),
    };
    assert_eq!(email.account, "example@example.com");
    assert_eq!(email.password, "password");
    assert_eq!(email.sender, "John Doe");
    assert_eq!(email.server, "localhost");
}

#[test]
fn test_oauth_client_creation() {
    let oauth_client = OAuthClient {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        redirect_url: "redirect_url".to_string(),
    };
    assert_eq!(oauth_client.client_id, "client_id");
    assert_eq!(oauth_client.client_secret, "client_secret");
    assert_eq!(oauth_client.redirect_url, "redirect_url");
}

#[test]
fn test_oauth_creation() {
    let oauth = OAuth {
        github: OAuthClient::default(),
        google: OAuthClient::default(),
    };
    assert_eq!(oauth.github.client_id, "");
    assert_eq!(oauth.github.client_secret, "");
    assert_eq!(oauth.github.redirect_url, "");
}

#[test]
fn test_tee_config_creation() {
    let tee_config = TeeConfig {
        email: Email::default(),
        sms: Sms::default(),
        oauth: OAuth {
            github: OAuthClient::default(),
            google: OAuthClient::default(),
        },
        rsa_key: "".to_string(),
        ecdsa_key: emp(),
        seal_key: "".to_string(),
    };
    assert_eq!(tee_config.email.account, "");
    assert_eq!(tee_config.oauth.github.client_id, "");
    assert_eq!(tee_config.rsa_key, "");
    assert_eq!(tee_config.seal_key, "");
}
