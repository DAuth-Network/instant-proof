extern crate  serde;
use serde::{Deserialize, Serialize};
use std::string::*;
use std::fmt::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Email {
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
    pub rsa_key: String,
    pub seal_key: String
}


impl TeeConfig {
    pub fn default() -> Self {
        Self {
            email: Email::default(),
            oauth: OAuth { 
                github: OAuthClient::default(), 
                google: OAuthClient::default() },
            rsa_key: emp(),
            seal_key: emp(),
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

fn emp() -> String {
    "".to_string()
}