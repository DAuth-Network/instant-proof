extern crate  serde;
use serde::{Deserialize, Serialize};
use std::string::*;
use std::fmt::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub email_account: String,
    pub email_password: String,
    pub email_sender: String,
    pub email_server: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_url: String,
}

impl Config {
    pub fn default() -> Self {
        Self {
            email_account: "".to_string(),
            email_password: "".to_string(),
            email_sender: "".to_string(),
            email_server: "".to_string(),
            github_client_id: "".to_string(),
            github_client_secret: "".to_string(),
            google_client_id: "".to_string(),
            google_client_secret: "".to_string(),
            google_redirect_url: "".to_string(),
        }
    }
}

