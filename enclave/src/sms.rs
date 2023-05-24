

use http_req::{request::{RequestBuilder, Method}, tls, uri::Uri};
use std::string::String;
use std::vec::Vec;
use super::err::*;
use std::string::ToString;
use std::str;
use std::collections::HashMap;
use serde_json::{Result, Value, json, to_string};

use super::config::Sms;
use super::log::*;
use super::oauth::*;

pub fn sendsms(conf: &Sms, to_account:&str, c_code: &str) -> GenericResult<()> {
    let body = format!("[DAuth Verification Code] Please use the following code to verify your account: {}", c_code);
    let token_req = format!(
        "Body={}&From={}&To={}",
        &body,
        conf.sender,
        to_account);
    let token_headers = HashMap::from([
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Authorization", &conf.password)
    ]);
    let sms_resp = http_req(
        &conf.server, 
        Method::POST,
        Some(token_req),
        token_headers
    );
    if sms_resp.is_err() {
        return Err(GenericError::from("http error"))
    }
    let v: Value = serde_json::from_str(&sms_resp?)?;
    if v["status"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    let status = v["status"].clone().to_string();
    match status.as_str() {
        "queued" => Ok(()),
        "sent" => Ok(()),
        _ => {
            error(&format!("sms failed: {:?}", v));
            Err(GenericError::from("sms failed"))
        }
    }
}