
use std::string::String;
use std::vec::Vec;
use std::string::ToString;
use http_req::{request::{RequestBuilder, Method, post}, tls, uri::Uri};
use std::net::TcpStream;
use serde_json::{Result, Value, json, to_string};
use std::collections::HashMap;


use crate::config::OAuth;

use super::config::OAuthClient;
use super::err::*;
use super::log::*;

pub fn oauth_worker(
    auth_type: i32, 
    conf: &OAuth, 
    auth_code: &str
) -> GenericResult<String> {
    match auth_type {
        1 => {
            let gauth = GoogleOAuthWorker::new(&conf.google);
            let token = gauth.get_access_token(&auth_code)?;
            return Ok(gauth.get_profile(&token)?)
        },
        /* 
        2 => twitter_oauth(&enclave_state.config, code),
        3 => discord_oauth(&enclave_state.config, code),
        4 => telegram_oauth(&enclave_state.config, code),
        */
        5 => {
            let gauth = GithubOAuthWorker::new(&conf.github);
            let token = gauth.get_access_token(&auth_code)?;
            return Ok(gauth.get_profile(&token)?);
        },
        _ => {
            return Err(GenericError::from("error type"));
        },
    };
}

pub trait OAuthTrait {
    fn new(conf: &OAuthClient) -> Self;
    fn get_access_token(&self, code: &str) -> GenericResult<String>;
    fn get_profile(&self, token: &str) -> GenericResult<String>;
}

pub struct GoogleOAuthWorker {
    conf: OAuthClient,
    access_token_url: String,
    profile_url: String,
}

impl OAuthTrait for GoogleOAuthWorker {
    fn new(conf: &OAuthClient) -> Self {
        Self { 
            conf: conf.clone(),
            access_token_url: "https://www.googleapis.com/oauth2/v4/token".to_string(),
            profile_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string()
        }
    } 
  
    fn get_profile(&self, token: &str) -> GenericResult<String> {
        let bt = format!("Bearer {}", token);
        let user_headers = HashMap::from([
            ("Authorization",  bt.as_str())
        ]);
        let account_resp = http_req(
            &self.profile_url,
            Method::GET,
            None,
            user_headers
        );
        let v2: Value = serde_json::from_str(&account_resp?)?;
        if v2["sub"].is_null() {
            return Err(GenericError::from("google oauth failed"));
        }
        Ok(v2["sub"].clone().to_string())
    }
  
    fn get_access_token(&self, code: &str) -> GenericResult<String> {
        let token_req = format!(
            "code={}&client_id={}&client_secret={}&grant_type={}&redirect_url={}",
            code,
            &self.conf.client_id,
            &self.conf.client_secret,
            "authorization_code",
            &self.conf.redirect_url
        );
        let token_headers = HashMap::from([
            ("Content-Type", "application/x-www-form-urlencoded"),
        ]);
        let token_resp = http_req(
            &self.access_token_url,
            Method::POST,
            Some(token_req),
            token_headers);
        let v: Value = serde_json::from_str(&token_resp?)?;
        if v["access_token"].is_null() {
            return Err(GenericError::from("github oauth failed"));
        }
        Ok(v["access_token"].clone().to_string())
    }
}
  
struct GithubOAuthWorker {
    conf: OAuthClient,
    access_token_url: String,
    profile_url: String,

}
  
impl OAuthTrait for GithubOAuthWorker {
    fn new(conf: &OAuthClient) -> Self {
        Self { 
            conf: conf.clone(),
            access_token_url: "http://github.com:443/login/oauth/access_token".to_string(),
            profile_url: "http://api.github.com:443/user".to_string()
        }
    } 
  
    fn get_profile(&self, token: &str) -> GenericResult<String> { 
        let account_headers = HashMap::from([
            ("Authorization", token)
        ]);
        let account_resp = http_req(
            &self.profile_url,
            Method::GET,
            None,
            account_headers);
        if account_resp.is_err() {
            return Err(GenericError::from("github profile failed"));
        }
        let v2: Value = serde_json::from_str(&account_resp?)?;
        if v2["id"].is_null() {
            return Err(GenericError::from("github oauth failed"));
        }
        Ok(v2["id"].clone().to_string())
    }
  
    fn get_access_token(&self, code: &str) -> GenericResult<String>  {
        let token_req = format!(
            "client_id={}&client_secret={}&code={}",
            self.conf.client_id,
            self.conf.client_secret,
            code);
        let token_headers = HashMap::from([
            ("Content-Type", "application/x-www-form-urlencoded")
        ]);
        let token_resp = http_req(
            &self.access_token_url, 
            Method::POST,
            Some(to_string(&token_req).unwrap()),
            token_headers
        );
        if token_resp.is_err() {
            return Err(GenericError::from("http error"))
        }
        let v: Value = serde_json::from_str(&token_resp?)?;
        if v["access_token"].is_null() {
            return Err(GenericError::from("github oauth failed"));
        }
        Ok(v["access_token"].clone().to_string())
    }
}

/* 
pub fn google_oauth(conf: &OAuthClient, code: &str) -> GenericResult<String>{
    let token_req = format!(
        "code={}&client_id={}&client_secret={}&grant_type={}&redirect_url={}",
        code,
        conf.client_id,
        conf.client_secret,
        "authorization_code",
        conf.redirect_url
    );
    let token_headers = HashMap::from([
        ("Content-Type", "application/x-www-form-urlencoded"),
    ]);
    let token_resp = http_req(
        "https://www.googleapis.com/oauth2/v4/token",
        Method::POST,
        Some(token_req),
        token_headers);
    let v: Value = serde_json::from_str(&token_resp?)?;
    if v["access_token"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    let token = v["access_token"].clone().to_string();
    let bt = format!("Bearer {}", token);
    let user_headers = HashMap::from([
        ("Authorization",  bt.as_str())
    ]);
    let account_resp = http_req(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        Method::GET,
        None,
        user_headers
    );
    let v2: Value = serde_json::from_str(&account_resp?)?;
    if v2["sub"].is_null() {
        return Err(GenericError::from("google oauth failed"));
    }
    Ok(v2["sub"].clone().to_string())
}

/* 
pub fn twitter_oauth(conf: &Config, code: &str) -> GenericResult<String>{
    Ok("".to_string())
}


pub fn discord_oauth(conf: &Config, code: &str) -> GenericResult<String>{
    Ok("".to_string())
}


pub fn telegram_oauth(conf: &Config, code: &str) -> GenericResult<String>{
    Ok("".to_string())
}
*/

pub fn github_oauth(conf: &OAuthClient, code: &str) -> GenericResult<String>{
    let token_req = format!(
        "client_id={}&client_secret={}&code={}",
        conf.client_id,
        conf.client_secret,
        code);
    let token_headers = HashMap::from([
        ("Content-Type", "application/x-www-form-urlencoded")
    ]);
    let token_resp = http_req(
        &"http://github.com:443/login/oauth/access_token".to_string(), 
        Method::POST,
        Some(to_string(&token_req).unwrap()),
        token_headers
    );
    if token_resp.is_err() {
        return Err(GenericError::from("http error"))
    }
    let v: Value = serde_json::from_str(&token_resp?)?;
    if v["access_token"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    let token = v["access_token"].clone().to_string();
    let account_headers = HashMap::from([
        ("Authorization", token.as_str())
    ]);
    let account_resp = http_req(
        "http://api.github.com:443/user",
        Method::GET,
        None,
        account_headers);
    if account_resp.is_err() {
        return Err(GenericError::from("github profile failed"));
    }
    let v2: Value = serde_json::from_str(&account_resp?)?;
    if v2["id"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    Ok(v2["id"].clone().to_string())
}
*/

fn http_req(
    url: &str, 
    method: Method,
    body: Option<String>, 
    headers: HashMap<&str, &str>
) -> GenericResult<String> {
    let addr: Uri = url.parse().unwrap();
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.corr_port());
    let stream = TcpStream::connect(conn_addr);
    let mut req_body = String::new();
    info(&format!("url {:?}", &addr));
    match stream {
        Ok(r) => {
            let mut stream = tls::Config::default()
                .connect(addr.host().unwrap_or(""), r)
                .unwrap();   
            let mut writer = Vec::new();
            let mut req = RequestBuilder::new(&addr);
            req.method(method)
                .header("Connection", "Close")
                .header("Accept", "application/json");
            if body.is_some() {
                req_body = body.unwrap();
                req.body(req_body.as_bytes()).header("Content-Length", &req_body.as_bytes().len());
            }
            for (key, val) in headers.into_iter() {
                req.header(key, val);
            }
            let response = req.send(&mut stream, &mut writer).unwrap();
            if !response.status_code().is_success() {
                error("http post failed");
                info(&format!("http status {}", response.status_code()));
                let body = String::from_utf8_lossy(&writer);
                info(&format!("access token response is {}", body));
                return Err(GenericError::from(body));
            }
            let body = String::from_utf8_lossy(&writer);
            info(&format!("access token response is {}", body));
            return Ok(body.to_string());
        },
        Err(err) => {
            error(&format!("{:?}", err));
            return Err(GenericError::from(err));
        }
    };
}

