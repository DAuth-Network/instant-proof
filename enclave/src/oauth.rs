use super::config::OAuthConf;
use super::err::*;
use super::log::*;
use crate::model::AuthType;
use crate::os_utils::*;
use crate::*;
use http_req::{
    request::{post, Method, RequestBuilder},
    tls,
    uri::Uri,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{json, to_string, Result, Value};
use std::collections::HashMap;
use std::net::TcpStream;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

pub fn get_oauth_client(auth_type: AuthType) -> Option<&'static dyn OAuthClient> {
    let conf = &config(None).inner;
    match auth_type {
        AuthType::Google => Some(&conf.google),
        AuthType::Github => Some(&conf.github),
        AuthType::Apple => Some(&conf.apple),
        _ => {
            error("invalid auth type");
            None
        }
    }
}

pub struct GoogleOAuthClient {
    pub conf: OAuthConf,
}

pub struct GithubOAuthClient {
    pub conf: OAuthConf,
}

pub struct AppleOAuthClient {
    pub conf: OAuthConf,
}

impl OAuthClient for GoogleOAuthClient {
    fn new(conf: OAuthConf) -> Self {
        Self { conf }
    }
    fn oauth(&self, code: &str, redirect_url: &str) -> GenericResult<InnerAccount> {
        google_oauth(&self.conf, code, redirect_url)
    }
}

impl OAuthClient for GithubOAuthClient {
    fn new(conf: OAuthConf) -> Self {
        Self { conf }
    }
    fn oauth(&self, code: &str, redirect_url: &str) -> GenericResult<InnerAccount> {
        github_oauth(&self.conf, code, redirect_url)
    }
}

impl OAuthClient for AppleOAuthClient {
    fn new(conf: OAuthConf) -> Self {
        Self { conf }
    }
    fn oauth(&self, code: &str, redirect_url: &str) -> GenericResult<InnerAccount> {
        apple_oauth(&self.conf, code, redirect_url)
    }
}

fn google_oauth(conf: &OAuthConf, code: &str, redirect_url: &str) -> GenericResult<InnerAccount> {
    let token_req = format!(
        "code={}&client_id={}&client_secret={}&grant_type={}&redirect_uri={}",
        code, conf.client_id, conf.client_secret, "authorization_code", redirect_url
    );
    let token_headers = HashMap::from([("Content-Type", "application/x-www-form-urlencoded")]);
    let token_resp = http_req(
        "https://www.googleapis.com/oauth2/v4/token",
        Method::POST,
        Some(token_req),
        token_headers,
    );
    let v: Value = serde_json::from_str(&token_resp?)?;
    if v["access_token"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    let token = v["access_token"].clone().to_string();
    let bt = format!("Bearer {}", token);
    let user_headers = HashMap::from([("Authorization", bt.as_str())]);
    let account_resp = http_req(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        Method::GET,
        None,
        user_headers,
    );
    let v2: Value = serde_json::from_str(&account_resp?)?;
    if v2["email"].is_null() {
        return Err(GenericError::from("google oauth failed"));
    }
    Ok(InnerAccount {
        account: v2["email"].clone().to_string(),
        auth_type: AuthType::Google,
    })
}

fn apple_oauth(conf: &OAuthConf, code: &str, redirect_url: &str) -> GenericResult<InnerAccount> {
    let client_secret = gen_apple_client_secret(&conf);
    info(&client_secret);
    let token_req = format!(
        "code={}&client_id={}&client_secret={}&grant_type={}",
        code, conf.client_id, client_secret, "authorization_code"
    );
    let token_headers = HashMap::from([("Content-Type", "application/x-www-form-urlencoded")]);
    let token_resp = http_req(
        "https://appleid.apple.com/auth/token",
        Method::POST,
        Some(token_req),
        token_headers,
    );
    let v: Value = serde_json::from_str(&token_resp?)?;
    if v["id_token"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    let token = v["id_token"].clone().to_string();
    info(&format!("apple id_token {}", token));
    match extract_apple_token(&token, "") {
        Some(r) => Ok(InnerAccount {
            account: r.email,
            auth_type: AuthType::Apple,
        }),
        None => Err(GenericError::from("google oauth failed")),
    }
}

fn gen_apple_client_secret(conf: &OAuthConf) -> String {
    let t = system_time();
    println!("current iat {}", t);
    let claims = AppleClientSecret {
        iss: &conf.iss.as_ref().unwrap(),
        sub: &conf.sub.as_ref().unwrap(),
        aud: "https://appleid.apple.com",
        iat: t,
        exp: t + 3600,
    };
    let pem_key = &conf.client_secret;
    println!("{}", &pem_key);
    let pem_key_b = pem_key.as_bytes();
    let key = EncodingKey::from_ec_pem(pem_key_b).unwrap();
    let header = Header {
        alg: Algorithm::ES256,
        kid: Some(conf.kid.as_ref().unwrap().to_string()),
        ..Default::default()
    };
    encode(&header, &claims, &key).unwrap()
}

fn extract_apple_token(token: &str, pub_key: &str) -> Option<AppleIdToken> {
    let mut validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<AppleIdToken>(
        &token,
        &DecodingKey::from_secret(pub_key.as_ref()),
        &validation,
    );
    match token_data {
        Ok(t) => Some(t.claims),
        _ => {
            info("apple id_token decode failed");
            None
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppleIdToken {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub nonce: String,
    pub nonce_supported: bool,
    pub email: String,
    pub email_verified: bool,
    pub is_private_email: bool,
    pub real_user_status: u64,
    pub transfer_sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppleClientSecret<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: &'a str,
    pub iat: u64,
    pub exp: u64,
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

fn github_oauth(conf: &OAuthConf, code: &str, redirect_url: &str) -> GenericResult<InnerAccount> {
    let token_req = format!(
        "client_id={}&client_secret={}&code={}",
        conf.client_id, conf.client_secret, code
    );
    let token_headers = HashMap::from([("Content-Type", "application/x-www-form-urlencoded")]);
    let token_resp = http_req(
        &"http://github.com:443/login/oauth/access_token".to_string(),
        Method::POST,
        Some(to_string(&token_req).unwrap()),
        token_headers,
    );
    if token_resp.is_err() {
        return Err(GenericError::from("http error"));
    }
    let v: Value = serde_json::from_str(&token_resp?)?;
    if v["access_token"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    let token = v["access_token"].clone().to_string();
    let account_headers = HashMap::from([("Authorization", token.as_str())]);
    let account_resp = http_req(
        "http://api.github.com:443/user",
        Method::GET,
        None,
        account_headers,
    );
    if account_resp.is_err() {
        return Err(GenericError::from("github profile failed"));
    }
    let v2: Value = serde_json::from_str(&account_resp?)?;
    if v2["id"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    Ok(InnerAccount {
        account: v2["login"].clone().to_string(),
        auth_type: AuthType::Github,
    })
}

pub fn http_req(
    url: &str,
    method: Method,
    body: Option<String>,
    headers: HashMap<&str, &str>,
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
                req.body(req_body.as_bytes())
                    .header("Content-Length", &req_body.as_bytes().len());
            }
            for (key, val) in headers.into_iter() {
                req.header(key, val);
            }
            let response = req.send(&mut stream, &mut writer).unwrap();
            if !response.status_code().is_success() {
                error("http post failed");
                info(&format!("http status {}", response.status_code()));
                let body = String::from_utf8_lossy(&writer);
                info(&format!("http response is {}", body));
                return Err(GenericError::from(body));
            }
            let body = String::from_utf8_lossy(&writer);
            info(&format!("http response is {}", body));
            return Ok(body.to_string());
        }
        Err(err) => {
            error(&format!("{:?}", err));
            return Err(GenericError::from(err));
        }
    };
}
