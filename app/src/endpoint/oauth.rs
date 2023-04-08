use super::config::Config;
use super::err::*;
use std::string::String;
use std::vec::Vec;
use std::string::ToString;
use http_req::{request::{RequestBuilder, Method, get, post}, tls, uri::Uri};
use std::{net::TcpStream, convert::TryFrom};
use serde_json::{Result, Value, Map, json, to_string};
use crate::persistence::*;
use serde::{Deserialize, Serialize};

pub fn google_oauth2(cid: &str, cse: &str, code: &str) -> GenericResult<String>{
    let token_req = format!(
        "code={}&client_id={}&client_secret={}grant_type=authorization_code",
        code,
        cid,
        cse,
    );
    let token_resp = http_post_body(
        "https://oauth2.googleapis.com/token",
        token_req,
        Some("application/x-www-form-urlencoded")
    );
    let v: Value = serde_json::from_str(&token_resp).unwrap();
    let token = v["access_token"].clone().to_string();
    let account_resp = http_get(
        "https://www.googleapis.com/auth/userinfo.email",
        "Authorization",
        &format!("Bearer {}", token)
    );
    println!();
    Ok(account_resp)
}

fn twitter_oauth(conf: &Config, code: &str) -> GenericResult<String>{
    Ok("".to_string())
}


fn discord_oauth(conf: &Config, code: &str) -> GenericResult<String>{
    Ok("".to_string())
}


fn telegram_oauth(conf: &Config, code: &str) -> GenericResult<String>{
    Ok("".to_string())
}


pub fn github_oauth2(cid: &str, cse: &str, code: &str) -> GenericResult<String>{
    let token_req = json!({
        "client_id": cid,
        "client_secret": cse,
        "code": code
    });
    let token_resp = http_post(
        &"http://127.0.0.1:5000/access_token".to_string(), 
        to_string(&token_req).unwrap(),
        None
    );
    if token_resp.len() == 0 {
        return Err(GenericError::from("http error"))
    }
    let v: Value = serde_json::from_str(&token_resp).unwrap();
    if v["access_token"].is_null() {
        return Err(GenericError::from("github oauth failed"));
    }
    let token = v["access_token"].clone().to_string();
    let account_resp = http_get_header(
        "https://api.github.com:443/user",
        "Authorization",
        &format!("token {}", &token));
    let v2: Value = serde_json::from_str(&account_resp).unwrap();
    Ok(v2["account"].clone().to_string())
}


fn http_get_header(url: &str, header: &str, value: &str) -> String {
    let addr = Uri::try_from(url).unwrap();
    // let addr: Uri = url.parse().unwrap();
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.corr_port());
    let stream = TcpStream::connect(conn_addr);
    match stream {
        Ok(r) => {
            let mut stream = tls::Config::default()
                .connect(addr.host().unwrap_or(""), r)
                .unwrap();   
            let mut writer = Vec::new();
        
            let response = RequestBuilder::new(&addr)
                .method(Method::GET)
                .header("Connection", "Close")
                .header(&header, &value)
                .header("Accept", "application/json")
                .send(&mut stream, &mut writer)
                .unwrap();
            
            let body = String::from_utf8_lossy(&writer);
            println!("get oauth account response is {:?}", body);
            return body.to_string();
        },
        Err(err) => {
            println!("{:?}", err);
            return "".to_string()
        }
    };
}

fn http_post_body(
    url: &str, 
    req: String, 
    content:Option<&str>) -> String {
    let addr = Uri::try_from(url).unwrap();
    let conn_addr = format!("{}:{}", addr.host().unwrap(), addr.corr_port());
    let stream = TcpStream::connect(conn_addr);
    println!("url {:?}", &addr);
    println!("http post request {}", &req);
    match stream {
        Ok(r) => {
            let mut stream = tls::Config::default()
                .connect(addr.host().unwrap_or(""), r)
                .unwrap();   
            let mut writer = Vec::new();
        
            let response = 
            match content {
                Some(c) => {
                    RequestBuilder::new(&addr)
                        .method(Method::POST)
                        .body(req.as_bytes())
                        .header("Connection", "Close")
                        .header("Content-Type", c)
                        .header("Accept", "application/json")
                        .send(&mut stream, &mut writer)
                        .unwrap()
                },
                None => {
                    RequestBuilder::new(&addr)
                        .method(Method::POST)
                        .body(req.as_bytes())
                        .header("Connection", "Close")
                        .header("Accept", "application/json")
                        .send(&mut stream, &mut writer)
                        .unwrap()
                },
            };
            if !response.status_code().is_success() {
                println!("http post failed");
                return "".to_string();
            }
            let body = String::from_utf8_lossy(&writer);
            println!("access token response is {}", body);
            return body.to_string();
        },
        Err(err) => {
            println!("{:?}", err);
            return "".to_string()
        }
    };
}


fn http_post(
    url: &str, 
    req: String, 
    content:Option<&str>) -> String {
    println!("new http post");
    println!("url is {}", &url);
    let mut writer = Vec::new();
    let response = post(url, req.as_bytes(), &mut writer).unwrap();
    if response.status_code().is_success() {
        let body = String::from_utf8_lossy(&writer);
        println!("access token response is {}", body);
        return body.to_string();
    } else {
        println!("{}", response.status_code());
        println!("post failed");
        return "".to_string();
    }
}


fn http_get(
    url: &str, 
    header_name: &str,
    header_v: &str) -> String {
    println!("new http post");
    let mut writer = Vec::new();
    let response = get(&url, &mut writer).unwrap();
    if response.status_code().is_success() {
        let body = String::from_utf8_lossy(&writer);
        println!("access token response is {}", body);
        return body.to_string();
    } else {
        println!("{}", response.status_code());
        println!("post failed");
        return "".to_string();
    }
}


#[derive(Deserialize, Serialize, Debug)]
pub struct GithubOAuthReq {
    client_id: String,
    client_secret: String,
    code: String
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GithubOAuthResp {
    access_token: String,
    scope: String,
    token_type: String
}


pub fn github_oauth(
    client_id: &str,
    client_secret: &str,
    code: &str
) -> GenericResult<String> {
    let http_client = reqwest::blocking::Client::new();
    let github_oauth_req = GithubOAuthReq {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        code: code.to_string()
    };
    info!("{:?}", &github_oauth_req);
    let res = http_client.post("https://github.com/login/oauth/access_token")
        .form(&github_oauth_req)
        .header("Accept", "application/json")
        .send().unwrap();
    let token_resp = res.text().unwrap();
    info!("token response {}", &token_resp);
    let resp: GithubOAuthResp = serde_json::from_str(&token_resp)?;
    let access_token = resp.access_token;
    info!("access token {}", &access_token);
    let user_profile = http_client.post("https://api.github.com/user")
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "keysafe-protocol")
        .send().unwrap().text().unwrap();
    let email = parse_github_oauth_profile(user_profile)?;
    Ok(email)
}

fn parse_github_oauth_profile(oauth_result: String) -> GenericResult<String> {
    let parsed: Value = serde_json::from_str(&oauth_result).unwrap(); 
    let obj: Map<String, Value> = parsed.as_object().unwrap().clone();
    info!("access obj {:?}", obj);
    let email = obj.get("id");
    if email.is_none() {
        return Err(GenericError::from("parse github profile failed"));
    }
    Ok(email.unwrap().as_i64().unwrap().to_string())
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GoogleOAuthReq {
    client_id: String,
    client_secret: String,
    code: String,
    grant_type: String,
    redirect_uri: String
}

pub fn google_oauth(
    cid: &str, 
    cse: &str, 
    url: &str, 
    code: &str
) -> GenericResult<String>{
    let token_req = GoogleOAuthReq {
        client_id: cid.to_string(),
        client_secret: cse.to_string(),
        code: code.to_string(),
        grant_type: "authorization_code".to_string(),
        redirect_uri: url.to_string()
    };
    info!("token request {:?}", &token_req);
    let http_client = reqwest::blocking::Client::new();
    let token_resp = http_client.post("https://www.googleapis.com/oauth2/v4/token")
        .form(&token_req)
        .header("Accept", "application/json")
        .send().unwrap();
    if !token_resp.status().is_success() {
        let token_resp_txt = token_resp.text()?;
        info!("access token response is {:?}", token_resp_txt);    
        return Err(GenericError::from("google oauth access token fail"));
    }
    let token_resp_txt = token_resp.text()?;
    info!("access token response is {:?}", token_resp_txt);
    let v: Value = serde_json::from_str(&token_resp_txt).unwrap();
    let token = v["access_token"].clone().to_string();
    let bear_token = format!("Bearer {}", token);
    let account_resp = http_client.get("https://www.googleapis.com/oauth2/v3/userinfo")
        .header("Authorization", bear_token)
        .send().unwrap();
    if !account_resp.status().is_success() {
        let account_resp_txt = account_resp.text()?;
        info!("oauth response is {}", account_resp_txt);
        return Err(GenericError::from("google oauth access token fail"))
    }
    let account_resp_txt = account_resp.text()?;
    info!("oauth response is {}", account_resp_txt);
    parse_google_oauth_profile(account_resp_txt)
}


fn parse_google_oauth_profile(oauth_result: String) -> GenericResult<String> {
    let parsed: Value = serde_json::from_str(&oauth_result).unwrap(); 
    let obj: Map<String, Value> = parsed.as_object().unwrap().clone();
    info!("access obj {:?}", obj);
    let email = obj.get("sub");
    if email.is_none() {
        return Err(GenericError::from("parse google profile failed"));
    }
    Ok(email.unwrap().as_str().unwrap().to_string())
}
