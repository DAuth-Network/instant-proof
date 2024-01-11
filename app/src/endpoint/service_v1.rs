/*
This file describes api version 1.1, including:
- send_otp
- auth_in_one
 */

extern crate openssl;
#[macro_use]
use std::str;
use actix_http::header::{HeaderMap, ORIGIN};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use elliptic_curve::JwkEcKey;
use log::{error, info};
use serde::Serialize as Serialize2;
use serde_derive::{Deserialize, Serialize};
extern crate sgx_types;
extern crate sgx_urts;
use super::service;
use super::tee::*;
use crate::config::*;
use crate::error as derr;
use crate::model::*;
use crate::persistence::dauth::*;
use crate::persistence::dclient::*;
use p256::PublicKey;

#[derive(Deserialize)]
pub struct AuthOtpReq {
    client_id: String,
    session_id: String,
    cipher_account: String,
    id_type: IdType,
    request_id: Option<String>,
}

// with BaseResp
#[post("/send_otp")]
pub async fn send_otp(
    req: web::Json<AuthOtpReq>,
    http_req: HttpRequest,
    endex: web::Data<service::AppState>,
) -> HttpResponse {
    info!("auth email with session_id {}", &req.session_id);
    // validate client
    let client_o = service::get_client(
        &endex.clients,
        &req.client_id,
        http_req.headers(),
        &endex.env,
    );
    if client_o.is_none() {
        info!("client id not found");
        return service::fail_resp(derr::Error::new(derr::ErrorKind::ClientError));
    }
    let client = client_o.unwrap();
    let tee = &endex.tee;
    let auth_otp_in = OtpIn {
        session_id: &req.session_id,
        cipher_account: &req.cipher_account,
        id_type: req.id_type,
        client: &client,
    };
    match tee.send_otp_v1(auth_otp_in) {
        Ok(_) => service::succ_resp(),
        Err(e) => service::fail_resp(e),
    }
}

#[derive(Deserialize)]
pub struct AuthInOneReq {
    client_id: String,
    session_id: String,
    cipher_code: String,
    id_type: IdType,
    request_id: Option<String>,
    sign_mode: Option<SignMode>, // default proof, or JWT
    account_plain: Option<bool>,
    user_key: Option<String>,
    user_key_signature: Option<String>,
}

#[post("/auth_in_one")]
pub async fn auth_in_one(
    req: web::Json<AuthInOneReq>,
    http_req: HttpRequest,
    endex: web::Data<service::AppState>,
) -> HttpResponse {
    info!("register mail confirm with session_id {}", &req.session_id);
    info!("auth email with session_id {}", &req.session_id);
    // validate client
    let client_o = service::get_client(
        &endex.clients,
        &req.client_id,
        http_req.headers(),
        &endex.env,
    );
    if client_o.is_none() {
        info!("client id not found");
        return service::fail_resp(derr::Error::new(derr::ErrorKind::ClientError));
    }
    let client = client_o.unwrap();
    let tee = &endex.tee;
    let request_id = match &req.request_id {
        Some(r) => {
            if r.starts_with("0x") {
                r[2..].to_string()
            } else {
                r.to_string()
            }
        }
        None => "None".to_string(),
    };
    let sign_mode = match &req.sign_mode {
        Some(r) => r.to_owned(),
        None => SignMode::Proof,
    };
    let auth_in = AuthInV1 {
        session_id: &req.session_id,
        cipher_code: &req.cipher_code,
        request_id: &request_id,
        client: &client,
        id_type: req.id_type,
        sign_mode,
        account_plain: &req.account_plain,
        user_key: &req.user_key,
        user_key_signature: &req.user_key_signature,
    };
    let auth_result = tee.auth_in_one_v1(auth_in);
    if auth_result.is_err() {
        return service::fail_resp(auth_result.err().unwrap());
    }
    let auth_out = auth_result.unwrap();
    let account = auth_out.account;
    let insert_r = insert_account_if_new(&endex.db_pool, &account);
    if insert_r.is_err() {
        error!("insert account error {}", insert_r.err().unwrap());
        return service::fail_resp(derr::Error::new(derr::ErrorKind::DbError));
    }
    let auth = Auth::new_v1(&account, &client.client_name, &request_id);
    let insert_auth_r = insert_auth(&endex.db_pool, auth);
    if insert_auth_r.is_err() {
        error!("insert auth error {}", insert_auth_r.err().unwrap());
        return service::fail_resp(derr::Error::new(derr::ErrorKind::DbError));
    }
    service::json_resp(auth_out.cipher_sign)
}
