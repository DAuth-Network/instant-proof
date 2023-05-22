extern crate openssl;
#[macro_use]
use std::str;
use actix_http::header::{HeaderMap, ORIGIN};
use serde::Serialize as Serialize2;
use serde_derive::{Deserialize, Serialize};
use actix_web::{
    get, post, web, HttpResponse, HttpRequest, Responder 
};
use jsonwebkey_convert::*;
use log::{error, info};
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use mysql::*;
use crate::ecall;
use crate::persistence::dauth::*;
use crate::persistence::dclient::*;
use crate::endpoint::utils;
use crate::endpoint::session;

use super::err::*;
use super::session::SessionState;
use super::config::*;

static SUCC: &'static str = "success";
static FAIL: &'static str = "fail";

/// BaseResp is a base response for most request
/// status can either be:
/// SUCCESS or 
/// FAIL
#[derive(Debug, Serialize, Deserialize)]
pub struct BaseResp {
    status: String,
    error_code: String,
    error_msg: String
}

fn fail_resp(err: DAuthError) -> HttpResponse {
    HttpResponse::Ok().json(BaseResp {
        status: FAIL.to_string(),
        error_code: err.clone().to_string(),
        error_msg: err.clone().to_message()
    })
}

fn succ_resp() -> HttpResponse {
    HttpResponse::Ok().json(BaseResp {
        status: SUCC.to_string(),
        error_code: "".to_string(),
        error_msg: "".to_string()
    })
}

fn json_resp<S: Serialize2>(resp: S) -> HttpResponse {
    HttpResponse::Ok().json(resp)
}


/// AppState includes:
/// enclave instance, db_pool instance and config instance
/// It is Passed to every request handler
#[derive(Debug)]
pub struct AppState {
    pub enclave: SgxEnclave,
    pub rsa_pub_key: RSAPublicKey,
    pub thread_pool: rayon::ThreadPool,
    pub db_pool: Pool,
    pub clients: Vec<Client>,
    pub env: Env,
    // pub conf: HashMap<String, String>
}

/// Exchange Key Request includes a user public key for secure channel
#[derive(Deserialize)]
pub struct ExchangeKeyReq {
    client_id: String,
    key: String
}

/// Exchange key Response returns tee public key
#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeKeyResp {
    status: String,
    key: String,
    session_id: String
}

fn sgx_success(t: sgx_status_t) -> bool {
    t == sgx_status_t::SGX_SUCCESS
}

/* Exchange key function takes exchange key req from user as user pub key,
   and return exchange key resp as tee pub key.
   Browser accept pub key format as 04 + hex of pub key,
   while tee accept pub key format as [u8;64].
   Remove 04 before send to tee and add 04 before send to browser.
*/
#[post("/exchange_key")]
pub async fn exchange_key(
    req: web::Json<ExchangeKeyReq>,
    http_req: HttpRequest,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>    
) ->  impl Responder {
    info!("exchange key with {}", &req.key);
    let e = &endex.enclave;
    let pool = &endex.thread_pool;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    // remove 04 from pub key
    if get_client_name(
        &endex.clients, &req.client_id, &http_req.headers(), &endex.env
    ).is_none() {
        info!("client id not found");
        return fail_resp(DAuthError::ClientError);
    }
    let user_key_r = hex::decode(&req.key[2..]);
    if user_key_r.is_err() {
        info!("user pub key invalid");
        return fail_resp(DAuthError::DataError);
    }
    let user_key: [u8;64] = user_key_r.unwrap().try_into().unwrap();
    let mut out_key: [u8;64] = [0; 64];
    let mut session_id: [u8;32] = [0;32];
    let result = pool.install(|| {
        unsafe {
            ecall::ec_key_exchange(
                e.geteid(), 
                &mut sgx_result, 
                &user_key,
                &mut out_key,
                &mut session_id
            )
        }
    });
    if !sgx_success(result) {
        error!("unsafe call failed.");
        return fail_resp(DAuthError::SgxError);
    }
    if !sgx_success(sgx_result) {
        error!("sgx return error.");
        return fail_resp(DAuthError::SgxError);
    }
    let out_key_hex = hex::encode(&out_key);
    let session_id_hex = hex::encode(&session_id);
    info!("exchange key from sgx {} {}", &out_key_hex, &session_id_hex);
    sessions.register_session(&session_id_hex);
    json_resp(ExchangeKeyResp {
        status: SUCC.to_string(),
        key: format!("04{}", out_key_hex),  // add 04 before send to browser
        session_id: session_id_hex
    })
}


#[derive(Deserialize)]
pub struct AuthOtpReq {
    client_id: String,
    session_id: String,
    cipher_account: String,
    account_type: String,
    request_id: Option<String>
}

struct CipherContent {
    content: String,
}

impl CipherContent {
    fn from_str(content: String) -> Self {
        Self {
            content
        }
    }
    fn as_bytes(&self) -> GenericResult<Vec<u8>> {
        match hex::decode(&self.content) {
            Ok(b) => Ok(b),
            Err(e) => Err(e.into())
        }
    }
}

struct SealContent {
    content: String,
}

impl SealContent {
    fn new(content: String) -> Self {
        Self {
            content
        }
    }
    fn as_hex(&self) -> GenericResult<Vec<u8>> {
        match hex::decode(&self.content) {
            Ok(b) => Ok(b),
            Err(e) => Err(e.into())
        }
    }
}


// with BaseResp
#[post("/auth_otp")]
pub async fn auth_otp(
    req: web::Json<AuthOtpReq>,
    http_req: HttpRequest,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>
) -> HttpResponse {
    info!("auth email with session_id {}", &req.session_id);
    // validate client
    let client_name = get_client_name(
        &endex.clients, 
        &req.client_id,
        &http_req.headers(),
        &endex.env
    );
    if client_name.is_none() {
        return fail_resp(DAuthError::ClientError);
    }
    if !validate_session(&sessions, &req.session_id) {
        close_ec_session(endex.enclave.geteid(), &req.session_id);
        return fail_resp(DAuthError::SessionError);
    }
    let session_id_b: [u8;32] = hex::decode(&req.session_id).unwrap().try_into().unwrap();

    let c_channel = CipherContent {
        content: req.cipher_account.clone(),
    };
    let c_channel_b = match c_channel.as_bytes() {
        Ok(b) => b,
        Err(e) => {
            error!("cipher channel decode error: {}", e);
            return fail_resp(DAuthError::DataError);
        }
    };
    let auth_type = AuthType::from_str(&req.account_type);
    if auth_type.is_none() {
        return fail_resp(DAuthError::DataError);
    }
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    // sendmail
    let pool = &endex.thread_pool;
    let result = pool.install(|| {
        unsafe {
            ecall::ec_send_otp(
                endex.enclave.geteid(), 
                &mut sgx_result, 
                auth_type.unwrap() as i32,
                &session_id_b,
                c_channel_b.as_ptr() as *const u8,
                c_channel_b.len(),
            )
        }
    }); 
    if !sgx_success(result) {
        error!("unsafe call failed.");
        return fail_resp(DAuthError::SgxError);
    }
    info!("sgx result {}", &sgx_result);
    match sgx_result {
        sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => {
            return fail_resp(DAuthError::SessionError);
        },
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => {
            return fail_resp(DAuthError::DataError);
        },
        sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE => {
            return fail_resp(DAuthError::SendChannelError);
        },
        sgx_status_t::SGX_SUCCESS => {
            return succ_resp();
        },
        _ => {
            error!("sgx return unknown error {}", sgx_result);
            return fail_resp(DAuthError::SgxError);
        },
    }
}

#[derive(Deserialize)]
pub struct AuthOtpConfirmReq {
    client_id: String,
    session_id: String,
    cipher_code: String,
    request_id: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthSuccessResp {
    status: String,
    cipher_dauth: String
}

#[post("/auth_otp_confirm")]
pub async fn auth_otp_confirm(
    req: web::Json<AuthOtpConfirmReq>,
    http_req: HttpRequest,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>
) -> HttpResponse {
    info!("register mail confirm with session_id {}", &req.session_id);
    // validate client
    let client_name = get_client_name(
        &endex.clients, 
        &req.client_id,
        &http_req.headers(),
        &endex.env
    );
    if client_name.is_none() {
        return fail_resp(DAuthError::ClientError);
    }
    // verify session_id
    if !validate_session(&sessions, &req.session_id) {
        close_ec_session(endex.enclave.geteid(), &req.session_id);
        return fail_resp(DAuthError::SessionError);
    }
    let session_id_b: [u8;32] = hex::decode(&req.session_id).unwrap().try_into().unwrap();
    let c_code = CipherContent {
        content: req.cipher_code.clone(),
    };
    let c_code_b = match c_code.as_bytes() {
        Ok(b) => b,
        Err(e) => {
            error!("cipher code decode error: {}", e);
            return fail_resp(DAuthError::DataError);
        }
    };
    let request_id = match req.request_id {
        Some(ref r) => r.clone(),
        None => "None".to_string(),
    };
    let request_id_b = request_id.as_bytes();

    let e = &endex.enclave;
    let pool = &endex.thread_pool;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    const max_len: usize = 512;
    let mut account_b = [0_u8;max_len];
    let mut account_b_size = 0;
    let mut cipher_dauth = [0_u8;max_len];
    let mut cipher_dauth_size = 0;
    let result = pool.install(|| {
        unsafe {
            ecall::ec_confirm_otp(
                e.geteid(), 
                &mut sgx_result, 
                &session_id_b,
                c_code_b.as_ptr() as *const u8,
                c_code_b.len(),
                request_id_b.as_ptr() as *const u8,
                request_id_b.len(),
                account_b.as_ptr() as *mut u8,
                max_len,
                &mut account_b_size,
                cipher_dauth.as_ptr() as *mut u8,
                &mut cipher_dauth_size,
            )
        }
    });
    if !sgx_success(result) {
        error!("unsafe call failed.");
        return fail_resp(DAuthError::SgxError);
    }
    match sgx_result {
        sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => {
            return fail_resp(DAuthError::SessionError);
        },
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => {
            return fail_resp(DAuthError::DataError);
        },
        sgx_status_t::SGX_SUCCESS => {
            info!("confirm mail success");
        },
        _ => {
            error!("sgx return unknown error {}", sgx_result);
            return fail_resp(DAuthError::SgxError);
        },
    }
    let account_slice = &account_b[0..account_b_size];
    let account = serde_json::from_slice(account_slice).unwrap();
    let dauth_slice = &cipher_dauth[0..cipher_dauth_size];
    info!("dauth slice {:?}", &dauth_slice);
    info!("dauth size {}", cipher_dauth_size);
    let insert_r = insert_account_if_new(&endex.db_pool, &account);
    if insert_r.is_err() {
        error!("insert account error {}", insert_r.err().unwrap());
        return fail_resp(DAuthError::DbError);
    }
    let auth = Auth::new(&account, client_name.unwrap(), request_id);
    let insert_auth_r = insert_auth(&endex.db_pool, auth);
    if insert_auth_r.is_err() {
        error!("insert auth error {}", insert_auth_r.err().unwrap());
        return fail_resp(DAuthError::DbError);
    }
    json_resp(
        AuthSuccessResp{
            status: SUCC.to_string(),
            cipher_dauth: hex::encode(dauth_slice)
        }
    )
}


#[derive(Debug, Serialize, Deserialize)]
pub struct AuthOauthReq {
    client_id: String,
    session_id: String,
    cipher_code: String,
    auth_type: String,
    request_id: Option<String>
}


#[post("/auth_oauth")]
pub async fn auth_oauth(
    req: web::Json<AuthOauthReq>,
    http_req: HttpRequest,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>
) -> HttpResponse {
    info!("github oauth with session_id {}", &req.session_id);
    // validate client
    let client_name = get_client_name(
        &endex.clients, 
        &req.client_id,
        &http_req.headers(),
        &endex.env
    );
    if client_name.is_none() {
        return fail_resp(DAuthError::ClientError);
    }
    // verify session_id
    if !validate_session(&sessions, &req.session_id) {
        close_ec_session(endex.enclave.geteid(), &req.session_id);
        return fail_resp(DAuthError::SessionError);
    }
    // validate auth_type
    let auth_type_r = AuthType::from_str(&req.auth_type);
    if auth_type_r.is_none() {
        return fail_resp(DAuthError::DataError);
    }
    let request_id = match req.request_id {
        Some(ref r) => r.clone(),
        None => "None".to_string(),
    };
    let request_id_b = request_id.as_bytes();

    let session_id_b: [u8;32] = hex::decode(&req.session_id).unwrap().try_into().unwrap();
    let e = &endex.enclave;
    let pool = &endex.thread_pool;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    let auth_type = auth_type_r.unwrap();
    let code_b = hex::decode(&req.cipher_code).unwrap();

    let mut account_b = [0_u8;1024];
    let mut account_b_size = 0;
    let mut cipher_dauth = [0_u8;1024];
    let mut cipher_dauth_size = 0;

    let result = pool.install(|| {
        unsafe {
            ecall::ec_auth_oauth(
                e.geteid(), 
                &mut sgx_result, 
                &session_id_b,
                code_b.as_ptr() as *const u8,
                code_b.len(),
                request_id_b.as_ptr() as *const u8,
                request_id_b.len(),
                auth_type as i32,
                account_b.as_ptr() as *mut u8,
                1024,
                &mut account_b_size,
                cipher_dauth.as_ptr() as *mut u8,
                &mut cipher_dauth_size,
            )
        }
    });
    info!("unsafe result is {:?}", &result);
    if result != sgx_status_t::SGX_SUCCESS {
        return fail_resp(DAuthError::SgxError);
    }
    info!("sgx result is {:?}", &sgx_result);
    match sgx_result {
        sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => {
            error!("sgx session error");
            return fail_resp(DAuthError::SessionError);
        }
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => {
            error!("decrypt authorization code failed");
            return fail_resp(DAuthError::OAuthCodeError);
        },
        sgx_status_t::SGX_ERROR_INVALID_FUNCTION => {
            error!("oauth failed");
            return fail_resp(DAuthError::OAuthProfileError);
        },
        sgx_status_t::SGX_SUCCESS => {
            info!("oauth succeed");
        },
        _ => {
            error!("sgx failed.");
            return fail_resp(DAuthError::SgxError);
        },
    }
    let account_slice = &account_b[0..account_b_size];
    let account = serde_json::from_slice(account_slice).unwrap();
    let dauth_slice = &cipher_dauth[0..cipher_dauth_size];
    let insert_r = insert_account_if_new(&endex.db_pool, &account);
    if insert_r.is_err() {
        error!("insert account error {}", insert_r.err().unwrap());
        return fail_resp(DAuthError::DbError);
    }
    let auth = Auth::new(&account, client_name.unwrap(), request_id);
    let insert_auth_r = insert_auth(&endex.db_pool, auth);
    if insert_auth_r.is_err() {
        error!("insert auth error {}", insert_auth_r.err().unwrap());
        return fail_resp(DAuthError::DbError);
    }
    json_resp(
        AuthSuccessResp{
            status: SUCC.to_string(),
            cipher_dauth: hex::encode(dauth_slice)
        }
    )
}


#[get("/health")]
pub async fn health(endex: web::Data<AppState>) -> impl Responder {
    // for health check
    info!("dauth sdk is up and running");
    HttpResponse::Ok().body("dauth sdk is up and running!")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResp {
    keys: Vec<RSAPublicKey>
}

/* 
#[get("/jwks.json")]
pub async fn jwks(endex: web::Data<AppState>) -> impl Responder {
    // for health check
    info!("get rsa pub key");
    let pub_key = endex.rsa_pub_key.clone();
    json_resp(JwksResp {
        keys: vec![pub_key]
    })
}
*/

fn close_ec_session(eid: sgx_enclave_id_t, session_id: &str) {
    let session_id_b_r = hex::decode(session_id);
    if session_id_b_r.is_err() {
        error!("session id invalid");
        return;
    }
    let session_id_b = session_id_b_r.unwrap().try_into().unwrap();
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    unsafe {
        ecall::ec_close_session(
            eid,
            &mut sgx_result,
            &session_id_b
        );
    }
}


fn get_client_name(
    clients: &Vec<Client>, 
    client_id: &str, 
    headers: &HeaderMap,
    env: &Env
) -> Option<String> {
    for client in clients {
        debug!("comparing {}", &client.client_id);
        if client.client_id == client_id {
            match env {
                Env::PROD => {
                    let origin_v = headers.get(ORIGIN);
                    if origin_v.is_none() {
                        error!("origin is none");
                        return None
                    }
                    let origin = origin_v.unwrap().to_str().unwrap();
                    debug!("comparing origin {} {}",origin, client.client_origin);
                    if origin.eq(&client.client_origin) {
                        return Some(client.client_name.clone());
                    } else {
                        error!("origin not match");
                        return None;
                    }        
                }, 
                _ => {
                    return Some(client.client_name.clone());
                }
            }
        }
    }
    None
}


fn validate_session(
    sessions: &SessionState, 
    session_id: &str
) -> bool {
    // validate session
    // TODO: add a function to sessions with name validate_session
    if let None = sessions.get_session(&session_id) {
        info!("session not found");
        return false;
    }
    let session_id_r = hex::decode(&session_id);
    if session_id_r.is_err() {
        info!("decode session id failed");
        return false;
    }
    let session_r = sessions.get_session(&session_id);
    if session_r.is_none() {
        info!("session not found");
        return false;
    }
    let session = session_r.unwrap();
    if session.expire() {
        info!("session expired");
        sessions.close_session(session_id);
        return false;
    }
    return true;
}


