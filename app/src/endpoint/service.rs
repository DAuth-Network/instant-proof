extern crate openssl;
#[macro_use]
use std::str;
use serde::Serialize as Serialize2;
use serde_derive::{Deserialize, Serialize};
use actix_web::{
    get, post, web, HttpResponse, HttpRequest, Responder 
};
use log::{error, info};
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use mysql::*;
use crate::ecall;
use crate::endpoint::utils::GenericError;
use crate::persistence::*;
use crate::endpoint::utils;
use crate::endpoint::auth_token;
use crate::endpoint::oauth::*;
use std::collections::HashMap;
use crate::endpoint::session;

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


fn fail_resp(error_code: &str, error_msg: &str) -> HttpResponse {
    HttpResponse::Ok().json(BaseResp {
        status: FAIL.to_string(),
        error_code: error_code.to_string(),
        error_msg: error_msg.to_string()
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
    pub thread_pool: rayon::ThreadPool,
    pub db_pool: Pool,
    pub conf: HashMap<String, String>
}


/// Exchange Key Request includes a user public key for secure channel
#[derive(Deserialize)]
pub struct ExchangeKeyReq {
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
#[post("/dauth/exchange_key")]
pub async fn exchange_key(
    req: web::Json<ExchangeKeyReq>,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>    
) ->  impl Responder {
    info!("exchange key with {}", &req.key);
    let e = &endex.enclave;
    let pool = &endex.thread_pool;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    // remove 04 from pub key
    let user_key: [u8;64] = hex::decode(&req.key[2..]).unwrap().try_into().unwrap();
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
        return fail_resp("SgxError", "Sgx call failed");
    }
    if !sgx_success(sgx_result) {
        error!("sgx return error.");
        return fail_resp("DataError", "unable to generate session for the public key");
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
pub struct AuthEmailReq {
    session_id: String,
    cipher_email: String,
}

// with BaseResp
#[post("/dauth/auth_email")]
pub async fn auth_email(
    req: web::Json<AuthEmailReq>,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>
) -> HttpResponse {
    info!("auth email with session_id {}", &req.session_id);
    // validate session
    // TODO: add a function to sessions with name validate_session
    if let None = sessions.get_session(&req.session_id) {
        info!("session not found");
        return fail_resp("SessionError", "session not found");
    }
    let session = sessions.get_session(&req.session_id).unwrap();
    let session_id_b: [u8;32] = hex::decode(&req.session_id).unwrap().try_into().unwrap();
    let e = &endex.enclave;
    if session.expire() {
        info!("session expired");
        sessions.close_session(&req.session_id);
        close_ec_session(e.geteid(), &session_id_b);
        return fail_resp("SessionError", "session expired");
    }

    let email_b_r = hex::decode(&req.cipher_email);
    if email_b_r.is_err() {
        info!("email decode error");
        return fail_resp("DataError", "email decode error");
    }
    let email_b = email_b_r.unwrap();
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    // sendmail
    let pool = &endex.thread_pool;
    let result = pool.install(|| {
        unsafe {
            ecall::ec_send_cipher_email(
                e.geteid(), 
                &mut sgx_result, 
                &session_id_b,
                email_b.as_ptr() as *const u8,
                email_b.len(),
            )
        }
    }); 
    if !sgx_success(result) {
        error!("unsafe call failed.");
        return fail_resp("SgxError", "sgx call failed.");
    }
    info!("sgx result {}", &sgx_result);
    match sgx_result {
        sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => {
            return fail_resp("SessionError", "session invalid");
        },
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => {
            return fail_resp("DataError", "decrypt email failed");
        },
        sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE => {
            return fail_resp("SendmailError", "sendmail failed");
        },
        sgx_status_t::SGX_SUCCESS => {
            return succ_resp();
        },
        _ => {
            error!("sgx return unknown error {}", sgx_result);
            return fail_resp("SgxError", "sgx call failed");
        },
    }
}

#[derive(Deserialize)]
pub struct AuthEmailConfirmReq {
    session_id: String,
    cipher_code: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthSuccessResp {
    status: String,
    cipher_token: String
}

#[post("/dauth/auth_email_confirm")]
pub async fn auth_email_confirm(
    req: web::Json<AuthEmailConfirmReq>,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>
) -> HttpResponse {
    info!("register mail confirm with session_id {}", &req.session_id);
    // verify session_id
    if let None = sessions.get_session(&req.session_id) {
        info!("session not found");
        return fail_resp("SessionError", "session not found");
    }

    let session = sessions.get_session(&req.session_id).unwrap();
    let session_id_b: [u8;32] = hex::decode(&req.session_id).unwrap().try_into().unwrap();
    let e = &endex.enclave;
    let pool = &endex.thread_pool;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    if session.expire() {
        info!("session expired");
        sessions.close_session(&req.session_id);
        close_ec_session(e.geteid(), &session_id_b);
        return fail_resp("SessionError", "session expired");
    }

    let code_b = hex::decode(&req.cipher_code).unwrap();
    let mut email_hash = [0_u8;32];
    let mut email_seal = [0_u8;1024];
    let mut email_size = 0;
    let result = pool.install(|| {
        unsafe {
            ecall::ec_confirm_email(
                e.geteid(), 
                &mut sgx_result, 
                &session_id_b,
                code_b.as_ptr() as *const u8,
                code_b.len(),
                &mut email_hash,
                &mut email_seal,
                &mut email_size,
            )
        }
    });
    if !sgx_success(result) {
        error!("unsafe call failed.");
        return fail_resp("SgxError", "sgx call failed");
    }
    match sgx_result {
        sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => {
            return fail_resp("SessionError", "session invalid");
        },
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => {
            return fail_resp("DataError", "decrypt code failed or code not match");
        },
        sgx_status_t::SGX_SUCCESS => {
            info!("confirm mail success");
        },
        _ => {
            error!("sgx return unknown error {}", sgx_result);
            return fail_resp("SgxError", "sgx call failed");
        },
    }
    let email_hash_hex = hex::encode(email_hash);
    let size: usize = email_size.try_into().unwrap();
    let email_seal_hex = hex::encode(&email_seal[..size]);
    // after confirm mail success, if new email, insert_mail
    // increase auth_hist
    // return token
    let account = Account {
        acc_hash: email_hash_hex.clone(),
        acc_seal: email_seal_hex,
    };
    let insert_r = insert_account_if_new(&endex.db_pool, &account);
    if insert_r.is_err() {
        return fail_resp("DBError", "insert account failed");
    }
    let a_id = query_latest_auth_id(&endex.db_pool, &account.acc_hash);
    let next_id = a_id + 1;
    let auth =  Auth {
        acc_hash: email_hash_hex.clone(),
        auth_id: next_id,
        auth_type: AuthType::Email,
        auth_datetime: utils::now_datetime().unwrap(),
        auth_exp: utils::system_time() + 3600,
    };
    let token_r = sign_auth_jwt(
        e.geteid(), pool, &session_id_b ,&auth);
    if token_r.is_err() {
        return fail_resp("SGXError", "sign auth failed");
    }
    let token = token_r.unwrap();
    insert_auth(&endex.db_pool, auth);
    json_resp(
        AuthSuccessResp{
            status: SUCC.to_string(),
            cipher_token: token
        }
    )
}


#[derive(Debug, Serialize, Deserialize)]
pub struct AuthOauthReq {
    session_id: String,
    cipher_code: String,
    oauth_type: String
}


#[post("/dauth/auth_oauth")]
pub async fn auth_oauth(
    req: web::Json<AuthOauthReq>,
    http_req: HttpRequest,
    endex: web::Data<AppState>,
    sessions: web::Data<session::SessionState>
) -> HttpResponse {
    info!("github oauth with session_id {}", &req.session_id);
    // verify session_id
    if let None = sessions.get_session(&req.session_id) {
        info!("session not found");
        return fail_resp("DataError", "session not found");
    }

    let session = sessions.get_session(&req.session_id).unwrap();
    let session_id_b: [u8;32] = hex::decode(&req.session_id).unwrap().try_into().unwrap();
    let e = &endex.enclave;
    let pool = &endex.thread_pool;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    if session.expire() {
        info!("session expired");
        sessions.close_session(&req.session_id);
        close_ec_session(e.geteid(), &session_id_b);
        return fail_resp("DataError", "session expired");
    }
    let auth_type_r = AuthType::from_str(&req.oauth_type);
    if auth_type_r.is_none() {
        return fail_resp("ReqError", "oauth type not found");
    }
    let auth_type = auth_type_r.unwrap();
    let code_b = hex::decode(&req.cipher_code).unwrap();
    let mut acc_hash = [0_u8;32];
    let mut acc_seal = [0_u8;1024];
    let mut acc_seal_size = 0;

    let result = unsafe {
        ecall::ec_auth_oauth(
            e.geteid(), 
            &mut sgx_result, 
            &session_id_b,
            code_b.as_ptr() as *const u8,
            code_b.len(),
            auth_type as i32,
            &mut acc_hash,
            &mut acc_seal,
            &mut acc_seal_size
        )
    };
    info!("unsafe result is {:?}", &result);
    if result != sgx_status_t::SGX_SUCCESS {
        return fail_resp("SGXError", "");
    }
    info!("sgx result is {:?}", &sgx_result);
    match sgx_result {
        sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => {
            error!("sgx session error");
            return fail_resp("SessionError", "sgx session not found");
        }
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => {
            error!("decrypt authorization code failed");
            return fail_resp("DataError", "authorization code invalid");
        },
        sgx_status_t::SGX_ERROR_INVALID_FUNCTION => {
            error!("oauth failed");
            return fail_resp("OauthError", "oauth failed");
        },
        sgx_status_t::SGX_SUCCESS => {
            info!("oauth succeed");
        },
        _ => {
            error!("sgx failed.");
            return fail_resp("SgxError", "");
        },
    }
    let auth_hash_hex = hex::encode(acc_hash);
    let size: usize = acc_seal_size.try_into().unwrap();
    let auth_seal_hex = hex::encode(&acc_seal[..size]);
    // after oauth success, if new oauth, update, else do nothing
    // insert auth
    let auth_account = Account {
        acc_hash: auth_hash_hex.clone(),
        acc_seal: auth_seal_hex,
    };
    let result = insert_account_if_new(&endex.db_pool, &auth_account);
    if result.is_err() {
        error!("insert account failed");
        return fail_resp("DBError", "insert account failed");
    }
    let a_id = query_latest_auth_id(&endex.db_pool, &auth_hash_hex);
    let next_id = a_id + 1;
    let auth = Auth {
        acc_hash: auth_hash_hex.clone(),
        auth_id: next_id,
        auth_type: auth_type,        
        auth_datetime: utils::now_datetime().unwrap(),
        auth_exp: utils::system_time() + 3600,
    };
    let token_r = sign_auth_jwt(
        e.geteid(), pool, &session_id_b, &auth);
    if token_r.is_err() {
        return fail_resp("SgxError", "sign auth failed");
    }
    let token = token_r.unwrap();
    insert_auth(&endex.db_pool, auth);
    json_resp(AuthSuccessResp{
        status: SUCC.to_string(),
        cipher_token: token
    })
}


fn sign_auth_jwt(
    eid: sgx_enclave_id_t, 
    pool: &rayon::ThreadPool, 
    session_id: &[u8;32],
    auth: &Auth
) -> utils::GenericResult<String> {
    info!("sign auth for {:?} {} times", &auth.acc_hash, &auth.auth_id);
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    let hash_b = hex::decode(&auth.acc_hash).unwrap().try_into().unwrap();
    let mut token: [u8;1024] = [0_u8;1024];
    let mut token_size = 0;
    let result = pool.install(|| {
        unsafe {
            ecall::ec_sign_auth_jwt(
                eid,
                &mut sgx_result,
                session_id,
                &hash_b,
                auth.auth_id,
                auth.auth_exp,
                &mut token,
                &mut token_size
            )
        }
    }); 
    match result {
        sgx_status_t::SGX_SUCCESS => {
            let size: usize = token_size.try_into().unwrap();
            let token_s = hex::encode(&token[..size]);
            Ok(token_s)
        },
        _ => {
            error!("sgx failed.");
            Err(GenericError::from("ec_auth_sign failed"))
        }
    }

}


fn close_ec_session(eid: sgx_enclave_id_t, session_id_b: &[u8;32]) {
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    unsafe {
        ecall::ec_close_session(
            eid,
            &mut sgx_result,
            &session_id_b
        );
    }
}


#[get("/dauth/health")]
pub async fn health(endex: web::Data<AppState>) -> impl Responder {
    // for health check
    HttpResponse::Ok().body("Webapp is up and running!")
}


