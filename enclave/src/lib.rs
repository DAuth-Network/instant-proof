#![crate_name = "enclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tseal;
extern crate tiny_keccak;
extern crate libsecp256k1;
extern crate jsonwebtoken;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate serde;
extern crate serde_json;
extern crate http_req;
extern crate sgx_rand;

#[macro_use]
extern crate serde_cbor;

#[cfg(target_env = "sgx")]
extern crate sgx_tseal;


use std::convert::TryInto;
use config::*;
use http_req::uri::Authority;
use jsonwebtoken::crypto::sign;
use serde::{Deserialize, Serialize};
use sgx_trts::enclave;
use sgx_types::*;
use sgx_tcrypto::*;

use std::mem::MaybeUninit;
use std::slice;
use std::sync::{Once, SgxMutex};

use std::ffi::CStr;
use std::os::raw::c_char;

use std::string::{String, ToString};
//use std::backtrace::{self, PrintFormat};
// use std::prelude::v1::*;
use std::str;
use std::vec::Vec;
use std::ptr;

pub mod sgx_utils;
pub mod os_utils;
pub mod err;
pub mod session;
pub mod web3;
pub mod config;
pub mod oauth;
pub mod log;
pub mod sms;
pub mod model;

use self::err::*;
use self::session::*;
use self::log::*;
use self::model::*;
use oauth::*;
use libsecp256k1::{SecretKey, PublicKey};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};


// EnclaveState includes session state that constatntly changes
struct EnclaveState {
    sessions: Sessions,
    pub_k_r1: [u8;64],
    pub_k_k1: [u8;65],
}

// EnclaveConfig includes config set once and never changes
struct EnclaveConfig {
    pub config: TeeConfig,
}

// Rust doesn't support mutable statics, as it could lead to bugs in a multithreading setting
// and it cannot prevent this. So we need to use a mutex even if we have one thread
struct StateReader {
    inner: SgxMutex<EnclaveState>,
}

struct ConfigReader {
    inner: SgxMutex<EnclaveConfig>,
}

fn state() -> &'static StateReader {
    // Create an uninitialized static
    static mut SINGLETON: MaybeUninit<StateReader> = MaybeUninit::uninit();
    static ONCE: Once = Once::new();
    unsafe {
        ONCE.call_once(|| {
            // gen secp256r1 keypair
            let ecc_handle = SgxEccHandle::new();
            let _result = ecc_handle.open();
            let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();
            // gen secp256k1 keypair
            let prv_k1 = SecretKey::parse(&prv_k.r).unwrap();
            let pub_k1 = PublicKey::from_secret_key(&prv_k1);

            let singleton = StateReader {
                inner: SgxMutex::new(EnclaveState {
                    sessions: Sessions::new(prv_k),
                    pub_k_r1: sgx_utils::key_to_bigendian(&pub_k),
                    pub_k_k1: pub_k1.serialize(),
                }),
            };
            // Store it to the static var, i.e. initialize it
            SINGLETON.write(singleton);
        });
        // Now we give out a shared reference to the data, which is safe to use
        // concurrently.
        SINGLETON.assume_init_ref()
    }
}

fn config() -> &'static ConfigReader {
    // Create an uninitialized static
    static mut SINGLETON: MaybeUninit<ConfigReader> = MaybeUninit::uninit();
    static ONCE: Once = Once::new();
    unsafe {
        ONCE.call_once(|| {
            let singleton = ConfigReader {
                inner: SgxMutex::new(EnclaveConfig {
                    config: TeeConfig::default(),
                }),
            };
            // Store it to the static var, i.e. initialize it
            SINGLETON.write(singleton);
        });
        // Now we give out a shared reference to the data, which is safe to use
        // concurrently.
        SINGLETON.assume_init_ref()
    }
}

#[no_mangle]
pub extern "C" fn ec_key_exchange(
    user_key: *const u8,
    tee_key: &mut [u8;64],
    session_id: &mut [u8;32],
) -> sgx_status_t {
    // set tee_key
    let user_key_slice = unsafe { slice::from_raw_parts(user_key, 64) };
    let pub_k_r1 = get_pub_k_r1();
    info(&format!("user pub key {:?}", &user_key_slice));
    info(&format!("tee pub key {:?}", &pub_k_r1));
    let sid = register_session(user_key_slice);
    *tee_key = pub_k_r1;
    *session_id = sid.try_into().unwrap();
    if sid == [0;32] {
        // unable to calculate share key for the given public key
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE
    } else {
        sgx_status_t::SGX_SUCCESS
    }
}

fn get_pub_k_r1() -> [u8;64] {
    let state = state().inner.lock().unwrap();
    state.pub_k_r1.clone()
}


#[no_mangle]
pub extern "C" fn ec_set_conf(
    config_b: *const u8,
    config_b_size: usize
) -> sgx_status_t {
    let config_slice = unsafe { slice::from_raw_parts(config_b, config_b_size) };
    let new_config = serde_json::from_slice(config_slice).unwrap();
    info(&format!("sgx config {:?}", &new_config));
    config().inner.lock().unwrap().config = new_config;
    sgx_status_t::SGX_SUCCESS
}

/*
  ec_register_email decrypts cipher_email and cipher_account,
  1, generate a random 6 digits, bind with user session
  2, send the digits to user email
 */
#[no_mangle]
pub extern "C" fn ec_send_otp(
    auth_type_i: i32,
    session_id: &[u8;32],
    cipher_channel: *const u8,
    cipher_channel_size: usize,
) -> sgx_status_t {
    info("sgx send otp");
    let channel_slice = unsafe { 
        slice::from_raw_parts(cipher_channel, cipher_channel_size as usize) 
    };
    let session_r = get_session(session_id);
    if session_r.is_none() {
        error(&format!("sgx session {:?} not found.", session_id));
        return sgx_status_t::SGX_ERROR_AE_SESSION_INVALID;
    }
    let mut session = session_r.unwrap();
    let channel_bytes_r = session.decrypt(channel_slice);
    if channel_bytes_r.is_err() {
        error("decrypt email failed");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    let channel_bytes = channel_bytes_r.unwrap();
    let channel = match str::from_utf8(&channel_bytes) {
        Ok(r) => r,
        Err(_) => {
            info("decrypt bytes to str failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    info(&format!("channel is {}", channel));
    let otp = sgx_utils::rand();
    //TODO: sendmail error
    let auth_type = AuthType::from_int(auth_type_i).unwrap();
    session.code = otp.to_string();
    let inner_account = InnerAccount {
        account: channel.to_string(),
        auth_type: auth_type,
    };
    session.data = inner_account.to_str();
    update_session(&session_id, &session);
    let send_r = match auth_type {
        AuthType::Email => os_utils::sendmail(
            &get_config_email(), 
            &channel, 
            &otp.to_string()),
        AuthType::Sms => sms::sendsms(
            &get_config_sms(), 
            &channel, 
            &otp.to_string()),
        _ => {
            error("invalid auth type");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    if send_r.is_err() {
        error("send otp failed");
        return sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE;
    }
    sgx_status_t::SGX_SUCCESS
}

fn get_config_email() -> Email {
    let conf = config().inner.lock().unwrap();
    conf.config.email.clone()
}

fn get_config_sms() -> Sms {
    let conf = config().inner.lock().unwrap();
    conf.config.sms.clone()
}

#[no_mangle]
pub extern "C" fn ec_confirm_otp(
    session_id: &[u8;32],
    cipher_code: *const u8,
    code_size: usize,
    request_id: *const u8,
    request_id_size: usize,
    account_b: *mut u8,
    max_len: u32,
    account_b_size: *mut u32,
    signature: &mut[u8;65]
) -> sgx_status_t {
    let request_id_slice = unsafe { slice::from_raw_parts(request_id, request_id_size) };
    let request_id = match str::from_utf8(&request_id_slice) {
        Ok(r) => r,
        Err(_) => {
            error("get request id failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    // set tee_key
    let session_r = get_session(session_id);
    if session_r.is_none() {
        return sgx_status_t::SGX_ERROR_AE_SESSION_INVALID;
    }
    let session = session_r.unwrap();

    let code_slice = unsafe { slice::from_raw_parts(cipher_code, code_size) };
    info(&format!("code {:?}", &code_slice));
    let code_bytes_r = session.decrypt(code_slice);
    if code_bytes_r.is_err() {
        error("decrypt code failed");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    let code_bytes = code_bytes_r.unwrap();
    let code = match str::from_utf8(&code_bytes) {
        Ok(r) => r,
        Err(_) => {
            error("decrypt bytes to str failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    info(&format!("code is {}", &code));
    info(&format!("session code is {}", &session.code));
    if !code.eq(&session.code) {
        info("confirm code not match, returning");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    //when code input equals to code sent, seal and hash account and sign
    let inner_account = match InnerAccount::from_str(&session.data) {
        Some(r) => r,
        None => {
            error("invalid inner account");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    let sealed_r = sgx_utils::i_seal(
        inner_account.account.as_bytes(),
        &get_config_seal_key()
    );
    let sealed = match sealed_r {
        Ok(r) => r,
        Err(_) => {
            error("seal account failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    let sealed_len = sealed.len();
    let raw_hashed = sgx_utils::hash(inner_account.account.as_bytes()).unwrap();
    info(&format!("account seal {:?}", sealed));
    info(&format!("account hash {:?}", raw_hashed));
    let account = Account {
        auth_type: inner_account.auth_type,
        acc_seal: os_utils::encode_hex(&sealed),
        acc_hash: os_utils::encode_hex(&raw_hashed),
    };
    let auth = format!("{}/{}/{}",
        &account.acc_hash,
        &request_id,
        &account.auth_type.to_string());
    let signature_sgx = web3::eth_sign(&auth, get_prv_k());
    let account_sgx = serde_json::to_vec(&account).unwrap();
    if account_sgx.len() > max_len as usize {
        error("account too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    unsafe {
        ptr::copy_nonoverlapping(
            account_sgx.as_ptr(), 
            account_b, 
            account_sgx.len());
        *account_b_size = account_sgx.len().try_into().unwrap();
    }
    *signature = signature_sgx.try_into().unwrap();
    sgx_status_t::SGX_SUCCESS
}

fn get_config_seal_key() -> String {
    let conf = config().inner.lock().unwrap();
    conf.config.seal_key.clone()
}



#[no_mangle]
pub extern "C" fn ec_auth_oauth(
    session_id: &[u8;32],
    cipher_code: *const u8,
    code_size: usize,
    request_id: *const u8,
    request_id_size: usize,
    auth_type_i: i32,
    account_b: *mut u8,
    max_len: u32,
    account_b_size: *mut u32,
    signature: &mut[u8;65]
) -> sgx_status_t {
    let request_id_slice = unsafe { slice::from_raw_parts(request_id, request_id_size) };
    let request_id = match str::from_utf8(&request_id_slice) {
        Ok(r) => r,
        Err(_) => {
            error("get request id failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    // verify session and decrypt code
    let code_slice = unsafe { slice::from_raw_parts(cipher_code, code_size) };
    info(&format!("code {:?}", &code_slice));
    // set tee_key
    let session_r = get_session(session_id);
    if session_r.is_none() {
        return sgx_status_t::SGX_ERROR_AE_SESSION_INVALID;
    }
    let session = session_r.unwrap();
    let code_bytes_r = session.decrypt(code_slice);
    if code_bytes_r.is_err() {
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    let code_bytes = code_bytes_r.unwrap();
    let code = match str::from_utf8(&code_bytes) {
        Ok(r) => r,
        Err(_) => {
            error("decrypt bytes to str failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    info(&format!("oauth code is {}", &code));
    let auth_type = AuthType::from_int(auth_type_i).unwrap();
    let oauth_result = match auth_type {
        AuthType::Google => google_oauth(&get_config_oauth().google, code),
        /* 
        2 => twitter_oauth(&enclave_state.config, code),
        3 => discord_oauth(&enclave_state.config, code),
        4 => telegram_oauth(&enclave_state.config, code),
        */
        AuthType::Github => github_oauth(&get_config_oauth().github, code),
        _ => Err(GenericError::from("error type"))
    };
    if oauth_result.is_err() {
        return sgx_status_t::SGX_ERROR_INVALID_FUNCTION;
    }
    let auth_account = oauth_result.unwrap();
    info(&format!("auth account is {}", &auth_account));
    let sealed_r = sgx_utils::i_seal(
        auth_account.as_bytes(),
        &get_config_seal_key()
    );
    let sealed = match sealed_r {
        Ok(r) => r,
        Err(_) => {
            error("seal oauth failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    let sealed_len = sealed.len();
    let raw_hashed = sgx_utils::hash(auth_account.as_bytes()).unwrap();
    let account = Account {
        auth_type: auth_type,
        acc_seal: os_utils::encode_hex(&sealed),
        acc_hash: os_utils::encode_hex(&raw_hashed),
    };
    let auth = format!("{}/{}/{}",
        &account.acc_hash,
        &request_id,
        &account.auth_type.to_string());
    let signature_sgx = web3::eth_sign(&auth, get_prv_k());
    let account_sgx = serde_json::to_vec(&account).unwrap();
    if account_sgx.len() > max_len as usize {
        error("account too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    unsafe {
        ptr::copy_nonoverlapping(
            account_sgx.as_ptr(), 
            account_b, 
            account_sgx.len());
        *account_b_size = account_sgx.len().try_into().unwrap();
    }
    *signature = signature_sgx.try_into().unwrap();
    sgx_status_t::SGX_SUCCESS
}

fn get_config_oauth() -> OAuth {
    let conf = config().inner.lock().unwrap();
    conf.config.oauth.clone()
}

#[no_mangle]
pub extern "C" fn ec_sign_auth(
    auth_hash: &[u8;32],
    auth_id: i32,
    exp: u64,
    pub_k: &mut [u8;65],
    signature: &mut [u8;65]
) -> sgx_status_t {
    info(&format!("sign with hash {:?} and seq {}", auth_hash, auth_id));
    let prv_k: sgx_ec256_private_t = get_prv_k();
    let pub_k_k1 = get_pub_k_k1();
    let msg_sha = web3::gen_auth_bytes(
        &pub_k_k1, 
        auth_hash, 
        auth_id,
        exp);
    // info(format!("message is {:?}", &v);
    let private_key = libsecp256k1::SecretKey::parse_slice(&prv_k.r).unwrap();
    let message = libsecp256k1::Message::parse_slice(&msg_sha).unwrap();
    let (sig, r_id) = libsecp256k1::sign(&message, &private_key);
    let last_byte = r_id.serialize() + 27;
    let mut sig_buffer: Vec<u8> = Vec::with_capacity(65);
    sig_buffer.extend_from_slice(&sig.serialize());
    sig_buffer.push(last_byte);
    *pub_k = pub_k_k1;
    *signature = sig_buffer.try_into().unwrap();
    //*signature = signed.try_into().unwrap();
    sgx_status_t::SGX_SUCCESS
}

fn get_pub_k_k1() -> [u8;65] {
    let enclave_state = state().inner.lock().unwrap();
    enclave_state.pub_k_k1
}

fn get_prv_k() -> sgx_ec256_private_t {
    let enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.prv_k
}

#[no_mangle]
pub extern "C" fn ec_sign_auth_jwt(
    session_id: &[u8;32],
    auth_hash: &[u8;32],
    auth_id: i32,
    exp: usize,
    request_id: *const c_char,
    token_b: &mut [u8;2048],
    token_b_size: &mut i32
) -> sgx_status_t {
    info(&format!("sign with hash {:?} and seq {}", auth_hash, auth_id));
    let session_r = get_session(session_id);
    if session_r.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    let session = session_r.unwrap();
    let acc_hash_s = os_utils::encode_hex(auth_hash);
    let request_id = unsafe { CStr::from_ptr(request_id).to_str() };
    let request_id = request_id.expect("Failed to recover hostname");
    let my_claims = Claims {
        sub: acc_hash_s,
        issuer: "dauth".to_string(),
        audience: "sample_client".to_string(),
        request_id: request_id.to_string(),
        exp: exp,
    };
    let pem_key = get_config_rsa_key();
    let pem_key_b = pem_key.as_bytes();  
    let key = EncodingKey::from_rsa_pem(pem_key_b).unwrap();
    let token = encode(
        &Header::new(Algorithm::RS256), 
        &my_claims, 
        &key
    ).unwrap();
    let cipher_token = session.encrypt(token.as_bytes());
    let len = cipher_token.len();
    info(&format!("cipher_token len: {}", len));
    let mut cipher_token_slice: [u8;2048] = [0;2048];
    for i in 0..len {
        cipher_token_slice[i] = cipher_token[i];
    }
    *token_b = cipher_token_slice;
    *token_b_size = len.try_into().unwrap();
    sgx_status_t::SGX_SUCCESS
}

fn get_config_rsa_key() -> String{
    config().inner.lock().unwrap().config.rsa_key.clone()
}

//TODO: get sign pub key automatically
#[no_mangle]
pub extern "C" fn ec_get_sign_pub_key(
    pub_key: &mut[u8;2048],
    pub_key_size: *mut u32
) -> sgx_status_t {
    let mut enclave_state = state().inner.lock().unwrap();
    // let pub_key_slice = enclave_state.rsa_pub_key.to_public_key_pem();
    // pkcs1::ToRsaPublicKey::to_pkcs1_pem(&pub_key_slice);
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn ec_close_session(
    session_id: &[u8;32],
) -> sgx_status_t {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.close_session(session_id);
    sgx_status_t::SGX_SUCCESS
}


pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    issuer: String,
    audience: String,
    exp: usize,
    request_id: String,
}

fn get_session(session_id: &[u8;32]) -> Option<Session> {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.get_session(session_id)
}

fn update_session(session_id: &[u8;32], session: &Session) {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.update_session(session_id, session);
}

fn register_session(user_key_slice: &[u8]) -> [u8;32] {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.register_session(
        user_key_slice.try_into().unwrap())
}

//Testing functions
#[no_mangle]
pub extern "C" fn ec_test(
) -> sgx_status_t {
    info("testing");
    let pem_key = br###"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"###;
    let my_claims = Claims {
        sub: "c4326162ae0616bf6cdeee9def166f2ed6901fe1c20c1caeb75aab11a14fccdb".to_string(),
        issuer: "dauth".to_string(),
        audience: "demo".to_string(),
        exp: 1690233226,
        request_id: "".to_string()
    };
    let key = EncodingKey::from_rsa_pem(pem_key).unwrap();
    let token = encode(
        &Header::new(Algorithm::RS256), 
        &my_claims, 
        &key
    ).unwrap();
    println!("token is {}", token);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_send_seal_email(
    session_id: &[u8;32],
    seal_email: *const u8,
    email_size: usize,
) -> sgx_status_t {
    let email_slice = unsafe { slice::from_raw_parts(seal_email, email_size as usize) };
    let mut enclave_state = state().inner.lock().unwrap();
    let session_r = enclave_state.sessions.get_session(session_id);
    if session_r.is_none() {
        error(&format!("sgx session {:?} not found.", session_id));
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    let mut session = session_r.unwrap();
    //let email_bytes = session.decrypt(email_slice);
    let email_bytes = sgx_utils::unseal(email_slice);
    let email = match str::from_utf8(&email_bytes) {
        Ok(r) => {
            r
        },
        Err(_) => {
            error("decrypt bytes to str failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    error(&format!("email is {}", email));
    let r = sgx_utils::rand();
    //TODO: sendmail error
    session.code = r.to_string();
    session.data = email.to_string();
    enclave_state.sessions.update_session(&session_id, &session);
    os_utils::sendmail(&get_config_email(), &email, &r.to_string());
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_test_seal_unseal(
) -> sgx_status_t {
    //let plain_text = "80141b0d0e96bf36bdc20473be2f274c8a65dae10d610539a228d038257a7152e99c3b93b055c80d28590dcb48edda9c63801d0ff2c5961f5ba4cf038a4b3555d31dc4bd3a8180cb7001af4db10ed1707b284f08d1a07cd2f3fa6b5d2977117633e1c95e109e9223facf1ce7c245546971f0b6fc97eb3fad9b494d6c70b861e84878b4bef2517801507df0a30048c84ebc2".as_bytes();

    let plain_text = "80".as_bytes();
    info(&format!("origin text is {:?}", plain_text));

    let (sealed, sealed_len)= sgx_utils::seal(&plain_text);
    let raw_sealed = &sealed[0..sealed_len.try_into().unwrap()];
    info(&format!("sealed content is {:?}", raw_sealed));
    //let sealed2: [u8;1024] = [4, 0, 2, 0, 0, 0, 0, 0, 72, 32, 243, 55, 106, 230, 178, 242, 3, 77, 59, 122, 75, 72, 167, 120, 11, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 170, 104, 90, 10, 215, 117, 210, 222, 215, 179, 19, 175, 198, 117, 135, 93, 120, 206, 179, 187, 199, 61, 114, 235, 213, 52, 233, 80, 195, 147, 171, 105, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 105, 41, 87, 138, 236, 184, 166, 220, 249, 66, 139, 214, 56, 173, 251, 78, 108, 143, 44, 33, 138, 91, 23, 155, 220, 94, 31, 130, 12, 83, 172, 27, 153, 219, 250, 32, 89, 120, 58, 33, 114, 70, 81, 59, 137, 119, 122, 33, 70, 150, 139, 247, 17, 21, 56, 40, 125, 234, 217, 198, 193, 60, 158, 12, 104, 57, 112, 171, 18, 237, 69, 222, 122, 242, 0, 211, 36, 64, 22, 28, 63, 151, 181, 160, 222, 245, 76, 61, 103, 177, 141, 200, 246, 194, 163, 184, 234, 28, 144, 184, 97, 147, 68, 176, 33, 128, 36, 17, 107, 196, 210, 240, 50, 179, 173, 221, 216, 232, 246, 255, 228, 179, 7, 29, 118, 108, 202, 230, 165, 203, 185, 194, 67, 1, 8, 210, 117, 251, 217, 83, 242, 93, 76, 91, 35, 228, 239, 93, 166, 181, 81, 172, 30, 138, 60, 162, 230, 59, 143, 211, 24, 249, 42, 247, 4, 149, 105, 11, 244, 129, 61, 31, 162, 174, 125, 102, 255, 7, 7, 139, 125, 63, 134, 183, 88, 208, 24, 0, 244, 237, 63, 161, 189, 170, 99, 218, 31, 178, 113, 45, 65, 190, 11, 170, 195, 55, 203, 90, 99, 64, 18, 138, 74, 50, 235, 42, 62, 248, 197, 81, 131, 216, 96, 167, 193, 103, 166, 10, 231, 152, 195, 2, 124, 29, 169, 111, 236, 49, 250, 99, 165, 161, 215, 69, 223, 93, 60, 86, 104, 41, 176, 195, 204, 237, 73, 139, 109, 221, 89, 208, 8, 246, 74, 201, 88, 63, 16, 236, 111, 59, 140, 121, 55, 171, 1, 226, 78, 236, 217, 176, 158, 83, 22, 138, 136, 213, 241, 88, 114, 19, 159, 135, 115, 106, 255, 32, 34, 56, 113, 112, 13, 179, 169, 165, 150, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let unsealed = sgx_utils::unseal(raw_sealed);
    let unsealed_txt = std::str::from_utf8(&unsealed);
    // let unsealed_txt = os_utils::encode_hex(&unsealed);
    // info(format!("{}", unsealed_txt);
    
    match unsealed_txt {
        Ok(r) => info(&format!("unsealed txt is {:?}", r)),
        Err(err) => info("unseal failed")
    }
    sgx_status_t::SGX_SUCCESS
}


// when email format incorrect, return [0_u8;32]
#[no_mangle]
pub extern "C" fn ec_calc_email_hash(
    session_id: &[u8;32],
    cipher_email: *const u8,
    cipher_email_size: usize,
    email_hash: &mut[u8;32]
) -> sgx_status_t {
    let email_slice = unsafe { slice::from_raw_parts(cipher_email, cipher_email_size as usize) };
    let mut enclave_state = state().inner.lock().unwrap();
    let session_r = enclave_state.sessions.get_session(session_id);
    if session_r.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    let mut session = session_r.unwrap();
    let email_bytes_r = session.decrypt(email_slice);
    let email_bytes = email_bytes_r.unwrap();
    let hash_r = sgx_utils::hash(&email_bytes);
    match hash_r {
        Ok(r) => {
            *email_hash = r;
            sgx_status_t::SGX_SUCCESS
        },
        Err(err) => {
            sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE
        }
    }
}

