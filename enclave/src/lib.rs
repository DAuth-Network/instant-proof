/*
This file describes all tee ecall entrance, including:
- ec_exchange_key
    - collect user public key to generate a shared key and save in user session
- ec_set_conf
    - set tee config passing from app
- ec_send_otp
    - send otp code to user email or phone
- ec_auth_in_one
    - auth in one step
- ec_auth_in_one_v1
    - backward compatible with v1.1
*/

#![crate_name = "enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
extern crate jsonwebtoken;
extern crate libsecp256k1;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tseal;
extern crate sgx_types;
extern crate tiny_keccak;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate sgx_tunittest;
extern crate base64;
extern crate bip32;
extern crate http_req;
extern crate serde;
extern crate serde_json;
extern crate sgx_rand;

#[macro_use]
extern crate serde_cbor;
#[cfg(target_env = "sgx")]
extern crate sgx_tseal;
use config::*;
use jsonwebtoken::crypto::sign;
use os_utils::{decode_hex, encode_hex};
use serde::{Deserialize, Serialize};
use sgx_tcrypto::*;
use sgx_types::*;
use std::convert::TryInto;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::slice;
use std::string::{String, ToString};
use std::sync::{Once, SgxMutex};
//use std::backtrace::{self, PrintFormat};
// use std::prelude::v1::*;
use bip32::{Prefix, XPrv};
use sgx_tunittest::*;
use std::ptr;
use std::str;
use std::vec::Vec;

pub mod auth;
pub mod config;
pub mod err;
pub mod log;
pub mod model;
pub mod oauth;
pub mod os_utils;
pub mod otp;
pub mod session;
pub mod sgx_utils;
pub mod signer;
use self::auth::*;
use self::err::*;
use self::log::*;
use self::model::*;
use self::session::*;
use libsecp256k1::{PublicKey, SecretKey};
use oauth::*;
use os_utils::*;
use sgx_utils::*;
use signer::*;

// EnclaveState includes session state that constatntly changes
struct EnclaveState {
    sessions: Sessions,
    pub_k_r1: [u8; 64],
    pub_k_k1: [u8; 65],
}

// EnclaveConfig includes config set once and never changes
struct EnclaveConfig {
    pub config: TeeConfig,
    pub dauth: AuthService,
    pub jwt: signer::JwtSignerAgent,
    pub jwt_fb: signer::JwtFbSignerAgent,
    pub proof: signer::ProofSignerAgent,
    pub proofv1: signer::ProofSignerAgentV1,
    pub both_signer: signer::BothSignerAgent,
    pub both_signerv1: signer::BothSignerAgentV1,
    pub mail: otp::MailChannelClient,
    pub mail_api: otp::MailApiChannelClient,
    pub sms: otp::SmsChannelClient,
    pub google: oauth::GoogleOAuthClient,
    pub github: oauth::GithubOAuthClient,
    pub apple: oauth::AppleOAuthClient,
    pub twitter: oauth::TwitterOAuthClient,
}

// Rust doesn't support mutable statics, as it could lead to bugs in a multithreading setting
// and it cannot prevent this. So we need to use a mutex even if we have one thread
struct StateReader {
    inner: SgxMutex<EnclaveState>,
}

struct ConfigReader {
    inner: EnclaveConfig,
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

fn config(tee_config: Option<TeeConfig>) -> &'static ConfigReader {
    // Create an uninitialized static
    static mut SINGLETON: MaybeUninit<ConfigReader> = MaybeUninit::uninit();
    static ONCE: Once = Once::new();
    unsafe {
        ONCE.call_once(|| {
            let tee_conf = tee_config.unwrap();
            let singleton = ConfigReader {
                inner: EnclaveConfig {
                    config: tee_conf.clone(),
                    dauth: AuthService {},
                    mail: otp::MailChannelClient::new(tee_conf.otp.email.clone()),
                    mail_api: otp::MailApiChannelClient::new(tee_conf.otp.email_api.clone()),
                    sms: otp::SmsChannelClient::new(tee_conf.otp.sms.clone()),
                    github: oauth::GithubOAuthClient::new(tee_conf.oauth.github.clone()),
                    google: oauth::GoogleOAuthClient::new(tee_conf.oauth.google.clone()),
                    apple: oauth::AppleOAuthClient::new(tee_conf.oauth.apple.clone()),
                    twitter: oauth::TwitterOAuthClient::new(tee_conf.oauth.twitter.clone()),
                    jwt: signer::JwtSignerAgent {
                        conf: tee_conf.signer.jwt.clone(),
                    },
                    jwt_fb: signer::JwtFbSignerAgent {
                        conf: tee_conf.signer.jwt_fb.clone(),
                    },
                    proof: signer::ProofSignerAgent {
                        conf: tee_conf.signer.proof.clone(),
                    },
                    proofv1: signer::ProofSignerAgentV1 {
                        conf: tee_conf.signer.proof.clone(),
                    },
                    both_signer: signer::BothSignerAgent {
                        jwt: signer::JwtSignerAgent {
                            conf: tee_conf.signer.jwt.clone(),
                        },
                        proof: signer::ProofSignerAgent {
                            conf: tee_conf.signer.proof.clone(),
                        },
                    },
                    both_signerv1: signer::BothSignerAgentV1 {
                        jwt: signer::JwtSignerAgent {
                            conf: tee_conf.signer.jwt.clone(),
                        },
                        proof: signer::ProofSignerAgentV1 {
                            conf: tee_conf.signer.proof.clone(),
                        },
                    },
                },
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
    tee_key: &mut [u8; 64],
    session_id: &mut [u8; 32],
) -> sgx_status_t {
    // set tee_key
    let user_key_slice = unsafe { slice::from_raw_parts(user_key, 64) };
    let pub_k_r1 = get_pub_k_r1();
    info(&format!("user pub key {:?}", &user_key_slice));
    info(&format!("tee pub key {:?}", &pub_k_r1));
    let sid = register_session(user_key_slice);
    *tee_key = pub_k_r1;
    *session_id = sid.try_into().unwrap();
    if sid == [0; 32] {
        // unable to calculate share key for the given public key
        sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE
    } else {
        sgx_status_t::SGX_SUCCESS
    }
}

fn get_pub_k_r1() -> [u8; 64] {
    let state: std::sync::SgxMutexGuard<EnclaveState> = state().inner.lock().unwrap();
    state.pub_k_r1.clone()
}

#[no_mangle]
pub extern "C" fn ec_set_conf(config_b: *const u8, config_b_size: usize) -> sgx_status_t {
    let config_slice = unsafe { slice::from_raw_parts(config_b, config_b_size) };
    let new_config = serde_json::from_slice(config_slice).unwrap();
    info(&format!("sgx config {:?}", &new_config));
    config(new_config);
    info("set config success");
    sgx_status_t::SGX_SUCCESS
}

/*
 ec_register_email decrypts cipher_email and cipher_account,
 1, generate a random 6 digits, bind with user session
 2, send the digits to user email
*/
pub trait OtpChannelClient {
    fn new(conf: config::OtpChannelConf) -> Self
    where
        Self: Sized;
    fn send_otp(&self, to_account: &str, client: &Client, c_code: &str) -> GenericResult<()>;
}

#[no_mangle]
pub extern "C" fn ec_send_otp(
    otp_req: *const u8,
    otp_req_size: usize,
    error_code: &mut u8,
) -> sgx_status_t {
    info("sgx send otp");
    let req_slice = unsafe { slice::from_raw_parts(otp_req, otp_req_size as usize) };
    let req: AuthIn = serde_json::from_slice(req_slice).unwrap();
    let result = config(None).inner.dauth.send_otp(&req);
    if result.is_err() {
        unsafe {
            *error_code = result.err().unwrap().to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    unsafe {
        *error_code = 255;
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_send_otp_v1(
    otp_req: *const u8,
    otp_req_size: usize,
    error_code: &mut u8,
) -> sgx_status_t {
    info("sgx send otp");
    let req_slice = unsafe { slice::from_raw_parts(otp_req, otp_req_size as usize) };
    let req: OtpIn = serde_json::from_slice(req_slice).unwrap();
    let result = config(None).inner.dauth.send_otp_v1(&req);
    if result.is_err() {
        unsafe {
            *error_code = result.err().unwrap().to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    unsafe {
        *error_code = 255;
    }
    sgx_status_t::SGX_SUCCESS
}

fn decrypt_text(cipher_text: &str, session: &Session) -> Result<String, Error> {
    let cipher_text_b_r = decode_hex(cipher_text);
    if cipher_text_b_r.is_err() {
        error("decode account failed");
        return Err(Error::new(ErrorKind::DataError));
    }
    let cipher_text_b = cipher_text_b_r.unwrap();
    let text_b_r = session.decrypt(&cipher_text_b);
    if text_b_r.is_err() {
        error("decrypt otp account failed");
        return Err(Error::new(ErrorKind::DataError));
    }
    let text_b = text_b_r.unwrap();
    match str::from_utf8(&text_b) {
        Ok(v) => Ok(v.to_string()),
        Err(e) => {
            error(&format!("decrypt otp account failed {:?}", e));
            Err(Error::new(ErrorKind::DataError))
        }
    }
}

pub trait OAuthClient {
    fn new(conf: config::OAuthConf) -> Self
    where
        Self: Sized;
    fn oauth(&self, c_code: &str, redirect_url: &str) -> GenericResult<InnerAccount>;
}

#[no_mangle]
pub extern "C" fn ec_auth_in_one(
    auth_req: *const u8,
    auth_req_size: usize,
    max_len: u32,
    account_o: *mut u8,
    account_o_size: *mut u32,
    cipher_dauth_o: *mut u8,
    cipher_dauth_o_size: *mut u32,
    error_code: &mut u8,
) -> sgx_status_t {
    // get request
    let req_slice = unsafe { slice::from_raw_parts(auth_req, auth_req_size) };
    let req: AuthIn = match serde_json::from_slice(req_slice) {
        Ok(v) => v,
        Err(e) => {
            error("invalid auth_in req bytes");
            unsafe {
                *error_code = Error::new(ErrorKind::DataError).to_int();
            }
            return sgx_status_t::SGX_SUCCESS;
        }
    };
    let result = config(None).inner.dauth.auth_in_one(&req);
    if result.is_err() {
        unsafe {
            *error_code = result.err().unwrap().to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let (account, cipher_dauth_b) = result.unwrap();
    let account_b = account.to_json_bytes();
    if account_b.len() > max_len as usize {
        error("account too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    if cipher_dauth_b.len() > max_len as usize {
        error("auth too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    unsafe {
        ptr::copy_nonoverlapping(account_b.as_ptr(), account_o, account_b.len());
        *account_o_size = account_b.len().try_into().unwrap();
        ptr::copy_nonoverlapping(
            cipher_dauth_b.as_ptr(),
            cipher_dauth_o,
            cipher_dauth_b.len(),
        );
        *cipher_dauth_o_size = cipher_dauth_b.len().try_into().unwrap();
    }
    unsafe {
        *error_code = 255;
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_auth_in_one_v1(
    auth_req: *const u8,
    auth_req_size: usize,
    max_len: u32,
    account_o: *mut u8,
    account_o_size: *mut u32,
    cipher_dauth_o: *mut u8,
    cipher_dauth_o_size: *mut u32,
    error_code: &mut u8,
) -> sgx_status_t {
    // get request
    let req_slice = unsafe { slice::from_raw_parts(auth_req, auth_req_size) };
    let req: AuthInV1 = match serde_json::from_slice(req_slice) {
        Ok(v) => v,
        Err(e) => {
            error("invalid auth_in req bytes");
            unsafe {
                *error_code = Error::new(ErrorKind::DataError).to_int();
            }
            return sgx_status_t::SGX_SUCCESS;
        }
    };
    let result = config(None).inner.dauth.auth_in_one_v1(&req);
    if result.is_err() {
        unsafe {
            *error_code = result.err().unwrap().to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let (account, cipher_dauth_b) = result.unwrap();
    let account_b = account.to_json_bytes();
    if account_b.len() > max_len as usize {
        error("account too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    if cipher_dauth_b.len() > max_len as usize {
        error("auth too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    unsafe {
        ptr::copy_nonoverlapping(account_b.as_ptr(), account_o, account_b.len());
        *account_o_size = account_b.len().try_into().unwrap();
        ptr::copy_nonoverlapping(
            cipher_dauth_b.as_ptr(),
            cipher_dauth_o,
            cipher_dauth_b.len(),
        );
        *cipher_dauth_o_size = cipher_dauth_b.len().try_into().unwrap();
    }
    unsafe {
        *error_code = 255;
    }
    sgx_status_t::SGX_SUCCESS
}

fn get_config_seal_key() -> String {
    let conf = &config(None).inner;
    conf.config.seal_key.clone()
}

//TODO: get sign pub key automatically
#[no_mangle]
pub extern "C" fn ec_get_sign_pub_key(
    pub_key: &mut [u8; 2048],
    pub_key_size: *mut u32,
) -> sgx_status_t {
    let mut enclave_state = state().inner.lock().unwrap();
    // let pub_key_slice = enclave_state.rsa_pub_key.to_public_key_pem();
    // pkcs1::ToRsaPublicKey::to_pkcs1_pem(&pub_key_slice);
    sgx_status_t::SGX_SUCCESS
}

fn ec_close_session(session_id: &String) -> sgx_status_t {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.close_session(session_id);
    sgx_status_t::SGX_SUCCESS
}

fn get_session(session_id: &str) -> Option<Session> {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.get_session(session_id)
}

fn update_session(session_id: &str, session: &Session) {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.update_session(session_id, session);
}

fn register_session(user_key_slice: &[u8]) -> [u8; 32] {
    let mut enclave_state = state().inner.lock().unwrap();
    enclave_state
        .sessions
        .register_session(user_key_slice.try_into().unwrap())
}

//Testing functions
#[no_mangle]
pub extern "C" fn ec_test() -> sgx_status_t {
    println!("running ec_test");
    rsgx_unit_tests!(
        test_eth_message,
        test_encode_hex,
        test_decode_hex,
        test_decode_hex_with_spaces,
        test_decode_hex_with_invalid_characters,
        test_session_register,
        test_session_register_invalid,
        test_session_update,
        test_session_close,
        test_inner_account_default,
        test_inner_account_build,
        test_pub_k_from_user,
        test_as_u32_be_with_valid_input,
        test_as_u32_be_with_all_zero_input,
        test_as_u32_be_with_all_one_input,
        test_rand,
        test_as_u32_le_with_valid_input,
        test_as_u32_le_with_all_zero_input,
        test_as_u32_le_with_all_one_input,
        test_encrypt_decrypt,
        test_encrypt_decrypt_invalid
    );
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_test_seal_unseal() -> sgx_status_t {
    let plain_text = "80".as_bytes();
    info(&format!("origin text is {:?}", plain_text));

    let (sealed, sealed_len) = sgx_utils::seal(&plain_text);
    let raw_sealed = &sealed[0..sealed_len.try_into().unwrap()];
    info(&format!("sealed content is {:?}", raw_sealed));
    let unsealed = sgx_utils::unseal(raw_sealed);
    let unsealed_txt = std::str::from_utf8(&unsealed);
    // let unsealed_txt = os_utils::encode_hex(&unsealed);
    // info(format!("{}", unsealed_txt);

    match unsealed_txt {
        Ok(r) => info(&format!("unsealed txt is {:?}", r)),
        Err(err) => info("unseal failed"),
    }
    sgx_status_t::SGX_SUCCESS
}
