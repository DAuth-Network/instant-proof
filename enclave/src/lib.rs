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
use sgx_trts::enclave;
use sgx_types::*;
use std::convert::TryInto;

use std::mem::MaybeUninit;
use std::slice;
use std::sync::{Once, SgxMutex};

use std::ffi::CStr;
use std::os::raw::c_char;

use std::string::{String, ToString};
//use std::backtrace::{self, PrintFormat};
// use std::prelude::v1::*;
use std::ptr;
use std::str;
use std::vec::Vec;

pub mod config;
pub mod err;
pub mod log;
pub mod model;
pub mod oauth;
pub mod os_utils;
pub mod session;
pub mod sgx_utils;
pub mod sms;
pub mod web3;

use self::err::*;
use self::log::*;
use self::model::*;
use self::session::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use libsecp256k1::{PublicKey, SecretKey};
use oauth::*;

// EnclaveState includes session state that constatntly changes
struct EnclaveState {
    sessions: Sessions,
    pub_k_r1: [u8; 64],
    pub_k_k1: [u8; 65],
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
    config().inner.lock().unwrap().config = new_config;
    info("set config success");
    sgx_status_t::SGX_SUCCESS
}

/*
 ec_register_email decrypts cipher_email and cipher_account,
 1, generate a random 6 digits, bind with user session
 2, send the digits to user email
*/
#[no_mangle]
pub extern "C" fn ec_send_otp(
    otp_req: *const u8,
    otp_req_size: usize,
    error_code: &mut u8,
) -> sgx_status_t {
    info("sgx send otp");
    let req_slice = unsafe { slice::from_raw_parts(otp_req, otp_req_size as usize) };
    let req: OtpIn = serde_json::from_slice(req_slice).unwrap();
    // verify session
    let session_r = get_session(&req.session_id);
    if session_r.is_none() {
        error(&format!("sgx session {:?} not found.", &req.session_id));
        unsafe {
            *error_code = Error::new(ErrorKind::SessionError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let mut session = session_r.unwrap();
    // decrypt account
    let account_r = decrypt_text_to_text(&req.cipher_account, &session);
    if account_r.is_err() {
        error(&format!("decrypt opt account failed."));
        unsafe {
            *error_code = Error::new(ErrorKind::DataError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let account = account_r.unwrap();
    info(&format!("otp account is {}", account));
    let otp = sgx_utils::rand();
    //TODO: sendmail error
    session.code = otp.to_string();
    let inner_account = InnerAccount {
        account: account.to_string(),
        auth_type: req.auth_type,
    };
    session.data = inner_account.to_str();
    update_session(&req.session_id, &session);
    let send_r = match req.auth_type {
        AuthType::Email => os_utils::sendmail(&get_config_email(), &account, &otp.to_string()),
        AuthType::Sms => sms::sendsms(&get_config_sms(), &account, &otp.to_string()),
        _ => {
            error("invalid auth type");
            unsafe {
                *error_code = Error::new(ErrorKind::DataError).to_int();
            }
            return sgx_status_t::SGX_SUCCESS;
        }
    };
    if send_r.is_err() {
        error("send otp failed");
        unsafe {
            *error_code = Error::new(ErrorKind::SendChannelError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    unsafe {
        *error_code = 255;
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

fn decrypt_text_to_text(cipher_text: &str, session: &Session) -> Result<String, Error> {
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

#[no_mangle]
pub extern "C" fn ec_auth_in_one(
    auth_req: *const u8,
    auth_req_size: usize,
    max_len: u32,
    account_b: *mut u8,
    account_b_size: *mut u32,
    cipher_dauth: *mut u8,
    cipher_dauth_size: *mut u32,
    error_code: &mut u8,
) -> sgx_status_t {
    // get request
    let req_slice = unsafe { slice::from_raw_parts(auth_req, auth_req_size) };
    let req_r = serde_json::from_slice(req_slice);
    if req_r.is_err() {
        error("invalid auth type");
        unsafe {
            *error_code = Error::new(ErrorKind::DataError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let req: AuthIn = req_r.unwrap();
    // get session
    let session_r = get_session(&req.session_id);
    if session_r.is_none() {
        error(&format!("sgx session {:?} not found.", &req.session_id));
        unsafe {
            *error_code = Error::new(ErrorKind::SessionError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let mut session = session_r.unwrap();
    // decrypt code
    let code_r = decrypt_text_to_text(&req.cipher_code, &session);
    if code_r.is_err() {
        error(&format!("decrypt code failed."));
        unsafe {
            *error_code = Error::new(ErrorKind::DataError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let code = code_r.unwrap();
    info(&format!("auth code is {}", &code));
    let mut account: InnerAccount = InnerAccount {
        account: "".to_string(),
        auth_type: AuthType::Email,
    };
    match req.auth_type.as_str() {
        "None" => {
            // compare otp
            if !code.eq(&session.code) {
                info("confirm code not match, returning");
                unsafe {
                    *error_code = Error::new(ErrorKind::OtpCodeError).to_int();
                }
                return sgx_status_t::SGX_SUCCESS;
            }
            account = InnerAccount::from_str(&session.data).unwrap();
        }
        _ => {
            // oauth
            let auth_type = AuthType::from_str(&req.auth_type);
            if auth_type.is_none() {
                error("invalid auth type");
                unsafe {
                    *error_code = Error::new(ErrorKind::DataError).to_int();
                }
                return sgx_status_t::SGX_SUCCESS;
            }
            let auth_type = auth_type.unwrap();
            account.auth_type = auth_type;
            let oauth_result = match auth_type {
                AuthType::Google => google_oauth(&get_config_oauth().google, &code),
                AuthType::Github => github_oauth(&get_config_oauth().github, &code),
                _ => {
                    error("invalid auth type");
                    unsafe {
                        *error_code = Error::new(ErrorKind::DataError).to_int();
                    }
                    return sgx_status_t::SGX_SUCCESS;
                }
            };
            if oauth_result.is_err() {
                error("oauth failed");
                unsafe {
                    *error_code = Error::new(ErrorKind::OAuthCodeError).to_int();
                }
                return sgx_status_t::SGX_SUCCESS;
            }
            let oauth_result = oauth_result.unwrap();
            account.account = oauth_result;
        }
    }
    // when success, seal the account
    info(&format!("account is {:?}", &account));
    let sealed_r = sgx_utils::i_seal(account.account.as_bytes(), &get_config_seal_key());
    let sealed = match sealed_r {
        Ok(r) => r,
        Err(_) => {
            error("seal account failed");
            return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
        }
    };
    let raw_hashed = sgx_utils::hash(account.account.as_bytes()).unwrap();
    let account_hash = os_utils::encode_hex(&raw_hashed);
    info(&format!("account seal {:?}", sealed));
    info(&format!("account hash {:?}", raw_hashed));
    let out_account = Account {
        auth_type: account.auth_type,
        acc_seal: os_utils::encode_hex(&sealed),
        acc_hash: account_hash.clone(),
    };
    // update account to account_hash
    account.account = account_hash;
    // sign the auth
    let auth = InnerAuth {
        account: &account,
        auth_in: &req,
    };
    let mut dauth_signed = vec![];
    match req.sign_mode {
        SignMode::JWT => {
            info("signing jwt");
            let claim = auth.to_jwt_claim(&get_issuer());
            let pem_key = get_config_rsa_key();
            let pem_key_b = pem_key.as_bytes();
            let key = EncodingKey::from_rsa_pem(pem_key_b).unwrap();
            let token = encode(&Header::new(Algorithm::RS256), &claim, &key).unwrap();
            dauth_signed = token.as_bytes().to_vec();
        }
        SignMode::PROOF => {
            info("signing proof");
            let eth_string = auth.to_eth_string();
            let signature_b = web3::eth_sign(&eth_string, get_config_edcsa_key());
            dauth_signed = EthSigned::new(auth.to_eth_auth(), &signature_b).to_json_bytes();
        }
        _ => {
            error("invalid sign mode");
            unsafe {
                *error_code = Error::new(ErrorKind::DataError).to_int();
            }
            return sgx_status_t::SGX_SUCCESS;
        }
    }
    let cipher_dauth_b = session.encrypt(&dauth_signed);
    info(&format!("dauth is {:?}", &dauth_signed));
    info(&format!("cipher dauth is {:?}", &cipher_dauth_b));
    // return
    let account_sgx = out_account.to_json_bytes();
    if account_sgx.len() > max_len as usize {
        error("account too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    if cipher_dauth_b.len() > max_len as usize {
        error("auth too long");
        return sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE;
    }
    unsafe {
        ptr::copy_nonoverlapping(account_sgx.as_ptr(), account_b, account_sgx.len());
        *account_b_size = account_sgx.len().try_into().unwrap();
        ptr::copy_nonoverlapping(cipher_dauth_b.as_ptr(), cipher_dauth, cipher_dauth_b.len());
        *cipher_dauth_size = cipher_dauth_b.len().try_into().unwrap();
    }
    ec_close_session(&req.session_id);
    unsafe {
        *error_code = 255;
    }
    sgx_status_t::SGX_SUCCESS
}

fn get_config_seal_key() -> String {
    let conf = config().inner.lock().unwrap();
    conf.config.seal_key.clone()
}

fn get_config_edcsa_key() -> String {
    let conf = config().inner.lock().unwrap();
    conf.config.ecdsa_key.clone()
}

fn get_config_oauth() -> OAuth {
    let conf = config().inner.lock().unwrap();
    conf.config.oauth.clone()
}

fn get_pub_k_k1() -> [u8; 65] {
    let enclave_state = state().inner.lock().unwrap();
    enclave_state.pub_k_k1
}

fn get_prv_k() -> sgx_ec256_private_t {
    let enclave_state = state().inner.lock().unwrap();
    enclave_state.sessions.prv_k
}

fn get_issuer() -> String {
    let conf = config().inner.lock().unwrap();
    conf.config.jwt_issuer.clone()
}

fn get_config_rsa_key() -> String {
    config().inner.lock().unwrap().config.rsa_key.clone()
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

#[no_mangle]
pub extern "C" fn ec_close_session(session_id: &String) -> sgx_status_t {
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
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ec_test_seal_unseal() -> sgx_status_t {
    //let plain_text = "80141b0d0e96bf36bdc20473be2f274c8a65dae10d610539a228d038257a7152e99c3b93b055c80d28590dcb48edda9c63801d0ff2c5961f5ba4cf038a4b3555d31dc4bd3a8180cb7001af4db10ed1707b284f08d1a07cd2f3fa6b5d2977117633e1c95e109e9223facf1ce7c245546971f0b6fc97eb3fad9b494d6c70b861e84878b4bef2517801507df0a30048c84ebc2".as_bytes();

    let plain_text = "80".as_bytes();
    info(&format!("origin text is {:?}", plain_text));

    let (sealed, sealed_len) = sgx_utils::seal(&plain_text);
    let raw_sealed = &sealed[0..sealed_len.try_into().unwrap()];
    info(&format!("sealed content is {:?}", raw_sealed));
    //let sealed2: [u8;1024] = [4, 0, 2, 0, 0, 0, 0, 0, 72, 32, 243, 55, 106, 230, 178, 242, 3, 77, 59, 122, 75, 72, 167, 120, 11, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 170, 104, 90, 10, 215, 117, 210, 222, 215, 179, 19, 175, 198, 117, 135, 93, 120, 206, 179, 187, 199, 61, 114, 235, 213, 52, 233, 80, 195, 147, 171, 105, 0, 0, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 105, 41, 87, 138, 236, 184, 166, 220, 249, 66, 139, 214, 56, 173, 251, 78, 108, 143, 44, 33, 138, 91, 23, 155, 220, 94, 31, 130, 12, 83, 172, 27, 153, 219, 250, 32, 89, 120, 58, 33, 114, 70, 81, 59, 137, 119, 122, 33, 70, 150, 139, 247, 17, 21, 56, 40, 125, 234, 217, 198, 193, 60, 158, 12, 104, 57, 112, 171, 18, 237, 69, 222, 122, 242, 0, 211, 36, 64, 22, 28, 63, 151, 181, 160, 222, 245, 76, 61, 103, 177, 141, 200, 246, 194, 163, 184, 234, 28, 144, 184, 97, 147, 68, 176, 33, 128, 36, 17, 107, 196, 210, 240, 50, 179, 173, 221, 216, 232, 246, 255, 228, 179, 7, 29, 118, 108, 202, 230, 165, 203, 185, 194, 67, 1, 8, 210, 117, 251, 217, 83, 242, 93, 76, 91, 35, 228, 239, 93, 166, 181, 81, 172, 30, 138, 60, 162, 230, 59, 143, 211, 24, 249, 42, 247, 4, 149, 105, 11, 244, 129, 61, 31, 162, 174, 125, 102, 255, 7, 7, 139, 125, 63, 134, 183, 88, 208, 24, 0, 244, 237, 63, 161, 189, 170, 99, 218, 31, 178, 113, 45, 65, 190, 11, 170, 195, 55, 203, 90, 99, 64, 18, 138, 74, 50, 235, 42, 62, 248, 197, 81, 131, 216, 96, 167, 193, 103, 166, 10, 231, 152, 195, 2, 124, 29, 169, 111, 236, 49, 250, 99, 165, 161, 215, 69, 223, 93, 60, 86, 104, 41, 176, 195, 204, 237, 73, 139, 109, 221, 89, 208, 8, 246, 74, 201, 88, 63, 16, 236, 111, 59, 140, 121, 55, 171, 1, 226, 78, 236, 217, 176, 158, 83, 22, 138, 136, 213, 241, 88, 114, 19, 159, 135, 115, 106, 255, 32, 34, 56, 113, 112, 13, 179, 169, 165, 150, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
