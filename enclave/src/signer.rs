use crate::get_config_seal_key;

use super::config;
use super::err::*;
use super::log::*;
use super::model::*;
use super::os_utils::*;
use super::sgx_utils;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::string::*;
use std::vec::Vec;
use tiny_keccak::*;

pub fn get_signer(sign_mode: &SignMode) -> &'static dyn SignerAgent {
    let conf = &config(None).inner;
    match sign_mode {
        SignMode::Jwt => &conf.jwt,
        SignMode::JwtFb => &conf.jwt_fb,
        SignMode::Proof => &conf.proof,
        _ => &conf.both_signer,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InnerAuth<'a> {
    pub account: &'a InnerAccount,
    pub auth_in: &'a AuthIn,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EthAuth {
    pub acc_and_type_hash: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_plain: Option<String>,
}

impl<'a> InnerAuth<'a> {
    fn to_eth_auth(&self) -> EthAuth {
        match self.auth_in.account_plain {
            Some(true) => EthAuth {
                acc_and_type_hash: self.account.acc_and_type_hash.as_ref().unwrap().to_string(),
                request_id: self.auth_in.request_id.clone(),
                account_plain: Some(self.account.account.to_string()),
            },
            _ => EthAuth {
                acc_and_type_hash: self.account.acc_and_type_hash.as_ref().unwrap().to_string(),
                request_id: self.auth_in.request_id.clone(),
                account_plain: None,
            },
        }
    }
    fn to_jwt_fb_claim(&self, issuer: &str) -> JwtFbClaims {
        let iat = system_time();
        match self.auth_in.account_plain {
            Some(true) => JwtFbClaims {
                alg: "RS256".to_string(),
                sub: issuer.to_string(),
                iss: issuer.to_string(),
                aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
                iat,
                exp: iat + 3600,
                uid: self.account.account.to_string(),
            },
            _ => JwtFbClaims {
                alg: "RS256".to_string(),
                sub: issuer.to_string(),
                iss: issuer.to_string(),
                aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
                iat,
                exp: iat + 3600,
                uid: self.account.acc_hash.as_ref().unwrap().to_string(),
            },
        }
    }
    fn to_jwt_claim(&self, issuer: &str) -> JwtClaims {
        let iat = system_time();
        match self.auth_in.account_plain {
            Some(true) => JwtClaims {
                alg: "RS256".to_string(),
                sub: self.account.account.to_string(),
                idtype: self.account.id_type.to_string(),
                iss: issuer.to_string(),
                aud: self.auth_in.client.client_id.clone(),
                iat,
                exp: iat + 3600,
            },
            _ => JwtClaims {
                alg: "RS256".to_string(),
                sub: self.account.acc_hash.as_ref().unwrap().to_string(),
                idtype: self.account.id_type.to_string(),
                iss: issuer.to_string(),
                aud: self.auth_in.client.client_id.clone(),
                iat,
                exp: iat + 3600,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct JwtFbClaims {
    alg: String,
    sub: String,
    iss: String,
    aud: String, // hard code to "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
    iat: u64,
    exp: u64,
    uid: String,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    alg: String,
    sub: String,
    idtype: String,
    iss: String,
    aud: String, // hard code to "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
    iat: u64,
    exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthSigned {
    /* when id type is email, all account information is available at client, skip auth */
    auth: EthAuth,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ustore: Option<UserKeyStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeyStore {
    pub user_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_key_sealed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_key_signed: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwtSigned {
    pub token: String,
}

impl ToJsonBytes for EthSigned {}
impl EthSigned {
    pub fn new(eauth: EthAuth, signed: &[u8], ustore: Option<UserKeyStore>) -> Self {
        Self {
            auth: eauth,
            signature: encode_hex(signed),
            ustore,
        }
    }
}

pub trait SignerAgent {
    fn sign(&self, auth: &InnerAuth) -> GenericResult<Vec<u8>>;
}

pub struct JwtSignerAgent {
    pub conf: config::SignerConf,
}

pub struct JwtFbSignerAgent {
    pub conf: config::SignerConf,
}

pub struct ProofSignerAgent {
    pub conf: config::SignerConf,
}

pub struct BothSignerAgent {
    pub jwt: JwtSignerAgent,
    pub proof: ProofSignerAgent,
}

impl SignerAgent for JwtSignerAgent {
    fn sign(&self, auth: &InnerAuth) -> GenericResult<Vec<u8>> {
        let claim = auth.to_jwt_claim(&self.conf.signer);
        let pem_key = self.conf.signing_key.as_bytes();
        let key = EncodingKey::from_rsa_pem(pem_key)?;
        let token = encode(&Header::new(Algorithm::RS256), &claim, &key)?;
        Ok(token.as_bytes().to_vec())
    }
}

impl SignerAgent for JwtFbSignerAgent {
    fn sign(&self, auth: &InnerAuth) -> GenericResult<Vec<u8>> {
        let claim = auth.to_jwt_fb_claim(&self.conf.signer);
        let pem_key = self.conf.signing_key.as_bytes();
        let key = EncodingKey::from_rsa_pem(pem_key)?;
        let token = encode(&Header::new(Algorithm::RS256), &claim, &key)?;
        Ok(token.as_bytes().to_vec())
    }
}

impl SignerAgent for ProofSignerAgent {
    fn sign(&self, auth: &InnerAuth) -> GenericResult<Vec<u8>> {
        let signature_b = eth_sign_abi(
            &auth.account.acc_and_type_hash.as_ref().unwrap().to_string(),
            &auth.auth_in.request_id,
            &self.conf.signing_key,
        );
        if auth.auth_in.user_key.as_ref().is_none() {
            info(&format!(
                "user key is None, return signature only: {:?}",
                &signature_b
            ));
            Ok(EthSigned::new(auth.to_eth_auth(), &signature_b, None).to_json_bytes())
        } else if auth.auth_in.user_key.as_ref().unwrap().eq("") {
            info("user key is empty, generate key");
            let user_key = sgx_utils::rand_bytes();
            let user_key_sealed = sgx_utils::i_seal(&user_key, &get_config_seal_key())?;
            let user_key_hex = encode_hex(&user_key);
            let user_key_sealed_hex = encode_hex(&user_key_sealed);
            let msg_to_sign = format!(
                "{}:{}",
                auth.account.acc_and_type_hash.as_ref().unwrap(),
                &user_key_sealed_hex
            );
            let user_key_signed = eth_sign_str(&msg_to_sign, &self.conf.signing_key);
            let user_key_signed_hex = encode_hex(&user_key_signed);
            let user_key_store = UserKeyStore {
                user_key: user_key_hex,
                user_key_sealed: Some(user_key_sealed_hex),
                user_key_signed: Some(user_key_signed_hex),
            };
            Ok(
                EthSigned::new(auth.to_eth_auth(), &signature_b, Some(user_key_store))
                    .to_json_bytes(),
            )
        } else if auth.auth_in.user_key.as_ref().is_some()
            && auth.auth_in.user_key_signature.as_ref().is_some()
        {
            let user_key_sealed_hex = auth.auth_in.user_key.as_ref().unwrap();
            let user_key_signature = auth.auth_in.user_key_signature.as_ref().unwrap();
            let msg_to_sign = format!(
                "{}:{}",
                auth.account.acc_and_type_hash.as_ref().unwrap(),
                &user_key_sealed_hex
            );
            let user_key_signed = eth_sign_str(&msg_to_sign, &self.conf.signing_key);
            let user_key_signed_hex = encode_hex(&user_key_signed);
            if user_key_signed_hex.eq(user_key_signature) {
                info("user key signature is valid");
                let user_key_unsealed = sgx_utils::i_unseal(
                    &decode_hex(&user_key_sealed_hex)?,
                    &get_config_seal_key(),
                )?;
                let user_key_hex = encode_hex(&user_key_unsealed);
                let user_key_store = UserKeyStore {
                    user_key: user_key_hex,
                    user_key_sealed: None,
                    user_key_signed: None,
                };
                Ok(
                    EthSigned::new(auth.to_eth_auth(), &signature_b, Some(user_key_store))
                        .to_json_bytes(),
                )
            } else {
                return Err(GenericError::from("invalid user key signature"));
            }
        } else {
            Err(GenericError::from("invalid request"))
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BothSignature {
    jwt: String,
    proof: EthSigned,
}

impl ToJsonBytes for BothSignature {}

impl SignerAgent for BothSignerAgent {
    fn sign(&self, auth: &InnerAuth) -> GenericResult<Vec<u8>> {
        let jwt = self.jwt.sign(&auth)?;
        let proof = self.proof.sign(&auth)?;
        let jwt_token = std::str::from_utf8(&jwt)?;
        let proof_obj: EthSigned = serde_json::from_slice(&proof)?;
        Ok(BothSignature {
            jwt: jwt_token.to_string(),
            proof: proof_obj,
        }
        .to_json_bytes())
    }
}

fn eth_sign_abi(account: &str, request_id: &str, prv_k: &str) -> Vec<u8> {
    let prv_k_b = decode_hex(prv_k).unwrap();
    let private_key = libsecp256k1::SecretKey::parse_slice(&prv_k_b).unwrap();
    info(&format!("sign raw parts: {} {}", account, request_id));
    let account_hash: [u8; 32] = decode_hex(account).unwrap().try_into().unwrap();
    // when request_id is hash encoded, decode; else hash it.
    let request_id_hash: [u8; 32] = match try_decode_hex(request_id) {
        Ok(r) => r,
        Err(e) => {
            error(&format!("request_id is not hash encoded: {}", e));
            eth_hash(request_id.as_bytes())
        }
    };
    let abi_encoded = abi_combine(&account_hash, &request_id_hash);
    info(&format!("abi encode is {:?}", &abi_encoded));
    let abi_hash = eth_hash(&abi_encoded);
    info(&format!("abi hash is {:?}", &abi_hash));
    let msg_to_sign = eth_message_b(&abi_hash);
    info(&format!("msg to sign is {:?}", &msg_to_sign));
    let message = libsecp256k1::Message::parse_slice(&msg_to_sign).unwrap();
    let (sig, r_id) = libsecp256k1::sign(&message, &private_key);
    let last_byte = r_id.serialize() + 27;
    let mut sig_buffer: Vec<u8> = Vec::with_capacity(65);
    sig_buffer.extend_from_slice(&sig.serialize());
    sig_buffer.push(last_byte);
    sig_buffer
}

fn try_decode_hex(s: &str) -> GenericResult<[u8; 32]> {
    let decode_r = decode_hex(s)?;
    match decode_r.try_into() {
        Ok(r) => Ok(r),
        Err(e) => Err(GenericError::from("not a 32 bytes")),
    }
}

pub fn eth_hash(b: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0_u8; 32];
    hasher.update(&b);
    hasher.finalize(&mut output);
    output
}

fn abi_combine(account_abi: &[u8; 32], request_id_abi: &[u8; 32]) -> Vec<u8> {
    let mut abi_all = Vec::with_capacity(2 * 32);
    abi_all.extend_from_slice(account_abi);
    abi_all.extend_from_slice(request_id_abi);
    abi_all
}

fn pad_length_string(s: &str) -> Vec<u8> {
    let l_p = pad_length(s.len() as u16);
    let s_p = pad_string(s);
    let mut padded = Vec::with_capacity(l_p.len() + s_p.len());
    padded.extend_from_slice(&l_p);
    padded.extend_from_slice(&s_p);
    padded
}

fn pad_string(s: &str) -> Vec<u8> {
    let s_len = s.len();
    let padded_len = (s_len + 31) / 32 * 32;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(s.as_bytes());
    padded.resize(padded_len, 0);
    padded
}

fn pad_length(l: u16) -> Vec<u8> {
    // all known size is less than 255, fit into 1 byte
    let mut padded = vec![0_u8; 30];
    padded.extend_from_slice(&l.to_be_bytes());
    padded
}

fn eth_sign_str(msg: &str, prv_k: &str) -> Vec<u8> {
    let msg_sha = eth_message(msg);
    let prv_k_b = decode_hex(prv_k).unwrap();
    let private_key = libsecp256k1::SecretKey::parse_slice(&prv_k_b).unwrap();
    let message = libsecp256k1::Message::parse_slice(&msg_sha).unwrap();
    let (sig, r_id) = libsecp256k1::sign(&message, &private_key);
    let last_byte = r_id.serialize() + 27;
    let mut sig_buffer: Vec<u8> = Vec::with_capacity(65);
    sig_buffer.extend_from_slice(&sig.serialize());
    sig_buffer.push(last_byte);
    sig_buffer
}

fn gen_auth_bytes(
    sgx_pub_key: &[u8; 65],
    auth_hash: &[u8; 32],
    auth_id: i32,
    exp: u64,
) -> [u8; 32] {
    let sgx_hex = encode_hex(sgx_pub_key);
    let auth_hex = encode_hex(auth_hash);
    let msg = format!("{}.{}.{}.{}", sgx_hex, auth_hex, auth_id, exp);
    eth_message(&msg)
}

fn eth_message_b(message: &[u8; 32]) -> [u8; 32] {
    let msg_prefix = "\x19Ethereum Signed Message:\n32".as_bytes();
    let mut msg_buffer = Vec::with_capacity(3 * 32);
    msg_buffer.extend_from_slice(msg_prefix);
    msg_buffer.extend_from_slice(message);
    let mut hasher = Keccak::v256();
    let mut output = [0_u8; 32];
    hasher.update(&msg_buffer);
    hasher.finalize(&mut output);
    output
}

fn eth_message(message: &str) -> [u8; 32] {
    let msg = format!(
        "{}{}{}",
        "\x19Ethereum Signed Message:\n",
        message.len(),
        message
    );
    info(&format!("signing msg is {}", msg));
    let mut hasher = Keccak::v256();
    let mut output = [0_u8; 32];
    hasher.update(msg.as_bytes());
    hasher.finalize(&mut output);
    output
}

#[test]
fn test_eth_message() {
    let message = "Hello, world!";
    let expected_hash = [
        0x82, 0x15, 0x65, 0x40, 0x31, 0x2c, 0x3a, 0x9b, 0x6c, 0x00, 0x22, 0x05, 0x20, 0x68, 0x65,
        0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
    ];
    let actual_hash = eth_message(message);
}
