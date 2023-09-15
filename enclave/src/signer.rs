use crate::get_config_seal_key;

use super::config;
use super::err::*;
use super::log::*;
use super::model::*;
use super::os_utils::*;
use super::sgx_utils;
use super::*;
use bip32::{DerivationPath, Prefix, XPrv};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::string::*;
use std::thread::AccessError;
use std::vec::Vec;
use tiny_keccak::*;

pub fn get_signer(sign_mode: &SignMode) -> &'static dyn SignerAgent {
    let conf = &config(None).inner;
    match sign_mode {
        SignMode::Jwt => &conf.jwt,
        SignMode::JwtFb => &conf.jwt_fb,
        SignMode::Proof => &conf.proof,
        SignMode::Proofv1 => &conf.proofv1,
        SignMode::Both => &conf.both_signer,
        SignMode::Bothv1 => &conf.both_signerv1,
        _ => &conf.proof,
    }
}

#[derive(Debug, Serialize)]
pub struct JwtFbClaims {
    alg: String,
    sub: String,
    iss: String,
    aud: String, // hard code to "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
    iat: u64,
    exp: u64,
    uid: String,
}

#[derive(Debug, Serialize)]
pub struct JwtClaims {
    alg: String,
    sub: String,
    acc_and_type_hash: String,
    idtype: String,
    iss: String,
    aud: String, // client id
    iat: u64,
    exp: u64,
}

pub trait AuthToSign {
    fn get_account(&self) -> InnerAccount;
    fn is_account_plain(&self) -> bool;
    fn get_id_key_salt(&self) -> Option<i32>;
    fn get_sign_msg(&self) -> Option<String>;
    fn get_request_id(&self) -> Option<String>;
    fn get_user_key(&self) -> Option<String>;
    fn get_user_key_signature(&self) -> Option<String>;
    fn get_client(&self) -> String;
    fn to_jwt(&self, issuer: &str) -> Option<JwtClaims>;
    fn to_jwt_fb(&self, issuer: &str) -> Option<JwtFbClaims>;
}

#[derive(Debug, Clone, Serialize)]
pub struct InnerAuth<'a> {
    pub account: &'a InnerAccount,
    pub auth_data: &'a AuthData,
    pub client: &'a Client,
}

#[derive(Debug, Clone, Serialize)]
pub struct InnerAuthV1<'a> {
    pub account: &'a InnerAccount,
    pub auth_in: &'a AuthInV1,
}

impl<'a> AuthToSign for InnerAuth<'a> {
    fn get_account(&self) -> InnerAccount {
        self.account.clone()
    }
    fn is_account_plain(&self) -> bool {
        match self.auth_data.account_plain {
            Some(true) => true,
            _ => false,
        }
    }
    fn get_id_key_salt(&self) -> Option<i32> {
        self.auth_data.id_key_salt
    }
    fn get_sign_msg(&self) -> Option<String> {
        self.auth_data.sign_msg.clone()
    }
    fn get_client(&self) -> String {
        self.client.client_id.clone()
    }
    fn get_request_id(&self) -> Option<String> {
        None
    }
    fn get_user_key(&self) -> Option<String> {
        self.auth_data.user_key.clone()
    }
    fn get_user_key_signature(&self) -> Option<String> {
        self.auth_data.user_key_signature.clone()
    }
    fn to_jwt(&self, issuer: &str) -> Option<JwtClaims> {
        let iat = system_time();
        let account = self.get_account();
        if account.acc_hash.is_none() || account.acc_and_type_hash.is_none() {
            return None;
        }
        let mut claim = JwtClaims {
            alg: "ES256".to_string(),
            sub: "".to_string(),
            acc_and_type_hash: account.acc_and_type_hash.unwrap(),
            idtype: self.account.id_type.to_string(),
            iss: issuer.to_string(),
            aud: self.get_client(),
            iat,
            exp: iat + 3600,
        };
        match self.is_account_plain() {
            true => claim.sub = account.account,
            _ => claim.sub = account.acc_hash.unwrap(),
        }
        Some(claim)
    }
    fn to_jwt_fb(&self, issuer: &str) -> Option<JwtFbClaims> {
        let iat = system_time();
        let account = self.get_account();
        if account.acc_hash.is_none() || account.acc_and_type_hash.is_none() {
            return None;
        }
        let mut claims = JwtFbClaims {
            alg: "RS256".to_string(),
            sub: issuer.to_string(),
            iss: issuer.to_string(),
            aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
            iat,
            exp: iat + 3600,
            uid: "".to_string(),
        };
        match self.is_account_plain() {
            true => claims.uid = account.account,
            _ => claims.uid = account.acc_hash.unwrap(),
        }
        Some(claims)
    }
}

impl<'a> AuthToSign for InnerAuthV1<'a> {
    fn get_account(&self) -> InnerAccount {
        self.account.clone()
    }
    fn is_account_plain(&self) -> bool {
        match self.auth_in.account_plain {
            Some(true) => true,
            _ => false,
        }
    }
    fn get_client(&self) -> String {
        self.auth_in.client.client_id.clone()
    }
    fn get_id_key_salt(&self) -> Option<i32> {
        None
    }
    fn get_request_id(&self) -> Option<String> {
        Some(self.auth_in.request_id.clone())
    }
    fn get_sign_msg(&self) -> Option<String> {
        None
    }
    fn get_user_key(&self) -> Option<String> {
        self.auth_in.user_key.clone()
    }
    fn get_user_key_signature(&self) -> Option<String> {
        self.auth_in.user_key_signature.clone()
    }
    fn to_jwt_fb(&self, issuer: &str) -> Option<JwtFbClaims> {
        let iat = system_time();
        let account = self.get_account();
        if account.acc_hash.is_none() || account.acc_and_type_hash.is_none() {
            return None;
        }
        let mut claims = JwtFbClaims {
            alg: "RS256".to_string(),
            sub: issuer.to_string(),
            iss: issuer.to_string(),
            aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit".to_string(),
            iat,
            exp: iat + 3600,
            uid: "".to_string(),
        };
        match self.is_account_plain() {
            true => claims.uid = account.account,
            _ => claims.uid = account.acc_hash.unwrap(),
        };
        Some(claims)
    }
    fn to_jwt(&self, issuer: &str) -> Option<JwtClaims> {
        let iat = system_time();
        let account = self.get_account();
        if account.acc_hash.is_none() || account.acc_and_type_hash.is_none() {
            return None;
        }
        let mut claims = JwtClaims {
            alg: "ES256".to_string(),
            sub: "".to_string(),
            acc_and_type_hash: account.acc_and_type_hash.unwrap(),
            idtype: self.account.id_type.to_string(),
            iss: issuer.to_string(),
            aud: self.get_client(),
            iat,
            exp: iat + 3600,
        };
        match self.is_account_plain() {
            true => claims.sub = account.account,
            _ => claims.sub = account.acc_hash.unwrap(),
        }
        Some(claims)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofAuth {
    pub acc_and_type_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_plain: Option<String>,
    pub id_pub_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofAuthV1 {
    pub acc_and_type_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_plain: Option<String>,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSigned {
    /* when id type is email, all account information is available at client, skip auth */
    auth: ProofAuth,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ustore: Option<UserKeyStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSignedV1 {
    /* when id type is email, all account information is available at client, skip auth */
    auth: ProofAuthV1,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ustore: Option<UserKeyStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeyStore {
    pub user_key_plain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_key_signature: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwtSigned {
    pub token: String,
}

impl ToJsonBytes for ProofSigned {}
impl ToJsonBytes for ProofSignedV1 {}
impl ProofSigned {
    pub fn new(auth: ProofAuth, signed: &[u8], ustore: Option<UserKeyStore>) -> Self {
        Self {
            auth: auth,
            signature: encode_hex(signed),
            ustore,
        }
    }
}

impl ProofSignedV1 {
    pub fn new(auth: ProofAuthV1, signed: &[u8], ustore: Option<UserKeyStore>) -> Self {
        Self {
            auth: auth,
            signature: encode_hex(signed),
            ustore,
        }
    }
}

pub trait SignerAgent {
    fn sign(&self, auth: &dyn AuthToSign) -> GenericResult<Vec<u8>>;
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

pub struct ProofSignerAgentV1 {
    pub conf: config::SignerConf,
}

pub struct BothSignerAgent {
    pub jwt: JwtSignerAgent,
    pub proof: ProofSignerAgent,
}

pub struct BothSignerAgentV1 {
    pub jwt: JwtSignerAgent,
    pub proof: ProofSignerAgentV1,
}

impl SignerAgent for JwtSignerAgent {
    fn sign(&self, auth: &dyn AuthToSign) -> GenericResult<Vec<u8>> {
        let claim = match auth.to_jwt(&self.conf.signer) {
            Some(r) => r,
            None => {
                error("invalid auth");
                return Err(GenericError::from("invalid auth"));
            }
        };
        let pem_key = self.conf.signing_key.as_bytes();
        let key = EncodingKey::from_ec_pem(pem_key)?;
        let token = encode(&Header::new(Algorithm::ES256), &claim, &key)?;
        Ok(token.as_bytes().to_vec())
    }
}

impl SignerAgent for JwtFbSignerAgent {
    fn sign(&self, auth: &dyn AuthToSign) -> GenericResult<Vec<u8>> {
        let claim = match auth.to_jwt_fb(&self.conf.signer) {
            Some(r) => r,
            None => {
                error("invalid auth");
                return Err(GenericError::from("invalid auth"));
            }
        };
        let pem_key = self.conf.signing_key.as_bytes();
        let key = EncodingKey::from_rsa_pem(pem_key)?;
        let token = encode(&Header::new(Algorithm::RS256), &claim, &key)?;
        Ok(token.as_bytes().to_vec())
    }
}

impl SignerAgent for ProofSignerAgent {
    fn sign(&self, auth: &dyn AuthToSign) -> GenericResult<Vec<u8>> {
        // verify id_key_salt and sign_msg presence
        let id_key_salt = auth.get_id_key_salt();
        let sign_msg = auth.get_sign_msg();
        if id_key_salt.is_none() || sign_msg.is_none() {
            error("id_key_salt and sign_msg must not be none");
            return Err(GenericError::from("invalid request"));
        }
        let id_key_salt = id_key_salt.as_ref().unwrap();
        let sign_msg = sign_msg.as_ref().unwrap();
        // generate new user private key and public key
        let account = auth.get_account();
        if account.acc_hash.is_none() || account.acc_and_type_hash.is_none() {
            error("account hash is none");
            return Err(GenericError::from("invalid request"));
        }
        let acc_hash = account.acc_hash.unwrap();
        let acc_and_type_hash = account.acc_and_type_hash.unwrap();
        let (id_priv_key, id_pub_key) =
            derive_key(&self.conf.signing_key, &acc_hash, id_key_salt.clone())?;
        let id_pub_key_hex = encode_hex(&id_pub_key);
        let signature_b = eth_sign_abi(&sign_msg, &id_priv_key);
        let mut proof_auth = ProofAuth {
            acc_and_type_hash: acc_and_type_hash.clone(),
            id_pub_key: id_pub_key_hex,
            account_plain: None,
        };
        match auth.is_account_plain() {
            true => proof_auth.account_plain = Some(account.account),
            _ => (),
        }
        // get user key and user key signature
        let user_key = auth.get_user_key();
        let user_key_signature = auth.get_user_key_signature();
        // when no user key field, return signature only
        if user_key.is_none() {
            info(&format!(
                "user key is None, return signature only: {:?}",
                &signature_b
            ));
            return Ok(ProofSigned::new(proof_auth, &signature_b, None).to_json_bytes());
        }
        // when user key is empty string, generate new key
        let user_key_str = user_key.unwrap();
        if user_key_str.eq("") {
            info("user key is empty, generate key");
            let user_key_store =
                gen_user_key_store(&acc_and_type_hash.clone(), &self.conf.signing_key)?;
            return Ok(
                ProofSigned::new(proof_auth, &signature_b, Some(user_key_store)).to_json_bytes(),
            );
        }
        // when user key and user key signature is present, verify signature
        if user_key_signature.is_none() {
            error("user key signature is none");
            return Err(GenericError::from("invalid request"));
        }
        let user_key_sig_str = user_key_signature.as_ref().unwrap();
        let msg_to_sign = format!("{}:{}", acc_and_type_hash, &user_key_str);
        let user_key_signed = eth_sign_str(&msg_to_sign, &self.conf.signing_key);
        let user_key_signed_hex = encode_hex(&user_key_signed);
        if user_key_signed_hex.eq(user_key_sig_str) {
            let user_key_store = decrypt_key_store(&user_key_str)?;
            Ok(ProofSigned::new(proof_auth, &signature_b, Some(user_key_store)).to_json_bytes())
        } else {
            Ok(ProofSigned::new(proof_auth, &signature_b, None).to_json_bytes())
        }
    }
}

impl SignerAgent for ProofSignerAgentV1 {
    fn sign(&self, auth: &dyn AuthToSign) -> GenericResult<Vec<u8>> {
        let account = auth.get_account();
        if account.acc_hash.is_none() || account.acc_and_type_hash.is_none() {
            error("account hash is none");
            return Err(GenericError::from("invalid request"));
        }
        let acc_hash = account.acc_hash.unwrap();
        let acc_and_type_hash = account.acc_and_type_hash.unwrap();
        let request_id = match auth.get_request_id() {
            Some(r) => r,
            None => {
                error("request id is none");
                return Err(GenericError::from("invalid request"));
            }
        };
        let mut proof_auth = ProofAuthV1 {
            acc_and_type_hash: acc_and_type_hash.clone(),
            request_id: request_id.clone(),
            account_plain: None,
        };
        match auth.is_account_plain() {
            true => proof_auth.account_plain = Some(account.account),
            _ => (),
        }
        let signature_b = eth_sign_abi_v1(&acc_and_type_hash, &request_id, &self.conf.signing_key);
        let user_key = auth.get_user_key();
        let user_key_signature = auth.get_user_key_signature();
        // when no user key field, return signature only
        if user_key.is_none() {
            info(&format!(
                "user key is None, return signature only: {:?}",
                &signature_b
            ));
            return Ok(ProofSignedV1::new(proof_auth, &signature_b, None).to_json_bytes());
        }
        // when user key is "", gen a new user key storeg
        let user_key_str = user_key.unwrap();
        if user_key_str.eq("") {
            info("user key is empty, generate key");
            let user_key_store = gen_user_key_store(&acc_and_type_hash, &self.conf.signing_key)?;
            return Ok(
                ProofSignedV1::new(proof_auth, &signature_b, Some(user_key_store)).to_json_bytes(),
            );
        }
        // when user key and user key signature is present, verify signature
        if user_key_signature.is_none() {
            error("user key signature is none");
            return Err(GenericError::from("invalid request"));
        }
        let user_key_sig_str = user_key_signature.unwrap();
        let msg_to_sign = format!("{}:{}", acc_and_type_hash, &user_key_str);
        let user_key_signed = eth_sign_str(&msg_to_sign, &self.conf.signing_key);
        let user_key_signed_hex = encode_hex(&user_key_signed);
        if user_key_signed_hex.eq(&user_key_sig_str) {
            info("user key signature is valid");
            let user_key_store = decrypt_key_store(&user_key_str)?;
            Ok(ProofSignedV1::new(proof_auth, &signature_b, Some(user_key_store)).to_json_bytes())
        } else {
            Ok(ProofSignedV1::new(proof_auth, &signature_b, None).to_json_bytes())
        }
    }
}

fn gen_user_key_store(acc_hash: &str, signing_key: &str) -> GenericResult<UserKeyStore> {
    let new_user_key = sgx_utils::rand_bytes();
    let user_key_sealed = sgx_utils::i_seal(&new_user_key, &get_config_seal_key())?;
    let user_key_hex = encode_hex(&new_user_key);
    let user_key_sealed_hex = encode_hex(&user_key_sealed);
    let msg_to_sign = format!("{}:{}", acc_hash, &user_key_sealed_hex);
    let user_key_signed = eth_sign_str(&msg_to_sign, &signing_key);
    let user_key_signed_hex = encode_hex(&user_key_signed);
    Ok(UserKeyStore {
        user_key_plain: user_key_hex,
        user_key: Some(user_key_sealed_hex),
        user_key_signature: Some(user_key_signed_hex),
    })
}

fn decrypt_key_store(user_key_str: &str) -> GenericResult<UserKeyStore> {
    info("user key signature is valid");
    let user_key_unsealed =
        sgx_utils::i_unseal(&decode_hex(&user_key_str)?, &get_config_seal_key())?;
    let user_key_hex = encode_hex(&user_key_unsealed);
    Ok(UserKeyStore {
        user_key_plain: user_key_hex,
        user_key: None,
        user_key_signature: None,
    })
}

fn derive_key(
    priv_k: &str,
    account_hash: &str,
    salt_index: i32,
) -> GenericResult<([u8; 32], [u8; 33])> {
    let master_k = decode_hex(priv_k).unwrap();
    let account_index = str_to_i32(account_hash);
    println!("account i32 is {}", account_index);
    let derive_path = format!("m/0/{}/{}", account_index.abs(), salt_index.abs());
    let dpk = derive_xprv(&master_k, &derive_path)?;
    let priv_kb = dpk.to_bytes();
    let pub_k = dpk.public_key();
    Ok((priv_kb, pub_k.to_bytes()))
}

fn derive_xprv(seed: &[u8], path: &str) -> GenericResult<XPrv> {
    let p: DerivationPath = match path.parse() {
        Ok(r) => r,
        Err(e) => {
            error("parse derive path failed");
            return Err(GenericError::from("invalid derive path"));
        }
    };
    match XPrv::derive_from_path(seed, &p) {
        Ok(r) => Ok(r),
        Err(e) => {
            error("derive failed");
            Err(GenericError::from("derive failed"))
        }
    }
}

fn str_to_i32(data_hash: &str) -> i32 {
    let bytes = decode_hex(data_hash).unwrap();
    let mut buf = [0_u8; 4];
    buf.copy_from_slice(&bytes[0..4]);
    i32::from_be_bytes(buf)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BothSignature {
    jwt: String,
    proof: ProofSigned,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BothSignatureV1 {
    jwt: String,
    proof: ProofSignedV1,
}

impl ToJsonBytes for BothSignature {}
impl ToJsonBytes for BothSignatureV1 {}

impl SignerAgent for BothSignerAgent {
    fn sign(&self, auth: &dyn AuthToSign) -> GenericResult<Vec<u8>> {
        let jwt = self.jwt.sign(auth)?;
        let proof = self.proof.sign(auth)?;
        let jwt_token = std::str::from_utf8(&jwt)?;
        let proof_obj: ProofSigned = serde_json::from_slice(&proof)?;
        Ok(BothSignature {
            jwt: jwt_token.to_string(),
            proof: proof_obj,
        }
        .to_json_bytes())
    }
}

impl SignerAgent for BothSignerAgentV1 {
    fn sign(&self, auth: &dyn AuthToSign) -> GenericResult<Vec<u8>> {
        let jwt = self.jwt.sign(auth)?;
        let proof = self.proof.sign(auth)?;
        let jwt_token = std::str::from_utf8(&jwt)?;
        let proof_obj: ProofSignedV1 = serde_json::from_slice(&proof)?;
        Ok(BothSignatureV1 {
            jwt: jwt_token.to_string(),
            proof: proof_obj,
        }
        .to_json_bytes())
    }
}

fn eth_sign_abi(msg: &str, prv_k: &[u8]) -> Vec<u8> {
    let private_key = libsecp256k1::SecretKey::parse_slice(&prv_k).unwrap();

    info(&format!("sign msg: {}", msg));
    // when msg is hash encoded, decode; else hash it.
    let msg_hash: [u8; 32] = match try_decode_hex(msg) {
        Ok(r) => r,
        Err(e) => {
            info(&format!("sign_msg is not hash encoded: {}", e));
            eth_hash(msg.as_bytes())
        }
    };
    let msg_to_sign = eth_message_b(&msg_hash);
    info(&format!("msg to sign is {:?}", &msg_to_sign));
    let message = libsecp256k1::Message::parse_slice(&msg_to_sign).unwrap();
    let (sig, r_id) = libsecp256k1::sign(&message, &private_key);
    let last_byte = r_id.serialize() + 27;
    let mut sig_buffer: Vec<u8> = Vec::with_capacity(65);
    sig_buffer.extend_from_slice(&sig.serialize());
    sig_buffer.push(last_byte);
    sig_buffer
}

fn eth_sign_abi_v1(account: &str, request_id: &str, prv_k: &str) -> Vec<u8> {
    let prv_k_b = decode_hex(prv_k).unwrap();
    let private_key = libsecp256k1::SecretKey::parse_slice(&prv_k_b).unwrap();

    info(&format!("sign raw parts: {} {}", account, request_id));
    let account_hash: [u8; 32] = decode_hex(account).unwrap().try_into().unwrap();
    // when request_id is hash encoded, decode; else hash it.
    let request_id_hash: [u8; 32] = match try_decode_hex(request_id) {
        Ok(r) => r,
        Err(e) => {
            info(&format!("request_id is not hash encoded: {}", e));
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

fn abi_combine(account_abi: &[u8; 32], request_id_abi: &[u8; 32]) -> Vec<u8> {
    let mut abi_all = Vec::with_capacity(2 * 32);
    abi_all.extend_from_slice(account_abi);
    abi_all.extend_from_slice(request_id_abi);
    abi_all
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
