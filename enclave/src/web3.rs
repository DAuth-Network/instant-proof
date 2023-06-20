use super::log::*;
use super::os_utils::*;
use sgx_types::*;
use std::string::*;
use std::vec::Vec;
use tiny_keccak::*;

pub fn eth_sign_abi(id_type: &str, account: &str, request_id: &str, prv_k: String) -> Vec<u8> {
    let prv_k_b = decode_hex(&prv_k).unwrap();
    let private_key = libsecp256k1::SecretKey::parse_slice(&prv_k_b).unwrap();
    info(&format!(
        "sign raw parts: {} {} {}",
        id_type, account, request_id
    ));
    let msg_b = abi_message(id_type, account, request_id);
    info(&format!("signing msg is {:?}", &msg_b));
    let msg_sha = hash_abi(&msg_b);
    let message = libsecp256k1::Message::parse_slice(&msg_sha).unwrap();
    let (sig, r_id) = libsecp256k1::sign(&message, &private_key);
    let last_byte = r_id.serialize() + 27;
    let mut sig_buffer: Vec<u8> = Vec::with_capacity(65);
    sig_buffer.extend_from_slice(&sig.serialize());
    sig_buffer.push(last_byte);
    sig_buffer
}

fn abi_message(id_type: &str, account: &str, request_id: &str) -> Vec<u8> {
    let id_abi = pad_all(id_type);
    let account_abi = pad_all(account);
    let request_id_abi = pad_all(request_id);
    abi_combine(id_abi, account_abi, request_id_abi)
}

fn hash_abi(b: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0_u8; 32];
    hasher.update(&b);
    hasher.finalize(&mut output);
    output
}

fn abi_combine(id_abi: Vec<u8>, account_abi: Vec<u8>, request_id_abi: Vec<u8>) -> Vec<u8> {
    let mut abi_all =
        Vec::with_capacity(3 * 32 + id_abi.len() + account_abi.len() + request_id_abi.len());
    abi_all.extend_from_slice(&pad_length(3 * 32 as u16));
    abi_all.extend_from_slice(&pad_length((96 + id_abi.len()) as u16));
    abi_all.extend_from_slice(&pad_length((96 + id_abi.len() + &account_abi.len()) as u16));
    abi_all.extend_from_slice(&id_abi);
    abi_all.extend_from_slice(&account_abi);
    abi_all.extend_from_slice(&request_id_abi);
    abi_all
}

fn pad_all(s: &str) -> Vec<u8> {
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

pub fn eth_sign_str(msg: &str, prv_k: String) -> Vec<u8> {
    let msg_sha = eth_message(msg);
    let prv_k_b = decode_hex(&prv_k).unwrap();
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
    assert_eq!(expected_hash, actual_hash);
}
