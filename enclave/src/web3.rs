use super::sgx_utils::*;
use super::os_utils::*;
use super::log::*;
use tiny_keccak::*;
use std::string::*;

pub fn gen_auth_bytes(sgx_pub_key: &[u8;65],
    auth_hash: &[u8;32],
    auth_id: i32,
    exp: u64
) -> [u8;32] {
    let sgx_hex = encode_hex(sgx_pub_key);
    let auth_hex = encode_hex(auth_hash);
    let msg = format!("{}.{}.{}.{}", sgx_hex, auth_hex, auth_id, exp);
    eth_message(msg)
}

pub fn eth_message(message: String) -> [u8; 32] {
    let msg = format!(
        "{}{}{}",
        "\x19Ethereum Signed Message:\n",
        message.len(),
        message
    );
    info(&format!("signing msg is {}", msg));
    let mut hasher = Keccak::v256();
    let mut output = [0_u8;32];
    hasher.update(msg.as_bytes());
    hasher.finalize(&mut output);
    output
}


