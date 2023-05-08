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
    eth_message(&msg)
}

pub fn eth_message(message: &String) -> [u8; 32] {
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


#[test]
fn test_eth_message() {
    let message = "Hello, world!";
    let expected_hash = [
        0x82, 0x15, 0x65, 0x40, 0x31, 0x2c, 0x3a, 0x9b, 0x6c, 0x00, 0x22, 0x05, 0x20, 0x68,
        0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
    ];
    let actual_hash = eth_message(message);
    assert_eq!(expected_hash, actual_hash);
}