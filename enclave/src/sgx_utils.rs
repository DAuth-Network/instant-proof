use sgx_tcrypto::*;
use sgx_tseal::{SgxSealedData, SgxUnsealedData};
use sgx_types::*;
use std::slice;
use std::string::{String, ToString};
use std::vec::Vec;

use std::convert::TryInto;

use crate::os_utils;

use super::err::*;
use super::log::*;

pub fn pub_k_from_user(user_key: &[u8; 64]) -> sgx_ec256_public_t {
    let mut gx: [u8; 32] = user_key[0..32].try_into().unwrap();
    let mut gy: [u8; 32] = user_key[32..].try_into().unwrap();
    gx.reverse();
    gy.reverse();
    sgx_ec256_public_t { gx, gy }
}

pub fn sig_from_user(signature: &[u8; 64]) -> sgx_ec256_signature_t {
    let gx: [u8; 32] = signature[0..32].try_into().unwrap();
    let gy: [u8; 32] = signature[32..].try_into().unwrap();
    let x: [u32; 8] = u8_to_u32(gx);
    let y: [u32; 8] = u8_to_u32(gy);
    sgx_ec256_signature_t { x, y }
}

fn u8_to_u32(x: [u8; 32]) -> [u32; 8] {
    let mut result = [0_u32; 8];
    for i in (0..32).step_by(4) {
        result[i / 4] = as_u32_le(&x[i..i + 4].try_into().unwrap());
    }
    result
}

fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

pub fn key_to_bigendian(pub_k: &sgx_ec256_public_t) -> [u8; 64] {
    let mut gx: [u8; 32] = pub_k.gx.clone();
    let mut gy: [u8; 32] = pub_k.gy.clone();
    gx.reverse();
    gy.reverse();
    [gx, gy].concat().try_into().unwrap()
}

pub fn compute_shared_dhkey(
    prv_k: &sgx_ec256_private_t,
    pub_k: &sgx_ec256_public_t,
) -> GenericResult<[u8; 32]> {
    let handle: SgxEccHandle = SgxEccHandle::new();
    handle.open()?;
    let share_k_result = handle.compute_shared_dhkey(prv_k, pub_k);
    match share_k_result {
        Ok(r) => Ok(r.s),
        Err(err) => Err(GenericError::from(err)),
    }
}

pub fn edcsa_verify_signature(
    data: &[u8],
    pub_k: &sgx_ec256_public_t,
    signature: &sgx_ec256_signature_t,
) -> GenericResult<bool> {
    let handle: SgxEccHandle = SgxEccHandle::new();
    handle.open()?;
    let result = handle.ecdsa_verify_slice(data, pub_k, signature);
    match result {
        Ok(r) => Ok(r),
        Err(err) => Err(GenericError::from(err)),
    }
}

pub fn sha256(pub_k: &sgx_ec256_public_t) -> GenericResult<([u8; 32])> {
    let slice = [pub_k.gx, pub_k.gy].concat();
    let hash_v = rsgx_sha256_slice(&slice)?;
    let r: [u8; 32] = hash_v.try_into()?;
    Ok(r)
}

pub fn hash(content: &[u8]) -> GenericResult<([u8; 32])> {
    let hash_v = rsgx_sha256_slice(content)?;
    let r: [u8; 32] = hash_v.try_into()?;
    Ok(r)
}

pub fn decrypt(key: &[u8; 16], cipher_text: &[u8]) -> GenericResult<Vec<u8>> {
    info(&format!("aes_gcm_128_decrypt invoked!"));
    // handle cipher_text length < 16
    if cipher_text.len() <= 16 {
        error("encrypted length must not be less than 16 bytes");
        return Err(GenericError::from("encrypted length shorter than 16"));
    }
    let mac: &[u8; 16] = &cipher_text[0..16].try_into()?;
    let cipher_text_core = &cipher_text[16..];
    let mut plain_text: Vec<u8> = vec![0; cipher_text_core.len()];
    let iv: [u8; 12] = [0; 12];
    let aad_array: [u8; 0] = [0; 0];
    info(&format!("key is {:?}", key));
    info(&format!("cipher text is {:?}", cipher_text));
    let result =
        rsgx_rijndael128GCM_decrypt(key, cipher_text_core, &iv, &aad_array, mac, &mut plain_text);
    match result {
        Ok(_) => Ok(plain_text),
        Err(err) => {
            error(&format!("decrypt failed {}", err));
            Err(GenericError::from(err))
        }
    }
}

pub fn encrypt(key: &[u8; 16], plain_text: &[u8]) -> Vec<u8> {
    info("aes_gcm_128_encrypt invoked!");
    let mut cipher_text: Vec<u8> = vec![0; plain_text.len()];
    let mut mac = [0; 16];
    let iv: [u8; 12] = [0; 12];
    let aad_array: [u8; 0] = [0; 0];
    let result =
        rsgx_rijndael128GCM_encrypt(key, plain_text, &iv, &aad_array, &mut cipher_text, &mut mac);
    match result {
        Ok(_) => [mac.to_vec(), cipher_text].concat(),
        Err(err) => {
            error(&format!("encrypt failed {}", err));
            Vec::new()
        }
    }
}

pub fn rand() -> u32 {
    let rand = sgx_rand::random::<u32>();
    let six_digits = rand % 1000000;
    if six_digits < 100000 {
        return six_digits + 100000;
    }
    six_digits
}

pub fn rand_bytes() -> [u8; 32] {
    sgx_rand::random::<[u8; 32]>()
}

// when using seal, sgx generates a seal_key using cpu and sgx signing key
// when using iseal, sgx use config key
pub fn i_seal(plain_binary: &[u8], key: &str) -> GenericResult<Vec<u8>> {
    let key_b = os_utils::decode_hex(&key)?;
    let key_b_128: [u8; 16] = key_b.try_into().unwrap();
    Ok(encrypt(&key_b_128, plain_binary))
}

pub fn i_unseal(plain_binary: &[u8], key: &str) -> GenericResult<Vec<u8>> {
    let key_b = os_utils::decode_hex(&key)?;
    let key_b_128: [u8; 16] = key_b.try_into().unwrap();
    match decrypt(&key_b_128, plain_binary) {
        Ok(r) => Ok(r),
        Err(err) => Err(GenericError::from(err)),
    }
}

pub fn seal(plain_binary: &[u8]) -> ([u8; 1024], u32) {
    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, plain_binary);
    if result.is_err() {
        info("seal failed");
        return ([0_u8; 1024], 1024);
    }
    let raw_sealed = [0_u8; 1024];
    let sgx_sealed = result.unwrap();
    let mac_len = sgx_sealed.get_add_mac_txt_len();
    let en_len = sgx_sealed.get_encrypt_txt_len();
    let seal_len = unsafe { sgx_calc_sealed_data_size(mac_len, en_len) };
    info(&format!("sealed len is {}", seal_len));
    unsafe {
        sgx_sealed.to_raw_sealed_data_t(raw_sealed.as_ptr() as *mut sgx_sealed_data_t, seal_len);
    };
    (raw_sealed, seal_len)
}

pub fn unseal(raw_sealed: &[u8]) -> Vec<u8> {
    info(&format!("unseal {:?}", raw_sealed));
    let opt = unsafe {
        SgxSealedData::<[u8]>::from_raw_sealed_data_t(
            raw_sealed.as_ptr() as *mut sgx_sealed_data_t,
            raw_sealed.len().try_into().unwrap(),
        )
    };
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            error("seal data init failed");
            return Vec::new();
        }
    };
    let result = sealed_data.unseal_data();
    match result {
        Ok(x) => x.get_decrypt_txt().to_vec(),
        Err(err) => {
            error(&format!("unseal data failed {}", err));
            Vec::new()
        }
    }
}

/// The following are for unit tests

pub fn test_pub_k_from_user() {
    // Sample user key with known expected output
    let user_key: [u8; 64] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    ];

    // Expected output after reversing gx and gy
    let pub_expect = sgx_ec256_public_t {
        gx: [
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ],
        gy: [
            64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43,
            42, 41, 40, 39, 38, 37, 36, 35, 34, 33,
        ],
    };

    // Call the function to be tested
    let pub_key = pub_k_from_user(&user_key);

    // Assert that the actual output matches the expected output
    assert_eq!(pub_key.gx, pub_expect.gx);
    assert_eq!(pub_key.gy, pub_expect.gy);
}

pub fn test_as_u32_be_with_valid_input() {
    // Sample array with known expected output
    let array: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    let expected_output = 0x12345678;

    // Call the function to be tested
    let actual_output = as_u32_be(&array);

    // Assert that the actual output matches the expected output
    assert_eq!(actual_output, expected_output);
}

pub fn test_as_u32_be_with_all_zero_input() {
    // Test with an array of all zeros
    let array: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    let expected_output = 0x00000000;

    // Call the function to be tested
    let actual_output = as_u32_be(&array);

    // Assert that the actual output matches the expected output
    assert_eq!(actual_output, expected_output);
}

pub fn test_as_u32_be_with_all_one_input() {
    // Test with an array of all ones
    let array: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
    let expected_output = 0xFFFFFFFF;

    // Call the function to be tested
    let actual_output = as_u32_be(&array);

    // Assert that the actual output matches the expected output
    assert_eq!(actual_output, expected_output);
}

pub fn test_rand() {
    let six_digits = rand();
    assert!(six_digits >= 100000);
    assert!(six_digits <= 999999);
}

pub fn test_as_u32_le_with_valid_input() {
    let array: [u8; 4] = [0x78, 0x56, 0x34, 0x12]; // Little-endian order
    let expected_output = 0x12345678;

    let actual_output = as_u32_le(&array);

    assert_eq!(actual_output, expected_output);
}

pub fn test_as_u32_le_with_all_zero_input() {
    let array: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    let expected_output = 0x00000000;

    let actual_output = as_u32_le(&array);

    assert_eq!(actual_output, expected_output);
}

pub fn test_as_u32_le_with_all_one_input() {
    let array: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
    let expected_output = 0xFFFFFFFF;

    let actual_output = as_u32_le(&array);

    assert_eq!(actual_output, expected_output);
}

pub fn test_encrypt_decrypt() {
    let secret = "hello,world".to_string();
    let bytes = rand_bytes();
    let key: [u8; 16] = bytes[0..16].try_into().unwrap();
    let cipher_text = encrypt(&key, secret.as_bytes());
    let plain_text = decrypt(&key, &cipher_text);
    assert_eq!(secret.as_bytes(), plain_text.unwrap().as_slice());
}

pub fn test_encrypt_decrypt_invalid() {
    let secret = "hello,world".to_string();
    let bytes = rand_bytes();
    let key: [u8; 16] = bytes[0..16].try_into().unwrap();
    let cipher_text = encrypt(&key, secret.as_bytes());
    let plain_text = decrypt(&key, &cipher_text[0..10]);
    match plain_text {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    }
}
