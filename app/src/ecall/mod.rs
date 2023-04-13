extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;


extern {

    pub fn ec_key_exchange(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        user_pub_key: &[u8;64],
        tee_pub_key: &mut [u8;64],
        session_id: &mut [u8;32]
    ) -> sgx_status_t;

    pub fn ec_set_conf(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        config_b: *const u8,
        config_b_size: usize
    ) -> sgx_status_t;

    pub fn ec_close_session(
        eid: sgx_enclave_id_t, 
        retval: *mut sgx_status_t,
        session_id: &[u8;32]
    ) -> sgx_status_t;

    pub fn ec_seal(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        value: *const u8,
        value_size: usize,
        value_hash: &mut[u8;32],
        value_seal: &mut [u8;1024],
        value_seal_size: *mut u32
    ) -> sgx_status_t;

    pub fn ec_send_cipher_email(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        cipher_email: *const u8,
        cipher_email_size: usize,
    ) -> sgx_status_t;

    pub fn ec_send_seal_email(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        seal_email: *const u8,
        seal_email_size: usize
    ) -> sgx_status_t;

    pub fn ec_confirm_email(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        cipher_code: *const u8,
        cipher_code_size: usize,
        email_hash: &mut [u8;32],
        email_seal: &mut [u8;1024],
        email_seal_size: *mut u32
    ) -> sgx_status_t;

    pub fn ec_auth_oauth(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        cipher_code: *const u8,
        cipher_code_size: usize,
        oauth_type: i32,
        auth_hash: &mut [u8;32],
        auth_seal: &mut [u8;1024],
        auth_seal_size: *mut u32
    ) -> sgx_status_t;

    pub fn ec_sign_auth(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        auth_hash: &[u8;32],
        auth_seq: i32,
        auth_exp: u64,
        pub_k: &mut [u8;65],
        signature: &mut [u8;65]
    ) -> sgx_status_t;

    pub fn ec_sign_auth_jwt(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        auth_hash: &[u8;32],
        auth_seq: i32,
        auth_exp: u64,
        token: &mut [u8;2048],
        token_size: *mut u32
    ) -> sgx_status_t;

    pub fn ec_test(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
    ) -> sgx_status_t;

}

