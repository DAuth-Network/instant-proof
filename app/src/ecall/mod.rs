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

    pub fn ec_send_otp(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        auth_type: i32,
        session_id: &[u8;32],
        cipher_channel: *const u8,
        cipher_channel_size: usize,
    ) -> sgx_status_t;

    pub fn ec_confirm_otp(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        cipher_code: *const u8,
        cipher_code_size: usize,
        request_id: *const u8,
        request_id_size: usize,
        account_b: *mut u8,
        max_len: usize,
        account_b_size: *mut usize,
        signature: &mut [u8;65]
    ) -> sgx_status_t;

    pub fn ec_auth_oauth(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        cipher_code: *const u8,
        cipher_code_size: usize,
        request_id: *const u8,
        request_id_size: usize,
        auth_type: i32,
        account_b: *mut u8,
        max_len: usize,
        account_b_size: *mut usize,
        signature: &mut [u8;65]
    ) -> sgx_status_t;


    /* 
    pub fn ec_sign_auth(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        auth_b: *const u8,
        auth_b_size: usize,
        pub_k: &mut [u8;65],
        signature: &mut [u8;65]
    ) -> sgx_status_t;

    pub fn ec_sign_auth_jwt(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        auth_b: *const u8,
        auth_b_size: usize,
        token: &mut [u8;2048],
        token_size: *mut u32
    ) -> sgx_status_t;
    */
    
    pub fn ec_get_sign_pub_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pub_key: &mut [u8;2048],
        pub_key_size: *mut u32
    ) -> sgx_status_t;

    pub fn ec_test(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
    ) -> sgx_status_t;

    pub fn ec_send_seal_email(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        session_id: &[u8;32],
        seal_email: *const u8,
        seal_email_size: usize
    ) -> sgx_status_t;

}

