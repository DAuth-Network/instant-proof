/*
    Session keeps user session_id and shared_key
    Sessions keeps the whole table of session_id -> share key
*/


use std::vec::Vec;
use std::fmt;
use std::collections::HashMap;
use sgx_types::*;
use std::convert::TryInto;
use std::prelude::v1::*;

use super::sgx_utils;
use super::os_utils;
use super::log::*;

/// User state includes a Map
/// which stores user account -> confirm code mapping
#[derive(Clone)]
pub struct Session {
    pub shr_k: [u8;16],
    pub session_id: [u8;32], // sha256
    pub code: String,
    pub data: String,
}

impl Session {
    
    pub fn new(session_id: [u8;32], shr_k: [u8;16]) -> Self {
        Self {
            shr_k: shr_k,
            session_id: session_id,
            code: "".to_string(),
            data: "".to_string()
        }
    }

    pub fn decrypt(&self, content: &[u8]) -> Vec<u8> {
        sgx_utils::decrypt(
            &self.shr_k,
            content,
        )
    }

    pub fn encrypt(&self, content: &[u8]) -> Vec<u8> {
        sgx_utils::encrypt(
            &self.shr_k,
            content
        )
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
         .field("shr_k", &os_utils::encode_hex(&self.shr_k))
         .field("session_id", &self.session_id)
         .finish()
    }
}



pub struct Sessions {
    pub state: HashMap<[u8;32], Session>,
    pub prv_k: sgx_ec256_private_t,
}

impl Sessions {
    pub fn new(
        prv_k: sgx_ec256_private_t
    ) -> Self {
        Self {
            state: HashMap::new(),
            prv_k: prv_k,
        }
    }

    pub fn register_session(&mut self, user_key: [u8;64]) -> [u8;32] {
        let user_pub_k = sgx_utils::pub_k_from_user(&user_key);    
        let shr_k_result = sgx_utils::compute_shared_dhkey(
            &self.prv_k, 
            &user_pub_k
        );

        if let Err(err) = shr_k_result {
            info(&format!("user pub key gen share key fail {}", err));
            return [0;32];
        }
        let mut shr_k_reverse = shr_k_result.unwrap().clone();
        shr_k_reverse.reverse();
        info(&format!("user share key {:?}", shr_k_reverse));
        let sha_result= sgx_utils::sha256(&user_pub_k);
        if let Err(err) = sha_result {
            info(&format!("sha256 failed {}", err));
            return [0;32];
        }
        let sha = sha_result.unwrap();
        let session = Session::new(
            sha, 
            shr_k_reverse[16..].try_into().unwrap());
        self.state.insert(sha, session);
        return sha;
    }

    pub fn close_session(&mut self, session_id: &[u8;32]) {
        if let Some(v) = self.state.get(session_id) {
            self.state.remove(session_id);
        }
    }

    pub fn get_session(&self, session_id: &[u8;32]) -> Option<Session> {
        match self.state.get(session_id) {
            None => None,
            Some(s) => Some(s.to_owned())
        }
    }

    pub fn update_session(&mut self, k:&[u8;32], v: &Session) {
        self.state.insert(k.clone(), v.clone());
    }

}

