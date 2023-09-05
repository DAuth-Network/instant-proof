use super::err::*;
use super::log::*;
use super::model::*;
use super::otp;
use super::sgx_utils;
use super::signer::*;
use super::*;

use serde_json::from_str;
use std::result::Result;
use std::vec::Vec;

pub trait Auth {
    fn send_otp(&self, otp_in: &AuthIn) -> Result<(), Error>;
    fn auth_in_one(&self, otp_confirm_in: &AuthIn) -> Result<(InnerAccount, Vec<u8>), Error>;
}

impl Auth for AuthService {
    fn send_otp(&self, req: &AuthIn) -> Result<(), Error> {
        // verify session
        let mut session = match get_session(&req.session_id) {
            Some(s) => s,
            None => {
                error(&format!("session id not found: {}", &req.session_id));
                return Err(Error::new(ErrorKind::SessionError));
            }
        };
        if session.expire() {
            error(&format!("sgx session {:?} expired.", &req.session_id));
            ec_close_session(&req.session_id);
            return Err(Error::new(ErrorKind::SessionError));
        }
        // decrypt otp data
        let otp_str = match decrypt_text(&req.cipher_data, &session) {
            Ok(r) => r,
            Err(err) => {
                error(&format!("decrypt opt data failed."));
                return Err(Error::new(ErrorKind::DataError));
            }
        };
        let otp_data = match serde_json::from_str::<OtpData>(&otp_str) {
            Ok(r) => r,
            Err(err) => {
                error(&format!("parse otp data failed: {}", err));
                return Err(Error::new(ErrorKind::DataError));
            }
        };
        info(&format!("otp account is {}", otp_data.account));
        let otp = sgx_utils::rand().to_string();
        //TODO: sendmail error
        // get otp_client and send mail
        let otp_client = match otp::get_otp_client(otp_data.id_type) {
            Some(r) => r,
            None => {
                error("id type not found");
                return Err(Error::new(ErrorKind::SendChannelError));
            }
        };
        // send otp
        match otp_client.send_otp(&otp_data.account, &req.client, &otp) {
            Ok(_) => {}
            Err(err) => {
                error(&format!("send otp failed: {}", err));
                return Err(Error::new(ErrorKind::SendChannelError));
            }
        }
        // update session
        session.code = otp;
        let inner_account = InnerAccount::build(otp_data.account, otp_data.id_type);
        session.data = inner_account;
        update_session(&req.session_id, &session);
        Ok(())
    }

    fn auth_in_one(&self, req: &AuthIn) -> Result<(InnerAccount, Vec<u8>), Error> {
        // get session
        let mut session = match get_session(&req.session_id) {
            Some(v) => v,
            None => {
                error(&format!("sgx session {:?} not found.", &req.session_id));
                return Err(Error::new(ErrorKind::SessionError));
            }
        };
        if session.expire() {
            error(&format!("sgx session {:?} expired.", &req.session_id));
            ec_close_session(&req.session_id);
            return Err(Error::new(ErrorKind::SessionError));
        }
        // decrypt code
        let auth_data_str = match decrypt_text(&req.cipher_data, &session) {
            Ok(r) => {
                info(&format!("auth code is {}", &r));
                r
            }
            Err(err) => {
                error("decrypt code failed.");
                return Err(Error::new(ErrorKind::DataError));
            }
        };
        let auth_data = match serde_json::from_str::<AuthData>(&auth_data_str) {
            Ok(r) => r,
            Err(err) => {
                error(&format!("parse auth data failed: {}", err));
                return Err(Error::new(ErrorKind::DataError));
            }
        };
        // get account when auth success
        let result: Result<InnerAccount, Error> = match auth_data.id_type {
            IdType::Mailto | IdType::Tel => {
                // when id_type is mailto or tel, code equal -> auth success
                if !auth_data.code.eq(&session.code) {
                    info("confirm code not match, returning");
                    Err(Error::new(ErrorKind::OtpCodeError))
                } else {
                    Ok(session.data.clone())
                }
            }
            _ => {
                // when id_type is others, oauth success -> auth success
                match oauth::get_oauth_client(auth_data.id_type) {
                    Some(r) => match r.oauth(&auth_data.code, &req.client.client_redirect_url) {
                        Ok(n) => Ok(n),
                        Err(e) => {
                            error(&format!("oauth failed {:?}", e));
                            Err(Error::new(ErrorKind::OAuthCodeError))
                        }
                    },
                    None => Err(Error::new(ErrorKind::DataError)),
                }
            }
        };
        let mut account = match result {
            Ok(r) => r,
            Err(e) => {
                error(&format!("auth failed {:?}", e));
                return Err(e);
            }
        };
        // when success, seal the account
        match account.seal_and_hash(&get_config_seal_key()) {
            Ok(()) => {}
            Err(e) => {
                error(&format!("seal and hash failed {:?}", e));
                return Err(e);
            }
        }
        // sign the auth
        let auth = InnerAuth {
            account: &account,
            auth_data: &auth_data,
            client: &req.client,
        };
        let signer = get_signer(&auth_data.sign_mode);
        let dauth_signed = match signer.sign(&auth) {
            Ok(r) => r,
            Err(e) => {
                error(&format!("sign failed {:?}", e));
                return Err(Error::new(ErrorKind::DataError));
            }
        };
        info(&format!("dauth is {:?}", &dauth_signed));
        let cipher_dauth_b = session.encrypt(&dauth_signed);
        info(&format!("cipher dauth is {:?}", &cipher_dauth_b));
        Ok((account, cipher_dauth_b))
    }
}
