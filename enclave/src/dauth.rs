pub fn send_otp() -> Result<(), Error> {
    // verify session
    let session = match get_session(&req.session_id) {
        Some(s) => s,
        None => {
            return Error::new(ErrorKind::SessionError);
        }
    };
    if session.expire() {
        error(&format!("sgx session {:?} expired.", &req.session_id));
        unsafe {
            *error_code = Error::new(ErrorKind::SessionError).to_int();
        }
        ec_close_session(&req.session_id);
        return sgx_status_t::SGX_SUCCESS;
    }
    // decrypt account
    let account_r = decrypt_text_to_text(&req.cipher_account, &session);
    if account_r.is_err() {
        error(&format!("decrypt opt account failed."));
        unsafe {
            *error_code = Error::new(ErrorKind::DataError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    let account = account_r.unwrap();
    info(&format!("otp account is {}", account));
    let otp = sgx_utils::rand();
    //TODO: sendmail error
    // get otp_client and send mail
    let otp_client_o = otp::get_otp_client(req.id_type);
    if otp_client_o.is_none() {
        unsafe {
            *error_code = Error::new(ErrorKind::SendChannelError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    // send otp
    let otp_client = otp_client_o.unwrap();
    let otp_r = otp_client.send_otp(&account, &req.client, &otp.to_string());
    if otp_r.is_err() {
        error("send otp failed");
        unsafe {
            *error_code = Error::new(ErrorKind::SendChannelError).to_int();
        }
        return sgx_status_t::SGX_SUCCESS;
    }
    // update session
    session.code = otp.to_string();
    let inner_account = InnerAccount::build(account, req.id_type);
    session.data = inner_account;
    update_session(&req.session_id, &session);
    unsafe {
        *error_code = 255;
    }
}

pub fn auth_in_one() -> Result {}
