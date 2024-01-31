/*
This file describes all ErrorKinds that could happen during an authentication:
- ErrorKind::ClientError => 0,
    Each client that is using dauth sdk will be assigned an client id.
    For testing purpose, an client_id demo will be assigned.
    If the client_id is empty, this error will be returned.
    This error doesn't happen inside sgx.
- ErrorKind::DecryptError => 1,
    When decryption data is invalid, this error will be returned.
- ErrorKind::SendChannelError => 2,
    When sending otp code to user failed, this error will be returned.
- ErrorKind::OAuthCodeError => 3,
    When exchanging oauth code failed, this error will be returned.
- ErrorKind::OAuthProfileError => 4,
    When getting oauth profile failed, this error will be returned.
- ErrorKind::SessionError => 5,
    When session is expired or not found, this error will be returned.
- ErrorKind::DataError => 6,
    DataError is a general error, when serializing or deserializing json, encrypt data, fails,
    this error will be returned.
- ErrorKind::SgxError => 7,
    SgxError is a general error, when sgx fails, this error will be returned.
- ErrorKind::DbError => 8,
    DbError is a general error, when insert or query db fails, this error will be returned.
    This doesn't happen inside sgx.
- ErrorKind::OtpCodeError => 9,
    When otp code mismatch, this error will be returned.
 */
use std::boxed::Box;
use std::error;
use std::fmt;

pub type GenericError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type GenericResult<T> = Result<T, GenericError>;

#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Error {
        Error { kind }
    }

    /// Return the kind of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind.clone()
    }

    pub fn from_int(error_code: u8) -> Option<Error> {
        match ErrorKind::from_int(error_code) {
            Some(kind) => Some(Error::new(kind)),
            None => None,
        }
    }

    pub fn to_int(&self) -> u8 {
        match self.kind {
            ErrorKind::ClientError => 0,
            ErrorKind::DecryptError => 1,
            ErrorKind::SendChannelError => 2,
            ErrorKind::OAuthCodeError => 3,
            ErrorKind::OAuthProfileError => 4,
            ErrorKind::SessionError => 5,
            ErrorKind::DataError => 6,
            ErrorKind::SgxError => 7,
            ErrorKind::DbError => 8,
            ErrorKind::OtpCodeError => 9,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ErrorKind {
    ClientError = 0,
    DecryptError = 1,
    SendChannelError = 2,
    OAuthCodeError = 3,
    OAuthProfileError = 4,
    SessionError = 5,
    DataError = 6,
    SgxError = 7,
    DbError = 8,
    OtpCodeError = 9,
}

impl ErrorKind {
    pub fn from_int(error_code: u8) -> Option<ErrorKind> {
        match error_code {
            0 => Some(ErrorKind::ClientError),
            1 => Some(ErrorKind::DecryptError),
            2 => Some(ErrorKind::SendChannelError),
            3 => Some(ErrorKind::OAuthCodeError),
            4 => Some(ErrorKind::OAuthProfileError),
            5 => Some(ErrorKind::SessionError),
            6 => Some(ErrorKind::DataError),
            7 => Some(ErrorKind::SgxError),
            8 => Some(ErrorKind::DbError),
            9 => Some(ErrorKind::OtpCodeError),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::ClientError => write!(f, "invalid client_id"),
            ErrorKind::DecryptError => write!(f, "decrypt failed"),
            ErrorKind::SendChannelError => write!(f, "send message failed"),
            ErrorKind::OAuthCodeError => write!(f, "failed to exchange oauth code"),
            ErrorKind::OAuthProfileError => write!(f, "failed to get oauth profile"),
            ErrorKind::SessionError => write!(f, "session expired or not found"),
            ErrorKind::DataError => write!(f, "data error, please check your parameter"),
            ErrorKind::SgxError => write!(f, "sgx failed"),
            ErrorKind::DbError => write!(f, "insert or query db failed"),
            ErrorKind::OtpCodeError => write!(f, "otp code mismatch"),
        }
    }
}
