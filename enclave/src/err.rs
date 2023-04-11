
use std::boxed::Box;
use std::error;

pub type GenericError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type GenericResult<T> = Result<T, GenericError>;


#[derive(Clone, Debug)]
pub enum ErrorKind {
    DecryptError,
    SendMailError,
    OauthAccessTokenError,
    OauthProfileError,
}

#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
}

