
use std::boxed::Box;

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
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

/// The kind of an error that can occur.
#[derive(Clone, Debug)]
pub enum ErrorKind {
    DbError(String),
    DataError(String),
    SessionError(String),
    SgxError(String),
    OauthError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ErrorKind::DbError(msg) => write!(f, "Database error: {}", msg),
            ErrorKind::DataError(msg) => write!(f, "Data error: {}", msg),
            ErrorKind::SessionError(msg) => write!(f, "Session error: {}", msg),
            ErrorKind::SgxError(msg) => write!(f, "SGX error: {}", msg),
            ErrorKind::OauthError(msg) => write!(f, "OAuth error: {}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match &self.kind {
            ErrorKind::DbError(msg) => msg,
            ErrorKind::DataError(msg) => msg,
            ErrorKind::SessionError(msg) => msg,
            ErrorKind::SgxError(msg) => msg,
            ErrorKind::OauthError(msg) => msg,
        }
    }
}

