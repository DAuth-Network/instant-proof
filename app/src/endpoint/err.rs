
use std::boxed::Box;

pub type GenericError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type GenericResult<T> = Result<T, GenericError>;

pub enum DAuthError {
    DecryptError = 1,
    SendmailError = 2,
    OAuthCodeError = 3,
    OAuthProfileError = 4,
    SessionNotFound = 5,
}

impl DAuthError {
    pub fn to_string(self) -> String {
        match self {
            DAuthError::DecryptError => "DecryptError".to_string(),
            DAuthError::SendmailError => "SendmailError".to_string(),
            DAuthError::OAuthCodeError => "OAuthCodeError".to_string(),
            DAuthError::OAuthProfileError => "OAuthProfileError".to_string(),
            DAuthError::SessionNotFound => "SessionNotFound".to_string(),
        }
    }

    pub fn from_int(error: i32) -> Option<DAuthError>{
        match error {
            1 => Some(DAuthError::DecryptError),
            2 => Some(DAuthError::SendmailError),
            3 => Some(DAuthError::OAuthCodeError),
            4 => Some(DAuthError::OAuthProfileError),
            5 => Some(DAuthError::SessionNotFound),
            _ => None,
        }
    }
}