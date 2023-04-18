
use std::boxed::Box;

pub type GenericError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type GenericResult<T> = Result<T, GenericError>;

#[derive(Debug, Clone)]
pub enum DAuthError {
    ClientError = 0,
    DecryptError = 1,
    SendmailError = 2,
    OAuthCodeError = 3,
    OAuthProfileError = 4,
    SessionError = 5,
    DataError = 6,
    SgxError = 7,
    DbError = 8,
}

impl DAuthError {
    pub fn to_string(self) -> String {
        match self {
            DAuthError::ClientError => "ClientError".to_string(),
            DAuthError::DecryptError => "DecryptError".to_string(),
            DAuthError::SendmailError => "SendmailError".to_string(),
            DAuthError::OAuthCodeError => "OAuthCodeError".to_string(),
            DAuthError::OAuthProfileError => "OAuthProfileError".to_string(),
            DAuthError::SessionError => "SessionError".to_string(),
            DAuthError::DataError => "DataError".to_string(),
            DAuthError::SgxError => "SgxError".to_string(),
            DAuthError::DbError => "DbError".to_string(),
        }
    }

    pub fn to_message(self) -> String {
        match self {
            DAuthError::ClientError => "invalid client_id".to_string(),
            DAuthError::DecryptError => "decrypt failed".to_string(),
            DAuthError::SendmailError => "sendmail failed".to_string(),
            DAuthError::OAuthCodeError => "failed to exchange oauth code".to_string(),
            DAuthError::OAuthProfileError => "failed to get oauth profile".to_string(),
            DAuthError::SessionError => "session expired or not found".to_string(),
            DAuthError::DataError => "data error, please check your parameter".to_string(),
            DAuthError::SgxError => "sgx failed".to_string(),
            DAuthError::DbError => "insert or query db failed".to_string(),
        }
    }

    pub fn from_int(error: i32) -> Option<DAuthError>{
        match error {
            0 => Some(DAuthError::ClientError),
            1 => Some(DAuthError::DecryptError),
            2 => Some(DAuthError::SendmailError),
            3 => Some(DAuthError::OAuthCodeError),
            4 => Some(DAuthError::OAuthProfileError),
            5 => Some(DAuthError::SessionError),
            6 => Some(DAuthError::DataError),
            7 => Some(DAuthError::SgxError),
            8 => Some(DAuthError::DbError),
            _ => None,
        }
    }
}