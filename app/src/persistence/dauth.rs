use mysql::*;
use mysql::prelude::*;
use time::PrimitiveDateTime;
use crate::endpoint::err::*;

#[derive(Debug, Clone)]
pub struct Account {
    pub acc_hash: String,
    pub acc_seal: String,
    pub auth_type: AuthType
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AuthType {
    Email = 0,
    Sms = 1,
    Google = 5,
    Twitter = 6,
    Discord = 7,
    Telegram = 8,
    Github = 9,
}

impl AuthType {
    pub const ALL: [Self;7] = [
        Self::Email,
        Self::Sms,
        Self::Discord,
        Self::Google,
        Self::Github,
        Self::Telegram,
        Self::Twitter
    ];

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "email" => Some(Self::Email),
            "sms" => Some(Self::Sms),
            "google" => Some(Self::Google),
            "twitter" => Some(Self::Twitter),
            "discord" => Some(Self::Discord),
            "telegram" => Some(Self::Telegram),
            "github" => Some(Self::Github),
            _ => None
        }
    }
    
    pub fn from_int(i: i32) -> Option<Self> {
        match i {
            0 => Some(Self::Email),
            1 => Some(Self::Sms),
            5 => Some(Self::Google),
            6 => Some(Self::Twitter),
            7 => Some(Self::Discord),
            8 => Some(Self::Telegram),
            9 => Some(Self::Github),
            _ => None
        }
    }

    pub fn to_string(self) -> String {
        match self {
            AuthType::Email => "email".to_string(),
            AuthType::Sms => "sms".to_string(),
            AuthType::Google => "google".to_string(),
            AuthType::Twitter => "twitter".to_string(),
            AuthType::Discord => "discord".to_string(),
            AuthType::Telegram => "telegram".to_string(),
            AuthType::Github => "github".to_string(),
        }
    }
}


#[derive(Debug, Clone)]
pub struct Auth {
    pub acc_hash: String,
    pub auth_id: i32,
    pub auth_type: AuthType,
    pub auth_datetime: PrimitiveDateTime,
    pub auth_exp: u64,
    pub audience: String,
    pub request_id: String,
}


pub fn insert_account_if_new(
    pool: &Pool, account: &Account
) -> GenericResult<()> {
    let existing_account = query_account(pool, &account)?;
    if !existing_account.is_empty() {
        return Ok(());
    }
    insert_account(pool, &account)?;
    Ok(())
}


pub fn insert_account(
    pool: &Pool, account: &Account
) -> GenericResult<()> {
    let mut conn = pool.get_conn()?;
    let mut tx = conn.start_transaction(TxOpts::default())?;
    let stmt = "insert into account(acc_hash, acc_seal, auth_type) values (?,?,?)";
    tx.exec_drop(
        stmt,
        (&account.acc_hash, &account.acc_seal, &account.auth_type.to_string()))?;
    tx.commit()?;
    Ok(())
}


pub fn query_account(
    pool: &Pool, account: &Account
) -> GenericResult<Vec<Account>> {
    let mut result: Vec<Account> = Vec::new();
    let mut conn = pool.get_conn()?;
    let stmt = format!(
        "select acc_hash, acc_seal from account where acc_hash='{}'",
        account.acc_hash
    );
    conn.query_iter(stmt)?.for_each(|row| {
        let r :(
            std::string::String,
            std::string::String,
            std::string::String,
        ) = from_row(row.unwrap());
        result.push(Account {
            acc_hash: r.0,
            acc_seal: r.1,
            auth_type: AuthType::from_str(&r.2).unwrap(),
        });
    });
    Ok(result)
}

pub fn insert_auth(
    pool: &Pool, hist: Auth
) -> GenericResult<()> {
    let mut conn = pool.get_conn()?;
    let mut tx = conn.start_transaction(TxOpts::default())?;
    tx.exec_drop(
        "insert into auth (
            acc_hash, auth_id, auth_type, auth_datetime, auth_exp, audience
        ) values (?, ?, ?, ?, ?, ?)",
        (hist.acc_hash,
            hist.auth_id,
            hist.auth_type.to_string(),
            hist.auth_datetime,
            hist.auth_exp,
            hist.audience))?;
    tx.commit()?;
    Ok(())
}

pub fn query_latest_auth_id(pool: &Pool, acc_hash: &String) -> i32{
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    let count: Option<i32> = tx.query_first(
        format!("select count(*) from auth where acc_hash = '{}'", acc_hash)
    ).unwrap();
    tx.commit().unwrap();
    return count.unwrap();
}
