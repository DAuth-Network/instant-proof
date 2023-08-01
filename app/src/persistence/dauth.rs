use super::*;
use crate::model::*;
use mysql::prelude::*;
use mysql::*;
use std::str::FromStr;

pub fn insert_account_if_new(pool: &Pool, account: &Account) -> GenericResult<()> {
    let existing_account = query_account(pool, &account)?;
    if !existing_account.is_empty() {
        return Ok(());
    }
    insert_account(pool, &account)?;
    Ok(())
}

pub fn insert_account(pool: &Pool, account: &Account) -> GenericResult<()> {
    let mut conn = pool.get_conn()?;
    let mut tx = conn.start_transaction(TxOpts::default())?;
    let stmt =
        "insert into account(acc_hash, acc_and_type_hash, acc_seal, id_type) values (?,?,?,?)";
    tx.exec_drop(
        stmt,
        (
            &account.acc_hash,
            &account.acc_and_type_hash,
            &account.acc_seal,
            &account.id_type.to_string(),
        ),
    )?;
    tx.commit()?;
    Ok(())
}

pub fn query_account(pool: &Pool, account: &Account) -> GenericResult<Vec<Account>> {
    let mut result: Vec<Account> = Vec::new();
    let mut conn = pool.get_conn()?;
    let stmt = format!(
        "select acc_hash, acc_and_type_hash, acc_seal, id_type from account where acc_hash='{}' and id_type='{}'",
        account.acc_hash,
        account.id_type.to_string()
    );
    conn.query_iter(stmt)?.for_each(|row| {
        let r: (
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
        ) = from_row(row.unwrap());
        result.push(Account {
            acc_hash: r.0,
            acc_and_type_hash: r.1,
            acc_seal: r.2,
            id_type: IdType::from_str(&r.3).unwrap(),
        });
    });
    Ok(result)
}

pub fn insert_auth(pool: &Pool, hist: Auth) -> GenericResult<()> {
    let mut conn = pool.get_conn()?;
    let mut tx = conn.start_transaction(TxOpts::default())?;
    tx.exec_drop(
        "insert into auth (
            acc_hash, acc_and_type_hash, id_type, acc_auth_seq, audience, auth_datetime, auth_exp, request_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            hist.acc_hash,
            hist.acc_and_type_hash,
            hist.id_type.to_string(),
            hist.auth_id,
            hist.audience,
            hist.auth_datetime,
            hist.auth_exp,
            hist.request_id,
        ),
    )?;
    tx.commit()?;
    Ok(())
}

pub fn query_latest_auth_id(pool: &Pool, account: &Account) -> i32 {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    let count: Option<i32> = tx
        .query_first(format!(
            "select count(*) from auth where acc_hash='{}' and id_type='{}'",
            account.acc_hash,
            account.id_type.to_string()
        ))
        .unwrap();
    tx.commit().unwrap();
    return count.unwrap();
}
