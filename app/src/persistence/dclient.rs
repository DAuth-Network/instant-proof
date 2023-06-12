use super::*;
use mysql::prelude::*;
use mysql::*;
use serde_derive::Serialize;
use time::PrimitiveDateTime;

#[derive(Debug, Clone, Serialize)]
pub struct Client {
    pub client_name: String,
    pub client_id: String,
    pub client_origin: String,
    pub client_redirect_url: String,
}

pub fn query_clients(pool: &Pool) -> GenericResult<Vec<Client>> {
    let mut result: Vec<Client> = Vec::new();
    let mut conn = pool.get_conn()?;
    let stmt = "select client_name, client_id, client_origin, client_redirect_url from client";
    conn.query_iter(stmt)?.for_each(|row| {
        let r: (
            std::string::String,
            std::string::String,
            std::string::String,
            std::string::String,
        ) = from_row(row.unwrap());
        result.push(Client {
            client_name: r.0,
            client_id: r.1,
            client_origin: r.2,
            client_redirect_url: r.3,
        });
    });
    Ok(result)
}
