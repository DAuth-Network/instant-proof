use mysql::*;
use mysql::prelude::*;
use time::PrimitiveDateTime;
use crate::endpoint::err::*;

#[derive(Debug, Clone)]
pub struct Client {
    pub client_name: String,
    pub client_id: String,
    pub client_origin: String,
}

pub fn query_client(
    pool: &Pool
) -> GenericResult<Vec<Client>> {
    let mut result: Vec<Client> = Vec::new();
    let mut conn = pool.get_conn()?;
    let stmt = "select client_name, client_id, client_origin from client";
    conn.query_iter(stmt)?.for_each(|row| {
        let r :(
            std::string::String,
            std::string::String,
            std::string::String
        ) = from_row(row.unwrap());
        result.push(Client {
            client_name: r.0,
            client_id: r.1,
            client_origin: r.2
        });
    });
    Ok(result)
}
