
use std::net::TcpStream;
use http_req::{request::{RequestBuilder, Method}, tls, uri::Uri};
use std::string::String;
use std::vec::Vec;
use super::err::*;
use std::io::prelude::*;
use std::io::Write;
use std::string::ToString;
use std::str;
use super::config::Email;
use super::log::*;


pub fn sendmail(conf: &Email, to_account:&str, c_code: &str) -> GenericResult<()> {
    info("send mail");
    let from_account = &conf.sender;
    let account = &conf.account;
    let password = &conf.password;
    let server = &conf.server;
    let port = 465;
    let conn_addr = format!("{}:{}", server, port);
    let raw_stream = TcpStream::connect(conn_addr).unwrap();
    let mut stream = tls::Config::default()
        .connect(server, raw_stream)
        .unwrap();
    tls_read(&mut stream);
    let cmds = [
        "EHLO dauth.network",
        "AUTH LOGIN",
        account,
        password,
        &format!("MAIL FROM: <{}>", from_account),
        &format!("RCPT TO: <{}>", to_account),
        "DATA"
    ];
    for c in cmds {
        tls_write(&mut stream, c);
    }
    let m_lines = &format!("subject: DAuth Verification Code
from: <{}> 
to: <{}> 

Please use the following code to verify your account:

{}
.", from_account, to_account, c_code);
    let result = tls_write(&mut stream, m_lines);
    tls_write(&mut stream, "QUIT");
    info(&format!("mail result is {}", result));
    if result.contains("250 Ok") {
        Ok(())
    } else {
        Err(GenericError::from("send mail failed"))
    }
}


fn tls_read(conn: &mut tls::Conn<TcpStream>) -> String {
    let mut buffer = [0;1024];
    //read();
    let size = conn.read(&mut buffer).unwrap();
    let output: &str = str::from_utf8(&buffer[0..size]).unwrap();
    info(&format!("S: {}", output));
    return output.to_string();
}

fn tls_write(conn: &mut tls::Conn<TcpStream>, content: &str) -> String {
    content.split('\n').for_each(|l| {
        info(&format!("C: {}", l));
        let l_enter = format!("{}\r\n", l);
        let r1 = conn.write(l_enter.as_bytes()).unwrap();
        info(&format!("{} bytes written", r1));
    });
    conn.flush().unwrap();
    tls_read(conn)
}


pub fn encode_hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|byte| encode_hex_byte(*byte).iter().map(|c| *c).collect())
        .collect();
    strs.join("")
}

fn encode_hex_byte(byte: u8) -> [char; 2] {
    [encode_hex_digit(byte >> 4), encode_hex_digit(byte & 0x0Fu8)]
}

fn encode_hex_digit(digit: u8) -> char {
    match char::from_digit(digit as u32, 16) {
        Some(c) => c,
        _ => panic!(),
    }
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    let mut r: Vec<u8> = Vec::new();
    let mut chars = hex.chars().enumerate();
    loop {
        let (pos, first) = match chars.next() {
            None => break,
            Some(elt) => elt,
        };
        if first == ' ' {
            continue;
        }
        let (_, second) = match chars.next() {
            None => panic!("pos = {}d", pos),
            Some(elt) => elt,
        };
        r.push((decode_hex_digit(first) << 4) | decode_hex_digit(second));
    }
    r
}

fn decode_hex_digit(digit: char) -> u8 {
    match digit {
        '0'..='9' => digit as u8 - '0' as u8,
        'a'..='f' => digit as u8 - 'a' as u8 + 10,
        'A'..='F' => digit as u8 - 'A' as u8 + 10,
        _ => panic!(),
    }
}
