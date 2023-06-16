use super::config;
use super::err::*;
use super::log::*;
use crate::*;
use http_req::{
    request::{Method, RequestBuilder},
    tls,
    uri::Uri,
};
use serde_json::{json, to_string, Result, Value};
use std::collections::HashMap;
use std::io::prelude::*;
use std::io::Write;
use std::net::TcpStream;
use std::str;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

pub fn get_otp_client(auth_type: AuthType) -> Option<&'static dyn OtpChannelClient> {
    let conf = &config(None).inner;
    match auth_type {
        AuthType::Email => Some(&conf.mail),
        AuthType::Sms => Some(&conf.sms),
        _ => {
            error("invalid auth type");
            None
        }
    }
}

pub struct MailChannelClient {
    pub conf: config::OtpChannelConf,
}

impl OtpChannelClient for MailChannelClient {
    fn new(conf: config::OtpChannelConf) -> Self {
        Self { conf }
    }
    fn send_otp(&self, to_account: &str, c_code: &str) -> GenericResult<()> {
        info("send mail");
        let from_account = &self.conf.sender;
        let account = &self.conf.account;
        let password = &self.conf.password;
        let server = &self.conf.server;
        let port = 465;
        let conn_addr = format!("{}:{}", server, port);
        let raw_stream = TcpStream::connect(conn_addr).unwrap();
        let mut stream = tls::Config::default().connect(server, raw_stream).unwrap();
        tls_read(&mut stream);
        let cmds = [
            "EHLO dauth.network",
            "AUTH LOGIN",
            account,
            password,
            &format!("MAIL FROM: <{}>", from_account),
            &format!("RCPT TO: <{}>", to_account),
            "DATA",
        ];
        for c in cmds {
            tls_write(&mut stream, c);
        }
        let m_lines = &format!(
            r###"subject: DAuth Verification Code
    from: <{}> 
    to: <{}> 
    
    Content-Type: text/html; charset=utf-8:
    
    <html lang="en-US">
  
        <head>
            <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
            <title>New Account Email Template</title>
            <meta name="description" content="New Account Email Template.">
            <style type="text/css">
                a:hover {{
                    text-decoration: underline !important;
                }}
            </style>
        </head>
  
        <body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
            <!-- 100% body table -->
            <table cellspacing="0" border="0" cellpadding="0" width="100%" bgcolor="#f2f3f8" style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;">
                <tr>
                    <td>
                        <table style="background-color: #f2f3f8; max-width:670px; margin:0 auto;" width="100%" border="0" align="center" cellpadding="0" cellspacing="0">
                            <tr>
                                <td style="height:80px;">&nbsp;</td>
                            </tr>
                            <tr>
                                <td style="text-align:center;">
                                    <a href="play.hexlink.io" title="logo" target="_blank">
                                          <img width="300" src="https://i.postimg.cc/HkJWJSNj/hexlink.png" title="logo" alt="logo">
                                        </a>
                                </td>
                            </tr>
                            <tr>
                                <td style="height:20px;">&nbsp;</td>
                            </tr>
                            <tr>
                            <td>
                            <table width="95%" border="0" align="center" cellpadding="0" cellspacing="0" style="max-width:670px; background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                <tr>
                                    <td style="height:40px;">&nbsp;</td>
                                </tr>
                                <tr>
                                    <td style="padding:0 35px;">
                                        <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">Verify Your Transaction
                                        </h1>
                                        <p style="font-size:15px; color:#455056; margin:8px 0 0; line-height:24px;">
                                            Please use the following verification code to complete your transaction procedures.
                                        </p>
                                        <br>
                                        <span style="margin:10px;"><strong>Code is valid for 5 minutes</strong>.</span><br>
                                        <span style="display:inline-block; vertical-align:middle; margin:15px 0 15px; border-bottom:1px solid #cecece; width:100px;"></span>
                                        <p style="color:#455056; font-size:18px;line-height:20px; margin:0; font-weight: 500;">
                                            <strong style="display: block;font-size: 13px; margin: 0 0 5px; color:rgba(0,0,0,.64); font-weight:normal;">Verification Code</strong>
                                            <h2 style="font-size:2.5em; background: #1890ff;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">${}</h2>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="height:40px;">&nbsp;</td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td style="height:20px;">&nbsp;</td>
                    </tr>
                    <tr>
                    <td style="text-align:center;">
                        <p style="font-size:14px; color:rgba(69, 80, 86, 0.7411764705882353); line-height:18px; margin:0 0 0;">&copy; <strong>dev.hexlink.io</strong> </p>
                    </td>
                </tr>
                <tr>
                    <td style="height:80px;">&nbsp;</td>
                </tr>
            </table>
        </td>
    </tr>
</table>
<!--/100% body table-->
</body>

</html>
."###,
            from_account, to_account, c_code
        );
        let result = tls_write(&mut stream, m_lines);
        tls_write(&mut stream, "QUIT");
        info(&format!("mail result is {}", result));
        if result.contains("250 Ok") {
            Ok(())
        } else {
            Err(GenericError::from("send mail failed"))
        }
    }
}

fn tls_read(conn: &mut tls::Conn<TcpStream>) -> String {
    let mut buffer = [0; 1024];
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

pub struct SmsChannelClient {
    pub conf: config::OtpChannelConf,
}

impl OtpChannelClient for SmsChannelClient {
    fn new(conf: config::OtpChannelConf) -> Self {
        Self { conf }
    }
    fn send_otp(&self, to_account: &str, c_code: &str) -> GenericResult<()> {
        let body = format!(
            "[DAuth Verification Code] Please use the following code to verify your account: {}",
            c_code
        );
        let token_req = format!("Body={}&From={}&To={}", &body, self.conf.sender, to_account);
        let token_headers = HashMap::from([
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Authorization", &self.conf.password),
        ]);
        let sms_resp = http_req(
            &self.conf.server,
            Method::POST,
            Some(token_req),
            token_headers,
        );
        if sms_resp.is_err() {
            return Err(GenericError::from("http error"));
        }
        let v: Value = serde_json::from_str(&sms_resp?)?;
        if v["status"].is_null() {
            return Err(GenericError::from("send sms got an empty response"));
        }
        let status = v["status"].as_str().unwrap();
        info(&status);
        match status {
            "queued" => Ok(()),
            "sent" => Ok(()),
            _ => {
                error(&format!("sms failed: {:?}", v));
                Err(GenericError::from("sms failed"))
            }
        }
    }
}
