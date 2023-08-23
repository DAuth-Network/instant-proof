extern crate base64;
extern crate httparse;
extern crate itertools;
extern crate serde_json;
extern crate sgx_tse;

use self::sgx_tse::*;

use sgx_types::*;
use std::backtrace::{self, PrintFormat};
//use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence};
use serde::{Deserialize, Serialize};
use sgx_rand::*;
use sgx_tcrypto::*;

use crate::config::Attest;

use self::itertools::Itertools;
use super::log::*;
use super::os_utils::*;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::ptr;
use std::str;
use std::string::String;
use std::sync::Arc;
use std::untrusted::fs;
use std::vec::Vec;

pub const DEV_HOSTNAME: &str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &str = "/sgx/dev/attestation/v3/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;

extern "C" {
    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;

    pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;

    pub fn ocall_get_quote(
        ret_val: *mut sgx_status_t,
        p_sigrl: *const u8,
        sigrl_len: u32,
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut u8,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestReport {
    quote: String,
}

pub struct QuoteService {
    spid: String,
    api_key: String,
}

impl QuoteService {
    pub fn new(attest: Attest) -> Self {
        QuoteService {
            spid: attest.spid,
            api_key: attest.api_key,
        }
    }

    #[allow(const_err)]
    pub fn create_attestation_report(
        &self,
        pub_k: &sgx_ec256_public_t,
        sign_type: sgx_quote_sign_type_t,
    ) -> Result<String, sgx_status_t> {
        // Workflow:
        // (1) ocall to get the target_info structure (ti) and epid group id (eg)
        // (1.5) get sigrl
        // (2) call sgx_create_report with ti+data, produce an sgx_report_t
        // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

        // (1) get ti + eg
        let mut ti: sgx_target_info_t = sgx_target_info_t::default();
        let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

        let res = unsafe {
            ocall_sgx_init_quote(
                &mut rt as *mut sgx_status_t,
                &mut ti as *mut sgx_target_info_t,
                &mut eg as *mut sgx_epid_group_id_t,
            )
        };

        println!("eg = {:?}", eg);

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(res);
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(rt);
        }

        let eg_num = as_u32_le(&eg);

        // (1.5) get sigrl
        let mut ias_sock: i32 = 0;

        let res = unsafe {
            ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32)
        };

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(res);
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(rt);
        }

        //println!("Got ias_sock = {}", ias_sock);

        // Now sigrl_vec is the revocation list, a vec<u8>
        let sigrl_vec: Vec<u8> = get_sigrl_from_intel(&self.api_key, ias_sock, eg_num);

        // (2) Generate the report
        // Fill ecc256 public key into report_data
        let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
        let mut pub_k_gx = pub_k.gx.clone();
        pub_k_gx.reverse();
        let mut pub_k_gy = pub_k.gy.clone();
        pub_k_gy.reverse();
        report_data.d[..32].clone_from_slice(&pub_k_gx);
        report_data.d[32..].clone_from_slice(&pub_k_gy);

        let rep = match rsgx_create_report(&ti, &report_data) {
            Ok(r) => {
                println!("Report creation => success {:?}", r.body.mr_signer.m);
                Some(r)
            }
            Err(e) => {
                println!("Report creation => failed {:?}", e);
                None
            }
        };

        let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
        let mut os_rng = os::SgxRng::new().unwrap();
        os_rng.fill_bytes(&mut quote_nonce.rand);
        println!("rand finished");
        let mut qe_report = sgx_report_t::default();
        const RET_QUOTE_BUF_LEN: u32 = 2048;
        let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] =
            [0; RET_QUOTE_BUF_LEN as usize];
        let mut quote_len: u32 = 0;

        // (3) Generate the quote
        // Args:
        //       1. sigrl: ptr + len
        //       2. report: ptr 432bytes
        //       3. linkable: u32, unlinkable=0, linkable=1
        //       4. spid: sgx_spid_t ptr 16bytes
        //       5. sgx_quote_nonce_t ptr 16bytes
        //       6. p_sig_rl + sigrl size ( same to sigrl)
        //       7. [out]p_qe_report need further check
        //       8. [out]p_quote
        //       9. quote_size
        let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
        };
        let p_report = (&rep.unwrap()) as *const sgx_report_t;
        let quote_type = sign_type;

        let spid: sgx_spid_t = decode_spid(&self.spid);

        let p_spid = &spid as *const sgx_spid_t;
        let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
        let p_qe_report = &mut qe_report as *mut sgx_report_t;
        let p_quote = return_quote_buf.as_mut_ptr();
        let maxlen = RET_QUOTE_BUF_LEN;
        let p_quote_len = &mut quote_len as *mut u32;

        let result = unsafe {
            ocall_get_quote(
                &mut rt as *mut sgx_status_t,
                p_sigrl,
                sigrl_len,
                p_report,
                quote_type,
                p_spid,
                p_nonce,
                p_qe_report,
                p_quote,
                maxlen,
                p_quote_len,
            )
        };

        if result != sgx_status_t::SGX_SUCCESS {
            return Err(result);
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            println!("ocall_get_quote returned {}", rt);
            return Err(rt);
        }

        // Added 09-28-2018
        // Perform a check on qe_report to verify if the qe_report is valid
        match rsgx_verify_report(&qe_report) {
            Ok(()) => println!("rsgx_verify_report passed!"),
            Err(x) => {
                println!("rsgx_verify_report failed with {:?}", x);
                return Err(x);
            }
        }

        // Check if the qe_report is produced on the same platform
        if ti.mr_enclave.m != qe_report.body.mr_enclave.m
            || ti.attributes.flags != qe_report.body.attributes.flags
            || ti.attributes.xfrm != qe_report.body.attributes.xfrm
        {
            println!("qe_report does not match current target_info!");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }

        println!("qe_report check passed");

        // Debug
        // for i in 0..quote_len {
        //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
        // }
        // println!("");

        // Check qe_report to defend against replay attack
        // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
        // it received is not modified by the untrusted SW stack, and not a replay.
        // The implementation in QE is to generate a REPORT targeting the ISV
        // enclave (target info from p_report) , with the lower 32Bytes in
        // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
        // p_qe_report and report.data to confirm the QUOTE has not be modified and
        // is not a replay. It is optional.

        let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
        rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
        let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
        let lhs_hash = &qe_report.body.report_data.d[..32];

        println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
        println!("report hs= {:02X}", lhs_hash.iter().format(""));

        if rhs_hash != lhs_hash {
            println!("Quote is tampered!");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }

        let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
        let res = unsafe {
            ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32)
        };

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(res);
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(rt);
        }

        let attn_report = get_report_from_intel(&self.api_key, ias_sock, quote_vec);
        println!("{}", attn_report);
        Ok(attn_report)
    }
}

fn parse_attn_resp(resp: &[u8]) -> String {
    info("parse attn resp");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    info(&format!("parse result {:?}", result));

    let msg: &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => {
            msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. "
        }
        _ => {
            println!("DBG:{}", respp.code.unwrap());
            msg = "Unknown error occured"
        }
    }

    println!("{}", msg);
    let mut len_num: u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name {
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => {
                cert = str::from_utf8(h.value).unwrap().to_string()
            }
            _ => (),
        }
    }
    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        println!("Attestation report: {}", attn_report);
    }

    attn_report
}

pub fn decode_spid(hex: &str) -> sgx_spid_t {
    let mut spid = sgx_spid_t::default();
    let hex = hex.trim();
    if hex.len() < 16 * 2 {
        println!("Input spid file len ({}) is incorrect!", hex.len());
        return spid;
    }
    let decoded_vec = decode_hex(hex).unwrap();
    spid.id.copy_from_slice(&decoded_vec[..16]);
    spid
}

fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
    println!("parse_response_sigrl");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);
    println!("parse response{:?}", respp);

    let msg: &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => {
            msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. "
        }
        _ => msg = "Unknown error occured",
    }

    println!("{}", msg);
    let mut len_num: u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            println!("content length = {}", len_num);
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        println!("Base64-encoded SigRL: {:?}", resp_body);

        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}

fn get_sigrl_from_intel(api_key: &str, fd: c_int, gid: u32) -> Vec<u8> {
    println!("get_sigrl_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    //let sigrl_arg = SigRLArg { group_id : gid };
    //let sigrl_req = sigrl_arg.to_httpreq();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                        SIGRL_SUFFIX,
                        gid,
                        DEV_HOSTNAME,
                        api_key);
    println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("{}", resp_string);

    parse_response_sigrl(&plaintext)
}

// TODO: support pse
fn get_report_from_intel(api_key: &str, fd: c_int, quote: Vec<u8>) -> String {
    println!("get_report_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                           REPORT_SUFFIX,
                           DEV_HOSTNAME,
                           api_key,
                           encoded_json.len(),
                           encoded_json);
    println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("resp_string = {}", resp_string);
    parse_attn_resp(&plaintext)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}
