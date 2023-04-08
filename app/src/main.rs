extern crate openssl;
#[macro_use]
extern crate log;
extern crate log4rs;

use std::str;
use std::ffi::CStr;

use actix_web::{dev::Service as _, web, App, HttpServer, middleware};
use actix_cors::Cors;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use actix_files as afs;

use log::{error, info, warn};
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

use mysql::*;

mod ecall;
mod endpoint;
mod persistence;
mod ocall;

use endpoint::service::*;
use endpoint::oauth::*;
use config::Config;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use ocall::*;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";



/// Create enclave instance when app starts
fn init_enclave() -> SgxEnclave {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let sgx_result = SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr);
    match sgx_result {
        Ok(r) => {
            info!("Init Enclave Successful {}!", r.geteid());
            return r;
        },
        Err(x) => {
            error!("Init Enclave Failed {}!", x.as_str());
            panic!("Init Enclave Failed, exiting");
        },
    };
}


/// Create enclave instance and generate key pairs inside tee
/// for secure communication
fn init_enclave_and_set_conf(conf: &HashMap<String, String>) -> SgxEnclave {
    let enclave = init_enclave();
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    let config = endpoint::config::Config {
        email_account: conf.get("email_account").unwrap().clone(),
        email_password: conf.get("email_password").unwrap().clone(),
        email_sender: conf.get("email_sender").unwrap().clone(),
        email_server: conf.get("email_server").unwrap().clone(),
        github_client_id: conf.get("github_client_id").unwrap().clone(),
        github_client_secret: conf.get("github_client_secret").unwrap().clone(),
        google_client_id: conf.get("google_client_id").unwrap().clone(),
        google_client_secret: conf.get("google_client_secret").unwrap().clone(),
        google_redirect_url: conf.get("google_redirect_url").unwrap().clone()
    };
    let config_b = serde_json::to_vec(&config).unwrap();
    let config_b_size = config_b.len();
    let result = unsafe {
        ecall::ec_set_conf(
            enclave.geteid(),
            &mut sgx_result,
            config_b.as_ptr() as *const u8,
            config_b_size
        );
        ecall::ec_test(enclave.geteid(), &mut sgx_result)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("set config in sgx done.");
        },
        _ => panic!("Enclave generate key-pair failed!")
    }
    return enclave;
}


/// Create database connection pool using conf from config file 
fn init_db_pool(conf: &HashMap<String, String>) -> Pool {
    let db_user = conf.get("db_user").unwrap();
    let db_host = conf.get("db_host").unwrap();
    let db_password = conf.get("db_password").unwrap();
    let db_port: &String = conf.get("db_port").unwrap();
    let db_name: &String = conf.get("db_name").unwrap();
    let db_url = format!("mysql://{}:{}@{}:{}/{}", 
        db_user, db_password, db_host, db_port, db_name);
    let ops = Opts::from_url(&db_url).unwrap();
    let pool = mysql::Pool::new(ops).unwrap();
    return pool;
}


/// Read config file and save config to hash map 
fn load_conf(fname: &str) -> HashMap<String, String> {
    Config::builder()
        .add_source(config::File::with_name(fname))
        .build()
        .unwrap()
        .try_deserialize::<HashMap<String, String>>()
        .unwrap()
}


/// This is the entrance of the web app server.
/// It binds all api to function defined in mod endpoint.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    info!("logging!");
    let conf = load_conf("conf");
    let workers: usize = conf.get("workers").unwrap().parse().unwrap();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(workers).build().unwrap();
    // edata stores environment and config information
    let edata: web::Data<AppState> = web::Data::new(AppState{
        enclave: init_enclave_and_set_conf(&conf),
        thread_pool: pool,
        db_pool: init_db_pool(&conf),
        conf: conf.clone()
    });
    // ustate stores user state information e.g. confirmation code that sends
    // to user's mailbox.
    let ustate: web::Data<endpoint::session::SessionState> = web::Data::new(endpoint::session::SessionState{
        state: Arc::new(Mutex::new(HashMap::new()))
    });

    // add certs to server for https service api
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder.set_private_key_file("certs/MyKey.key", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("certs/MyCertificate.crt").unwrap();

    let server_url = format!("0.0.0.0:{}", conf.get("node_api_port").unwrap());
    let server_port: u16 = conf.get("node_api_port").unwrap().parse().unwrap();
    let conf2 = conf.clone();
    let server = HttpServer::new(move || {
        let cors = Cors::permissive();
        let app = App::new()
            //.wrap(endpoint::middleware::VerifyToken) 
            //.wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::clone(&edata))
            .app_data(web::Data::clone(&ustate))
            .service(exchange_key)
            .service(auth_email)
            .service(auth_email_confirm)
            .service(auth_oauth)
            .service(health);
        // load index.html for testing only when env is dev
        let default_env = "prod".to_string();
        let env = conf.get("env").unwrap_or(&default_env);
        if env.eq("dev") {
            app.service(afs::Files::new("/", "./public").index_file("index.html"))
        } else {
            app
        }
    })
    .workers(workers);
    // uncomment to enable https
    let default_protocol = "https".to_string();
    let protocol = conf2.get("protocol").unwrap_or(&default_protocol);
    if protocol.eq("https") {
        server.bind_openssl(server_url, builder)?.run().await
    } else {
        server.bind(("0.0.0.0", server_port))?.run().await
    }
}
