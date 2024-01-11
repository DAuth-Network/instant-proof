/*
This file is the entrance for dauth api server based on actix-web server.
After compiling, the server compiles to an app file located in bin.

When running, the server:
- first loads log config file,
- then loads the config file for dauth api server,
- then it looks for environment variables including signing private keys and public keys and sealing key,
- then it creates a database connection pool,
- then it creates an enclave instance,
- then it creates a thread pool to control concurrent enclave execution,
- then it starts the http server as an api server.
 */

extern crate openssl;
#[macro_use]
extern crate log;
extern crate config as config_file;
extern crate log4rs;

use std::env;
use std::process::exit;
use std::str;

use actix_cors::Cors;
use actix_files as afs;
use actix_web::{dev::Service as _, web, App, HttpServer};
use log::{debug, error, info, warn};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use p256::{PublicKey, SecretKey};
extern crate sgx_types;
extern crate sgx_urts;
use mysql::*;
use sgx_types::*;
use sgx_urts::SgxEnclave;

mod config;
mod ecall;
mod endpoint;
mod error;
mod model;
mod ocall;
mod persistence;

use config_file::{Config, File};
use endpoint::service;
use endpoint::service_v1;
use endpoint::tee::*;
use ocall::*;
use persistence::dclient::*;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

/// Create enclave instance when app starts
fn init_enclave() -> SgxEnclave {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    let sgx_result = SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    );
    match sgx_result {
        Ok(r) => {
            info!("Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            error!("Init Enclave Failed {}!", x.as_str());
            panic!("Init Enclave Failed, exiting");
        }
    }
}

/// Create enclave instance and run all unit tests inside
fn init_enclave_and_run_tests() {
    let enclave = init_enclave();
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    unsafe {
        ecall::ec_test(enclave.geteid(), &mut sgx_result);
    };
    match sgx_result {
        sgx_status_t::SGX_SUCCESS => {
            println!("execute tests in enclave done.");
        }
        _ => {
            println!("execute tests in enclave failed!");
        }
    }
}

/// Create enclave instance and set config inside enclave
fn init_enclave_and_set_conf(conf: config::TeeConfig) -> SgxEnclave {
    let enclave = init_enclave();
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    let config_b = serde_json::to_vec(&conf).unwrap();
    let config_b_size = config_b.len();
    let result = unsafe {
        ecall::ec_test(enclave.geteid(), &mut sgx_result);
        ecall::ec_set_conf(
            enclave.geteid(),
            &mut sgx_result,
            config_b.as_ptr() as *const u8,
            config_b_size,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("set config in sgx done.");
        }
        _ => panic!("Enclave generate key-pair failed!"),
    }
    enclave
}

fn parse_pem(pem_pub_key: &str) -> PublicKey {
    pem_pub_key.parse::<p256::PublicKey>().unwrap()
}

/// Create database connection pool using conf from config file
fn init_db_pool(conf: &config::DbConfig) -> Pool {
    let db_user = &conf.user;
    let db_host = &conf.host;
    let db_password = &conf.password;
    let db_port = conf.port;
    let db_name = &conf.name;
    let db_url = format!(
        "mysql://{}:{}@{}:{}/{}",
        db_user, db_password, db_host, db_port, db_name
    );
    let ops = Opts::from_url(&db_url).unwrap();
    mysql::Pool::new(ops).unwrap()
}

/// Read config file and parse to DauthConfig
fn load_conf(fname: &str) -> config::DauthConfig {
    let mut conf = Config::builder()
        .add_source(File::with_name(fname))
        .build()
        .unwrap()
        .try_deserialize::<config::DauthConfig>()
        .unwrap();
    conf.signer.jwt.signing_key = env::var("PROOF_KEY_PEM").unwrap();
    conf.signer.jwt_fb.signing_key = env::var("JWT_FB_KEY").unwrap();
    conf.signer.proof.signing_key = env::var("PROOF_KEY").unwrap();
    conf
}

/// This is the entrance of the web app server.
/// It binds all api to function defined in mod endpoint.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log4rs::init_file("log4rs.yml", Default::default()).unwrap();
    info!("logging!");
    let args = env::args();
    if args.count() == 2 {
        // when extra args are passed, run unit tests
        info!("running unit test ");
        init_enclave_and_run_tests();
        exit(0);
    }
    // all signing and sealing key are stored in env
    let conf = load_conf("conf");
    let workers: usize = conf.api.workers.try_into().unwrap();
    // create a threadpool for enclave concurrent executing
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    // create a db pool for query and save user auth records
    let client_db = init_db_pool(&conf.db.client);
    // create an enclave instance and set config inside
    let enclave = init_enclave_and_set_conf(conf.to_tee_config(env::var("SEAL_KEY").unwrap()));
    // parse signing public key from env
    let jwt_pub_key = parse_pem(&env::var("PROOF_PUB_KEY").unwrap());
    // app level state, including db_pool and enclave instance
    let edata: web::Data<service::AppState> = web::Data::new(service::AppState {
        tee: TeeService::new(enclave, pool),
        jwt_pub_key,
        db_pool: init_db_pool(&conf.db.auth),
        clients: query_clients(&client_db).unwrap(),
        env: conf.api.env.clone(),
        port: conf.api.port,
    });

    // add certs to server for https service api
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("certs/MyKey.key", SslFiletype::PEM)
        .unwrap();
    builder
        .set_certificate_chain_file("certs/MyCertificate.crt")
        .unwrap();

    // subpath is for api versioning, e.g.
    // /dauth/v1.1 indicates api version 1.1
    // /dauth/v2 for api version 2
    let subpath = conf.api.prefix;
    let subpath_v1 = format!("{}/v1.1", subpath);
    let subpath_v2 = format!("{}/v2", subpath);

    // create http server
    let server = HttpServer::new(move || {
        let cors = Cors::permissive();
        let app = App::new()
            //.wrap(endpoint::middleware::VerifyToken)
            //.wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::clone(&edata))
            .service(
                web::scope(&subpath_v1)
                    .service(service::exchange_key)
                    .service(service_v1::send_otp)
                    .service(service_v1::auth_in_one)
                    .service(service::jwks)
                    .service(service::health),
            )
            .service(
                web::scope(&subpath_v2)
                    .service(service::exchange_key)
                    .service(service::send_otp)
                    .service(service::auth_in_one)
                    .service(service::jwks)
                    .service(service::health),
            );
        // load index.html for testing only when env is dev
        match conf.api.env {
            config::Env::TEST => {
                app.service(afs::Files::new("/", "./public").index_file("index.html"))
            }
            _ => app,
        }
    })
    .workers(workers);
    // protocol could be either http or https
    let protocol = conf.api.protocol;
    if protocol.eq("https") {
        let server_url = format!("{}:{}", &conf.api.host, &conf.api.port);
        server.bind_openssl(server_url, builder)?.run().await
    } else {
        server.bind((conf.api.host, conf.api.port))?.run().await
    }
}
