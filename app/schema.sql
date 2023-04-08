create database dauth3;
use dauth3;


drop table if exists account;
create table account (
    acc_hash varchar(128),
    acc_seal varchar(2048),
    PRIMARY KEY(acc_hash)
)
ROW_FORMAT=COMPRESSED
CHARACTER set = utf8mb4;

drop table if exists auth;
create table auth (
    acc_hash varchar(128),
    auth_id int not null,  /* auth seq or nonce */
    auth_type varchar(20),
    audience varchar(128),
    auth_datetime datetime,
    auth_exp SERIAL,
    INDEX i_date using btree(auth_datetime),
    INDEX i_account using btree(acc_hash),
    PRIMARY KEY(acc_hash, auth_id)
)
ROW_FORMAT=COMPRESSED
CHARACTER set = utf8mb4;


drop user 'duadmin'@'localhost';
drop user 'duadmin';
flush privileges;
create user 'duadmin'@'localhost' identified by 'ks123';
create user 'duadmin'@'%' identified by 'ks123';
grant all on dauth.* to 'duadmin'@'localhost';
grant all on dauth.* to 'duadmin'@'%';
flush privileges;
