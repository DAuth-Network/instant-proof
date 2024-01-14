#!/bin/bash

mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -nodes -sha256 -nodes -days 365
mv cert.pem certs/MyCertificate.crt
mv key.pem certs/MyKey.key 


cp ../app/conf.toml .
cp ../app/log4rs.yml .
cp ../scripts/run.sh .
cp ../scripts/proof_key .
cp ../scripts/proof_key_pem .
cp ../scripts/seal_key .
cp ../scripts/rsa.key .
cp ../scripts/proof_pub_key_pem .
mkdir logs 
