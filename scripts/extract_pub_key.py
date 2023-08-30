from ecdsa import SigningKey, SECP256k1, NIST256p
import sys
import subprocess

if __name__ == '__main__':
    private_key = sys.argv[1]
    sk = SigningKey.from_string(bytes.fromhex(private_key), curve=NIST256p)
    vk = sk.get_verifying_key()
    print(vk.to_string().hex())
    print(vk.to_pem())
    r = subprocess.run("openssl pkcs8 -topk8 -nocrypt", shell=True,
                       input=sk.to_pem(), capture_output=True)
    print(r.stdout.decode())
