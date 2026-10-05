#!/bin/sh
# Language: Shell (openssl CLI, ssh-keygen, gpg, curl, keytool)
# Expected artifacts: RSA-1024 genrsa, DSA keygen, EC prime256v1, des-ede3-cbc / aes-128-ecb / rc4 via openssl enc, md5 / sha1 digests
#   ssh-keygen -t dsa / rsa -b 1024 / ed25519, gpg RSA-2048 key, curl --tlsv1.0, keytool JKS keystore, openssl s_client -tls1
#   hardcoded passphrase | ML-KEM / ML-DSA keys via openssl 3.5 (PQC)
PASSPHRASE="hardcoded-shell-passphrase"

openssl genrsa -out weak.key 1024
openssl genrsa -out ok.key 2048
openssl dsaparam -out dsa.pem 1024
openssl ecparam -name prime256v1 -genkey -noout -out ec.key
openssl enc -des-ede3-cbc -in a -out b -pass pass:"$PASSPHRASE"
openssl enc -aes-128-ecb -in a -out b -pass pass:"$PASSPHRASE"
openssl enc -rc4 -in a -out b -pass pass:"$PASSPHRASE"
openssl dgst -md5 file.txt
openssl dgst -sha1 file.txt
openssl req -x509 -newkey rsa:1024 -sha1 -days 3650 -nodes -keyout k.pem -out c.pem
openssl s_client -connect example.com:443 -tls1
openssl genpkey -algorithm ML-KEM-768 -out kem.pem
openssl genpkey -algorithm ML-DSA-65 -out dsa65.pem

ssh-keygen -t dsa -f id_dsa
ssh-keygen -t rsa -b 1024 -f id_rsa_weak
ssh-keygen -t ed25519 -f id_ed25519
gpg --batch --gen-key --pinentry-mode loopback --passphrase "$PASSPHRASE" <<< "Key-Type: RSA
Key-Length: 2048"
curl --tlsv1.0 --insecure https://example.com
keytool -genkeypair -alias k -keyalg RSA -keysize 1024 -keystore store.jks -storetype JKS
