# Multi-language crypto coverage manifest (ground truth)

All original fixture files are unchanged. Files below were ADDED. Each source file starts with an
"Expected artifacts" header listing what a scanner should report. Secrets/keys here are fake test values.

| Language | File | Manifest (SCA) | Notable expected findings |
|---|---|---|---|
| C | src/c/crypto_legacy.c | CMakeLists.txt, conanfile.txt | MD5/SHA-1, DES-ECB, RC4, RSA-1024, DH-1024, TLS1.0/SSL3, rand(), ML-KEM-768, ML-DSA-65 (liboqs) |
| C++ | src/cpp/crypto_cpp.cpp | (CMake above) | Crypto++ MD5/3DES/AES-ECB, RSA-1024, Botan Kyber768, X25519, wolfSSL TLS1.1 |
| Python | src/python/classic_and_pqc.py | requirements.txt (root) | hashlib, cryptography, pycryptodome, oqs ML-KEM/ML-DSA/Falcon, ssl TLSv1 |
| Java | src/java/CryptoLegacy.java | pom.xml | JCA MD5/DES/ECB/RSA-1024, JKS+PKCS11, BouncyCastle Kyber/Dilithium |
| JavaScript | src/javascript/node_crypto_suite.js | package.json (root) | createHash md5, rc4, RSA-1024, Math.random, WebCrypto, ML-KEM (noble) |
| TypeScript | src/typescript/crypto_service.ts | package.json (root) | jose RS256/ES256/HS256/EdDSA, noble ML-KEM/ML-DSA |
| Go | src/go/main.go | go.mod | crypto/md5, des, rc4, RSA-1024, TLS10+InsecureSkipVerify, mlkem, circl Kyber/Dilithium |
| Rust | src/rust/main.rs | Cargo.toml | md5/sha1, RSA-1024, rustls, ml-kem, pqcrypto-kyber/dilithium |
| C# | src/csharp/CryptoLegacy.cs | CryptoFixture.csproj | DESCryptoServiceProvider, RSA-1024, SslProtocols.Tls, MLKem/MLDsa |
| PHP | src/php/crypto.php | composer.json | md5/sha1, DES-ECB, mcrypt, RSA-1024, mt_rand, TLSv1.0 stream ctx |
| Ruby | src/ruby/crypto_legacy.rb | Gemfile | OpenSSL::Cipher DES/RC4, RSA 1024, VERIFY_NONE |
| Kotlin | src/kotlin/CryptoLegacy.kt | build.gradle.kts | JCA DES/ECB, AndroidKeyStore, Tink |
| Swift | src/swift/CryptoLegacy.swift | Package.swift | Insecure.MD5/SHA1, CCCrypt DES, Secure Enclave, MLKEM768 |
| Scala | src/scala/CryptoLegacy.scala | build.sbt | JCA MD5/DES/RSA-1024, TLSv1.1 |
| Perl | src/perl/crypto_legacy.pl | - | Crypt::CBC DES/Blowfish, Crypt::RSA 1024, SSL_version TLSv1 |
| Shell | src/shell/crypto_ops.sh | - | openssl genrsa 1024, ssh-keygen dsa, curl --tlsv1.0, ML-KEM/ML-DSA genpkey |
| PowerShell | src/powershell/crypto_ops.ps1 | - | MD5/SHA1/DES, RSA-1024 cert SHA1, Ssl3/Tls |
| Dart | src/dart/crypto_legacy.dart | pubspec.yaml | md5/sha1, AES-ECB, RSA-1024 |

## Protocols / config / infra / container / binary
- config/sshd_config, ipsec.conf, tls-policy.yaml, smtp-tls.conf, openssl.cnf — weak + hybrid PQC (mlkem768x25519, X25519MLKEM768)
- infra/cloud-crypto.tf (AWS KMS/ACM/CloudHSM, Azure Key Vault, GCP KMS incl. ML-DSA), infra/k8s-secrets.yaml
- container/Dockerfile.legacy-crypto — container-image scan target (old OpenSSL, pycrypto, 1024-bit key)
- bin/algo_strings_demo — real ELF binary embedding algorithm identifiers (binary-scan target; not linked to libcrypto)
- Existing certs/, .env, nginx.conf, docker-compose, CI workflow, HSM/KMS python files remain as before

## PQC status contrast (for quantum-risk + Mosca)
Quantum-vulnerable: RSA, DSA, DH, ECDSA, ECDH, X25519, Ed25519. Classically broken: MD5, SHA-1, DES, RC4.
Quantum-safe present: ML-KEM, ML-DSA, SLH-DSA, Kyber/Dilithium/Falcon, hybrid X25519+ML-KEM.
