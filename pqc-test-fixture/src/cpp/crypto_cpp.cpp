// Language: C++ (Crypto++, Botan, wolfSSL)
// Expected artifacts: MD5, SHA-1, SHA-256 | DES-EDE3 (3DES), AES-CBC, AES-GCM, ChaCha20-Poly1305
//   RSA-1024 / RSA-3072, ECDSA secp256r1, X25519 key agreement | PBKDF2-HMAC-SHA1 | wolfSSL TLS 1.1 | Kyber-768 via Botan (PQC)
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/des.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/rsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/pwdbased.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/kyber.h>
#include <botan/x25519.h>
#include <wolfssl/ssl.h>

using namespace CryptoPP;

void hashes() {
    Weak::MD5 md5;                       // MD5
    SHA1 sha1;                           // SHA-1
    SHA256 sha256;                       // SHA-256
}

void ciphers() {
    CBC_Mode<DES_EDE3>::Encryption tdes;   // 3DES-CBC
    CBC_Mode<AES>::Encryption aesCbc;      // AES-CBC
    ECB_Mode<AES>::Encryption aesEcb;      // AES-ECB (weak mode)
    GCM<AES>::Encryption aesGcm;           // AES-GCM
}

void asymmetric() {
    AutoSeededRandomPool prng;
    InvertibleRSAFunction weak;  weak.GenerateRandomWithKeySize(prng, 1024);   // RSA-1024
    InvertibleRSAFunction good;  good.GenerateRandomWithKeySize(prng, 3072);   // RSA-3072
    ECDSA<ECP, SHA256>::PrivateKey ecKey;
    ecKey.Initialize(prng, ASN1::secp256r1());                                  // ECDSA P-256
}

void kdf() {
    PKCS5_PBKDF2_HMAC<SHA1> pbkdf;         // PBKDF2-HMAC-SHA1
}

void botan_section() {
    Botan::AutoSeeded_RNG rng;
    Botan::X25519_PrivateKey x(rng);                                   // X25519
    Botan::Kyber_PrivateKey kyber(rng, Botan::KyberMode::Kyber768_R3); // Kyber-768 (PQC)
}

void tls() {
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_1_client_method());  // TLS 1.1
    WOLFSSL_CTX* ok  = wolfSSL_CTX_new(wolfTLSv1_3_client_method());  // TLS 1.3
}
