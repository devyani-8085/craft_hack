/*
 * Language: C (OpenSSL / liboqs)
 * Expected artifacts: MD5, SHA-1, SHA-256 (hash) | DES-ECB, RC4, AES-128-ECB, AES-256-GCM (symmetric, modes ECB/GCM)
 *   RSA-1024 (quantum-vulnerable + classically weak), RSA-2048, ECDSA P-256, ECDH, DH-1024, Ed25519 (asymmetric)
 *   TLS 1.0 method (protocol) | rand()/srand (weak RNG) | ML-KEM-768 + ML-DSA-65 via liboqs (PQC, quantum-safe)
 *   Hardcoded key literal (secret)
 */
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>
#include <stdlib.h>

static const unsigned char HARDCODED_AES_KEY[32] = "0123456789abcdef0123456789abcdef";

void hashes(const unsigned char *d, size_t n, unsigned char *out) {
    MD5(d, n, out);                 /* MD5 - broken */
    SHA1(d, n, out);                /* SHA-1 - deprecated */
    SHA256(d, n, out);              /* SHA-256 - ok */
    EVP_Digest(d, n, out, NULL, EVP_sha512(), NULL);
}

void symmetric(void) {
    DES_cblock key; DES_key_schedule ks;
    DES_set_key(&key, &ks);
    DES_ecb_encrypt(&key, &key, &ks, DES_ENCRYPT);       /* DES-ECB */
    RC4_KEY rc4; RC4_set_key(&rc4, 16, HARDCODED_AES_KEY);  /* RC4 */
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, HARDCODED_AES_KEY, NULL);   /* AES-128-ECB */
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, HARDCODED_AES_KEY, NULL);   /* AES-256-GCM */
    EVP_EncryptInit_ex(c, EVP_des_ede3_cbc(), NULL, HARDCODED_AES_KEY, NULL);  /* 3DES-CBC */
    EVP_CIPHER_CTX_free(c);
}

void asymmetric(void) {
    RSA *weak = RSA_new(); BIGNUM *e = BN_new(); BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(weak, 1024, e, NULL);            /* RSA-1024 */
    EVP_PKEY_CTX *rsa = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_CTX_set_rsa_keygen_bits(rsa, 2048);         /* RSA-2048 */
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); /* ECDSA/ECDH P-256 */
    ECDSA_sign(0, NULL, 0, NULL, NULL, ec);
    ECDH_compute_key(NULL, 0, NULL, ec, NULL);
    DH *dh = DH_new(); DH_generate_parameters_ex(dh, 1024, 2, NULL); /* DH-1024 */
    EVP_PKEY_CTX *ed = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);  /* Ed25519 */
}

void protocol(void) {
    SSL_CTX *old = SSL_CTX_new(TLSv1_method());          /* TLS 1.0 */
    SSL_CTX *ssl3 = SSL_CTX_new(SSLv3_method());         /* SSL 3.0 */
    SSL_CTX *ok = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ok, TLS1_3_VERSION);
}

int weak_rng(void) { srand(42); return rand(); }         /* insecure RNG */

void pqc(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);  /* ML-KEM-768 (FIPS 203) */
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);   /* ML-DSA-65 (FIPS 204) */
    OQS_SIG *slh = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128s_simple); /* SLH-DSA family */
}
