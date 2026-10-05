// Language: Rust (ring, RustCrypto, openssl, rustls, pqcrypto, ml-kem)
// Expected artifacts: MD5, SHA-1, SHA-256 | AES-GCM, AES-128-ECB, 3DES, RC4, ChaCha20-Poly1305 | RSA-1024/2048, P-256 ECDSA, Ed25519, X25519
//   PBKDF2-SHA1 | rustls TLS 1.2/1.3 protocol versions | ML-KEM-768, Kyber768, Dilithium3 (PQC)
use aes_gcm::{Aes256Gcm, KeyInit};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use rsa::RsaPrivateKey;
use p256::ecdsa::SigningKey;
use ed25519_dalek::SigningKey as EdKey;
use x25519_dalek::StaticSecret;
use chacha20poly1305::ChaCha20Poly1305;
use openssl::symm::Cipher;
use openssl::rsa::Rsa;
use ring::{aead, digest, pbkdf2, signature};
use rustls::{ClientConfig, version::{TLS12, TLS13}};
use ml_kem::{MlKem768, KemCore};
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;

const HARDCODED_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

fn main() {
    let mut rng = rand::thread_rng();
    let _ = (Md5::new(), Sha1::new(), Sha256::new());           // MD5, SHA-1, SHA-256
    let _ = digest::SHA512;
    let _ = Aes256Gcm::new_from_slice(HARDCODED_KEY);           // AES-256-GCM
    let _ = Cipher::aes_128_ecb();                              // AES-128-ECB
    let _ = Cipher::des_ede3_cbc();                             // 3DES-CBC
    let _ = Cipher::rc4();
    let _ = ChaCha20Poly1305::new_from_slice(HARDCODED_KEY);
    let _ = aead::AES_256_GCM;

    let _ = RsaPrivateKey::new(&mut rng, 1024);                 // RSA-1024
    let _ = RsaPrivateKey::new(&mut rng, 2048);                 // RSA-2048
    let _ = Rsa::generate(1024);
    let _ = SigningKey::random(&mut rng);                       // ECDSA P-256
    let _ = EdKey::generate(&mut rng);                          // Ed25519
    let _ = StaticSecret::random_from_rng(&mut rng);            // X25519
    let _ = signature::ECDSA_P256_SHA256_ASN1;
    let _ = pbkdf2::PBKDF2_HMAC_SHA1;

    let _ = ClientConfig::builder_with_protocol_versions(&[&TLS12, &TLS13]);

    let (_dk, _ek) = MlKem768::generate(&mut rng);              // ML-KEM-768
    let _ = kyber768::keypair();                                // Kyber-768
    let _ = dilithium3::keypair();                              // Dilithium3
}
