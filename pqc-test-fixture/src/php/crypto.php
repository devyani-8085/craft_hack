<?php
/**
 * Language: PHP (openssl_*, sodium, hash, mcrypt, password_*)
 * Expected artifacts: md5(), sha1(), hash('sha256') | DES-ECB, AES-256-CBC, AES-128-ECB, aes-256-gcm, RC4, mcrypt_encrypt (removed ext)
 *   RSA-1024 / 2048, EC prime256v1, openssl_sign SHA1 | libsodium X25519 + Ed25519 + XChaCha20 | password_hash bcrypt / argon2id
 *   mt_rand / rand (weak) vs random_bytes | stream_context ssl crypto_method TLSv1_0 | hardcoded key
 */
$HARDCODED_KEY = "0123456789abcdef0123456789abcdef";

md5("data"); sha1("data"); hash("sha256", "data"); hash("sha512", "data"); hash_hmac("sha1", "data", $HARDCODED_KEY);

openssl_encrypt("data", "DES-ECB", $HARDCODED_KEY);
openssl_encrypt("data", "AES-256-CBC", $HARDCODED_KEY, 0, str_repeat("0", 16));
openssl_encrypt("data", "aes-128-ecb", $HARDCODED_KEY);
openssl_encrypt("data", "aes-256-gcm", $HARDCODED_KEY, 0, str_repeat("0", 12), $tag);
openssl_encrypt("data", "rc4", $HARDCODED_KEY);
mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $HARDCODED_KEY, "data", MCRYPT_MODE_ECB);

openssl_pkey_new(["private_key_bits" => 1024, "private_key_type" => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_new(["private_key_bits" => 2048, "private_key_type" => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_new(["curve_name" => "prime256v1", "private_key_type" => OPENSSL_KEYTYPE_EC]);
openssl_sign("data", $sig, $privKey, OPENSSL_ALGO_SHA1);

sodium_crypto_box_keypair();           // X25519
sodium_crypto_sign_keypair();          // Ed25519
sodium_crypto_secretbox("data", str_repeat("0", 24), $HARDCODED_KEY);
sodium_crypto_aead_xchacha20poly1305_ietf_encrypt("data", "", str_repeat("0", 24), $HARDCODED_KEY);

password_hash("pw", PASSWORD_BCRYPT);
password_hash("pw", PASSWORD_ARGON2ID);
hash_pbkdf2("sha1", "pw", "salt", 1000, 32);

mt_rand(); rand(); $strong = random_bytes(32);

$ctx = stream_context_create(["ssl" => ["crypto_method" => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT, "verify_peer" => false]]);
