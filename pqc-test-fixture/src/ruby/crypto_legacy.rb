# Language: Ruby (OpenSSL, Digest, bcrypt, rbnacl)
# Expected artifacts: MD5, SHA1, SHA256 | DES-EDE3-CBC, AES-128-ECB, AES-256-CBC, AES-256-GCM, RC4
#   RSA-1024 / 2048, EC prime256v1, DH | PBKDF2-HMAC-SHA1 | OpenSSL::SSL::TLS1_VERSION / TLS1_3_VERSION | rand (weak) vs SecureRandom
require "openssl"
require "digest"
require "securerandom"
require "bcrypt"
require "rbnacl"

HARDCODED_KEY = "0123456789abcdef0123456789abcdef"

Digest::MD5.hexdigest("data")
Digest::SHA1.hexdigest("data")
Digest::SHA256.hexdigest("data")
OpenSSL::HMAC.hexdigest("SHA1", HARDCODED_KEY, "data")

OpenSSL::Cipher.new("DES-EDE3-CBC")
OpenSSL::Cipher.new("aes-128-ecb")
OpenSSL::Cipher.new("aes-256-cbc")
OpenSSL::Cipher.new("aes-256-gcm")
OpenSSL::Cipher.new("rc4")

OpenSSL::PKey::RSA.new(1024)
OpenSSL::PKey::RSA.generate(2048)
OpenSSL::PKey::EC.generate("prime256v1")
OpenSSL::PKey::DH.new(1024)
OpenSSL::PKCS5.pbkdf2_hmac_sha1("pw", "salt", 1000, 32)
BCrypt::Password.create("pw")
RbNaCl::PrivateKey.generate          # X25519
RbNaCl::SigningKey.generate          # Ed25519

ctx = OpenSSL::SSL::SSLContext.new
ctx.min_version = OpenSSL::SSL::TLS1_VERSION       # TLS 1.0
ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
ctx.max_version = OpenSSL::SSL::TLS1_3_VERSION

rand(1000)                 # weak RNG
SecureRandom.hex(32)       # strong
