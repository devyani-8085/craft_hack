// Language: Go (crypto/*, x/crypto, circl, crypto/mlkem)
// Expected artifacts: MD5, SHA-1, SHA-256 | DES, 3DES, RC4, AES-CBC, AES-GCM, ChaCha20-Poly1305
//   RSA-1024 / RSA-2048, ECDSA P-256 / P-384, ECDH X25519, Ed25519, DSA | PBKDF2-SHA1, bcrypt, scrypt, argon2
//   tls.VersionTLS10 + InsecureSkipVerify | math/rand (weak) vs crypto/rand | ML-KEM-768 (stdlib) + Kyber768 / Dilithium3 (circl)
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	mrand "math/rand"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var hardcodedKey = []byte("0123456789abcdef0123456789abcdef")

func main() {
	_ = md5.New()
	_ = sha1.New()
	_ = sha256.New()

	des.NewCipher(hardcodedKey[:8])
	des.NewTripleDESCipher(hardcodedKey[:24])
	rc4.NewCipher(hardcodedKey)
	block, _ := aes.NewCipher(hardcodedKey)
	cipher.NewCBCEncrypter(block, make([]byte, 16))
	cipher.NewGCM(block)
	chacha20poly1305.New(hardcodedKey)

	rsa.GenerateKey(rand.Reader, 1024)
	rsa.GenerateKey(rand.Reader, 2048)
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdh.X25519().GenerateKey(rand.Reader)
	ed25519.GenerateKey(rand.Reader)
	var dp dsa.Parameters
	dsa.GenerateParameters(&dp, rand.Reader, dsa.L1024N160)

	pbkdf2.Key([]byte("pw"), []byte("salt"), 1000, 32, sha1.New)
	bcrypt.GenerateFromPassword([]byte("pw"), 10)
	scrypt.Key([]byte("pw"), []byte("salt"), 1<<15, 8, 1, 32)
	argon2.IDKey([]byte("pw"), []byte("salt"), 1, 64*1024, 4, 32)

	_ = &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}
	_ = &tls.Config{MinVersion: tls.VersionTLS13}

	_ = mrand.Int()

	mlkem.GenerateKey768()
	kyber768.GenerateKeyPair(rand.Reader)
	mode3.GenerateKey(rand.Reader)
}
