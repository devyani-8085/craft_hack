/**
 * Language: JavaScript (Node.js crypto, tls, WebCrypto, node-forge, bcrypt)
 * Expected artifacts: MD5, SHA-1, SHA-256, SHA3-256 | des-ede3-cbc, rc4, aes-128-ecb | RSA-1024/2048, EC prime256v1, ECDH secp384r1, Ed25519, X25519
 *   PBKDF2-SHA1 (1000 iters), scrypt | tls minVersion TLSv1 / TLSv1.3 | Math.random (weak RNG) vs crypto.randomBytes
 *   WebCrypto RSA-OAEP, ECDSA P-256, AES-GCM | hardcoded secret | ML-KEM-768 via @noble/post-quantum (PQC)
 */
const crypto = require("crypto");
const tls = require("tls");
const forge = require("node-forge");
const bcrypt = require("bcrypt");
const { ml_kem768 } = require("@noble/post-quantum/ml-kem");

const JWT_SECRET = "hardcoded-jwt-secret-do-not-use";

crypto.createHash("md5");
crypto.createHash("sha1");
crypto.createHash("sha256");
crypto.createHash("sha3-256");
crypto.createHmac("sha1", JWT_SECRET);

crypto.createCipheriv("des-ede3-cbc", Buffer.alloc(24), Buffer.alloc(8));
crypto.createCipheriv("aes-128-ecb", Buffer.alloc(16), null);
crypto.createCipheriv("rc4", Buffer.alloc(16), null);
crypto.createCipheriv("chacha20-poly1305", Buffer.alloc(32), Buffer.alloc(12));

crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
crypto.generateKeyPairSync("ed25519");
crypto.generateKeyPairSync("x25519");
crypto.createECDH("secp384r1");
crypto.createDiffieHellman(1024);

crypto.pbkdf2Sync("pw", "salt", 1000, 32, "sha1");
crypto.scryptSync("pw", "salt", 32);
bcrypt.hashSync("pw", 10);

tls.createServer({ minVersion: "TLSv1", ciphers: "RC4:3DES:HIGH" });
tls.createServer({ minVersion: "TLSv1.3" });
tls.connect({ host: "example.com", rejectUnauthorized: false });

const weakToken = Math.random().toString(36);
const strongToken = crypto.randomBytes(32);

(async () => {
  await crypto.webcrypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt"]);
  await crypto.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  await crypto.webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  forge.pki.rsa.generateKeyPair({ bits: 1024 });
  forge.md.md5.create();
  ml_kem768.keygen();   // PQC KEM
})();
