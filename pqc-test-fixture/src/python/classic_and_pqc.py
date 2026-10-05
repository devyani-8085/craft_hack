"""
Language: Python (hashlib, cryptography, pycryptodome, PyNaCl, oqs, ssl, hmac, bcrypt)
Expected artifacts: MD5, SHA-1, SHA-256, SHA3-256, BLAKE2b | AES-CBC/ECB/GCM, DES, 3DES, ARC4, ChaCha20
  RSA-1024/2048/4096, DSA-1024, ECDSA SECP256R1/SECP384R1, X25519, Ed25519
  PBKDF2-HMAC-SHA1, scrypt, bcrypt | ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLS_CLIENT | random.random (weak RNG), secrets (strong)
  ML-KEM-768, ML-DSA-65, Falcon-512 via oqs (PQC)
"""
import hashlib, hmac, random, secrets, ssl, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, x25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from Crypto.Cipher import DES, DES3, ARC4, AES as PyCAES
from nacl import secret as nacl_secret, public as nacl_public
import bcrypt
import oqs

HARDCODED_KEY = b"0123456789abcdef0123456789abcdef"


def hashing(data: bytes):
    hashlib.md5(data); hashlib.sha1(data); hashlib.sha256(data)
    hashlib.sha3_256(data); hashlib.blake2b(data)
    hmac.new(HARDCODED_KEY, data, hashlib.sha1)
    hashes.Hash(hashes.MD5()); hashes.Hash(hashes.SHA1()); hashes.Hash(hashes.SHA512())


def symmetric(iv: bytes):
    Cipher(algorithms.AES(HARDCODED_KEY), modes.CBC(iv))      # AES-256-CBC
    Cipher(algorithms.AES(HARDCODED_KEY[:16]), modes.ECB())   # AES-128-ECB
    Cipher(algorithms.AES(HARDCODED_KEY), modes.GCM(iv))      # AES-256-GCM
    Cipher(algorithms.TripleDES(HARDCODED_KEY[:24]), modes.CBC(iv[:8]))
    Cipher(algorithms.ChaCha20(HARDCODED_KEY, iv), mode=None)
    DES.new(HARDCODED_KEY[:8], DES.MODE_ECB)
    DES3.new(HARDCODED_KEY[:24], DES3.MODE_CBC, iv[:8])
    ARC4.new(HARDCODED_KEY)
    PyCAES.new(HARDCODED_KEY, PyCAES.MODE_ECB)


def asymmetric():
    rsa.generate_private_key(public_exponent=65537, key_size=1024)   # RSA-1024
    rsa.generate_private_key(public_exponent=65537, key_size=2048)   # RSA-2048
    rsa.generate_private_key(public_exponent=65537, key_size=4096)   # RSA-4096
    dsa.generate_private_key(key_size=1024)                          # DSA-1024
    ec.generate_private_key(ec.SECP256R1())                          # ECDSA/ECDH P-256
    ec.generate_private_key(ec.SECP384R1())                          # P-384
    ed25519.Ed25519PrivateKey.generate()
    x25519.X25519PrivateKey.generate()
    padding.PKCS1v15()                                               # RSA PKCS#1 v1.5
    padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    nacl_public.PrivateKey.generate()


def kdfs(salt: bytes):
    PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=salt, iterations=1000)   # weak iteration count
    Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    bcrypt.hashpw(b"pw", bcrypt.gensalt())


def protocols():
    ssl.SSLContext(ssl.PROTOCOL_TLSv1)             # TLS 1.0
    ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False                      # verification disabled


def rng():
    return random.random(), secrets.token_bytes(32), os.urandom(16)   # weak vs strong


def post_quantum():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:      # FIPS 203
        kem.generate_keypair()
    with oqs.Signature("ML-DSA-65") as sig:              # FIPS 204
        sig.generate_keypair()
    with oqs.Signature("Falcon-512") as f:
        f.generate_keypair()
    with oqs.KeyEncapsulation("Kyber768") as k:          # pre-standard Kyber name
        k.generate_keypair()
