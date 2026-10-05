"""
Deliberately exercises 3 distinct AES cipher modes via the `cryptography` hazmat
API so the Python AST analyzer (scanner/python_analyzer.py::_check_hazmat_cipher)
populates the `mode` field with three different values.
Expected Mode values: CBC, ECB, GCM (one per function below).
Expected Algorithm = AES in all three; Expected Library = cryptography.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_legacy_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Expected Mode = CBC (insecure without proper padding/MAC)."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def encrypt_weak_ecb(key: bytes, data: bytes) -> bytes:
    """Expected Mode = ECB (pattern-leaking, should be flagged HIGH/CRITICAL)."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def encrypt_modern_gcm(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Expected Mode = GCM (authenticated, current best practice)."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()
