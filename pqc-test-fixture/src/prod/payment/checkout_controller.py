"""
Production payment checkout controller.
Expected classification: Business Criticality = CRITICAL (score ~5.0)
  Sens=5.0 ('payment'/'card' keywords) | Exp=5.0 (Flask @app.route -> Signal 1, High confidence)
  Sys=5.0 ('/prod/' path -> production core) | Reg=5.0 (explicit PCI-DSS compliance keyword)
Expected Exposure = External (route signature: @app.route, path also under /prod/)
Expected Mode = RSA has no block-cipher mode; card token is AES-GCM encrypted -> Mode = GCM
"""
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

app = Flask(__name__)

# PCI_DSS_CARD_KEY: keyword "pci" placed directly on the matched line so it
# survives snippet extraction regardless of how much surrounding context
# the scanner captures (Reg factor -> 5.0).
PCI_DSS_CARD_KEY = os.environ["PCI_DSS_CARD_KEY"]


def encrypt_card_number(card_number: bytes, iv: bytes) -> bytes:
    """PCI-DSS compliant AES-256-GCM encryption of raw cardholder card data."""
    cipher = Cipher(algorithms.AES(PCI_DSS_CARD_KEY.encode()[:32]), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(card_number) + encryptor.finalize()


@app.route("/api/v1/charge", methods=["POST"])
def charge():
    """Public production endpoint that charges a customer's payment card."""
    body = request.get_json()
    card_number = body["card_number"].encode()
    iv = os.urandom(12)
    ciphertext = encrypt_card_number(card_number, iv)
    return jsonify({"status": "charged", "ref": ciphertext.hex()[:16]})
