"""
Public authentication API — standard application tier (not flagged as /prod/ or /core/).
Expected classification: Business Criticality = HIGH (score ~3.55)
  Sens=4.0 ('auth'/'token' keywords) | Exp=5.0 (Flask @app.route -> Signal 1, High confidence)
  Sys=2.0 (standard baseline tier) | Reg=3.0 (path contains 'auth' -> security baseline)
Expected Exposure = External (route signature: @app.route)
Expected Mode = None/blank (JWT signing here, no raw AES cipher call)
"""
from flask import Flask, request, jsonify
import jwt
import os

app = Flask(__name__)
AUTH_TOKEN_SECRET = os.environ["AUTH_TOKEN_SECRET"]


@app.route("/api/v1/login", methods=["POST"])
def login():
    """Public login endpoint issuing a signed auth token."""
    username = request.json["username"]
    token = jwt.encode({"user": username}, AUTH_TOKEN_SECRET, algorithm="HS256")
    return jsonify({"token": token})
