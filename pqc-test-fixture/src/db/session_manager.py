"""
Internal session-store helper. Not exposed via any HTTP route.
Expected classification: Business Criticality = MEDIUM (score ~2.15)
  Sens=4.0 ('secret'/'token' keywords, 2 matches) | Exp=1.0 (internal, no route signature)
  Sys=2.0 (standard baseline app code, not /prod/ or /tests/)
  Reg=1.0 (no compliance keyword)
Expected Exposure = Internal (no route decorator, no published port, no external keyword)
Expected Mode = None/blank (no AES cipher instantiation here — HMAC only)
"""
import hmac
import hashlib
import os

# Internal session secret token, read via bracket access (NOT '.get(' to avoid
# tripping the known Go-Gin false-positive route regex in engine.js).
SESSION_SECRET_TOKEN = os.environ["SESSION_SECRET_TOKEN"]


def sign_session_id(session_id: str) -> str:
    """HMAC-signs an internal session token before storing it in the session db."""
    return hmac.new(SESSION_SECRET_TOKEN.encode(), session_id.encode(), hashlib.sha256).hexdigest()


def store_user_session(user_id: str, session_id: str):
    signed = sign_session_id(session_id)
    # writes to internal session db (no network call, no route)
    return {"user_id": user_id, "session_id": session_id, "signed": signed}
