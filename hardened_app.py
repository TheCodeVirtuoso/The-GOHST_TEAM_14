"""
hardened_app.py — Patched JWT server (port 5001)
==================================================
THE FIX: algorithms=["RS256"] — pin to a single algorithm.

Why this works at the PyJWT library level (say this in the demo):
  - When PyJWT receives a token with alg=none, it checks whether "none"
    is in the allowed algorithms list. It is NOT, so PyJWT raises
    DecodeError BEFORE it even looks at the signature. Attack 1 blocked.
  - When PyJWT receives a token with alg=HS256, same check: "HS256" is
    not in ["RS256"], so DecodeError is raised immediately. Attack 2
    blocked. The server never tries to verify the forged HMAC signature.
  - The fix is enforced by the JWT library itself, not by application
    logic — an attacker cannot bypass it without the RSA private key.

Residual risks NOT covered by this fix (state these in Q&A):
  - Weak HS256 secrets brute-forceable with hashcat
  - Token replay (missing exp / jti claims)
  - Private key exfiltration on the server side

MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material
"""

import jwt
import json
import base64
import logging
import time as _time
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

# ── Live event log (same pattern as vulnerable server) ─────────────────────
_EVENTS = []
_TOTAL_EVENTS = 0

def _log_event(ip, alg, result, status_code, path="/admin"):
    global _TOTAL_EVENTS
    _TOTAL_EVENTS += 1
    _EVENTS.append({
        "ts":     _time.strftime("%H:%M:%S"),
        "ip":     ip,
        "alg":    alg,
        "result": result,
        "status": status_code,
        "path":   path,
    })
    if len(_EVENTS) > 50:
        _EVENTS.pop(0)

# ── Key loading ────────────────────────────────────────────────────────────
with open("private.pem") as f:
    PRIVATE_KEY = f.read()

with open("public.pem") as f:
    PUBLIC_KEY = f.read()

# ── User store ─────────────────────────────────────────────────────────────
USERS = {
    "alice": {"password": "pass123", "role": "user"},
    "admin": {"password": "secret99", "role": "admin"},
}

# ── JWT helpers ────────────────────────────────────────────────────────────

def decode_secure(token: str) -> dict:
    """
    THE SECURE DECODER.
    algorithms=["RS256"] pins the server to one algorithm.
    PyJWT rejects "none" and "HS256" at library level — no application
    logic needed, cannot be bypassed by token manipulation.
    """
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"],  # ← the one-line fix; only RS256 is accepted
    )


def require_auth(f):
    """Decorator: extract Bearer token, decode it securely, attach to request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Missing token"}), 401
        try:
            request.user = decode_secure(token)
        except Exception as e:
            try:
                raw = token.split(".")[0]
                raw += "=" * (4 - len(raw) % 4)
                bad_alg = json.loads(base64.urlsafe_b64decode(raw)).get("alg", "unknown")
            except Exception:
                bad_alg = "unknown"
            _log_event(request.remote_addr, bad_alg, "REJECTED", 401, path=request.path)
            return jsonify({"error": f"Token rejected: {str(e)}"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Request logger ─────────────────────────────────────────────────────────

@app.before_request
def log_request():
    """Log every incoming request so attacks are visible in the terminal."""
    auth = request.headers.get("Authorization", "<none>")
    logging.info(
        "[HARD:5001] %s %s | IP=%s | Auth=%s",
        request.method,
        request.path,
        request.remote_addr,
        auth[:80],
    )


# ── Endpoints ──────────────────────────────────────────────────────────────

@app.route("/public-key")
def get_public_key():
    """Public key endpoint — same as vulnerable server (key exposure is not the bug)."""
    return PUBLIC_KEY, 200, {"Content-Type": "text/plain"}


@app.route("/login", methods=["POST"])
def login():
    """Authenticate and return an RS256-signed JWT — identical to vulnerable server."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = USERS.get(username)
    if not user or user["password"] != password:
        _log_event(request.remote_addr, "N/A", "REJECTED", 401, path="/login")
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {"user": username, "role": user["role"]}
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    _log_event(request.remote_addr, "N/A", "SUCCESS", 200, path="/login")
    return jsonify({"token": token})


@app.route("/profile")
@require_auth
def profile():
    _log_event(request.remote_addr, "RS256", "SUCCESS", 200, path="/profile")
    return jsonify({"user": request.user})


@app.route("/admin")
@require_auth
def admin():
    """
    Admin-only endpoint. Attacks 1 and 2 must fail here with 401.
    The decode_secure() call above will reject forged tokens before
    this function even runs.
    """
    if request.user.get("role") != "admin":
        _log_event(request.remote_addr, "RS256", "FORBIDDEN", 403, path="/admin")
        return jsonify({"error": "Forbidden — admin only"}), 403
    _log_event(request.remote_addr, "RS256", "SUCCESS", 200, path="/admin")
    return jsonify({
        "message": "ADMIN ACCESS GRANTED (legitimate token)",
        "note": "This response should only appear with a real RS256 token signed by private.pem",
    })


@app.route("/events")
def events():
    """Dashboard polls this every 2s — mirrors vulnerable server's /events."""
    return jsonify({"total": _TOTAL_EVENTS, "events": list(reversed(_EVENTS))})


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 65)
    print("  HARDENED JWT SERVER — port 5001")
    print("  algorithms accepted: RS256 only  [patched]")
    print("  Fix: algorithms=['RS256'] — PyJWT rejects none/HS256 at lib level")
    print("=" * 65)
    app.run(host="0.0.0.0", port=5001, debug=False)
