"""
vulnerable_app.py — Deliberately misconfigured JWT server (port 5000)
=======================================================================
VULNERABILITY: The server trusts the 'alg' field from the incoming token header
and accepts RS256, HS256, and none. This enables three attacks:

  Attack 1 — alg=none  : skip signature verification entirely.
              Anyone can forge any claims with zero crypto knowledge.

  Attack 2 — RS256->HS256 confusion:
              Server verifies HS256 tokens using the PUBLIC key as HMAC secret.
              Attacker knows the public key (it's public!) so they can compute
              the identical HMAC and forge any payload.

  Attack 3 — Claim forgery:
              Direct consequence of Attack 1 or 2 — inject role=admin to
              escalate privilege to admin without knowing the private key.

MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material
Real-world CVEs: CVE-2015-9235 (node-jsonwebtoken), Auth0 SDK confusion (2022)

Implementation note: decode_vulnerable() is a custom decoder (not raw PyJWT)
because PyJWT >= 2.0 added safeguards that would block the demonstration.
The insecure PATTERN is identical to what vulnerable older libraries did.

DO NOT USE IN PRODUCTION.
"""

import jwt
import json
import base64
import hmac
import hashlib
import logging
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

# ── Live event log (polled by dashboard every 2s) ──────────────────────────
import time as _time
_EVENTS = []       # list of dicts, newest last, capped at 50
_TOTAL_EVENTS = 0  # monotonic counter — never resets, survives the 50-cap

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
# alice is a normal low-privilege user; admin is the target account
USERS = {
    "alice": {"password": "pass123", "role": "user"},
    "admin": {"password": "secret99", "role": "admin"},
}

# ── JWT helpers ────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Decode base64url string, re-adding stripped padding."""
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))


def decode_vulnerable(token: str) -> dict:
    """
    THE VULNERABLE DECODER.

    Root cause: trusts the 'alg' field from the token header.
    Accepted: RS256, HS256, none — the misconfiguration enabling all 3 attacks.

    Attack 1 (alg=none)  : skips signature check entirely.
    Attack 2 (HS256 confusion): verifies with PUBLIC key as HMAC secret;
      attacker knows the public key and computes the same HMAC.
    Attack 3 (claim forgery): inject role=admin in either forged token.

    Note: implemented as a custom decoder because PyJWT >= 2.0 added
    protections that would block the demo; the insecure pattern is identical
    to what CVE-2015-9235 and vulnerable older libraries did.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: expected header.payload.signature")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise ValueError(f"Malformed JWT: {e}")

    alg = header.get("alg", "").upper()

    if alg == "NONE":
        # ATTACK 1: server skips signature — anyone can forge any claims
        payload["_alg"] = "none"
        return payload

    elif alg == "HS256":
        # ATTACK 2: verify HMAC using the PUBLIC key as the secret.
        # Attacker fetches /public-key, computes same HMAC, server accepts it.
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(
            PUBLIC_KEY.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()
        if not hmac.compare_digest(sig_b64, expected_b64):
            raise ValueError("Invalid HMAC signature")
        payload["_alg"] = "HS256"
        return payload

    elif alg == "RS256":
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

    else:
        raise ValueError(f"Algorithm '{alg}' is not accepted")


def require_auth(f):
    """Decorator: extract Bearer token, decode it, attach claims to request.user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Missing token"}), 401
        try:
            request.user = decode_vulnerable(token)
        except Exception as e:
            # Log failed attempt — extract alg from header without full decode
            try:
                import base64 as _b64, json as _json
                raw_hdr = token.split(".")[0]
                raw_hdr += "=" * (4 - len(raw_hdr) % 4)
                bad_alg = _json.loads(_b64.urlsafe_b64decode(raw_hdr)).get("alg", "unknown")
            except Exception:
                bad_alg = "unknown"
            _log_event(request.remote_addr, bad_alg, "REJECTED", 401, path=request.path)
            return jsonify({"error": f"Token invalid: {str(e)}"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Request logger ─────────────────────────────────────────────────────────

@app.before_request
def log_request():
    """Log every incoming request: method, path, remote IP, Authorization header."""
    auth = request.headers.get("Authorization", "<none>")
    logging.info(
        "[VULN:5000] %s %s | IP=%s | Auth=%s",
        request.method,
        request.path,
        request.remote_addr,
        auth[:80],  # truncate long tokens in logs
    )


# ── Endpoints ──────────────────────────────────────────────────────────────

@app.route("/public-key")
def get_public_key():
    """
    Expose the RSA public key — intentional, mirrors real-world JWKS endpoints.
    AWS Cognito, Auth0, GCP all expose public keys so clients can verify tokens.
    The vulnerability is NOT exposing the key — it is accepting HS256.
    """
    return PUBLIC_KEY, 200, {"Content-Type": "text/plain"}


@app.route("/login", methods=["POST"])
def login():
    """Authenticate user and return an RS256-signed JWT."""
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
    """Return the authenticated user's token claims."""
    alg = request.user.get("_alg", "RS256")
    _log_event(request.remote_addr, alg, "SUCCESS", 200, path="/profile")
    return jsonify({"user": request.user})


@app.route("/admin")
@require_auth
def admin():
    """
    Admin-only endpoint. Returns the flag on success.
    Attacks 1, 2, and 3 all target this endpoint.
    """
    alg = request.user.get("_alg", "unknown")
    if request.user.get("role") != "admin":
        _log_event(request.remote_addr, alg, "FORBIDDEN", 403, path="/admin")
        return jsonify({"error": "Forbidden — admin only"}), 403
    _log_event(request.remote_addr, alg, "SUCCESS", 200, path="/admin")
    return jsonify({
        "message": "ADMIN ACCESS GRANTED",
        "flag": "flag{jwt_alg_confusion_2025}",
        "note": "You reached /admin with a forged token — no private key needed.",
    })


@app.route("/events")
def events():
    """Dashboard polls this every 2s to show live attack feed."""
    return jsonify({"total": _TOTAL_EVENTS, "events": list(reversed(_EVENTS))})


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 65)
    print("  VULNERABLE JWT SERVER — port 5000")
    print("  algorithms accepted: RS256, HS256, none  [intentional bug]")
    print("  Real-world pattern: AWS Cognito / Auth0 / GCP Identity")
    print("=" * 65)
    app.run(host="0.0.0.0", port=5000, debug=False)
