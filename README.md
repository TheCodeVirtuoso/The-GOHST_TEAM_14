# Problem #17 — JWT Authentication Bypass & Algorithm Confusion Attack

> **FoSC 23CSE313 · Cybersecurity Hackathon · Amrita School of Computing · TEAM-14**

| Field | Detail |
|-------|--------|
| **Track** | Offensive |
| **Difficulty** | Hard |
| **Architecture** | Cloud-Native |
| **MITRE ATT&CK** | T1550.001 — Use Alternate Authentication Material |
| **CVE References** | CVE-2015-9235 · Auth0 SDK Confusion (2022) |
| **Marks** | 30 |

---

## What This Project Is (Plain English)

When you log into a website, the server gives you a digital pass called a **JWT**.
Every request you make after login shows that pass — the server reads it and decides what you can do.

We found that the server can be tricked into **accepting a fake pass** — one we wrote ourselves —
giving us full admin access **without knowing any password or secret key.**

We built **six different ways to break this** and demonstrated all of them live.

---

## What This Project Is (Technical)

A deliberately vulnerable Flask REST API (port 5000) implementing JWT authentication
with a misconfigured decoder that **trusts the `alg` field from the incoming token header**.

This one misconfiguration enables three direct JWT exploits and exposes three additional attack surfaces:

| # | Attack | Script | MITRE | Crypto Required |
|---|--------|--------|-------|----------------|
| 1 | `alg=none` bypass | `attack_none.py` | T1550.001 | None |
| 2 | RS256 → HS256 algorithm confusion | `attack_confusion.py` | T1550.001 | Public key only |
| 3 | Claim forgery (`role=admin`) | `attack_forgery.py` | T1550.001 | None |
| 4 | Credential spray | `attack_spray.py` | T1110.003 | None |
| 5 | JWT secret crack (offline HS256) | `attack_crack.py` | T1110.002 | None |
| 6 | Token replay (no `exp`/`jti`) | `attack_replay.py` | T1550.001 | None |

A hardened server (port 5001) blocks the JWT attacks with a single `algorithms=["RS256"]` fix.
A live web dashboard (port 5002) shows all attacks from all laptops in real time.

---

## Deliverable Checklist

- [x] **(a)** `alg=none` vulnerability — `attack_none.py`
- [x] **(b)** RS256 → HS256 algorithm confusion using public key as HMAC secret — `attack_confusion.py`
- [x] **(c)** Arbitrary claim forgery (`role: admin`) to gain elevated access — `attack_forgery.py`
- [x] Working exploits against a locally deployed vulnerable Flask API
- [x] Hardened server with proper JWT validation — `hardened_app.py`
- [x] Hardening guide with algorithm pinning and public key management — see Section 9 below

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/TheCodeVirtuoso/The-GOHST_TEAM_14
cd The-GOHST_TEAM_14
pip install -r requirements.txt
```

### 2. Generate RSA key pair

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

Skip if `private.pem` and `public.pem` already exist.

### 3. Verify

```bash
python -c "import flask, jwt, cryptography, requests; print('All OK')"
```

---

## Running the Demo

### Option A — One command (recommended for demo day)

```bash
python demo.py
```

Auto-starts both servers, runs all attacks, prints results, saves `demo_output.txt` as backup.

```
[SUCCESS]  VULNERABLE :5000  HTTP 200  flag{jwt_alg_confusion_2025}
[BLOCKED]  HARDENED   :5001  HTTP 401  Token rejected
```

### Option B — Manual (separate terminals)

```bash
# Terminal 1
python vulnerable_app.py       # port 5000 — vulnerable server

# Terminal 2
python hardened_app.py         # port 5001 — hardened server

# Terminal 3 — run any attack
python attack_none.py          # Attack 1
python attack_confusion.py     # Attack 2
python attack_forgery.py       # Attack 3
python attack_spray.py         # Attack 4
python attack_crack.py         # Attack 5 — fully offline, no server needed
python attack_replay.py        # Attack 6
```

### Option C — Web Dashboard (best for live demo)

```bash
python vulnerable_app.py
python hardened_app.py
python dashboard.py            # port 5002

# Open: http://localhost:5002
```

Click attack buttons — results appear with live color-coded SUCCESS / BLOCKED labels.
The **Live Attack Feed** shows every hit from every laptop on the network in real time.

### Multi-Laptop Setup

```bash
# Server laptop — run once as Administrator
netsh advfirewall firewall add rule name="JWT Demo" dir=in action=allow protocol=TCP localport=5000-5002

# Attacker laptop — change TARGET in any attack script to server's LAN IP
TARGET = "http://<server-ip>:5000"
```

### Postman Setup

```bash
python postman_tokens.py       # prints all forged tokens ready to paste
```

| Request | Method | URL | Header / Body |
|---------|--------|-----|---------------|
| Login (spray) | POST | `:5000/login` | `{"username":"admin","password":"secret99"}` |
| Token Replay | GET | `:5000/profile` | `Authorization: Bearer <token>` — repeat 5× |
| Attack 1 | GET | `:5000/admin` | `Authorization: Bearer <none-token>` |
| Attack 2 | GET | `:5000/admin` | `Authorization: Bearer <hs256-token>` |
| Hardened (blocked) | GET | `:5001/admin` | Same tokens → HTTP 401 |

---

## Project Files

```
TEAM_14_HACKTHON/
├── vulnerable_app.py    ← Intentionally broken Flask API (port 5000)
├── hardened_app.py      ← Patched Flask API — JWT attacks blocked (port 5001)
├── attack_none.py       ← Attack 1: alg=none bypass
├── attack_confusion.py  ← Attack 2: RS256→HS256 algorithm confusion
├── attack_forgery.py    ← Attack 3: claim forgery (role=admin)
├── attack_spray.py      ← Attack 4: credential spray
├── attack_crack.py      ← Attack 5: JWT secret crack (offline)
├── attack_replay.py     ← Attack 6: token replay
├── demo.py              ← Auto-runs everything end-to-end
├── dashboard.py         ← Live web dashboard (port 5002)
├── postman_tokens.py    ← Generates tokens for Postman demo
├── requirements.txt     ← Pinned dependencies
├── private.pem          ← RSA 2048 private key (gitignored — never shared)
├── public.pem           ← RSA public key (intentionally exposed at /public-key)
├── README.md            ← This file
├── EXPLAINER.md         ← Plain English explainer with analogies
└── presentation.md      ← 10-slide deck covering all attacks
```

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/login` | POST | None | Returns RS256-signed JWT |
| `/public-key` | GET | None | RSA public key (mirrors JWKS endpoints) |
| `/profile` | GET | Bearer | Returns token claims |
| `/admin` | GET | Bearer + `role=admin` | Target — returns flag on success |
| `/events` | GET | None | Live event log polled by dashboard |

**Test credentials:**

| User | Password | Role |
|------|----------|------|
| alice | pass123 | user |
| admin | secret99 | admin |

---

## Threat Model

### Assets
- `/admin` endpoint and the data it protects
- User identity and session integrity
- Credential store (`/login`)

### Attacker Profile
- Any network user — no prior authentication needed for JWT attacks
- Low-privilege authenticated user (alice) for claim forgery demo
- Passive observer with one captured token for replay attack

### Attack Surface Diagram

```
[Attacker] ── forged JWT in Authorization header ──▶ [Server: jwt.decode()]
                                                              │
                                                trusts alg from token header
                                                              │
                                         ┌────────────────────┴────────────────────┐
                                      alg=none                               alg=HS256
                                   skip signature                      verify with PUBLIC key
                                   (Attack 1, 3)                           (Attack 2, 3)

[Attacker] ── credential list ──▶ POST /login (no rate limit) ── Attack 4
[Attacker] ── wordlist ──────────▶ offline HMAC crack ─────────── Attack 5
[Attacker] ── stolen token ──────▶ GET /profile (no exp/jti) ──── Attack 6
```

### Attack vs Endpoint Mapping

| Attack | Endpoint | Vulnerability Exploited |
|--------|----------|------------------------|
| alg=none | `/admin` | No algorithm whitelist |
| HS256 confusion | `/admin` | Mixed asymmetric + symmetric alg |
| Claim forgery | `/admin` | Unsigned payload trusted by server |
| Credential spray | `/login` | No rate limiting |
| Secret crack | Offline | Weak HS256 secret |
| Token replay | `/profile` | Missing `exp` and `jti` claims |

---

## Attack Technical Details

### Attack 1 — `alg=none` Bypass

**Root cause:** `alg=none` is a valid JWT spec value — "no signature required."
A server that includes `none` in its accepted algorithm list skips verification.

```
Forged token:
  base64url({"alg":"none","typ":"JWT"})
  .base64url({"user":"attacker","role":"admin"})
  .              ← empty signature
```

**CVE-2015-9235** — identical bug in node-jsonwebtoken, millions of apps affected.

---

### Attack 2 — RS256 → HS256 Algorithm Confusion

**Root cause:** RS256 = asymmetric (private signs, public verifies).
HS256 = symmetric (one secret for both). The server uses the RSA **public key** as the HMAC secret.
The attacker fetches the public key (it is public), computes the same HMAC, server accepts it.

```python
# Attacker does this:
pub_key    = requests.get("/public-key").text
sig        = HMAC_SHA256(secret=pub_key, msg=header+"."+payload)
bad_token  = header + "." + payload + "." + sig

# Server does this (wrong):
expected   = HMAC_SHA256(secret=PUBLIC_KEY, msg=header+"."+payload)
# They match → server accepts the forged token
```

**Auth0 SDK** shipped this exact confusion bug in 2022.

---

### Attack 3 — Claim Forgery (Privilege Escalation)

**Root cause:** Once signature is bypassed (Attack 1 or 2), the attacker controls the payload.

```
Legitimate:  {"user": "alice",    "role": "user"}   ← server issued
Forged:      {"user": "attacker", "role": "admin"}  ← attacker wrote
```

Any claim is forgeable: `role`, `sub`, `email`, `scope`, `permissions`.

---

### Attack 4 — Credential Spray

**Root cause:** No rate limiting on `/login`. Spray tries few passwords across many accounts
to stay under per-account lockout thresholds.

```
POST /login {"username":"admin","password":"admin"}    → 401
POST /login {"username":"admin","password":"secret99"} → 200 ✓  token captured
```

**MITRE T1110.003** — Password Spraying

---

### Attack 5 — JWT Secret Crack (Offline)

**Root cause:** HS256 with a weak secret is brute-forceable from any captured token.

```
For each candidate in wordlist:
    trial_sig = HMAC_SHA256(candidate, header.payload)
    if trial_sig == token.signature:
        secret_found → forge any token
```

Real-world: `hashcat --hash-type 16500 token.txt rockyou.txt`
**MITRE T1110.002** — Password Cracking

---

### Attack 6 — Token Replay

**Root cause:** Tokens issued without `exp` or `jti` live forever with no revocation possible.

```
Day 1:  Token intercepted from traffic / logs / shoulder surfing
Day 7:  Same token sent → HTTP 200 ACCEPTED
Day 30: Same token sent → HTTP 200 ACCEPTED
```

**MITRE T1550.001** — Use Alternate Authentication Material

---

## Hardening Guide

### Fix 1 — Algorithm Pinning (blocks Attacks 1, 2, 3)

```python
# VULNERABLE — server reads algorithm from the token
alg = header.get("alg")
jwt.decode(token, key, algorithms=[alg])   # attacker controls alg!

# FIXED — one line
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
#                              ^^^^^^^^^^^^^^^^^^
#           PyJWT rejects none and HS256 at library level before
#           reading the signature or payload — cannot be bypassed
```

### Fix 2 — Rate Limiting (blocks Attack 4)

```python
from flask_limiter import Limiter
limiter = Limiter(get_remote_address, app=app)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login(): ...
```

### Fix 3 — Token Expiry + Unique ID (blocks Attack 6)

```python
import time, uuid
payload = {
    "user": username,
    "role": user["role"],
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,   # expires in 1 hour
    "jti": str(uuid.uuid4()),          # unique ID — blacklistable on logout
}
```

### Fix 4 — Public Key Management

- Rotate RSA key pairs every 90 days
- Serve public keys via a JWKS endpoint with `kid` (key ID) for rotation
- Never reuse key pairs across environments (dev / staging / prod)

### Fix 5 — Use a Vetted Library

| Library | Safe version |
|---------|-------------|
| PyJWT (Python) | >= 2.0.0 |
| jsonwebtoken (Node.js) | >= 9.0.0 |
| java-jwt (Java) | >= 4.0.0 |

---

## Limitations & Bypasses

| Limitation | Explanation |
|-----------|-------------|
| Attack 1 needs `none` in accept list | A default-deny whitelist eliminates it entirely |
| Attack 2 needs the public key | If `/public-key` is behind auth, attacker needs another path |
| Attack 2 fails against strict JWKS | Libraries enforcing `kty` reject RSA keys for HS256 |
| Credential spray needs weak passwords | Strong password policy + MFA neutralises it |
| Secret crack applies only to HS256 | RSA private keys cannot be derived from a captured token |
| Token replay needs token interception | HTTPS blocks network sniffing — risk remains for leaked tokens |
| Forged tokens don't bypass `exp` | If a past expiry is set, PyJWT rejects it even on the vulnerable server |

---

## Architecture Fit — Real-World Relevance

| Platform | JWT Usage | Relevance |
|----------|-----------|-----------|
| **AWS Cognito** | RS256, JWKS endpoint | Same confusion possible if app decodes manually |
| **Auth0** | RS256 default — had HS256 confusion in SDK (2022) | Direct instance of Attack 2 |
| **GCP Identity / Firebase** | RS256, rotated JWKS | Algorithm pinning is the fix |
| **Azure AD** | RS256, open-id discovery | Misconfigured relying parties are vulnerable |

**How this is caught in production:**
- JWT algorithm allow-listing in API gateway (AWS API Gateway, Kong, NGINX)
- SIEM alert on `alg` field changes in incoming token headers
- PyJWT version pinning in `requirements.txt`
- Automated library audit in CI/CD pipeline

---

## MITRE ATT&CK Mapping

| Attack | Technique ID | Name |
|--------|-------------|------|
| alg=none bypass | T1550.001 | Use Alternate Authentication Material — Application Access Token |
| RS256→HS256 confusion | T1550.001 | Use Alternate Authentication Material — Application Access Token |
| Claim forgery | T1548 | Abuse Elevation Control Mechanism (via T1550.001) |
| Credential spray | T1110.003 | Brute Force: Password Spraying |
| JWT secret crack | T1110.002 | Brute Force: Password Cracking |
| Token replay | T1550.001 | Use Alternate Authentication Material — Application Access Token |

---

## Q&A Preparation

| Question | Answer |
|---------|--------|
| Why Flask? | Exposes JWT validation logic clearly. Same bug exists in FastAPI, Django, Express, Spring Boot. |
| Real-world impact? | CVE-2015-9235 — node-jsonwebtoken, millions of apps. Auth0 SDK had same confusion in 2022. |
| How would a SOC detect this? | WAF JWT inspection, SIEM alert on `alg` field changes, anomaly detection on token structure. |
| Is RS256 always safe? | Only when pinned server-side. Open algorithm list makes RS256 worse — gives attacker a known public key. |
| Minimum fix? | `algorithms=["RS256"]` in every `jwt.decode()`. PyJWT >= 2.0 enforces at library level. |
| Can you bypass the hardened server? | Not via JWT attacks — library rejects before reading payload. Spray and replay still work as separate attack classes. |
| Why expose the public key? | Mirrors real-world JWKS endpoints. AWS Cognito, Auth0, GCP all do this. Exposing is correct — accepting HS256 is the bug. |
| What does Attack 5 prove? | HS256 with a weak secret can be cracked offline from any captured token — no server contact needed. This is why HS256 is unsuitable for public APIs. |

---

## Team Roles

| Member | Responsibility |
|--------|---------------|
| Person 1 | `attack_none.py`, `attack_confusion.py` — core JWT exploits |
| Person 2 | `attack_forgery.py`, `attack_spray.py` — claim forgery and credential attacks |
| Person 3 | `attack_crack.py`, `attack_replay.py` — crypto crack and replay |
| Person 4 | `dashboard.py`, `demo.py`, documentation |

---

## Dependencies

```
flask>=2.3.0
PyJWT>=2.8.0
cryptography>=41.0.0
requests>=2.31.0
```

`pip install -r requirements.txt`

---

*TEAM-14 · FoSC 23CSE313 · Amrita School of Computing · 2025*
