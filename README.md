# Problem #17 — JWT Authentication Bypass & Algorithm Confusion

## FoSC 23CSE313 · Cybersecurity Hackathon · Amrita School of Computing

**MITRE ATT&CK:** T1550.001 — Use Alternate Authentication Material  
**Track:** Offensive  
**Difficulty:** Hard · **Marks:** 30 · **Team:** TEAM-14

---

## What This Project Demonstrates

A deliberately vulnerable Flask REST API that uses JWT tokens for authentication.  
Six separate exploits attack the server — forging admin tokens, cracking secrets, spraying credentials, and replaying stolen tokens — **all without knowing the server's private key**.

| # | Attack | Script | Crypto Needed |
|---|--------|--------|--------------|
| 1 | `alg=none` bypass | `attack_none.py` | None |
| 2 | RS256 → HS256 algorithm confusion | `attack_confusion.py` | Only the public key |
| 3 | Claim forgery (role=admin injection) | `attack_forgery.py` | None (consequence of Attack 1) |
| 4 | Credential spray | `attack_spray.py` | None |
| 5 | JWT secret crack (HS256 weak secret) | `attack_crack.py` | None — fully offline |
| 6 | Token replay (no expiry) | `attack_replay.py` | None |

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate RSA key pair (skip if `private.pem` and `public.pem` already exist)

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

### 3. Verify imports

```bash
python -c "import flask, jwt, cryptography, requests; print('All imports OK')"
```

---

## Running the Demo

### Option A — Fully automatic (recommended for demo)

```bash
python demo.py
```

`demo.py` starts both servers automatically, runs all attacks, prints results, then stops.  
Output is also saved to `demo_output.txt` — use it as backup if the live demo breaks.

**Expected output:**

```
[SUCCESS]   vs VULNERABLE server (port 5000)   HTTP 200  |  flag{jwt_alg_confusion_2025}
[BLOCKED]   vs HARDENED   server (port 5001)   HTTP 401  |  Token rejected: ...
```

---

### Option B — Manual (run each attack separately)

```bash
# Terminal 1 — vulnerable server
python vulnerable_app.py        # port 5000

# Terminal 2 — hardened server
python hardened_app.py          # port 5001

# Terminal 3 — run any attack script
python attack_none.py           # Attack 1: alg=none bypass
python attack_confusion.py      # Attack 2: RS256→HS256 confusion
python attack_forgery.py        # Attack 3: claim forgery (role=admin)
python attack_spray.py          # Attack 4: credential spray
python attack_crack.py          # Attack 5: JWT secret crack (offline — no server needed)
python attack_replay.py         # Attack 6: token replay
```

---

### Option C — Web dashboard (browser UI)

```bash
# Terminal 1
python vulnerable_app.py

# Terminal 2
python hardened_app.py

# Terminal 3
python dashboard.py             # port 5002

# Open browser
http://localhost:5002
```

Click **Run Attack** buttons to trigger exploits and see live color-coded results.  
The **Live Attack Feed** panel shows every hit on both servers in real time — including attacks run from teammate laptops.

**From another laptop on the same network:**

```bash
# On the attacker laptop
set SERVER_IP=10.236.147.152    # Windows — set to server's LAN IP
python dashboard.py

# Or just open browser to:
http://10.236.147.152:5002
```

> **Windows Firewall** — run once on the server laptop (as Administrator) to allow LAN connections:
> ```
> netsh advfirewall firewall add rule name="JWT Demo" dir=in action=allow protocol=TCP localport=5000-5002
> ```

---

## Project Files

```
TEAM_14_HACKTHON/
├── vulnerable_app.py    ← Intentionally broken Flask API (port 5000)
├── hardened_app.py      ← Patched Flask API — blocks JWT attacks (port 5001)
├── attack_none.py       ← Attack 1: alg=none bypass
├── attack_confusion.py  ← Attack 2: RS256→HS256 algorithm confusion
├── attack_forgery.py    ← Attack 3: claim forgery (role=admin injection)
├── attack_spray.py      ← Attack 4: credential spray
├── attack_crack.py      ← Attack 5: JWT secret crack (offline, no server needed)
├── attack_replay.py     ← Attack 6: token replay (no exp/jti enforcement)
├── demo.py              ← End-to-end runner (auto-starts both servers)
├── dashboard.py         ← Web UI dashboard with live attack feed (port 5002)
├── private.pem          ← RSA 2048 private key — server signing key, never shared
├── public.pem           ← RSA public key — exposed at /public-key (intentional)
└── README.md            ← This file
```

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/login` | POST | None | Returns RS256-signed JWT for valid credentials |
| `/public-key` | GET | None | Returns RSA public key (mirrors real JWKS endpoints) |
| `/profile` | GET | Bearer token | Returns token claims |
| `/admin` | GET | Bearer token (role=admin) | Target endpoint — returns flag on success |
| `/events` | GET | None | Live event log (polled by dashboard every 2s) |

**Test users:**

| Username | Password | Role |
|----------|----------|------|
| alice | pass123 | user |
| admin | secret99 | admin |

---

## Threat Model

**Assets:** Admin API endpoints (`/admin`), user session integrity, credential store

**Attacker profile:** Any user on the network — no prior authentication required for most attacks.

**Attack surface:** JWT validation logic, `/login` endpoint, token lifetime enforcement.

---

## Attack Details

### Attack 1 — `alg=none` Bypass

**Root cause:** Server includes `none` in its accepted algorithm list. The JWT spec defines `alg=none` as "no signature required" — the server skips verification entirely.

**Steps:**
1. Build a token with `{"alg": "none"}` in the header
2. Set `{"user": "attacker", "role": "admin"}` in the payload
3. Leave signature empty — `header.payload.`
4. Server accepts it, returns the flag

**CVE:** CVE-2015-9235 (node-jsonwebtoken — same bug, millions of apps affected)

---

### Attack 2 — RS256 → HS256 Algorithm Confusion

**Root cause:** Server accepts both RS256 (asymmetric) and HS256 (symmetric). For HS256, the server uses its RSA public key as the HMAC secret. The attacker fetches the public key from `/public-key`, signs a forged HS256 token with it, and the server verifies with the same key — and accepts it.

**Steps:**
1. Fetch public key from `/public-key`
2. Build forged token with `{"alg": "HS256", "role": "admin"}`
3. Sign with HS256 using the public key as the HMAC secret
4. Server verifies with the same public key — accepts it

**CVE:** CVE-2015-9235, Auth0 SDK algorithm confusion (2022)

---

### Attack 3 — Claim Forgery

**Root cause:** Direct consequence of Attack 1 or 2. Once the server accepts an unsigned or confusion-signed token, the attacker controls the entire payload.

**Steps:**
1. Use Attack 1 (alg=none) to bypass signature
2. Inject `"role": "admin"` into the payload
3. Call `/admin` — server reads `role` from the forged payload and grants access

**Impact:** Full admin access without the admin password or the private key.

---

### Attack 4 — Credential Spray

**Root cause:** No rate limiting on `/login`. Attacker tries common passwords across multiple accounts to avoid per-account lockout thresholds.

**Steps:**
1. Build a list of `username:password` pairs
2. POST each to `/login` with a small delay
3. Any HTTP 200 response → valid credential found → JWT captured for further attacks

**MITRE:** T1110.003 — Brute Force: Password Spraying

---

### Attack 5 — JWT Secret Crack (Offline)

**Root cause:** When a server uses HS256 with a weak secret, an attacker who captures any valid token can crack the secret entirely offline — no server contact needed.

**Steps:**
1. Capture a valid HS256-signed token
2. For each candidate in the wordlist: re-sign `header.payload` with that candidate
3. If the signature matches → secret found
4. Use the cracked secret to forge admin tokens signed with HS256

**Real-world tool:** `hashcat --hash-type 16500 token.txt rockyou.txt`

**MITRE:** T1110.002 — Brute Force: Password Cracking

---

### Attack 6 — Token Replay

**Root cause:** Tokens issued with no `exp` claim never expire. With no `jti` claim, there is no unique token ID to blacklist. A token captured once is valid forever.

**Steps:**
1. Intercept a valid JWT from network traffic, a leaked log, or a login response
2. Use the same token repeatedly — minutes, hours, or days later
3. Server accepts it every time — no expiry check, no one-time-use enforcement

**MITRE:** T1550.001 — Use Alternate Authentication Material

---

## Architecture Notes

Flask was chosen because it exposes JWT validation logic clearly for educational purposes.  
This vulnerability exists identically in FastAPI, Django REST, Express.js, and Spring Boot.

JWTs with RS256 are used in all major cloud identity providers:
- **AWS Cognito** — issues RS256 tokens, exposes public keys at a JWKS endpoint
- **Auth0** — RS256 by default, had algorithm confusion bug in its own SDK (2022)
- **GCP Identity Platform** — RS256 signed tokens for Firebase Auth

The exposed `/public-key` endpoint mirrors real-world JWKS endpoints. The vulnerability is **not** exposing the public key — it is accepting HS256 alongside RS256.

---

## MITRE ATT&CK Mapping

| Attack | Technique ID | Technique Name |
|--------|-------------|----------------|
| alg=none bypass | T1550.001 | Use Alternate Authentication Material — Application Access Token |
| RS256→HS256 confusion | T1550.001 | Use Alternate Authentication Material — Application Access Token |
| Claim forgery | T1550.001 | Consequence of above — forged token with escalated claims |
| Credential spray | T1110.003 | Brute Force: Password Spraying |
| JWT secret crack | T1110.002 | Brute Force: Password Cracking |
| Token replay | T1550.001 | Use Alternate Authentication Material — replayed token |

---

## Q&A Prep

| Question | Answer |
|----------|--------|
| Why Flask? | Exposes JWT validation logic clearly. Same vulnerability in FastAPI, Django, Express, Spring. |
| Would this work against a real API? | Yes. CVE-2015-9235 was this exact attack in node-jsonwebtoken used by millions of apps. |
| How would a company detect this? | WAF JWT inspection, SIEM alerts on `alg` field changes, API gateway algorithm allow-list. |
| Is RS256 always safe? | Only if algorithm is pinned server-side. An open algorithm list makes RS256 worse than HS256 with a strong secret. |
| What library version fixes the JWT attacks? | PyJWT >= 2.0 removed `none` from defaults. Always pin in `requirements.txt`. |
| Can you bypass the hardened app? | Not the JWT attacks. Credential spray and token replay are separate attack classes requiring rate limiting and `exp`/`jti` enforcement — documented as residual risks. |
| Why is the public key exposed? | It mirrors real-world JWKS endpoints. AWS Cognito, Auth0, GCP all expose public keys. The bug is accepting HS256, not exposing the key. |
| What is the single-line fix? | `algorithms=["RS256"]` in `jwt.decode()` — blocks alg=none, HS256 confusion, and claim forgery at the library level. |
