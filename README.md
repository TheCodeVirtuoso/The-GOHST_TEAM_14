# Problem #17 — JWT Authentication Bypass & Algorithm Confusion Attack

## FoSC 23CSE313 · Cybersecurity Hackathon · Amrita School of Computing

**MITRE ATT&CK:** T1550.001 — Use Alternate Authentication Material  
**Track:** Offensive (with defensive mitigation component)  
**Difficulty:** Hard · **Marks:** 30 · **Team:** TEAM-14

---

## What This Project Demonstrates

A deliberately vulnerable Flask REST API that uses JWT tokens for authentication.  
Three separate exploits forge admin tokens **without knowing the server's private key**.  
A patched server defeats all three with a single one-line fix.

| Attack | Technique | Crypto needed | Impact |
|--------|-----------|--------------|--------|
| 1 | `alg=none` bypass | None | Unauthenticated admin access |
| 2 | RS256 → HS256 confusion | Only public key | Admin access via algorithm switch |
| 3 | Claim forgery | Consequence of 1 or 2 | Inject `role=admin` into any forged token |

---

## Setup

### 1. Install dependencies

```bash
pip install flask pyjwt "pyjwt[crypto]" cryptography requests
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

`demo.py` starts both servers automatically, runs all attacks, prints results, then stops the servers.  
Output is also saved to `demo_output.txt` — use it as backup if the live demo breaks.

**Expected output:**

```
[SUCCESS]   vs VULNERABLE server (port 5000)   HTTP 200  |  flag{jwt_alg_confusion_2025}
[BLOCKED]   vs HARDENED   server (port 5001)   HTTP 401  |  Token rejected: ...
```

---

### Option B — Manual (three terminals)

```bash
# Terminal 1 — vulnerable server
python vulnerable_app.py        # port 5000

# Terminal 2 — hardened server
python hardened_app.py          # port 5001

# Terminal 3 — run attacks
python attack_none.py           # Attack 1
python attack_confusion.py      # Attack 2
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

**From another laptop on the same network:**

```bash
# On the attacker laptop — point dashboard at server's IP
set SERVER_IP=10.236.147.152    # Windows
python dashboard.py

# Or just open browser to:
http://10.236.147.152:5002
```

> **Windows Firewall** — run once on the server laptop to allow LAN connections:
> ```
> netsh advfirewall firewall add rule name="JWT Demo" dir=in action=allow protocol=TCP localport=5000-5002
> ```

---

## Project Files

```
TEAM_14_HACKTHON/
├── vulnerable_app.py   ← Intentionally broken Flask API (port 5000)
├── hardened_app.py     ← Patched Flask API — blocks all 3 attacks (port 5001)
├── attack_none.py      ← Attack 1: none-algorithm bypass
├── attack_confusion.py ← Attack 2: RS256→HS256 algorithm confusion
├── demo.py             ← End-to-end demo runner (auto-starts both servers)
├── dashboard.py        ← Web UI dashboard (port 5002)
├── private.pem         ← RSA 2048 private key — server signing key, never shared
├── public.pem          ← RSA public key — exposed at /public-key (intentional)
└── README.md           ← This file
```

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/login` | POST | None | Returns RS256-signed JWT for valid credentials |
| `/public-key` | GET | None | Returns RSA public key (mirrors real JWKS endpoints) |
| `/profile` | GET | Bearer token | Returns token claims |
| `/admin` | GET | Bearer token (role=admin) | Target endpoint — returns flag on success |

**Test users:**

| Username | Password | Role |
|----------|----------|------|
| alice | pass123 | user |
| admin | secret99 | admin |

---

## Threat Model

**Assets:** Admin API endpoints (`/admin`), user data, session integrity

**Attacker profile:** Authenticated low-privilege user (has a valid JWT for `alice`).  
No access to the server's RSA private key.

**Attack surface:** JWT validation logic — specifically the `algorithms` parameter in `jwt.decode()`.

---

### Attack 1 — `alg=none` Bypass

**What the bug is:** The server includes `none` in its accepted algorithm list. The JWT spec defines `alg=none` as "no signature required." When the server sees this, it skips verification entirely.

**Why it exists:** Misconfigured `algorithms` parameter — `["RS256", "HS256", "none"]` instead of `["RS256"]`.

**How the fix works:** `algorithms=["RS256"]` — PyJWT checks the `alg` field against the allowed list before touching the signature. `none` is not in the list → `DecodeError` raised immediately.

**CVE reference:** CVE-2015-9235 (node-jsonwebtoken — same bug, millions of apps affected)

---

### Attack 2 — RS256 → HS256 Algorithm Confusion

**What the bug is:** The server accepts both RS256 (asymmetric) and HS256 (symmetric). For HS256, one shared secret does both signing and verification. The server uses its RSA public key as that shared secret. The attacker fetches the public key from `/public-key` (it is intentionally public), signs a forged token with HS256 using that key, and the server verifies it with the same key — and accepts it.

**Why it exists:** Mixing asymmetric and symmetric algorithms in the same accept list without understanding that the verification key changes meaning between them.

**How the fix works:** Pinning to `algorithms=["RS256"]` means PyJWT rejects any HS256 token at the library level — the server never even attempts HMAC verification.

**CVE references:** CVE-2015-9235 (node-jsonwebtoken), Auth0 SDK algorithm confusion (2022)

---

### Attack 3 — Claim Forgery

**What the bug is:** Direct consequence of Attack 1 or 2. Since the attacker controls the JWT payload, they inject `"role": "admin"` into any forged token and call `/admin`.

**Impact:** Full admin access without knowing the admin password or the private key.

---

### After the Fix

**Residual risk** (out of scope for this problem):
- Weak HS256 secrets brute-forceable with hashcat + rockyou.txt
- Token replay (missing `exp` / `jti` claims)
- Private key exfiltration on the server side

**What the fix does NOT cover:** Weak JWT secrets, missing expiry validation, token replay.

---

## Limitations of These Attacks

- Attack 1 requires `none` to be in the server's algorithm list — a default-deny list eliminates it.
- Attack 2 requires the public key to be accessible. If `/public-key` is behind auth, this path fails.
- Attack 2 does not work if the server uses a JWKS endpoint with strict key-type enforcement.
- Neither attack bypasses `exp` (expiry) claims — a forged token still expires if a past timestamp is set.
- Alternative attack path not demonstrated: brute-forcing a weak HS256 secret (hashcat + rockyou.txt).

---

## Architecture Notes

Flask was chosen because it exposes the JWT validation logic clearly for educational purposes.  
In production this vulnerability exists identically in FastAPI, Django REST, and Node.js Express.

JWTs secured with RS256 are used in all major cloud-native identity providers:
- **AWS Cognito** — issues RS256 tokens, exposes public keys at a JWKS endpoint
- **Auth0** — RS256 by default, had algorithm confusion bug in its SDK (2022)
- **GCP Identity Platform** — RS256 signed tokens for Firebase Auth

**How this would be caught in production:**
- JWT algorithm allow-listing in API gateway config (e.g. AWS API Gateway authorizer)
- PyJWT version pinning in `requirements.txt` — PyJWT >= 2.0 removed `none` from defaults
- SIEM alerts on `alg` field changes in incoming tokens
- Regular JWT library audits in CI pipeline

---

## MITRE ATT&CK Mapping

| Attack Vector | Technique | Sub-technique |
|---------------|-----------|---------------|
| none algorithm bypass | T1550 — Use Alternate Authentication Material | T1550.001 — Application Access Token |
| RS256→HS256 confusion | T1550 — Use Alternate Authentication Material | T1550.001 — Application Access Token |
| Claim forgery (role escalation) | T1548 — Abuse Elevation Control Mechanism | via forged token from T1550.001 |

---

## Q&A Prep

| Question | Answer |
|----------|--------|
| Why Flask and not a real production framework? | Flask exposes JWT logic clearly. FastAPI, Django REST, Node.js Express — same vulnerability exists in all. |
| Would this work against a real API? | Yes. CVE-2015-9235 was this exact attack in node-jsonwebtoken used by millions of apps. |
| How would a company detect this? | WAF JWT inspection, SIEM alerts on `alg` field changes, API gateway algorithm allow-list. |
| Is RS256 always safe? | Only if algorithm is pinned server-side. RS256 with an open algorithm list is worse than HS256 with a strong secret. |
| What library version fixes this automatically? | PyJWT >= 2.0 removed `none` from defaults. Always pin in `requirements.txt`. |
| Can you bypass the hardened app? | Not without `private.pem`. You would need to compromise the server itself. |
