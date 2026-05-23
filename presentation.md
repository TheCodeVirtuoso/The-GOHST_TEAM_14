# JWT Authentication Bypass & Algorithm Confusion
### Problem #17 · FoSC 23CSE313 · Amrita School of Computing · TEAM-14
### MITRE ATT&CK: T1550.001 | Track: Offensive | Marks: 30

---

---
# SLIDE 1 — Title

## JWT Authentication Bypass & Algorithm Confusion Attack

**Problem #17 · TEAM-14 · Amrita School of Computing**

| | |
|--|--|
| Track | Offensive |
| Difficulty | Hard |
| Architecture | Cloud-Native |
| MITRE ATT&CK | T1550.001 — Use Alternate Authentication Material |
| CVE References | CVE-2015-9235 · Auth0 SDK (2022) |

> *"Six attacks. Zero private key knowledge. Full admin access."*

---

---
# SLIDE 2 — Technical Implementation *(10 Marks)*
## Core Functionality · Implementation Correctness · Complexity

### What We Built

| File | What It Does |
|------|-------------|
| `vulnerable_app.py` | Flask API on port 5000 — intentionally misconfigured JWT decoder |
| `hardened_app.py` | Same API on port 5001 — one-line fix applied |
| `attack_none.py` | Attack 1: alg=none bypass — no crypto needed |
| `attack_confusion.py` | Attack 2: RS256→HS256 confusion using public key |
| `attack_forgery.py` | Attack 3: Inject role=admin into forged payload |
| `attack_spray.py` | Attack 4: Credential spray across accounts |
| `attack_crack.py` | Attack 5: Offline HS256 secret brute-force |
| `attack_replay.py` | Attack 6: Token replay — no exp/jti enforcement |
| `dashboard.py` | Live browser UI showing all attacks in real time |
| `demo.py` | One-command runner — auto-starts servers and attacks |

### Confirmed Output
```
[SUCCESS]  VULNERABLE :5000  HTTP 200  flag{jwt_alg_confusion_2025}
[BLOCKED]  HARDENED   :5001  HTTP 401  Token rejected
```

---

---
# SLIDE 3 — Technical Implementation *(10 Marks)*
## Code Quality & Engineering Practice

### The Vulnerable Decoder — Root Cause in Code

```python
# ROOT CAUSE: trusts alg field from the token (attacker-controlled)
alg = header.get("alg", "").upper()

if alg == "NONE":
    return payload                    # Attack 1 — skips all verification

elif alg == "HS256":
    expected = hmac.new(
        PUBLIC_KEY.encode(),          # Attack 2 — uses PUBLIC key as secret
        signing_input, hashlib.sha256
    ).digest()
    # if matches → accepts forged token
```

### The Fix — One Line

```python
# VULNERABLE
jwt.decode(token, key, algorithms=[alg])       # user controls alg

# FIXED
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
#                              ^^^^^^^^^^^^^^^^^^
#          PyJWT rejects none + HS256 at library level
#          Cannot be bypassed by token manipulation
```

### Engineering Choices
- Custom decoder used (not raw PyJWT) — PyJWT ≥ 2.0 added safeguards that block the demo; custom decoder reproduces CVE-2015-9235 exactly
- `host="0.0.0.0"` on all servers — LAN accessible for multi-laptop demo
- `_TOTAL_EVENTS` monotonic counter — robust live feed without timestamp collision bugs
- `requirements.txt` with pinned versions — reproducible environment

---

---
# SLIDE 4 — Security Depth & Accuracy *(8 Marks)*
## Threat Model

### Assets & Attack Surface

```
[Attacker] ── forged JWT ──▶ jwt.decode() ──▶ trusts alg from header
                                                       │
                                    ┌──────────────────┴──────────────────┐
                                 alg=none                             alg=HS256
                              skip signature                   verify with PUBLIC key
                             (Attack 1, 3)                         (Attack 2, 3)

[Attacker] ── passwords ──▶ POST /login  (no rate limit)      ── Attack 4
[Attacker] ── wordlist ───▶ offline HMAC crack                ── Attack 5
[Attacker] ── stolen token ▶ GET /profile (no exp / jti)      ── Attack 6
```

### Attacker Profile

| Attribute | Detail |
|-----------|--------|
| Location | Same LAN — no physical access needed |
| Prior access | None required for JWT attacks |
| Skill level | Intermediate — understands base64url encoding |
| Tools | Python + requests (or Postman) |
| Goal | Reach `/admin`, capture flag, no private key |

### Assets at Risk

| Asset | Impact if Compromised |
|-------|----------------------|
| `/admin` endpoint | Full admin access, flag captured |
| RSA private key | Sign any token as any user |
| User credentials | Account takeover |
| JWT session tokens | Impersonation, replay |

---

---
# SLIDE 5 — Security Depth & Accuracy *(8 Marks)*
## ATT&CK Alignment · Attack Technical Validity

### All 6 Attacks — Technical Proof

| # | Attack | How It Works | Result |
|---|--------|-------------|--------|
| 1 | alg=none bypass | `{"alg":"none"}` → server skips signature | HTTP 200 + flag |
| 2 | HS256 confusion | Sign with HS256 using PUBLIC key → server verifies with same key | HTTP 200 + flag |
| 3 | Claim forgery | Inject `"role":"admin"` into unsigned payload | HTTP 200 + flag |
| 4 | Credential spray | Try common passwords at `/login` — no lockout | Credentials found |
| 5 | Secret crack | HMAC brute-force offline from captured token | Secret = "hackme" |
| 6 | Token replay | Same token reused 5× — no exp/jti | HTTP 200 every time |

### MITRE ATT&CK Mapping

| Attack | Technique ID | Name |
|--------|-------------|------|
| alg=none, HS256 confusion, Token replay | **T1550.001** | Use Alternate Authentication Material |
| Claim forgery | **T1548** | Abuse Elevation Control Mechanism |
| Credential spray | **T1110.003** | Brute Force: Password Spraying |
| Secret crack | **T1110.002** | Brute Force: Password Cracking |

### Real-World CVE Proof
- **CVE-2015-9235** — node-jsonwebtoken: exact same alg=none + HS256 confusion bug. Millions of apps.
- **Auth0 SDK (2022)** — Auth0's own SDK shipped Attack 2. Patched after disclosure.

---

---
# SLIDE 6 — Security Depth & Accuracy *(8 Marks)*
## Awareness of Limitations & Bypasses

### What Our Attacks Need to Work

| Attack | Precondition | How to Eliminate |
|--------|-------------|-----------------|
| alg=none | `none` must be in server's accept list | Default-deny whitelist |
| HS256 confusion | Server must accept HS256 | `algorithms=["RS256"]` only |
| Claim forgery | Requires Attack 1 or 2 first | Same fix as above |
| Credential spray | Weak passwords + no rate limit | Rate limiting + strong passwords + MFA |
| Secret crack | Server uses HS256 with weak secret | Use RS256 (asymmetric — uncrackable from token) |
| Token replay | No `exp` or `jti` in tokens | Add `exp=now+3600` and `jti=uuid4()` |

### What Our Fix Does NOT Cover

> `algorithms=["RS256"]` is the fix for Attacks 1, 2, 3.
> Credential spray and token replay are **separate attack classes** — they require:
> - Rate limiting at the API gateway level
> - Token expiry (`exp`) and unique ID (`jti`) in issued tokens

### Forged Tokens Do Not Bypass `exp`
If a valid token with a past expiry is captured and replayed,
PyJWT rejects it even on the **vulnerable** server.
The token replay attack only works when `exp` is missing entirely.

---

---
# SLIDE 7 — Architecture Fit & Feasibility *(6 Marks)*
## Correct Architecture Targeting · Real-World Deployment Viability

### Why This Vulnerability Exists in Production

| Platform | JWT Algorithm | Our Attack Applies If |
|----------|--------------|----------------------|
| **AWS Cognito** | RS256, JWKS endpoint | App decodes manually without pinning |
| **Auth0** | RS256 default | HS256 confusion — Auth0 SDK bug (2022) |
| **GCP Firebase** | RS256, rotated JWKS | Server accepts HS256 alongside RS256 |
| **Azure AD** | RS256, open-id discovery | Misconfigured relying party accepts none |

> The exposed `/public-key` endpoint **mirrors real-world JWKS endpoints**.
> AWS Cognito, Auth0, GCP all expose public keys — this is by design.
> **The bug is accepting HS256. Not exposing the key.**

### This Is Not Theoretical

- CVE-2015-9235 was in **node-jsonwebtoken** — millions of production apps
- Auth0 SDK shipped this exact confusion bug to **thousands of enterprise customers**
- Same vulnerability exists in FastAPI, Django REST, Express.js, Spring Boot

### How Production Systems Catch This
- JWT algorithm allow-listing in API gateway (AWS API Gateway, Kong, NGINX)
- SIEM alert on `alg` field changes in incoming token headers
- Automated JWT library audit in CI/CD pipeline
- PyJWT version pinning in `requirements.txt` — `PyJWT>=2.8.0`

---

---
# SLIDE 8 — Architecture Fit & Feasibility *(6 Marks)*
## Operational Considerations

### Multi-Laptop Demo Architecture

```
┌────────────────────────┐        LAN (Wi-Fi)       ┌────────────────────────┐
│     SERVER LAPTOP       │◀────────────────────────▶│    ATTACKER LAPTOP     │
│                         │                          │                        │
│  vulnerable_app.py:5000 │   HTTP attack requests   │  attack_none.py        │
│  hardened_app.py:5001   │◀────────────────────────▶│  attack_confusion.py   │
│  dashboard.py:5002      │                          │  any attack script     │
│                         │   dashboard polls        │                        │
│  0.0.0.0 bind           │◀────────────────────────▶│  browser :5002         │
└────────────────────────┘                          └────────────────────────┘
```

### Three Ways to Run the Demo

| Option | Command | Best For |
|--------|---------|---------|
| A — Automatic | `python demo.py` | Backup if live demo breaks |
| B — Manual | 3 terminals, run scripts | Explaining step by step |
| C — Dashboard | `python dashboard.py` + browser | Judges watching live |

### Dashboard Features
- Green dot / red dot — server status (live, every 3s)
- Attack 1 + Attack 2 buttons — one click, instant result
- **Live Attack Feed** — shows ALL hits from ALL laptops in real time
- Color coded: `VULN:5000` in red, `HARD:5001` in green
- Attack names shown: "Claim Forgery", "Token Replay", "Credential Spray"

### Postman Support
```bash
python postman_tokens.py    # prints ready-to-paste tokens for all attacks
```

---

---
# SLIDE 9 — Communication & Demo *(4 Marks)*
## Demo Clarity · Structure · Technical Handling

### Live Demo — Exact Order

| Step | Action | Expected Result | What to Say |
|------|--------|----------------|-------------|
| 1 | POST `/login` wrong password | HTTP 401 | *"No access without credentials"* |
| 2 | POST `/login` correct password | HTTP 200 + token | *"Credential spray found the password"* |
| 3 | GET `/profile` × 5 same token | HTTP 200 every time | *"Token replay — no expiry, valid forever"* |
| 4 | GET `/admin` alg=none token | HTTP 200 + flag | *"No signature. We wrote the payload. Server trusted it."* |
| 5 | GET `/admin` HS256 token | HTTP 200 + flag | *"Signed with the PUBLIC key. Server verified with same key. Accepted."* |
| 6 | Same tokens → port 5001 | HTTP 401 | *"One line fix. algorithms=['RS256']. Library rejects before reading payload."* |

### Key Points to Emphasise

- **Attack 1** → zero crypto. Just base64url encoding. Anyone can do it.
- **Attack 2** → the public key is public on purpose. The bug is accepting HS256.
- **Attack 3** → we control every field in the payload. role, user, email — anything.
- **The fix** → one line. Library-level enforcement. Cannot be bypassed by the token.

### Backup Plan
If live demo breaks → open `demo_output.txt` — pre-saved output from a working run.

---

---
# SLIDE 10 — Q&A Preparation *(4 Marks)*
## Q&A Depth

| Judge Question | Answer |
|---------------|--------|
| **Why Flask?** | Exposes JWT logic clearly. Same bug in FastAPI, Django, Express, Spring Boot. |
| **Real-world impact?** | CVE-2015-9235 — millions of apps. Auth0 SDK shipped Attack 2 in 2022. |
| **Is RS256 always safe?** | Only when pinned. Open algorithm list makes RS256 worse — attacker gets a known public key for HS256 confusion. |
| **One-line fix?** | `algorithms=["RS256"]`. PyJWT ≥ 2.0 rejects none + HS256 at library level — before reading payload. |
| **Can you bypass hardened server?** | Not via JWT attacks. Spray and replay still work — different attack class, different fix. |
| **Why expose the public key?** | Mirrors JWKS endpoints. AWS, Auth0, GCP all do this. Exposing is correct. Accepting HS256 is the bug. |
| **How does SOC detect this?** | WAF JWT inspection, SIEM alert on `alg` changes, API gateway algorithm allow-list. |
| **Attack 5 — what does it prove?** | HS256 weak secrets are crackable offline from any token. No server contact needed. This is why RS256 is preferred. |
| **Why no exp/jti in hardened server?** | Algorithm pinning is the scoped fix for this problem. Replay and spray are separate attack classes — rate limiting and token expiry are the respective fixes. |
| **MITRE techniques covered?** | T1550.001 (token abuse), T1548 (privilege escalation), T1110.002 (password cracking), T1110.003 (password spraying). |

---

*TEAM-14 · FoSC 23CSE313 · Amrita School of Computing · 2025*
