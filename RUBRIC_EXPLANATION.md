# Rubric Explanation — Problem #17
## JWT Authentication Bypass & Algorithm Confusion Attack
### TEAM-14 · FoSC 23CSE313 · Amrita School of Computing

---

# TECHNICAL IMPLEMENTATION — 10 Marks

## Core Functionality

We built a complete JWT attack toolkit targeting a locally deployed vulnerable Flask API.

**The problem asked us to build a tool that:**

| Requirement | What We Built | File |
|-------------|--------------|------|
| (a) Exploit the `none` algorithm vulnerability | `attack_none.py` — forges token with `alg=none`, empty signature, gains admin access | `attack_none.py` |
| (b) Exploit RS256→HS256 algorithm confusion using public key as HMAC secret | `attack_confusion.py` — fetches `/public-key`, signs HS256 token with it, server accepts | `attack_confusion.py` |
| (c) Forge arbitrary claims (`role: admin`) to gain elevated access | `attack_forgery.py` — injects `role=admin` into unsigned payload, reaches `/admin` | `attack_forgery.py` |

**Additional attacks built beyond the requirement:**

| Attack | Script |
|--------|--------|
| Credential spray (T1110.003) | `attack_spray.py` |
| JWT secret crack — offline HS256 brute-force (T1110.002) | `attack_crack.py` |
| Token replay — no `exp`/`jti` enforcement (T1550.001) | `attack_replay.py` |

**All attacks confirmed working:**
```
[SUCCESS]  VULNERABLE :5000  HTTP 200  flag{jwt_alg_confusion_2025}
[BLOCKED]  HARDENED   :5001  HTTP 401  Token rejected
```

---

## Implementation Correctness

### Attack 1 — alg=none (correct implementation)

```python
def forge_none_token():
    header  = base64url({"alg": "none", "typ": "JWT"})
    payload = base64url({"user": "attacker", "role": "admin"})
    return f"{header}.{payload}."   # empty signature — spec-compliant alg=none
```

The token is constructed exactly as the JWT spec defines `alg=none`:
three parts separated by dots, third part (signature) is empty.

### Attack 2 — HS256 confusion (correct implementation)

```python
pub_key = requests.get(f"{TARGET}/public-key").text          # fetch public key
sig     = HMAC_SHA256(secret=pub_key, msg=header+"."+payload) # sign with it
token   = f"{header}.{payload}.{base64url(sig)}"              # valid HS256 token
```

The server verifies: `HMAC_SHA256(PUBLIC_KEY, header.payload)` — matches exactly.

### Why custom decoder in vulnerable_app.py (not raw PyJWT):

PyJWT >= 2.0 added library-level safeguards that reject `alg=none` and algorithm confusion.
Using raw PyJWT would silently block the demo. Our custom `decode_vulnerable()` reproduces
the exact pattern of CVE-2015-9235 — making the demonstration historically accurate.

---

## Complexity

| Dimension | Detail |
|-----------|--------|
| Attack vectors | 6 distinct attacks across 4 different vulnerability classes |
| Cryptography | RSA-2048 key pair, HMAC-SHA256, base64url encoding |
| Live infrastructure | 3 Flask servers + browser dashboard running simultaneously |
| Multi-machine | Attack scripts work from teammate's laptop on LAN |
| Real-time monitoring | Live event feed polling both servers every 2 seconds |
| Offline attack | `attack_crack.py` runs with zero server contact |

---

## Code Quality & Engineering Practice

**Vulnerable decoder — clean separation of attack paths:**
```python
alg = header.get("alg", "").upper()

if alg == "NONE":                        # Attack 1 — skip verification
    payload["_alg"] = "none"
    return payload

elif alg == "HS256":                     # Attack 2 — public key as HMAC secret
    expected_sig = hmac.new(PUBLIC_KEY.encode(), signing_input, hashlib.sha256)
    payload["_alg"] = "HS256"
    return payload

elif alg == "RS256":                     # Correct path
    return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
```

**Engineering decisions:**
- `_TOTAL_EVENTS` monotonic counter — avoids timestamp collision bug (two events in same second)
- `host="0.0.0.0"` on all servers — LAN accessible without code change
- `path` field in every event — dashboard can identify attack type by endpoint, not just alg
- `requirements.txt` with pinned versions — reproducible environment across machines
- `.gitignore` excludes `private.pem` — private key never pushed to GitHub

---

---

# SECURITY DEPTH & ACCURACY — 8 Marks

## Threat Model

### Assets

| Asset | Impact if Compromised |
|-------|----------------------|
| `/admin` endpoint | Full admin access, flag captured |
| RSA private key (`private.pem`) | Sign any token as any user |
| User credentials | Account takeover via spray |
| JWT session tokens | Impersonation, replay, privilege escalation |

### Attacker Profile

| Attribute | Description |
|-----------|-------------|
| Location | Same LAN — no physical access needed |
| Prior access | None required for JWT attacks |
| Skill level | Intermediate — understands base64url |
| Tools | Python + requests, or Postman |
| Goal | Reach `/admin`, capture flag, no private key |

### Attack Surface

```
[Attacker] ── forged JWT ──▶ [Server: jwt.decode()]
                                       │
                           trusts alg from token header  ← ROOT CAUSE
                                       │
                    ┌──────────────────┴──────────────────┐
                 alg=none                            alg=HS256
              skip signature                  verify with PUBLIC key
             (Attack 1, 3)                        (Attack 2, 3)

[Attacker] ── passwords ──▶ POST /login (no rate limit)   ── Attack 4
[Attacker] ── wordlist ───▶ offline HMAC brute-force       ── Attack 5
[Attacker] ── stolen token ▶ GET /profile (no exp/jti)     ── Attack 6
```

---

## ATT&CK Alignment

| Attack | Tactic | Technique | Sub-technique |
|--------|--------|-----------|--------------|
| alg=none bypass | Defense Evasion | T1550 | T1550.001 — Application Access Token |
| RS256→HS256 confusion | Defense Evasion | T1550 | T1550.001 — Application Access Token |
| Claim forgery | Privilege Escalation | T1548 | Abuse Elevation Control Mechanism |
| Credential spray | Credential Access | T1110 | T1110.003 — Password Spraying |
| JWT secret crack | Credential Access | T1110 | T1110.002 — Password Cracking |
| Token replay | Defense Evasion | T1550 | T1550.001 — Application Access Token |

---

## Attack / Defence Technical Validity

### Attack 1 — alg=none (technically valid)

The JWT RFC 7519 defines `alg=none` as a valid "unsecured JWT."
Vulnerable servers that include `none` in their accepted algorithm list
skip signature verification entirely — any payload is trusted.

**Proof:** HTTP 200 + flag returned with zero signature.

### Attack 2 — RS256→HS256 confusion (technically valid)

RS256 uses asymmetric keys: private key signs, public key verifies.
HS256 uses a single shared secret for both sign and verify.

When a server accepts both, it uses `PUBLIC_KEY` as the HS256 secret.
The attacker computes `HMAC_SHA256(PUBLIC_KEY, header.payload)`.
The server computes the same. They match. Token accepted.

**Key insight:** The public key is the same value on both sides.
This is not a brute-force — it is a deterministic computation.

**Proof:** HTTP 200 + flag using only the publicly available key.

### Attack 3 — Claim Forgery (technically valid)

Once the signature is bypassed, the server reads the payload directly.
The `role` field in the payload controls access to `/admin`.
An attacker who controls the payload controls all authorisation decisions.

**Proof:** alice (role=user) → HTTP 403. Forged (role=admin) → HTTP 200.

### Defence — technically valid

```python
# hardened_app.py
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
```

PyJWT checks the `alg` field against `["RS256"]` before touching the signature.
`none` and `HS256` are not in the list → `DecodeError` raised immediately.
The application route handler never executes.

---

## Awareness of Limitations & Bypasses

| Attack | Precondition | How an Operator Eliminates It |
|--------|-------------|-------------------------------|
| alg=none | `none` must be in server's accepted list | Default-deny algorithm whitelist |
| HS256 confusion | Server must accept HS256 alongside RS256 | `algorithms=["RS256"]` only |
| Claim forgery | Requires Attack 1 or 2 first | Same fix as above |
| Credential spray | Weak passwords + no rate limiting | Rate limiting + strong password policy + MFA |
| Secret crack | Server uses HS256 with a weak secret | Use RS256 — RSA private key cannot be cracked from a token |
| Token replay | Missing `exp` and `jti` claims | Add `exp=now+3600`, `jti=uuid4()`, maintain jti blacklist |

**What our fix does NOT cover:**
- Credential spray → requires rate-limiting middleware (flask-limiter / API gateway)
- Token replay → requires `exp`/`jti` in token issuance + server-side revocation store
- These are separate vulnerability classes — documented explicitly as residual risks

**Edge case — forged tokens with past `exp`:**
If an attacker sets a past timestamp in a forged `exp` claim,
PyJWT rejects it even on the vulnerable server. Our attacks leave `exp` absent entirely.

---

---

# ARCHITECTURE FIT & FEASIBILITY — 6 Marks

## Correct Architecture Targeting

This vulnerability targets **cloud-native REST APIs** using JWT for authentication —
the dominant pattern in modern microservices.

**JWT algorithm confusion exists in the same form in:**

| Framework | Language | Vulnerable pattern |
|-----------|----------|-------------------|
| Flask + PyJWT < 2.0 | Python | `algorithms=[header["alg"]]` |
| Express + jsonwebtoken < 9.0 | Node.js | CVE-2015-9235 — exact same bug |
| Spring Security + JJWT < 0.12 | Java | Algorithm override in header |
| Django REST + PyJWT < 2.0 | Python | Same as Flask |

Our demo uses Flask because it exposes the JWT validation logic
most transparently for educational and demonstration purposes.

---

## Real-World Deployment Viability

### Real incidents this demo reproduces:

**CVE-2015-9235 — node-jsonwebtoken (2015)**
- Exact same alg=none + HS256 confusion vulnerability
- Used by millions of Node.js applications
- Affected: Express apps, Passport.js, many SaaS products
- Fix: algorithm whitelist enforced by library

**Auth0 SDK Algorithm Confusion (2022)**
- Auth0's own SDK had the RS256→HS256 confusion bug — identical to Attack 2
- Auth0 is used by thousands of enterprise companies for authentication
- Patched after responsible disclosure

### Platforms using this JWT pattern:

| Platform | JWT Algorithm | Public Key Exposure |
|----------|--------------|-------------------|
| AWS Cognito | RS256 | JWKS at cognito-idp endpoint |
| Auth0 | RS256 default | JWKS at tenant domain |
| GCP Identity / Firebase | RS256 | JWKS at googleapis.com |
| Azure AD | RS256 | JWKS at login.microsoftonline.com |

> All of these expose public keys — this is correct by design.
> The vulnerability is accepting HS256 alongside RS256, not the key exposure.

---

## Operational Considerations

### Three demo modes — handles any scenario:

| Mode | Command | Use Case |
|------|---------|---------|
| Automatic | `python demo.py` | Backup if live demo breaks — output pre-saved |
| Manual | 3 terminals, individual scripts | Step-by-step explanation to judges |
| Dashboard | `python dashboard.py` + browser | Visual live demo for audience |

### Multi-laptop operation:

```
SERVER LAPTOP                          ATTACKER LAPTOP
vulnerable_app.py (0.0.0.0:5000) ◀──── attack scripts (TARGET=server_ip)
hardened_app.py   (0.0.0.0:5001) ◀──── same scripts, different port
dashboard.py      (0.0.0.0:5002) ◀──── browser opens dashboard
```

Servers bind to `0.0.0.0` — LAN accessible without configuration.
Firewall rule opens ports 5000–5002 for incoming LAN connections.
`TARGET` constant in each script is the only change needed.

### Postman support:

```bash
python postman_tokens.py    # generates 4 ready-to-paste tokens
```

All attacks demonstrable via Postman with copy-paste tokens —
no command line knowledge required from the judge.

---

---

# COMMUNICATION & DEMO — 4 Marks

## Demo Clarity

### Live Demo Order — 6 steps, clear before/after contrast:

| Step | Action | Result | What It Proves |
|------|--------|--------|---------------|
| 1 | POST `/login` wrong password | HTTP 401 | Baseline — auth works normally |
| 2 | POST `/login` correct password (spray) | HTTP 200 + token | Credential spray found the password |
| 3 | GET `/profile` × 5, same token | HTTP 200 every time | Token replay — no expiry, valid forever |
| 4 | GET `/admin` with alg=none token | HTTP 200 + **flag** | Zero signature — server trusted fake token |
| 5 | GET `/admin` with HS256 token | HTTP 200 + **flag** | Signed with PUBLIC key — server accepted |
| 6 | Same tokens → port 5001 | HTTP 401 | One line fix blocks everything |

**Backup:** `demo_output.txt` — pre-saved output from a confirmed working run.

---

## Structure

Our project is structured in layers — each layer is independently demonstrable:

```
Layer 1 — Servers      : vulnerable_app.py  /  hardened_app.py
Layer 2 — Attacks      : 6 individual attack scripts
Layer 3 — Automation   : demo.py (runs everything with one command)
Layer 4 — Visualisation: dashboard.py (browser UI, live feed)
Layer 5 — Documentation: README, SETUP, CODE_GUIDE, THREAT_MODEL, EXPLAINER
```

---

## Q&A Depth

| Question | Answer |
|---------|--------|
| Why Flask? | Exposes JWT logic clearly. Same bug in FastAPI, Django, Express, Spring. |
| Real-world impact? | CVE-2015-9235 — millions of apps. Auth0 SDK shipped Attack 2 in 2022. |
| Is RS256 always safe? | Only when pinned. Open algorithm list makes RS256 worse — attacker uses known public key for HS256 confusion. |
| One-line fix? | `algorithms=["RS256"]`. PyJWT rejects none + HS256 at library level before reading the payload. |
| Can you bypass the hardened server? | Not via JWT attacks. Spray and replay are different attack classes needing different fixes. |
| Why expose the public key? | Mirrors JWKS endpoints. AWS, Auth0, GCP all expose public keys. Exposing is correct — accepting HS256 is the bug. |
| What does Attack 5 prove? | HS256 with weak secrets is crackable offline from any token. No server contact needed — pure math. |
| MITRE techniques? | T1550.001, T1548, T1110.002, T1110.003 — four techniques across six attacks. |

---

## Technical Handling

**If attack fails during demo:**
- Run `python demo.py` — auto demo with pre-saved backup output
- Open `demo_output.txt` — shows confirmed working output

**If server connection fails:**
```bash
netstat -ano | findstr :5000    # confirm server is LISTENING
netsh advfirewall firewall add rule name="JWT Demo" dir=in action=allow protocol=TCP localport=5000-5002
```

**If judge asks to see inside a token:**
- Paste any token into [jwt.io](https://jwt.io) — shows decoded header and payload live

---

---

# DOCUMENTATION — 2 Marks

## README

`README.md` — complete rubric-aligned documentation covering:
- Plain English explanation (non-technical intro)
- Technical overview with 6-attack table
- Deliverable checklist (a, b, c all checked)
- Setup instructions
- All demo options (A/B/C + Postman)
- API endpoint reference
- Threat model summary
- All 6 attack technical details with code snippets
- Hardening guide (5 fixes)
- Limitations table
- Architecture fit (AWS/Auth0/GCP table)
- Full MITRE ATT&CK mapping
- Q&A preparation table
- Team roles

---

## Setup Documentation

`SETUP.md` — standalone setup guide covering:
- System requirements table
- Step-by-step: clone → install → keygen → verify
- All 3 run options with expected terminal output
- Individual attack script usage
- Multi-laptop LAN configuration with firewall command
- Full Postman setup (5 requests with exact values)
- Troubleshooting table (7 common errors + fixes)
- Port reference table

---

## Code Comments

`CODE_GUIDE.md` — full code documentation covering:
- Architecture diagram showing how all files connect
- Every file explained: purpose, key code sections, why it was written that way
- Vulnerable decoder: root cause in code, why custom decoder vs PyJWT
- Each attack script: how it works, step by step
- Dashboard: live feed architecture, CORS proxy reason, monotonic counter explanation
- Security design decisions documented

---

## Threat Model Write-up

`THREAT_MODEL.md` — formal threat model covering:
- System boundary diagram
- Asset table with impact ratings
- Two attacker profiles (JWT attacker / credential attacker)
- Trust boundary diagram showing the root cause
- Three attack trees (reach /admin, persistent access, privilege escalation)
- Three full attack scenarios with step-by-step
- Likelihood × Impact risk matrix for all 6 attacks
- Mitigation table mapped to hardened_app.py
- Real-world CVE context (CVE-2015-9235, Auth0 2022)
- Full MITRE tactic → technique → sub-technique mapping
- Assumptions and scope statement

---

*TEAM-14 · FoSC 23CSE313 · Amrita School of Computing · 2025*
