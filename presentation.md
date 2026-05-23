# JWT Authentication Bypass & Algorithm Confusion
### Problem #17 — FoSC 23CSE313 Cybersecurity Hackathon
### Amrita School of Computing · TEAM-14

---

# Slide 1 — Title

## JWT Authentication Bypass & Algorithm Confusion Attack

**MITRE ATT&CK:** T1550.001 — Use Alternate Authentication Material  
**Track:** Offensive | **Marks:** 30 | **Team:** TEAM-14

> *"Six attacks. Zero private key knowledge. Full admin access."*

---

# Slide 2 — What is JWT?

## JSON Web Token (JWT)

A JWT has **3 parts** separated by dots:

```
eyJhbGciOiJSUzI1NiJ9 . eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciJ9 . <signature>
      HEADER                         PAYLOAD                           SIGNATURE
  {"alg": "RS256"}          {"user": "alice", "role": "user"}
```

**How authentication works:**
1. User logs in → server issues a signed JWT
2. User sends JWT in every request (`Authorization: Bearer <token>`)
3. Server verifies the signature → trusts the claims inside

**Two signing algorithms:**
| Algorithm | Type | Key used to sign | Key used to verify |
|-----------|------|-----------------|-------------------|
| RS256 | Asymmetric | Private key (secret) | Public key (shared) |
| HS256 | Symmetric | Shared secret | Same shared secret |

---

# Slide 3 — The Vulnerability

## Root Cause — Trusting `alg` from the Token Header

```python
# VULNERABLE — server reads alg from the token itself
alg = header.get("alg")          # attacker controls this!
if alg == "none":   # skip verification
if alg == "HS256":  # verify with PUBLIC key as HMAC secret
if alg == "RS256":  # verify with public key (correct)
```

```python
# FIXED — one line
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
#                              ^^^^^^^^^^^^^^^^^^^^
#                        only RS256 accepted — none and HS256 rejected
```

**3 JWT attacks enabled by this one misconfiguration + 3 additional attacks:**

| # | Attack | Needs |
|---|--------|-------|
| 1 | alg=none bypass | Nothing |
| 2 | RS256→HS256 confusion | Only the public key |
| 3 | Claim forgery | Consequence of 1 or 2 |
| 4 | Credential spray | Common wordlist |
| 5 | JWT secret crack | Captured token + wordlist |
| 6 | Token replay | One intercepted token |

---

# Slide 4 — Attack 1: alg=none Bypass

## No signature. No crypto. Full admin access.

**CVE-2015-9235** — node-jsonwebtoken (millions of apps affected)

**How it works:**

```
Normal token:   header.payload.SIGNATURE
Forged token:   header.payload.           ← empty signature
                {"alg":"none"}   {"role":"admin"}
```

**Attack steps:**
1. Build header: `{"alg": "none", "typ": "JWT"}`
2. Build payload: `{"user": "attacker", "role": "admin"}`
3. Base64url encode both → join with dots → empty signature
4. Send to `/admin` → **HTTP 200 + flag captured**

**Demo result:**
```
[SUCCESS ✓]  forged none token  →  HTTP 200
             flag = flag{jwt_alg_confusion_2025}
[BLOCKED  ✗]  same token on hardened server  →  HTTP 401
```

> The JWT spec defines `alg=none` as valid — vulnerable libraries honour it

---

# Slide 5 — Attack 2: RS256 → HS256 Algorithm Confusion

## Attacker signs with the PUBLIC key. Server verifies with the PUBLIC key. Accepts it.

**CVE-2015-9235 + Auth0 SDK confusion (2022)**

**The trick:**
- RS256: private key signs → public key verifies ✓
- HS256: **one shared secret** does both
- Server uses PUBLIC key as the HMAC secret for HS256 verification
- Attacker fetches the public key → uses it as the HMAC secret → server accepts

```
Step 1:  GET /public-key          → attacker gets the RSA public key
Step 2:  Build forged payload     → {"user": "attacker", "role": "admin"}
Step 3:  Sign with HS256          → HMAC-SHA256(public_key, header.payload)
Step 4:  GET /admin               → HTTP 200 + flag
```

**Why the public key is exposed:**
> AWS Cognito, Auth0, GCP all expose public keys at JWKS endpoints.  
> The bug is **accepting HS256**, not exposing the key.

---

# Slide 6 — Attack 3: Claim Forgery (Privilege Escalation)

## The attacker controls the entire payload — inject any claim.

**Direct consequence of Attack 1 or 2**

```
Legitimate alice token:       {"user": "alice",    "role": "user"}   ← server issued
Forged attacker token:        {"user": "attacker", "role": "admin"}  ← attacker built
```

**What can be forged:**
- `role` → escalate from user to admin
- `user` / `sub` → impersonate any account
- `email`, `scope`, `permissions` → any claim the app trusts

**Demo — side by side:**
```
[1] alice (real token, role=user)    → /admin → HTTP 403  FORBIDDEN
[2] attacker (forged, role=admin)    → /admin → HTTP 200  SUCCESS ✓
                                                flag{jwt_alg_confusion_2025}
[3] forge as user=admin, role=admin  → /admin → HTTP 200  SUCCESS ✓
```

> No password guessed. No private key. Just base64url-encode whatever you want.

---

# Slide 7 — Attack 4: Credential Spray

## Try a few common passwords across many accounts — avoid lockout.

**MITRE:** T1110.003 — Brute Force: Password Spraying

**Difference from brute force:**

| Brute Force | Credential Spray |
|-------------|-----------------|
| Many passwords → one account | Few passwords → many accounts |
| Triggers account lockout | Stays under lockout threshold |

**Attack flow:**
```
POST /login  {"username": "admin", "password": "admin"}     → 401
POST /login  {"username": "admin", "password": "password"}  → 401
POST /login  {"username": "admin", "password": "secret99"}  → 200 ✓  TOKEN CAPTURED
POST /login  {"username": "alice", "password": "pass123"}   → 200 ✓  TOKEN CAPTURED
```

**Demo result:**
```
[HIT]  admin:secret99  →  HTTP 200  token=eyJhbGciOiJSUzI1NiJ9...
[HIT]  alice:pass123   →  HTTP 200  token=eyJhbGciOiJSUzI1NiJ9...
```

> Once a valid token is captured → use it for Token Replay or Claim Forgery

---

# Slide 8 — Attack 5: JWT Secret Crack (Offline)

## HS256 with a weak secret = crackable with no server contact.

**MITRE:** T1110.002 — Brute Force: Password Cracking  
**Real tool:** `hashcat --hash-type 16500 token.txt rockyou.txt`

**Why HS256 is dangerous with weak secrets:**
```
HS256 signature = HMAC-SHA256(secret, header.payload)

Attacker has: header.payload.signature  (from any captured token)
Attacker tries: HMAC-SHA256("password", header.payload) → matches? No
               HMAC-SHA256("secret",   header.payload) → matches? No
               HMAC-SHA256("hackme",   header.payload) → matches? YES ✓
```

**Once cracked:**
- Attacker knows the secret
- Can sign ANY token with ANY claims using that secret
- Full admin access — no server vulnerability needed

**Demo result:**
```
[1] Captured HS256 token:  eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ...
[2] Cracking... trying 15 candidates...
[CRACKED]  Secret = "hackme"
[3] Forged admin token using cracked secret — accepted by server
```

> RS256 is immune: an RSA private key cannot be cracked from a token

---

# Slide 9 — Attack 6: Token Replay

## Steal one token. Use it forever. Server never rejects it.

**MITRE:** T1550.001 — Use Alternate Authentication Material

**Root cause — missing JWT claims:**
| Claim | Purpose | Present in vulnerable server? |
|-------|---------|------------------------------|
| `exp` | Expiry time | ❌ No — token lives forever |
| `iat` | Issued at | ❌ No |
| `jti` | Unique token ID | ❌ No — no blacklist possible |

**Attack flow:**
```
Day 1:  Attacker intercepts alice's token (from traffic, leaked log, etc.)
Day 2:  Attacker uses same token   → HTTP 200  ACCEPTED
Day 7:  Attacker uses same token   → HTTP 200  ACCEPTED
Day 30: Attacker uses same token   → HTTP 200  ACCEPTED
```

**Demo — 5 replays, all accepted:**
```
Replay #1: HTTP 200 [ACCEPTED]  →  {'user': 'alice', 'role': 'user'}
Replay #2: HTTP 200 [ACCEPTED]  →  {'user': 'alice', 'role': 'user'}
Replay #3: HTTP 200 [ACCEPTED]  →  ...
```

> Fix: `exp = now + 3600` and `jti = uuid4()` with a server-side blacklist

---

# Slide 10 — Summary & MITRE ATT&CK Mapping

## Six Attacks. One Misconfigured Server.

| # | Attack | Result on Vulnerable | MITRE |
|---|--------|---------------------|-------|
| 1 | alg=none bypass | HTTP 200 + flag | T1550.001 |
| 2 | RS256→HS256 confusion | HTTP 200 + flag | T1550.001 |
| 3 | Claim forgery (role=admin) | HTTP 200 + flag | T1550.001 |
| 4 | Credential spray | Credentials found | T1110.003 |
| 5 | JWT secret crack | Secret cracked offline | T1110.002 |
| 6 | Token replay | Token reused indefinitely | T1550.001 |

**The single-line fix for attacks 1–3:**
```python
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
```

**Real-world impact:**
- CVE-2015-9235 — node-jsonwebtoken (2015, millions of apps)
- Auth0 SDK algorithm confusion (2022)
- AWS Cognito, GCP Identity, Firebase — all use RS256 (correct)

**Key takeaway:**
> Never trust the `alg` field from an incoming token.  
> Always pin the algorithm server-side. Never accept `none` or mix asymmetric + symmetric.
