# Threat Model Write-up
## Problem #17 — JWT Attack Toolkit · TEAM-14
### MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material

---

## 1. System Overview

The target system is a REST API using JSON Web Tokens (JWT) for authentication.
It is representative of cloud-native APIs deployed on AWS, GCP, or Azure —
specifically services using identity providers such as AWS Cognito, Auth0, or
GCP Identity Platform.

```
┌────────────────────────────────────────────────────────────────┐
│                        System Boundary                         │
│                                                                │
│  ┌──────────┐     JWT     ┌─────────────────────────────────┐  │
│  │  Client   │ ──────────▶│           REST API              │  │
│  │ (Browser/ │            │  /login  /profile  /admin       │  │
│  │  Script)  │◀────────── │                                 │  │
│  └──────────┘   Response  │  jwt.decode(token, key, algs)   │  │
│                           └───────────────┬─────────────────┘  │
│                                           │                    │
│                           ┌───────────────▼─────────────────┐  │
│                           │         Key Store               │  │
│                           │  private.pem  /  public.pem     │  │
│                           └─────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

---

## 2. Assets

| Asset | Value | Impact if Compromised |
|-------|-------|----------------------|
| `/admin` endpoint | High | Attacker gains admin-level access, captures flag |
| RSA private key (`private.pem`) | Critical | Attacker can sign any token as any user |
| User credentials (alice, admin) | High | Account takeover, token capture |
| JWT session tokens | High | Impersonation, privilege escalation, replay |
| `/login` endpoint | Medium | Entry point for credential attacks |
| RSA public key (`public.pem`) | Low | Intentionally public — exposure is by design |

---

## 3. Attacker Profile

### Primary Attacker (JWT Attacks)

| Attribute | Detail |
|-----------|--------|
| **Location** | On the same network (LAN) — no physical access needed |
| **Skill level** | Intermediate — understands JWT structure and base64url encoding |
| **Prior access** | None required for Attacks 1, 2, 3 |
| **Tools** | Python, requests library, any HTTP client (curl, Postman) |
| **Goal** | Reach `/admin` and capture the flag without knowing `private.pem` |

### Secondary Attacker (Credential / Token Attacks)

| Attribute | Detail |
|-----------|--------|
| **Location** | Network-accessible — can be remote |
| **Skill level** | Low — credential spray requires only an HTTP client |
| **Prior access** | None required |
| **Tools** | Any HTTP client, wordlist |
| **Goal** | Obtain a valid JWT through non-cryptographic means |

---

## 4. Trust Boundaries

```
TRUSTED ZONE                          UNTRUSTED ZONE
─────────────────────────────────     ─────────────────────────────
  Server private key (private.pem)      All incoming HTTP requests
  Server-side session state             JWT token contents (header + payload)
  Python application code               alg field in JWT header        ← KEY ISSUE
  Flask route handlers                  Any claim in JWT payload
                                        Network traffic
```

**The critical trust violation:**
The vulnerable server places the `alg` field from the token header in the
TRUSTED zone — it acts on whatever algorithm the attacker specifies.
This is the root cause of Attacks 1, 2, and 3.

---

## 5. Attack Surface

| Surface | Exposure | Attacks Enabled |
|---------|---------|----------------|
| `POST /login` | Public — no auth | Credential spray (Attack 4) |
| `GET /public-key` | Public — no auth | HS256 confusion (Attack 2) |
| `GET /profile` | JWT required | Token replay (Attack 6) |
| `GET /admin` | JWT + role=admin | Attacks 1, 2, 3 |
| JWT `alg` header field | Parsed by server | Attacks 1, 2 |
| JWT payload claims | Trusted by server | Attack 3 |
| HS256 token signatures | Brute-forceable | Attack 5 |

---

## 6. Attack Trees

### Attack Tree 1 — Reach `/admin` without credentials

```
GOAL: GET /admin → HTTP 200

├── [A] Forge a valid-looking token
│   ├── [A1] alg=none bypass ──────────────────── Attack 1
│   │         No signature needed
│   │         Success if server accepts "none"
│   │
│   └── [A2] HS256 algorithm confusion ─────────── Attack 2
│             Fetch public key from /public-key
│             Sign forged token with public key as HMAC secret
│             Success if server accepts HS256
│
└── [B] Obtain a real admin token
    ├── [B1] Credential spray → admin:secret99 ── Attack 4
    └── [B2] Crack HS256 secret from token ────── Attack 5
```

### Attack Tree 2 — Maintain persistent access

```
GOAL: Keep access even after password change

└── [C] Token replay ──────────────────────────── Attack 6
          Capture any valid token
          Use it indefinitely
          Success if no exp / jti claim present
```

### Attack Tree 3 — Privilege escalation

```
GOAL: Access admin endpoint as a regular user

└── [D] Claim forgery ─────────────────────────── Attack 3
          Prerequisite: Attack 1 OR Attack 2
          Inject role=admin into forged payload
          Server reads role from payload and grants access
```

---

## 7. Threat Scenarios

### Scenario 1 — External Attacker, No Prior Knowledge

An attacker on the same Wi-Fi network with no accounts and no credentials.

```
Step 1: GET /public-key                     ← no auth needed
Step 2: Build HS256 token with role=admin   ← uses public key as HMAC secret
Step 3: GET /admin                          ← HTTP 200, flag captured

Time required: < 30 seconds
Crypto knowledge needed: None
Tools needed: Python + requests
```

**MITRE:** T1550.001

---

### Scenario 2 — Compromised Low-Privilege Session

An attacker who has stolen alice's JWT (from a leaked log, network sniff, or shoulder surfing).

```
Step 1: Intercept/obtain alice's JWT token
Step 2: Decode payload → {"user": "alice", "role": "user"}
Step 3: Build new token with alg=none, payload={"role": "admin"}
Step 4: GET /admin → HTTP 200

Alternatively:
Step 3: Keep replaying alice's token for /profile access
        → token never expires, no jti → permanent access
```

**MITRE:** T1550.001, T1548

---

### Scenario 3 — Credential-First Attack

An attacker who wants a legitimate token before escalating.

```
Step 1: POST /login {"username":"admin","password":"admin"}  → 401
Step 2: POST /login {"username":"admin","password":"secret99"} → 200
        Token captured — admin account compromised via spray

Step 3: Use captured token for /admin → HTTP 200 (legitimate)
Step 4: Replay that token indefinitely → no expiry
```

**MITRE:** T1110.003 → T1550.001

---

## 8. Likelihood and Impact Matrix

| Attack | Likelihood | Impact | Risk |
|--------|-----------|--------|------|
| alg=none bypass | High — one-liner exploit | Critical — full admin | **Critical** |
| HS256 confusion | High — public key is known | Critical — full admin | **Critical** |
| Claim forgery | High — consequence of above | Critical — privilege escalation | **Critical** |
| Credential spray | Medium — needs weak password | High — account takeover | **High** |
| Secret crack | Medium — needs HS256 usage | High — sign anything | **High** |
| Token replay | High — no expiry by default | Medium — session hijack | **High** |

---

## 9. Mitigations

| Attack | Mitigation | Implemented in hardened_app.py? |
|--------|-----------|--------------------------------|
| alg=none | `algorithms=["RS256"]` | Yes |
| HS256 confusion | `algorithms=["RS256"]` | Yes |
| Claim forgery | `algorithms=["RS256"]` (payload integrity follows) | Yes |
| Credential spray | Rate limiting on `/login` | No — out of scope |
| Secret crack | Use RS256 (asymmetric — cannot crack private key) | Yes (RS256 used) |
| Token replay | Add `exp` + `jti` to all issued tokens | No — out of scope |

**Out-of-scope mitigations** (documented as residual risks):
- Credential spray → requires rate limiting middleware or API gateway policy
- Token replay → requires `exp`/`jti` in token issuance + server-side jti store

These are separate vulnerability classes from the JWT algorithm confusion bugs
and require different defense layers.

---

## 10. Real-World Threat Context

### CVE-2015-9235 — node-jsonwebtoken

Exact same vulnerability as Attack 1 and 2.
Affected millions of Node.js applications.
Root cause: library accepted `alg=none` from the token header.
Fix: algorithm whitelist enforced by the library.

### Auth0 SDK Algorithm Confusion (2022)

Auth0's own SDK had an HS256/RS256 confusion bug — identical to Attack 2.
Auth0 is used by thousands of companies for authentication.
Root cause: SDK did not reject HS256 tokens when configured for RS256.

### Real-World Platforms Using This Pattern

| Platform | JWT Algorithm | JWKS / Public Key Exposure |
|----------|--------------|---------------------------|
| AWS Cognito | RS256 | Public JWKS at cognito-idp endpoint |
| Auth0 | RS256 (default) | Public JWKS at tenant domain |
| GCP Identity / Firebase | RS256 | Public JWKS at googleapis.com |
| Azure AD | RS256 | Public JWKS at login.microsoftonline.com |

All of these expose public keys — this is correct and expected.
The vulnerability only exists if the server also accepts HS256 or none.

---

## 11. MITRE ATT&CK Full Mapping

| Tactic | Technique | Sub-technique | Attack in This Project |
|--------|-----------|--------------|------------------------|
| Credential Access | T1110 — Brute Force | T1110.002 — Password Cracking | JWT secret crack |
| Credential Access | T1110 — Brute Force | T1110.003 — Password Spraying | Credential spray |
| Defense Evasion / Lateral Movement | T1550 — Use Alternate Authentication Material | T1550.001 — Application Access Token | alg=none, HS256 confusion, token replay |
| Privilege Escalation | T1548 — Abuse Elevation Control Mechanism | — | Claim forgery (role=admin) |

---

## 12. Assumptions and Scope

**In scope:**
- JWT validation logic and algorithm handling
- `/login`, `/profile`, `/admin`, `/public-key` endpoints
- Token structure and claim integrity

**Out of scope:**
- Transport security (HTTPS) — assumed present in production
- Physical access to server
- Server-side code injection or OS-level exploits
- Database attacks

**Key assumption:**
The attacker is on the same network as the server (LAN).
All attacks except credential spray and secret crack also work over the internet
if the server is internet-facing.
