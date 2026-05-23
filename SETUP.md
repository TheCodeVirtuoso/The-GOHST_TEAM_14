# Setup Documentation
## Problem #17 — JWT Attack Toolkit · TEAM-14

---

## System Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Python | 3.10+ | 3.11 or 3.12 recommended |
| RAM | 256 MB | Flask is lightweight |
| Network | LAN (Wi-Fi or Ethernet) | For multi-laptop demo |
| OS | Windows 10/11, macOS, Linux | All supported |
| OpenSSL | Any recent version | For RSA key generation |

---

## Step 1 — Get the Code

```bash
git clone https://github.com/TheCodeVirtuoso/The-GOHST_TEAM_14
cd The-GOHST_TEAM_14
```

Or download the ZIP from GitHub and extract it.

---

## Step 2 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**

| Package | Version | Purpose |
|---------|---------|---------|
| `flask` | >= 2.3.0 | Web server for both vulnerable and hardened APIs |
| `PyJWT` | >= 2.8.0 | JWT encoding and decoding |
| `cryptography` | >= 41.0.0 | RSA key operations (needed by PyJWT for RS256) |
| `requests` | >= 2.31.0 | HTTP client used by all attack scripts |

If `pip` is not found, try `pip3` or `python -m pip`.

---

## Step 3 — Generate RSA Key Pair

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

**Skip this step** if `private.pem` and `public.pem` already exist in the folder.

**What these files are:**

| File | Description | Shared? |
|------|-------------|---------|
| `private.pem` | RSA 2048-bit private key — server uses this to sign tokens | **Never shared** — in `.gitignore` |
| `public.pem` | RSA public key — server exposes this at `/public-key` | Intentionally public |

---

## Step 4 — Verify Everything Works

```bash
python -c "import flask, jwt, cryptography, requests; print('All imports OK')"
```

Expected output: `All imports OK`

If you see an error, install the missing package:
```bash
pip install <package-name>
```

---

## Step 5 — Run the Demo

### Fastest way (one command):

```bash
python demo.py
```

This automatically:
1. Starts the vulnerable server on port 5000
2. Starts the hardened server on port 5001
3. Runs Attack 1 and Attack 2 against both
4. Prints results
5. Saves output to `demo_output.txt`

### Manual way (three terminals):

**Terminal 1 — Vulnerable server:**
```bash
python vulnerable_app.py
```
Expected output:
```
=================================================================
  VULNERABLE JWT SERVER — port 5000
  algorithms accepted: RS256, HS256, none  [intentional bug]
=================================================================
```

**Terminal 2 — Hardened server:**
```bash
python hardened_app.py
```
Expected output:
```
=================================================================
  HARDENED JWT SERVER — port 5001
  algorithms accepted: RS256 only  [patched]
=================================================================
```

**Terminal 3 — Dashboard:**
```bash
python dashboard.py
```
Open browser: `http://localhost:5002`

---

## Running Individual Attack Scripts

All attack scripts can be run independently once the servers are started:

```bash
python attack_none.py          # Attack 1 — no server setup needed beyond running vuln server
python attack_confusion.py     # Attack 2
python attack_forgery.py       # Attack 3
python attack_spray.py         # Attack 4
python attack_crack.py         # Attack 5 — no server needed at all (offline)
python attack_replay.py        # Attack 6
```

---

## Multi-Laptop Setup (Server + Attacker on Different Machines)

### On the Server Laptop:

**1. Find your LAN IP:**
```bash
# Windows
ipconfig
# Look for "IPv4 Address" under your Wi-Fi adapter

# macOS / Linux
ifconfig | grep inet
```

**2. Open firewall ports (Windows — run as Administrator):**
```
netsh advfirewall firewall add rule name="JWT Demo Ports" dir=in action=allow protocol=TCP localport=5000-5002
```

**3. Start servers** (they already bind to `0.0.0.0` — accessible on LAN):
```bash
python vulnerable_app.py
python hardened_app.py
python dashboard.py
```

### On the Attacker Laptop:

**1. Edit TARGET in attack scripts** — change `localhost` to server's LAN IP:
```python
TARGET = "http://10.236.147.152:5000"   # ← replace with actual server IP
```

**2. Run any attack:**
```bash
python attack_none.py
python attack_confusion.py
```

**3. View dashboard** — open browser on attacker laptop:
```
http://10.236.147.152:5002
```

Or set `SERVER_IP` and run the dashboard on the attacker laptop:
```bash
set SERVER_IP=10.236.147.152    # Windows
python dashboard.py
```

---

## Postman Setup

**1. Generate tokens:**
```bash
python postman_tokens.py
```

Copy the 4 tokens printed.

**2. In Postman — create these requests:**

### Request 1 — Login (Credential Spray)
- Method: `POST`
- URL: `http://localhost:5000/login`
- Body → raw → JSON: `{"username": "admin", "password": "secret99"}`

### Request 2 — Token Replay
- Method: `GET`
- URL: `http://localhost:5000/profile`
- Headers: `Authorization: Bearer <paste token from Request 1>`

### Request 3 — Attack 1 (alg=none)
- Method: `GET`
- URL: `http://localhost:5000/admin`
- Headers: `Authorization: Bearer <paste TOKEN 3 from postman_tokens.py>`

### Request 4 — Attack 2 (HS256 confusion)
- Method: `GET`
- URL: `http://localhost:5000/admin`
- Headers: `Authorization: Bearer <paste TOKEN 4 from postman_tokens.py>`

### Request 5 — Hardened server (blocked)
- Method: `GET`
- URL: `http://localhost:5001/admin`
- Headers: `Authorization: Bearer <paste TOKEN 3 or 4>`
- Expected: **HTTP 401**

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: No module named 'jwt'` | PyJWT not installed | `pip install PyJWT` |
| `ModuleNotFoundError: No module named 'cryptography'` | cryptography not installed | `pip install cryptography` |
| `FileNotFoundError: private.pem` | Key files not generated | Run `openssl genrsa -out private.pem 2048` |
| `Address already in use` (port 5000) | Old server still running | Kill old process: `taskkill /F /IM python.exe` |
| Teammate can't connect | Windows Firewall blocking | Run the `netsh` firewall command above as Administrator |
| Dashboard shows server as red/down | Server not started | Start `vulnerable_app.py` and `hardened_app.py` first |
| Live feed not updating | Old server running (no /events) | Restart `vulnerable_app.py` |

---

## Port Reference

| Port | Service | URL |
|------|---------|-----|
| 5000 | Vulnerable Flask API | `http://localhost:5000` |
| 5001 | Hardened Flask API | `http://localhost:5001` |
| 5002 | Web Dashboard | `http://localhost:5002` |
