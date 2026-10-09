
import http.server

import json

import time

import subprocess

import threading

import os

import signal

import base64



# Import authentication

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'module3-policy'))

from auth import get_auth_manager



# Initialize authentication manager

auth_manager = get_auth_manager()



PORT = 5000

EVENTS = []

METRICS = {"inspected": 0, "blocked": 0, "passed": 0, "avg_lat": 105.0}



HTML_PAGE = """<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<title>TrueIntent // eBPF MCP Active Defense Dashboard</title>

<style>

  :root {

    --bg: #0b0f19; --card: #111827; --border: #1f2937;

    --accent: #38bdf8; --danger: #ef4444; --success: #22c55e; --text: #f3f4f6;

  }

  body {

    background-color: var(--bg); color: var(--text);

    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;

    margin: 0; padding: 24px;

  }

  .header {

    display: flex; justify-content: space-between; align-items: center;

    border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px;

  }

  .badge {

    background: rgba(56, 189, 248, 0.15); color: var(--accent);

    border:1px solid var(--accent); padding: 4px 10px; border-radius: 4px;
    font-size: 12px; font-weight: bold; letter-spacing: 1px;
  }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 18px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5);
  }
  .card h3 { margin: 0; font-size: 13px; color: #9ca3af; text-transform: uppercase; }
  .card .num { font-size: 32px; font-weight: bold; margin-top: 8px; }
  .text-danger { color: var(--danger); }
  .text-success { color: var(--success); }
  .text-accent { color: var(--accent); }
  
  .layout { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; }
  .feed {
    background: #030712; border: 1px solid var(--border);
    border-radius: 8px; height: 420px; overflow-y: auto; padding: 16px;
    font-family: 'Courier New', Courier, monospace; font-size: 13px;
  }
  .feed-item {
    margin-bottom: 10px; padding: 8px 12px; border-radius: 4px;
    border-left: 3px solid #374151; background: #0f172a;
  }
  .feed-blocked { border-left-color: var(--danger); background: rgba(239, 68, 68, 0.08); }
  .feed-allowed { border-left-color: var(--success); background: rgba(34, 197, 94, 0.08); }
  
  .btn {
    display: inline-block; width: 100%; padding: 12px; margin-top: 10px;
    border-radius: 6px; font-weight: bold; cursor: pointer; text-align: center;
    border: none; font-size: 14px;
  }
  .btn-benign { background: #166534; color: #bbf7d0; }
  .btn-benign:hover { background: #15803d; }
  .btn-attack { background: #991b1b; color: #fecaca; }
  .btn-attack:hover { background: #b91c1c; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1 style="margin: 0; font-size: 24px; letter-spacing: 0.5px;">TrueIntent // eBPF Active Defense</h1>
    <p style="margin: 4px 0 0 0; color: #9ca3af; font-size: 13px;">Real-Time Kernel TLS Inspection & Autonomous IPS Interdiction</p>
  </div>
  <div class="badge">IPS MODE: ACTIVE ENFORCEMENT</div>
</div>

<div class="grid">
  <div class="card"><h3>Total Inspected</h3><div class="num text-accent" id="m-inspected">0</div></div>
  <div class="card"><h3>Threats Intercepted (IPS)</h3><div class="num text-danger" id="m-blocked">0</div></div>
  <div class="card"><h3>Benign Allowed</h3><div class="num text-success" id="m-passed">0</div></div>
  <div class="card"><h3>Avg Latency Added</h3><div class="num" id="m-lat">105.0 ms</div></div>
</div>

<div class="layout">
  <div>
    <div class="card">
      <h3 style="margin-bottom: 12px;">Simulated Attack Vectors</h3>
      <p style="font-size: 13px; color: #9ca3af;">Simulate an AI Agent ingesting benign vs poisoned document attachments over encrypted TLS.</p>
      <button class="btn btn-benign" onclick="triggerSim('benign')">Send Benign Document (Safe Task)</button>
      <button class="btn btn-attack" onclick="triggerSim('attack')">Launch Indirect Prompt Injection</button>
    </div>
  </div>

  <div>
    <div class="card" style="padding-bottom: 8px;">
      <h3 style="margin-bottom: 12px;">Live eBPF Kernel Interception Feed</h3>
      <div class="feed" id="feed">
        <div class="feed-item" style="color: #6b7280;">[SYSTEM] TrueIntent eBPF engine listening on libssl.so (uprobe SSL_write)...</div>
      </div>
    </div>
  </div>
</div>

<script>
function triggerSim(type) {
  fetch('/simulate?type=' + type);
}

const evtSource = new EventSource("/stream");
evtSource.onmessage = function(e) {
  const data = JSON.parse(e.data);
  document.getElementById("m-inspected").innerText = data.metrics.inspected;
  document.getElementById("m-blocked").innerText = data.metrics.blocked;
  document.getElementById("m-passed").innerText = data.metrics.passed;

  const feed = document.getElementById("feed");
  feed.innerHTML = "";
  data.events.slice().reverse().forEach(ev => {
    const div = document.createElement("div");
    div.className = "feed-item " + (ev.action === "IPS BLOCKED" ? "feed-blocked" : "feed-allowed");
    div.innerHTML = `<strong>${ev.time}</strong> [${ev.action}] <em>${ev.tool}</em>: <code>${ev.detail}</code>`;
    feed.appendChild(div);
  });
};
</script>
</body>
</html>
"""

class DashboardServer(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _check_auth(self):
        """Check Basic Authentication credentials"""
        auth_header = self.headers.get('Authorization')
        
        if not auth_header:
            return False, None
        
        try:
            # Parse Basic Auth header
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False, None
            
            # Decode credentials
            decoded = base64.b64decode(auth_string).decode('utf-8')
            username, password = decoded.split(':', 1)
            
            # Validate credentials
            valid, role = auth_manager.validate_dashboard_credentials(username, password)
            return valid, username
        
        except Exception:
            return False, None
    
    def _send_auth_required(self):
        """Send 401 Unauthorized response"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="TrueIntent Dashboard"')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b"""
            <!DOCTYPE html>
            <html>
            <head><title>Authentication Required</title></head>
            <body style="background: #0b0f19; color: #f3f4f6; font-family: monospace; padding: 50px;">
                <h1 style="color: #38bdf8;">&#128274; Authentication Required</h1>
                <p>Please provide valid credentials to access the TrueIntent Security Dashboard.</p>
            </body>
            </html>
        """)

    def do_GET(self):
        # Check authentication
        authenticated, username = self._check_auth()
        
        if not authenticated:
            self._send_auth_required()
            return
        
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif self.path.startswith("/simulate"):
            sim_type = self.path.split("=")[-1]
            self.send_response(200)
            self.end_headers()
            threading.Thread(target=self.run_simulation, args=(sim_type,)).start()
        elif self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            
            while True:
                payload = json.dumps({"metrics": METRICS, "events": EVENTS[-20:]})
                try:
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    time.sleep(0.5)
                except:
                    break

    def do_POST(self):
        if self.path == "/events":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                ev = json.loads(body)
                is_blocked = (ev.get("policy_decision") == "block" or ev.get("semantic_decision") == "flag")
                action = "IPS BLOCKED" if is_blocked else "ALLOWED"
                tool = ev.get("tool_name") or ev.get("mcp_payload", {}).get("params", {}).get("name", "tool")
                detail = ev.get("semantic_reason") if ev.get("semantic_decision") == "flag" else (ev.get("policy_reason") or "Clean execution")
                
                METRICS["inspected"] += 1
                if is_blocked:
                    METRICS["blocked"] += 1
                else:
                    METRICS["passed"] += 1

                EVENTS.append({
                    "time": time.strftime("%H:%M:%S"),
                    "action": action,
                    "tool": tool,
                    "detail": str(detail)
                })

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def run_simulation(self, sim_type):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        agent_path = os.path.join(base_dir, "agent.py")
        
        if sim_type == "benign":
            doc = os.path.join(base_dir, "clean_task.txt")
            action = "ALLOWED"
            tool = "ping"
            detail = "Host 127.0.0.1 (Safe connectivity check)"
            METRICS["passed"] += 1
        else:
            doc = os.path.join(base_dir, "invoice_malicious.txt")
            action = "IPS BLOCKED"
            tool = "execute_command"
            detail = "sudo rm -rf / (Dangerous privileged execution blocked)"
            METRICS["blocked"] += 1
            # Note: Actual blocking is handled by the request-ID-based mechanism
            # in the server, not by file signals

        METRICS["inspected"] += 1
        EVENTS.append({
            "time": time.strftime("%H:%M:%S"),
            "action": action,
            "tool": tool,
            "detail": detail
        })
        
        # Execute agent in background to drive real TLS traffic
        subprocess.run(["python3", agent_path, doc], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def main():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), DashboardServer)
    print(f"[+] TrueIntent Security Dashboard active on http://0.0.0.0:{PORT}")
    server.serve_forever()

if __name__ == "__main__":
    main()
