
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler

import ssl

import json

import os

import sys

import threading

import time

from collections import defaultdict, deque



# Import authentication

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'module3-policy'))

from auth import get_auth_manager

from audit_logger import get_audit_logger



# Initialize authentication manager

auth_manager = get_auth_manager()

# Initialize audit logger

audit_logger = get_audit_logger()



# Secure enforcement using request-ID-based blocking instead of file signals

blocked_requests = set()

blocked_requests_lock = threading.Lock()

# Cleanup old blocked request IDs every 60 seconds

blocked_requests_expiry = defaultdict(float)



# Rate limiting using token bucket algorithm

class RateLimiter:

    """Token bucket rate limiter for per-IP request throttling"""

    

    def __init__(self, requests_per_second=10, burst_size=20):

        """

        Initialize rate limiter.

        

        Args:

            requests_per_second: Average requests allowed per second

            burst_size: Maximum burst of requests allowed

        """

        self.rate = requests_per_second

        self.burst_size = burst_size

        self.buckets = defaultdict(lambda: {"tokens": burst_size, "last_update": time.time()})

        self.lock = threading.Lock()

        

        # Track request history for adaptive rate limiting

        self.request_history = defaultdict(lambda: deque(maxlen=100))

        

        # Blacklist for IPs that exceeded limits repeatedly

        self.blacklist = {}

        self.blacklist_duration = 300  # 5 minutes

    

    def _refill_bucket(self, bucket):

        """Refill tokens based on elapsed time"""

        now = time.time()

        elapsed = now - bucket["last_update"]

        

        # Add tokens based on time elapsed

        tokens_to_add = elapsed * self.rate

        bucket["tokens"] = min(self.burst_size, bucket["tokens"] + tokens_to_add)

        bucket["last_update"] = now

    

    def is_allowed(self, client_ip):

        """

        Check if request from client_ip is allowed.

        

        Returns:

            (allowed, reason, retry_after)

        """

        with self.lock:

            # Check blacklist first

            if client_ip in self.blacklist:

                blacklist_until = self.blacklist[client_ip]

                if time.time() < blacklist_until:

                    remaining = int(blacklist_until - time.time())

                    return False, "IP temporarily blacklisted due to excessive requests", remaining

                else:

                    # Blacklist expired

                    del self.blacklist[client_ip]

            

            bucket = self.buckets[client_ip]

            self._refill_bucket(bucket)

            

            # Check if we have tokens available

            if bucket["tokens"] >= 1:

                bucket["tokens"] -= 1

                

                # Record request timestamp

                self.request_history[client_ip].append(time.time())

                

                return True, "", 0

            else:

                # Rate limit exceeded

                # Check if this IP should be blacklisted

                recent_violations = self.request_history[client_ip]

                

                # If more than 50 requests in last 10 seconds, blacklist

                recent_count = sum(1 for ts in recent_violations if time.time() - ts < 10)

                if recent_count > 50:

                    self.blacklist[client_ip] = time.time() + self.blacklist_duration

                    return False, f"IP blacklisted for {self.blacklist_duration}s due to abuse", self.blacklist_duration

                

                # Calculate retry-after time

                tokens_needed = 1 - bucket["tokens"]

                retry_after = int(tokens_needed / self.rate) + 1

                

                return False, "Rate limit exceeded", retry_after

    

    def get_stats(self, client_ip):

        """Get rate limiting statistics for a client IP"""

        with self.lock:

            bucket = self.buckets.get(client_ip)

            if not bucket:

                return {

                    "available_tokens": self.burst_size,

                    "requests_last_minute": 0,

                    "blacklisted": False

                }

            

            self._refill_bucket(bucket)

            

            # Count requests in last minute

            recent = self.request_history[client_ip]

            recent_count = sum(1 for ts in recent if time.time() - ts < 60)

            

            return {

                "available_tokens": int(bucket["tokens"]),

                "requests_last_minute": recent_count,

                "blacklisted": client_ip in self.blacklist

            }



# Initialize rate limiter (10 req/sec, burst of 20)

rate_limiter = RateLimiter(requests_per_second=10, burst_size=20)



def cleanup_blocked_requests():

    """Remove expired blocked request IDs to prevent memory leak"""

    while True:

        time.sleep(60)

        current_time = time.time()

        with blocked_requests_lock:

            expired = [req_id for req_id, exp_time in blocked_requests_expiry.items() 

                      if current_time > exp_time]

            for req_id in expired:

                blocked_requests.discard(req_id)

                del blocked_requests_expiry[req_id]



# Start cleanup thread

cleanup_thread = threading.Thread(target=cleanup_blocked_requests, daemon=True)

cleanup_thread.start()



class SecureMCPHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):

        return  # Suppress default HTTP logging to keep stdout clean



    def do_POST(self):

        # Get client IP address

        client_ip = self.client_address[0]

        

        # Handle IPS control endpoint on different port (no rate limiting or auth on control endpoint)

        if self.server.server_address[1] == 8444:

            self._handle_ips_control()

            return

        

        # Check authentication for MCP endpoint

        api_key = self.headers.get('X-API-Key') or self.headers.get('Authorization', '').replace('Bearer ', '')

        

        valid, key_name = auth_manager.validate_api_key(api_key)

        

        if not valid:

            # Log failed authentication attempt

            audit_logger.log_auth_attempt(client_ip, key_name or "unknown", False, method="api_key")

            

            resp_bytes = json.dumps({

                "jsonrpc": "2.0",

                "error": {

                    "code": -32001,

                    "message": "Authentication required. Provide a valid API key in X-API-Key header or Authorization: Bearer header."

                }

            }).encode('utf-8')

            self.send_response(401)  # Unauthorized

            self.send_header('Content-Type', 'application/json')

            self.send_header('WWW-Authenticate', 'Bearer realm="MCP Server"')

            self.send_header('Content-Length', str(len(resp_bytes)))

            self.end_headers()

            self.wfile.write(resp_bytes)

            

            sys.stderr.write(f"[AUTH FAILED] {client_ip} - Invalid or missing API key\n")

            sys.stderr.flush()

            return

        

        # Log successful authentication

        audit_logger.log_auth_attempt(client_ip, key_name, True, method="api_key")

        

        # Log successful authentication

        sys.stderr.write(f"[AUTH SUCCESS] {client_ip} - Authenticated as '{key_name}'\n")

        sys.stderr.flush()

        

        # Apply rate limiting to main MCP endpoint

        allowed, reason, retry_after = rate_limiter.is_allowed(client_ip)

        

        if not allowed:

            # Log rate limit violation

            audit_logger.log_rate_limit(client_ip, reason, retry_after)

            

            resp_bytes = json.dumps({

                "jsonrpc": "2.0",

                "error": {

                    "code": -32099,

                    "message": f"Rate limit exceeded: {reason}",

                    "data": {

                        "retry_after": retry_after,

                        "client_ip": client_ip

                    }

                }

            }).encode('utf-8')

            self.send_response(429)  # Too Many Requests

            self.send_header('Content-Type', 'application/json')

            self.send_header('Retry-After', str(retry_after))

            self.send_header('X-RateLimit-Limit', str(rate_limiter.burst_size))

            self.send_header('X-RateLimit-Remaining', '0')

            self.send_header('Content-Length', str(len(resp_bytes)))

            self.end_headers()

            self.wfile.write(resp_bytes)

            

            # Log rate limit violation

            sys.stderr.write(f"[RATE LIMIT] {client_ip} - {reason}\n")

            sys.stderr.flush()

            return

        

        content_length = int(self.headers.get('Content-Length', 0))

        body = self.rfile.read(content_length).decode('utf-8')

        

        try:

            req = json.loads(body)

            req_id = req.get("id")

            

            # Check if this specific request ID has been blocked by IPS
            # For tool requests, allow a brief grace period (up to 200ms) for out-of-band
            # eBPF inspection pipeline to inspect payload and signal blocking.
            for _ in range(10):
                with blocked_requests_lock:
                    if req_id in blocked_requests:
                        break
                time.sleep(0.02)

            with blocked_requests_lock:
                if req_id in blocked_requests:

                    # Remove from blocked set after use

                    blocked_requests.discard(req_id)

                    if req_id in blocked_requests_expiry:

                        del blocked_requests_expiry[req_id]

                    

                    resp_bytes = json.dumps({

                        "jsonrpc": "2.0",

                        "id": req_id,

                        "error": {"code": -32000, "message": "CRITICAL: Blocked by TrueIntent eBPF IPS Enforcement"}

                    }).encode('utf-8')

                    self.send_response(403)

                    self.send_header('Content-Type', 'application/json')

                    self.send_header('Content-Length', str(len(resp_bytes)))

                    self.end_headers()

                    self.wfile.write(resp_bytes)

                    return

            

            method = req.get("method")

            params = req.get("params", {})

            tool = params.get("name")

            

            # Get rate limit stats for response headers

            stats = rate_limiter.get_stats(client_ip)

            

            # Normal execution response
            exec_output = "Execution completed safely."
            if tool == "read_file":
                filepath = params.get("arguments", {}).get("path", "")
                if filepath and os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            exec_output = f.read()
                    except Exception as e:
                        exec_output = f"Error reading file: {e}"
                else:
                    exec_output = f"File not found: {filepath}"

            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"status": "success", "executed_tool": tool, "output": exec_output}
            }

            

            resp_bytes = json.dumps(response).encode('utf-8')

            self.send_response(200)

            self.send_header('Content-Type', 'application/json')

            self.send_header('X-RateLimit-Limit', str(rate_limiter.burst_size))

            self.send_header('X-RateLimit-Remaining', str(stats["available_tokens"]))

            self.send_header('Content-Length', str(len(resp_bytes)))

            self.end_headers()

            self.wfile.write(resp_bytes)

        except Exception as e:

            resp_bytes = json.dumps({

                "jsonrpc": "2.0",

                "error": {"code": -32603, "message": f"Internal error: {str(e)}"}

            }).encode('utf-8')

            self.send_response(500)

            self.send_header('Content-Type', 'application/json')

            self.send_header('Content-Length', str(len(resp_bytes)))

            self.end_headers()

            self.wfile.write(resp_bytes)

    

    def _handle_ips_control(self):

        """Handle IPS control commands from semantic inspector"""

        content_length = int(self.headers.get('Content-Length', 0))

        body = self.rfile.read(content_length).decode('utf-8')

        

        try:

            cmd = json.loads(body)

            if cmd.get("action") == "block":

                req_id = cmd.get("request_id")

                if req_id:

                    block_request(req_id)

                    resp_bytes = json.dumps({"status": "blocked", "request_id": req_id}).encode('utf-8')

                    self.send_response(200)

                    self.send_header('Content-Type', 'application/json')

                    self.send_header('Content-Length', str(len(resp_bytes)))

                    self.end_headers()

                    self.wfile.write(resp_bytes)

                else:

                    self.send_response(400)

                    self.send_header('Content-Length', '0')

                    self.end_headers()

            else:

                self.send_response(400)

                self.send_header('Content-Length', '0')

                self.end_headers()

        except Exception:

            self.send_response(500)

            self.send_header('Content-Length', '0')

            self.end_headers()

    

    def do_GET(self):

        """Handle GET requests for rate limit statistics"""

        if self.path == "/stats":

            client_ip = self.client_address[0]

            stats = rate_limiter.get_stats(client_ip)

            

            # Add global statistics

            with rate_limiter.lock:

                total_clients = len(rate_limiter.buckets)

                blacklisted_count = len(rate_limiter.blacklist)

            

            response = {

                "client_ip": client_ip,

                "client_stats": stats,

                "global_stats": {

                    "total_clients_tracked": total_clients,

                    "blacklisted_ips": blacklisted_count,

                    "rate_limit": f"{rate_limiter.rate} req/sec",

                    "burst_size": rate_limiter.burst_size

                }

            }

            

            resp_bytes = json.dumps(response, indent=2).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
        elif self.path == "/reset-limits":
            client_ip = self.client_address[0]
            with rate_limiter.lock:
                rate_limiter.blacklist.pop(client_ip, None)
                if client_ip in rate_limiter.buckets:
                    rate_limiter.buckets[client_ip]["tokens"] = rate_limiter.burst_size
                    rate_limiter.buckets[client_ip]["last_update"] = time.time()
                rate_limiter.request_history[client_ip].clear()
            with blocked_requests_lock:
                blocked_requests.clear()
                blocked_requests_expiry.clear()
            resp_bytes = json.dumps({"status": "reset", "client_ip": client_ip}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()

def block_request(req_id, expiry_seconds=30):

    """

    Mark a request ID as blocked by the IPS.

    Called by the semantic inspector when a threat is detected.

    """

    with blocked_requests_lock:

        blocked_requests.add(req_id)

        blocked_requests_expiry[req_id] = time.time() + expiry_seconds



def run_server():
    server_address = ('127.0.0.1', 8443)
    httpd = ThreadingHTTPServer(server_address, SecureMCPHandler)
    
    # Also start IPS control endpoint on 8444
    ips_control_address = ('127.0.0.1', 8444)
    ips_httpd = ThreadingHTTPServer(ips_control_address, SecureMCPHandler)

    

    # Try multiple cert locations for flexibility

    cert_locations = [
        os.path.join(os.path.dirname(__file__), "..", "module1-interceptor"),
        os.path.expanduser("~/try/module1-interceptor"),
        os.path.expanduser("~/mcp-tls-guard/module1-interceptor"),
        os.path.dirname(__file__)
    ]

    

    certfile = None

    keyfile = None

    

    for cert_dir in cert_locations:

        potential_cert = os.path.join(cert_dir, "cert.pem")

        potential_key = os.path.join(cert_dir, "key.pem")

        if os.path.exists(potential_cert) and os.path.exists(potential_key):

            certfile = potential_cert

            keyfile = potential_key

            break

    

    if not certfile or not keyfile:

        print("[ERROR] Could not find cert.pem and key.pem files")

        print("Searched locations:", cert_locations)

        sys.exit(1)



    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    

    # Start IPS control server in background thread

    ips_thread = threading.Thread(target=ips_httpd.serve_forever, daemon=True)

    ips_thread.start()

    

    print("[+] Secure MCP Tool Server active on https://127.0.0.1:8443")

    print("[+] IPS Control Endpoint active on http://127.0.0.1:8444")

    print("[+] Rate Limiting: 10 req/sec with burst of 20")

    print("[+] Stats endpoint: https://127.0.0.1:8443/stats")

    print(f"[+] Using certificates from: {os.path.dirname(certfile)}")

    httpd.serve_forever()



if __name__ == "__main__":

    run_server()
