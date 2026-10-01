
from http.server import HTTPServer, BaseHTTPRequestHandler

import ssl

import json

import os

import sys



ABORT_FLAG_FILE = "/tmp/trueintent_abort.signal"



class SecureMCPHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):

        return  # Suppress default HTTP logging to keep stdout clean



    def do_POST(self):

        content_length = int(self.headers.get('Content-Length', 0))

        body = self.rfile.read(content_length).decode('utf-8')

        

        # Check if Active Enforcement (IPS) signaled to abort this execution

        if os.path.exists(ABORT_FLAG_FILE):

            os.remove(ABORT_FLAG_FILE)

            self.send_response(403)

            self.send_header('Content-Type', 'application/json')

            self.end_headers()

            self.wfile.write(json.dumps({

                "jsonrpc": "2.0",

                "error": {"code": -32000, "message": "CRITICAL: Blocked by TrueIntent eBPF IPS Enforcement"}
            }).encode('utf-8'))
            return

        try:
            req = json.loads(body)
            method = req.get("method")
            params = req.get("params", {})
            tool = params.get("name")
            
            # Normal execution response
            response = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {"status": "success", "executed_tool": tool, "output": "Execution completed safely."}
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.end_headers()

def run_server():
    server_address = ('127.0.0.1', 8443)
    httpd = HTTPServer(server_address, SecureMCPHandler)
    
    cert_dir = os.path.expanduser("~/mcp-tls-guard/module1-interceptor")
    certfile = os.path.join(cert_dir, "cert.pem")
    keyfile = os.path.join(cert_dir, "key.pem")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    
    print("[+] Secure MCP Tool Server active on https://127.0.0.1:8443")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
