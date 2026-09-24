
#!/usr/bin/env python3

import json, ssl, sys

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer



class Handler(BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"



    def _reply(self, obj):

        body = json.dumps(obj).encode()

        self.send_response(200)

        self.send_header("Content-Type", "application/json")

        self.send_header("Content-Length", str(len(body)))

        self.end_headers()

        self.wfile.write(body)



    def do_GET(self):

        self._reply({"status": "ok"})



    def do_POST(self):

        n = int(self.headers.get("Content-Length", 0))

        raw = self.rfile.read(n)

        try:

            req = json.loads(raw)

            self._reply({"jsonrpc": "2.0", "id": req.get("id"),

                         "result": {"echo": req}})

        except Exception:

            self._reply({"error": "bad json"})



    def log_message(self, fmt, *args):

        pass



def main():

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("cert.pem", "key.pem")
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"listening on https://127.0.0.1:{port}", flush=True)
    srv.serve_forever()

if __name__ == "__main__":
    main()
