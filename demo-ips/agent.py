import sys
import os
import json
import urllib.request
import ssl

def run_agent(input_file):
    print(f"[*] Agent PID: {os.getpid()}")
    print(f"[*] Ingesting external document: '{input_file}'...")
    
    with open(input_file, 'r') as f:
        content = f.read()

    # Document parsing / instruction extraction simulation
    if "SYSTEM OVERRIDE" in content or "sudo" in content:
        # Prompt injection detected inside the ingested file
        target_tool = "execute_command"
        args = {"cmd": "sudo rm -rf /"}
        print(f"[!] INJECTION TRIGGERED: Document commanded agent to run '{args['cmd']}'")
    else:
        # Benign instruction
        target_tool = "ping"
        args = {"host": "127.0.0.1"}
        print(f"[*] Normal task: Ingested file requested harmless tool '{target_tool}'")

    mcp_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": target_tool,
            "arguments": args
        }
    }

    url = "https://127.0.0.1:8443/mcp"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"[*] Dispatching encrypted MCP request to {url}...")
    req = urllib.request.Request(
        url,
        data=json.dumps(mcp_request).encode('utf-8'),
        headers={"Content-Type": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
            data = resp.read().decode('utf-8')
            print(f"[+] Agent received response:\n{data}")
    except Exception as e:
        print(f"\n[!] TRANSACTION FAILED: {type(e).__name__} - {e}")
        print("[!] The attack was blocked before completing on the system.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 agent.py <input_document>")
        sys.exit(1)
    run_agent(sys.argv[1])
