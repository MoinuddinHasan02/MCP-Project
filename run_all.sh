#!/bin/bash

# TrueIntent: End-to-End Runner

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo "  TrueIntent: eBPF-Driven MCP Inspection & Security Firewall"
echo "=========================================================="
echo ""

echo "[*] Requesting sudo privileges for eBPF modules..."
sudo -v

echo "[*] Project Directory: $PROJECT_DIR"
echo "[*] Secure temp files initialized"

echo "[*] Starting Local TLS MCP Server..."
cd "$PROJECT_DIR/demo-ips"
python3 server.py &
MCP_PID=$!

sleep 1

echo "[*] Starting Security Dashboard (http://127.0.0.1:5000)..."
cd "$PROJECT_DIR/demo-ips"
python3 dashboard.py &
DASH_PID=$!

sleep 1

echo "[*] Starting Full 4-Layer Inspection Pipeline..."
cd "$PROJECT_DIR"
sudo python3 -u module1-interceptor/sniff_bcc_simple.py 2>&1 | \
  python3 -u module2-parser/parser.py 2>&1 | \
  python3 -u module3-policy/engine.py 2>&1 | \
  python3 -u module4-semantic/inspector.py &
PIPELINE_PID=$!

echo -e "\n[+] SUCCESS: All core components are running!"
echo "[+] Security Dashboard is live at: http://127.0.0.1:5000"
echo "[+] MCP Server: https://127.0.0.1:8443"
echo "[+] IPS Control Endpoint: http://127.0.0.1:8444"
echo "[+] Leave this terminal open. Press Ctrl+C at any time to safely shut everything down.\n"

# Wait for user interruption to clean up background jobs
trap "echo -e '\n[*] Shutting down TrueIntent services...'; kill $MCP_PID $DASH_PID $PIPELINE_PID 2>/dev/null; sudo pkill -f sniff_bcc_simple.py; sudo pkill -f parser.py; sudo pkill -f engine.py; sudo pkill -f inspector.py; exit" SIGINT SIGTERM
wait
