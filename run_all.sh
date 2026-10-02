#!/bin/bash

echo "[*] Requesting sudo privileges for eBPF modules..."
sudo -v

echo "[*] TrueIntent now uses secure temporary files with proper permissions"
echo "[*] Log file will be created automatically in system temp directory"

echo "[*] Starting Local MCP Server..."
cd ~/mcp-tls-guard/demo-ips
python3 server.py &
MCP_PID=$!

echo "[*] Starting Security Dashboard (http://127.0.0.1:5000)..."
python3 dashboard.py &
DASH_PID=$!

echo "[*] Starting eBPF Inspection Pipeline..."
cd ~/mcp-tls-guard
sudo python3 -u module1-interceptor/sniff.py | python3 -u module2-parser/parser.py | sudo python3 -u module3-policy/engine.py &
PIPELINE_PID=$!

echo -e "\n[+] SUCCESS: All core components are running!"
echo "[+] Security Dashboard is live at: http://127.0.0.1:5000"
echo "[+] MCP Server: https://127.0.0.1:8443"
echo "[+] Secure temp files are being used with 0600 permissions"
echo "[+] Leave this terminal open. Press Ctrl+C at any time to safely shut everything down."

# Wait for user interruption to clean up background jobs
trap "echo -e '\n[*] Shutting down TrueIntent services...'; sudo kill $MCP_PID $DASH_PID $PIPELINE_PID 2>/dev/null; sudo pkill -f sniff.py; sudo pkill -f parser.py; sudo pkill -f engine.py; exit" SIGINT SIGTERM
wait
