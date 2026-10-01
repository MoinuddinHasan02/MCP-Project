
#!/bin/bash



echo "[*] Preparing stream log..."

touch /tmp/trueintent_ebpf_stream.log



echo "[*] Starting Local MCP Server..."

cd ~/mcp-tls-guard/demo-ips

python3 server.py &

MCP_PID=$!



echo "[*] Starting Security Dashboard (http://127.0.0.1:5000)..."

python3 dashboard.py &

DASH_PID=$!



echo "[*] Starting eBPF Inspection Pipeline..."

cd ~/mcp-tls-guard

sudo python3 module1-interceptor/sniff.py | python3 module2-parser/parser.py | sudo python3 module3-policy/policy.py &

PIPELINE_PID=$!



echo -e "\n[+] All core components are running in the background!"

echo "[+] Press Ctrl+C at any time to shut down the background services."



# Wait for user interruption to clean up background jobs

trap "kill $MCP_PID $DASH_PID $PIPELINE_PID 2>/dev/null; exit" SIGINT SIGTERM

wait

