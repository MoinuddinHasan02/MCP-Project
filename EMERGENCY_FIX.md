# 🚨 EMERGENCY FIX: Enable Threat Blocking

## Problem

The malicious command `sudo rm -rf /` was **NOT blocked** because you're only running the eBPF interceptor, not the full security pipeline!

## Current (WRONG) Setup

```
Terminal 1: sudo python3 sniff_bcc_simple.py  ❌ ONLY CAPTURES, DOESN'T BLOCK
Terminal 2: python3 server.py                  ✅ Running
Terminal 3: curl ... (sends attack)             ❌ Gets through!
```

## Fixed Setup

### Stop Everything

In Terminal 1, press `Ctrl+C`

### Terminal 1: Run FULL Pipeline (REQUIRED!)

```bash
cd ~/try

# THIS IS THE CORRECT COMMAND - Run all 4 modules together!
sudo python3 -u module1-interceptor/sniff_bcc_simple.py 2>&1 | \
  python3 -u module2-parser/parser.py 2>&1 | \
  python3 -u module3-policy/engine.py 2>&1 | \
  python3 -u module4-semantic/inspector.py
```

**Why this works:**
- `sniff_bcc_simple.py` → Captures SSL/TLS traffic
- `parser.py` → Extracts JSON-RPC calls
- `engine.py` → Checks capability policies  
- `inspector.py` → **DETECTS THREATS AND SENDS BLOCK COMMAND TO SERVER** ✅

### Terminal 2: Keep Server Running

```bash
cd ~/try/demo-ips
python3 server.py
```

### Terminal 3: Re-test Malicious Command

```bash
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"sudo rm -rf /"}}}'
```

## Expected Result (After Fix)

### Terminal 1 Output:
```
[🚨 IPS TRIGGERED] Threat Detected: Privilege escalation attempt
  ↳ Privilege escalation attempt: 'sudo'
  ↳ Destructive file operation: 'rm -rf'
[🚨 IPS TRIGGERED] Request ID 2 has been blocked
```

### Terminal 3 Output:
```json
{"error": "Request blocked by IPS", "reason": "Threat detected"}
```

OR

```
403 Forbidden
```

## How the Blocking Works

1. **eBPF captures** encrypted traffic → Plaintext JSON
2. **Parser extracts** MCP call → `{"cmd": "sudo rm -rf /"}`
3. **Policy engine** checks → Tool `execute_command` is allowed (passes)
4. **Semantic inspector** analyzes arguments → **THREAT DETECTED!**
5. **Inspector sends block** → `POST http://127.0.0.1:8444/ips-control {"action":"block","request_id":2}`
6. **Server blocks request** → Returns 403 or error

## Verify It's Working

### Test 1: Benign Request (Should Pass)
```bash
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```
**Expected:** ✅ Success response

### Test 2: Malicious Command (Should Block)
```bash
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"sudo rm -rf /"}}}'
```
**Expected:** 🚫 Blocked (403 or error)

### Test 3: Path Traversal (Should Block)
```bash
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../etc/passwd"}}}'
```
**Expected:** 🚫 Blocked (403 or error)

## Check Audit Logs

```bash
cd ~/try/module3-policy
python3 audit_logger.py recent 10
```

Should show:
```
[TIMESTAMP] threat_detected - Privilege escalation attempt
[TIMESTAMP] request_blocked - Request ID: 2
```

## Troubleshooting

### Pipeline not showing output?
```bash
# Check stderr
sudo python3 -u module1-interceptor/sniff_bcc_simple.py 2>&1 | ...
```

### Still not blocking?
```bash
# Check if inspector is running
ps aux | grep inspector.py

# Check server IPS endpoint
curl -X POST http://127.0.0.1:8444/ips-control \
  -H "Content-Type: application/json" \
  -d '{"action":"status"}'
```

### Server not receiving blocks?
```bash
# Check server is listening on port 8444
sudo ss -tulpn | grep 8444
```

## Summary

**DON'T run:** `sudo python3 sniff_bcc_simple.py` alone  
**DO run:** Full pipeline with all 4 modules piped together

**The pipe (`|`) is critical** - it connects the modules so threats get blocked!
