# 🧪 Full Pipeline Testing Guide

This guide walks you through testing the complete TrueIntent security pipeline on Linux.

## ✅ Prerequisites Verified

Based on your terminal output, you have:
- ✅ Ubuntu system with kernel 5.15+
- ✅ BCC installed (`python3-bpfcc`)
- ✅ libssl at `/usr/lib/x86_64-linux-gnu/libssl.so.3`
- ✅ eBPF capturing traffic successfully
- ✅ Server running and authenticating
- ✅ API key: `qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE`

## 🚀 Quick Test (What You Just Ran)

### Terminal 1: eBPF Interceptor
```bash
cd ~/try/module1-interceptor
sudo python3 sniff_bcc_simple.py
```

**Status:** ✅ Working - Capturing plaintext SSL/TLS traffic

### Terminal 2: MCP Server
```bash
cd ~/try/demo-ips
python3 server.py
```

**Status:** ✅ Working - Authentication successful

### Terminal 3: Test Request
```bash
curl -k -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

**Status:** ✅ Working - Returns success response

**Note:** The `curl: (56) OpenSSL SSL_read` error is **harmless** - it's just curl complaining about connection close. The request succeeds and returns valid JSON.

---

## 🔥 Next: Full Pipeline Integration

Now test the **complete security stack** with all modules connected.

### Step 1: Stop Current Processes

In your terminals, press `Ctrl+C` to stop:
- Terminal 1: Stop `sniff_bcc_simple.py`
- Terminal 2: Stop `server.py`

### Step 2: Start Full Pipeline

Open **Terminal 1** and run:

```bash
cd ~/try

# Start complete pipeline (eBPF → Parser → Policy → Inspector)
sudo python3 -u module1-interceptor/sniff_bcc_simple.py 2>&1 | \
  python3 -u module2-parser/parser.py 2>&1 | \
  python3 -u module3-policy/engine.py 2>&1 | \
  python3 -u module4-semantic/inspector.py
```

**Expected output:**
```
[*] Found libssl: /usr/lib/x86_64-linux-gnu/libssl.so.3
[*] Loading eBPF program...
[*] Attached to SSL_write
[*] Attached to SSL_read
[Parser] Ready to parse traffic...
[Policy] Loading policies...
[Inspector] Semantic analysis ready...
```

### Step 3: Start Server

Open **Terminal 2** and run:

```bash
cd ~/try/demo-ips
python3 server.py
```

**Expected output:**
```
[+] Secure MCP Tool Server active on https://127.0.0.1:8443
[+] IPS Control Endpoint active on http://127.0.0.1:8444
[+] Rate Limiting: 10 req/sec with burst of 20
```

### Step 4: Test Benign Request

Open **Terminal 3** and run:

```bash
# Test 1: Normal request (should succeed)
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

**Expected result:** 
```json
{"jsonrpc": "2.0", "id": 1, "result": {"status": "success", ...}}
```

**What to watch:**
- Terminal 1: Should show traffic flowing through all 4 modules
- Terminal 2: Should show `[AUTH SUCCESS]`

### Step 5: Test Malicious Request 🚨

Now send a **dangerous command** (will be blocked):

```bash
# Test 2: Command injection (SHOULD BE BLOCKED)
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"sudo rm -rf /"}}}'
```

**Expected result:**
```json
{"error": "Threat detected", "threat_level": "CRITICAL"}
```
OR
```
403 Forbidden
```

**What to watch:**
- Terminal 1: Should show `[THREAT DETECTED]` or `[BLOCKED]`
- Terminal 2: May show `[SECURITY] Malicious request blocked`

### Step 6: Test Path Traversal

```bash
# Test 3: Path traversal (SHOULD BE BLOCKED)
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../etc/passwd"}}}'
```

### Step 7: Test Obfuscated Attack

```bash
# Test 4: Hex-encoded malicious command (SHOULD BE BLOCKED)
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f"}}}'
```

### Step 8: Test Rate Limiting

```bash
# Test 5: Rapid-fire requests (trigger rate limit)
for i in {1..25}; do
  curl -sk -X POST https://127.0.0.1:8443/mcp \
    -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":'$i',"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}' &
done
wait
```

**Expected:** Some requests get `429 Too Many Requests` after exceeding 20/sec burst limit

### Step 9: Test Authentication

```bash
# Test 6: Invalid API key (SHOULD BE REJECTED)
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: INVALID_KEY_ATTACK" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

**Expected:** `401 Unauthorized` or `403 Forbidden`

---

## 📊 Check Audit Logs

After running tests, verify the audit trail:

```bash
cd ~/try/module3-policy

# View recent events
python3 audit_logger.py recent 10

# Query specific threat types
python3 audit_logger.py query threat_detected

# Export report
python3 audit_logger.py export /tmp/security_report.txt 1
cat /tmp/security_report.txt
```

**Expected output:**
```
[2024-XX-XX XX:XX:XX] EVENT: request_allowed - Tool: ping
[2024-XX-XX XX:XX:XX] EVENT: threat_detected - Threat: command_injection
[2024-XX-XX XX:XX:XX] EVENT: threat_detected - Threat: path_traversal
[2024-XX-XX XX:XX:XX] EVENT: rate_limit_exceeded - IP: 127.0.0.1
```

---

## 🎯 Success Criteria

Your pipeline is working correctly if:

1. ✅ **eBPF captures traffic** - Terminal 1 shows JSON events
2. ✅ **Parser extracts data** - MCP calls are parsed correctly
3. ✅ **Policy engine validates** - Checks against policy files
4. ✅ **Inspector detects threats** - Blocks malicious payloads
5. ✅ **Audit logs created** - Events recorded in `~/.trueintent/audit/`
6. ✅ **Benign requests pass** - Normal operations work
7. ✅ **Malicious requests blocked** - Attacks prevented
8. ✅ **Rate limiting works** - Excessive requests throttled
9. ✅ **Authentication enforced** - Invalid keys rejected

---

## 🐛 Troubleshooting

### Pipeline not showing output?

```bash
# Check if processes are running
ps aux | grep python3

# Check for errors
sudo dmesg | tail -20  # Kernel errors
journalctl -xe | tail -50  # System logs
```

### Server not blocking threats?

The server itself may not block - the **inspector module** should block. Check:

```bash
# View inspector output
tail -f /tmp/pipeline.log
```

### Audit logs empty?

```bash
# Check audit directory
ls -la ~/.trueintent/audit/

# Verify permissions
stat ~/.trueintent/auth.json  # Should be 0600
```

### eBPF errors?

```bash
# Check kernel version
uname -r  # Need 4.x or higher

# Check BCC installation
python3 -c "from bcc import BPF; print('BCC OK')"

# Check libssl
ldconfig -p | grep libssl
```

---

## 🔄 Automated Test Script

For automated testing, use:

```bash
cd ~/try
sudo bash test_full_pipeline.sh
```

This runs all 6 test cases automatically and reports pass/fail.

---

## 📈 Performance Monitoring

Monitor resource usage:

```bash
# CPU/Memory
top -p $(pgrep -f "sniff_bcc|parser.py|engine.py|inspector.py|server.py")

# Network
sudo ss -tulpn | grep 8443

# eBPF stats
sudo bpftool prog show
sudo bpftool map dump name events  # If using perf events
```

---

## 🎉 What You've Achieved

✅ **Real eBPF SSL/TLS interception** at kernel level  
✅ **Zero-trust security pipeline** with 4 layers  
✅ **Semantic threat detection** with 60+ patterns  
✅ **Audit trail** with HMAC integrity  
✅ **Rate limiting** with token bucket  
✅ **Strong authentication** with SHA-256 API keys  

---

## 📝 Next Steps

1. ✅ Test full pipeline (you're here!)
2. ⏭️ Test dashboard at `http://127.0.0.1:5000`
3. ⏭️ Update `run_all.sh` to use new pipeline
4. ⏭️ Create pull request to merge `security-fixes` → `main`
5. ⏭️ Document Linux-only requirement in README
6. ⏭️ Add CI/CD tests (GitHub Actions)

---

## 🔒 Security Notes

- eBPF requires `sudo` - runs in kernel space
- API keys stored in `~/.trueintent/auth.json` (mode 0600)
- Audit logs in `~/.trueintent/audit/` (tamper-evident chain)
- Certificate files in `module1-interceptor/` (self-signed for demo)

**Production checklist:**
- [ ] Replace self-signed certs with real CA certs
- [ ] Use secrets manager for API keys (not file storage)
- [ ] Enable remote syslog for audit logs
- [ ] Set up alerting for threat detections
- [ ] Add DDoS protection (CloudFlare, AWS Shield)
- [ ] Rotate API keys regularly
- [ ] Enable SIEM integration

---

## 📚 Related Documentation

- `EBPF_QUICKSTART.md` - eBPF setup guide
- `EBPF_INTEGRATION.md` - Technical architecture
- `SECURITY_IMPROVEMENTS.md` - Security fixes applied
- `module4-semantic/README.md` - Threat detection patterns

---

**Status:** ✅ eBPF integration verified working  
**Last tested:** 2024-XX-XX on Ubuntu with kernel 5.15+  
**Contact:** Your team on GitHub
