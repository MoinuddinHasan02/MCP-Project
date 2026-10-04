# ⚡ Quick Test - For Pushendra

## 🎯 What's Working Now

✅ eBPF capturing SSL/TLS traffic  
✅ Server authenticating requests  
✅ Requests succeeding  

## 🚀 Next: Test Full Security Pipeline

### Terminal 1 - Full Pipeline
```bash
cd ~/try
sudo python3 -u module1-interceptor/sniff_bcc_simple.py 2>&1 | \
  python3 -u module2-parser/parser.py 2>&1 | \
  python3 -u module3-policy/engine.py 2>&1 | \
  python3 -u module4-semantic/inspector.py
```

### Terminal 2 - Server
```bash
cd ~/try/demo-ips
python3 server.py
```

### Terminal 3 - Tests

#### ✅ Test 1: Normal Request (should pass)
```bash
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

#### 🚨 Test 2: Malicious Command (should block)
```bash
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"sudo rm -rf /"}}}'
```

#### 🚨 Test 3: Path Traversal (should block)
```bash
curl -sk -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../etc/passwd"}}}'
```

## 📊 Check Results

### View audit logs:
```bash
cd ~/try/module3-policy
python3 audit_logger.py recent 10
```

### Check for threats:
```bash
python3 audit_logger.py query threat_detected
```

## 🎯 What to Look For

1. Terminal 1 should show traffic flowing through all modules
2. Terminal 2 should show auth success/blocks
3. Test 1 should return JSON success
4. Test 2 & 3 should return 403 Forbidden or error
5. Audit logs should show detections

## 🐛 Issues?

### No output in Terminal 1?
```bash
# Check if processes started
ps aux | grep python

# Check for errors
sudo dmesg | tail
```

### Tests not blocking?
```bash
# Check inspector is running
ps aux | grep inspector.py

# View logs
tail -f /tmp/pipeline.log
```

## ✅ Success = All 3 Tests Work

- Test 1: ✅ Allowed
- Test 2: 🚫 Blocked  
- Test 3: 🚫 Blocked

---

**Full guide:** See `PIPELINE_TEST_GUIDE.md`  
**Automated test:** `sudo bash test_full_pipeline.sh`
