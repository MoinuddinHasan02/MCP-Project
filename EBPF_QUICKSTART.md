# eBPF Integration Quick Start

## TL;DR - Get eBPF Working in 5 Minutes

### Step 1: Get a Linux Machine
```bash
# Option A: Use WSL2 on Windows (if you have Windows 11)
wsl --install Ubuntu-22.04

# Option B: Use a VM (VirtualBox, VMware)
# Download Ubuntu 22.04 LTS ISO

# Option C: Use a cloud instance
# AWS EC2, Google Cloud, DigitalOcean, etc.
```

### Step 2: Clone and Setup
```bash
# Clone your repo
git clone https://github.com/MoinuddinHasan02/MCP-Project.git
cd MCP-Project

# Checkout the security-fixes branch
git checkout security-fixes

# Navigate to interceptor module
cd module1-interceptor

# Run setup script
sudo bash setup_ebpf.sh
```

### Step 3: Test eBPF Capture
```bash
# Terminal 1: Start eBPF interceptor
sudo python3 sniff_bcc.py

# Terminal 2: Start MCP server
cd ../demo-ips
python3 server.py

# Terminal 3: Initialize auth and get API key
cd ../module3-policy
python3 auth.py init
# Copy the API key shown

# Terminal 4: Send test request
curl -k -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

**Expected**: Terminal 1 should show captured SSL/TLS traffic with the JSON-RPC request.

---

## Why eBPF Integration Matters

### Current State (Without eBPF)
- ❌ Uses file-based stub (`/tmp/trueintent_ebpf_stream.log`)
- ❌ No actual SSL/TLS interception
- ❌ Can't see encrypted traffic
- ❌ Limited to test scenarios

### After eBPF Integration
- ✅ Real kernel-level SSL/TLS interception
- ✅ Captures plaintext before encryption
- ✅ No application modification needed
- ✅ Production-ready security monitoring

---

## Architecture with Real eBPF

```
┌─────────────────────────────────────────────────┐
│  Linux Kernel Space                              │
│                                                  │
│  ┌──────────────────────────────────────────┐  │
│  │  eBPF Program (uprobe on libssl.so)      │  │
│  │  - Hooks SSL_write() / SSL_read()        │  │
│  │  - Captures plaintext data                │  │
│  │  - Sends to userspace via perf buffer    │  │
│  └────────────┬─────────────────────────────┘  │
│               │                                  │
└───────────────┼──────────────────────────────────┘
                │ Perf Events
┌───────────────▼──────────────────────────────────┐
│  User Space                                       │
│                                                   │
│  ┌──────────────────────────────────────────┐   │
│  │  sniff_bcc.py (Python BCC)               │   │
│  │  - Loads eBPF program                     │   │
│  │  - Polls perf buffer                      │   │
│  │  - Filters & formats events              │   │
│  └────────────┬─────────────────────────────┘   │
│               │ Structured JSON                  │
│  ┌────────────▼─────────────────────────────┐   │
│  │  parser.py → engine.py → inspector.py    │   │
│  │  Security Analysis Pipeline               │   │
│  └──────────────────────────────────────────┘   │
└───────────────────────────────────────────────────┘
```

---

## Which Approach Should You Use?

### Recommended: Python BCC (`sniff_bcc.py`)

**Pros:**
- ✅ Pure Python, easy to modify
- ✅ No compilation needed
- ✅ Better error messages
- ✅ Easier debugging
- ✅ Native pipeline integration

**Cons:**
- ⚠️ Requires python3-bpfcc package
- ⚠️ Slightly more overhead than C

**Use when:** You want the easiest setup and maintainability

### Alternative: C Binary (`sslsniff` + `sniff_wrapper.py`)

**Pros:**
- ✅ Uses existing compiled code
- ✅ Potentially faster
- ✅ More control over eBPF details

**Cons:**
- ⚠️ Requires compilation
- ⚠️ Harder to debug
- ⚠️ Need C knowledge to modify

**Use when:** You need maximum performance or already have working C code

---

## File Changes Needed

### 1. Update `run_all.sh`

**Current (stub version):**
```bash
sudo python3 -u module1-interceptor/sniff.py | \
  python3 -u module2-parser/parser.py | \
  sudo python3 -u module3-policy/engine.py
```

**New (real eBPF):**
```bash
sudo python3 -u module1-interceptor/sniff_bcc.py | \
  python3 -u module2-parser/parser.py | \
  sudo python3 -u module3-policy/engine.py | \
  sudo python3 -u module4-semantic/inspector.py
```

### 2. No Changes Needed To:
- ✅ Parser (module2) - already handles JSON input
- ✅ Policy engine (module3) - format-agnostic
- ✅ Semantic inspector (module4) - works with any input
- ✅ Dashboard - receives events via HTTP

---

## Testing Checklist

### Basic Functionality
- [ ] eBPF program loads without errors
- [ ] Captures SSL_write events
- [ ] Captures SSL_read events
- [ ] Filters out non-JSON traffic
- [ ] Outputs structured data

### Pipeline Integration
- [ ] Parser receives eBPF output
- [ ] Policy engine evaluates requests
- [ ] Semantic inspector detects threats
- [ ] Dashboard displays events
- [ ] Audit logs are created

### Security Testing
- [ ] Benign requests pass through
- [ ] Malicious payloads are blocked
- [ ] Authentication is enforced
- [ ] Rate limiting works
- [ ] All events are logged

### Performance
- [ ] Handles 100 req/sec without drops
- [ ] CPU usage < 20%
- [ ] Memory usage stable
- [ ] No event loss in perf buffer

---

## Troubleshooting Guide

### "Permission denied" or "Operation not permitted"

**Solution:** Must run as root
```bash
sudo python3 sniff_bcc.py
```

### "Could not find libssl.so"

**Solution:** Install OpenSSL
```bash
sudo apt install libssl-dev
ldconfig -p | grep libssl  # Verify
```

### "Failed to load BPF program"

**Solution:** Install/update BCC
```bash
sudo apt install --reinstall python3-bpfcc bpfcc-tools
python3 -c "from bcc import BPF"  # Test
```

### "No events captured"

**Possible issues:**
1. No SSL traffic → Send test request
2. Wrong process → Check PID filter
3. eBPF not attached → Check `/sys/kernel/debug/tracing/uprobe_events`

**Debug:**
```bash
# Check if uprobe attached
sudo cat /sys/kernel/debug/tracing/uprobe_events | grep SSL

# Monitor raw eBPF events
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### "libbpf: failed to load object"

**Solution:** Update kernel or BCC
```bash
# Check kernel version (need >= 4.4)
uname -r

# Update kernel
sudo apt update && sudo apt upgrade
```

---

## WSL2 Considerations

If using WSL2 on Windows:

### Enable eBPF in WSL2
```bash
# 1. Update to latest WSL2
wsl --update

# 2. Check kernel version
uname -r  # Need >= 5.15

# 3. Install BCC
sudo apt install bpfcc-tools python3-bpfcc

# 4. Test eBPF
sudo python3 sniff_bcc.py
```

### Known WSL2 Limitations
- ⚠️ Some eBPF features may be limited
- ⚠️ Performance may be lower than native Linux
- ✅ Basic SSL interception works
- ✅ Good for development/testing

---

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/trueintent.service`:

```ini
[Unit]
Description=TrueIntent eBPF Security Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/trueintent
ExecStart=/usr/bin/python3 -u module1-interceptor/sniff_bcc.py | \
          /usr/bin/python3 -u module2-parser/parser.py | \
          /usr/bin/python3 -u module3-policy/engine.py | \
          /usr/bin/python3 -u module4-semantic/inspector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable trueintent
sudo systemctl start trueintent
sudo systemctl status trueintent
```

### Monitoring

```bash
# View logs
sudo journalctl -u trueintent -f

# Check performance
sudo perf top -p $(pgrep -f sniff_bcc.py)

# Monitor events
cd ~/mcp-tls-guard/module3-policy
python3 audit_logger.py recent 50
```

---

## Next Steps

1. **Choose Linux Environment**
   - WSL2 for development
   - VM or cloud for production

2. **Run Setup Script**
   ```bash
   cd module1-interceptor
   sudo bash setup_ebpf.sh
   ```

3. **Test Capture**
   ```bash
   sudo python3 sniff_bcc.py
   ```

4. **Integrate with Pipeline**
   - Update `run_all.sh`
   - Test end-to-end
   - Deploy to production

5. **Add to Git**
   ```bash
   git add module1-interceptor/sniff_bcc.py
   git add module1-interceptor/EBPF_INTEGRATION.md
   git add module1-interceptor/setup_ebpf.sh
   git commit -m "Add real eBPF integration"
   git push origin security-fixes
   ```

---

## Resources

- **Full Guide**: See `module1-interceptor/EBPF_INTEGRATION.md`
- **BCC Tutorial**: https://github.com/iovisor/bcc/blob/master/docs/tutorial.md
- **eBPF Docs**: https://ebpf.io/
- **Troubleshooting**: https://github.com/iovisor/bcc/blob/master/FAQ.txt

---

**Questions?** Check the detailed `EBPF_INTEGRATION.md` guide or open an issue on GitHub.
