# eBPF Integration Guide

## Overview

This guide explains how to integrate the real eBPF code for SSL/TLS interception in a Linux environment.

## Prerequisites

### System Requirements
- **OS**: Ubuntu 22.04 or 24.04 LTS
- **Kernel**: Linux >= 5.15 (check with `uname -r`)
- **Privileges**: Root/sudo access
- **Architecture**: x86_64

### Install Dependencies

```bash
# Update package list
sudo apt update

# Install BCC (BPF Compiler Collection)
sudo apt install -y bpfcc-tools python3-bpfcc

# Install kernel headers (required for eBPF)
sudo apt install -y linux-headers-$(uname -r)

# Install build tools (for C compilation)
sudo apt install -y clang llvm libelf-dev gcc make

# Install OpenSSL development files
sudo apt install -y libssl-dev

# Verify installations
python3 -c "from bcc import BPF; print('BCC installed successfully')"
```

## Option 1: Python BCC Integration (Recommended)

This approach uses Python BCC bindings for eBPF.

### Advantages
- Pure Python, easier to debug
- No compilation needed
- Better integration with pipeline
- Real-time event processing

### Setup

```bash
cd ~/mcp-tls-guard/module1-interceptor

# Make executable
chmod +x sniff_bcc.py

# Test it
sudo python3 sniff_bcc.py
```

### Usage in Pipeline

```bash
# Replace sniff.py with sniff_bcc.py in run_all.sh
sudo python3 -u module1-interceptor/sniff_bcc.py | \
  python3 -u module2-parser/parser.py | \
  sudo python3 -u module3-policy/engine.py | \
  sudo python3 -u module4-semantic/inspector.py
```

### Troubleshooting

**Error: "Could not find libssl.so"**
```bash
# Find libssl location
ldconfig -p | grep libssl

# Update path in sniff_bcc.py if needed
```

**Error: "Failed to load eBPF program"**
```bash
# Check kernel version (need >= 4.4)
uname -r

# Verify kernel headers installed
ls /usr/src/linux-headers-$(uname -r)

# Check if BPF is enabled
cat /boot/config-$(uname -r) | grep BPF
```

**Error: "Permission denied"**
```bash
# Must run as root
sudo python3 sniff_bcc.py

# Or use capabilities (advanced)
sudo setcap cap_sys_admin,cap_net_admin+ep $(which python3)
```

## Option 2: Use Existing C Binary

This uses the pre-compiled `sslsniff` binary.

### Advantages
- Uses existing tested code
- Potentially more efficient
- No Python overhead

### Setup

```bash
cd ~/mcp-tls-guard/module1-interceptor

# Compile the binary (if not already compiled)
./build.sh

# Verify binary exists
ls -lh sslsniff

# Make wrapper executable
chmod +x sniff_wrapper.py

# Test it
sudo ./sslsniff
```

### Usage in Pipeline

```bash
sudo python3 -u module1-interceptor/sniff_wrapper.py | \
  python3 -u module2-parser/parser.py | \
  sudo python3 -u module3-policy/engine.py | \
  sudo python3 -u module4-semantic/inspector.py
```

### Customizing sslsniff Output

Edit `sslsniff.c` to change output format:

```c
// In sslsniff.c, modify the output section
printf("[%llu] [%d] [%s] [%d] %.*s\n",
    timestamp,
    pid,
    direction,
    fd,
    data_len,
    data
);
```

Then recompile:
```bash
./build.sh
```

## Option 3: Hybrid Approach

Use C binary for capture, Python for processing.

### Architecture

```
┌─────────────────────────────────────────────┐
│  sslsniff (C binary)                        │
│  - eBPF kernel program                      │
│  - High-performance capture                 │
│  - Outputs to file or pipe                  │
└────────────┬────────────────────────────────┘
             │ Raw SSL data
┌────────────▼────────────────────────────────┐
│  sniff.py (Python)                          │
│  - Reads from sslsniff                      │
│  - Filters & formats                        │
│  - Adds metadata                            │
└────────────┬────────────────────────────────┘
             │ Structured JSON
┌────────────▼────────────────────────────────┐
│  Rest of Pipeline                           │
│  - Parser, Policy, Inspector                │
└─────────────────────────────────────────────┘
```

## Comparison of Options

| Feature | BCC Python | C Binary | Hybrid |
|---------|-----------|----------|--------|
| Setup Complexity | Medium | High | High |
| Performance | Good | Excellent | Excellent |
| Debuggability | Easy | Hard | Medium |
| Integration | Native | Wrapper | Best |
| Dependencies | python3-bpfcc | clang, llvm | Both |
| Maintenance | Easy | Hard | Medium |
| **Recommended** | ✅ Yes | For prod | For experts |

## Testing eBPF Integration

### 1. Test SSL Capture

```bash
# Terminal 1: Start the MCP server
cd ~/mcp-tls-guard/demo-ips
python3 server.py

# Terminal 2: Start eBPF capture
cd ~/mcp-tls-guard
sudo python3 module1-interceptor/sniff_bcc.py

# Terminal 3: Send test request
curl -k -X POST https://127.0.0.1:8443/mcp \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
```

**Expected**: Terminal 2 should show captured JSON-RPC traffic

### 2. Test Full Pipeline

```bash
# Run the complete pipeline
sudo python3 -u module1-interceptor/sniff_bcc.py | \
  python3 -u module2-parser/parser.py | \
  sudo python3 -u module3-policy/engine.py | \
  sudo python3 -u module4-semantic/inspector.py
```

Send requests and verify:
- ✅ SSL traffic is captured
- ✅ JSON-RPC is extracted
- ✅ Policy decisions are made
- ✅ Threats are detected

### 3. Performance Test

```bash
# In one terminal: start pipeline
sudo python3 -u module1-interceptor/sniff_bcc.py | \
  python3 -u module2-parser/parser.py | \
  sudo python3 -u module3-policy/engine.py | \
  sudo python3 -u module4-semantic/inspector.py

# In another: stress test
cd ~/mcp-tls-guard
python3 stress_test.py
```

Monitor:
- CPU usage: `top`
- Memory: `free -h`
- Dropped events: Check stderr

## Security Considerations

### Running as Root

eBPF requires root privileges. To minimize risk:

1. **Use capabilities instead of root**:
```bash
sudo setcap cap_sys_admin,cap_net_admin,cap_bpf+ep $(which python3)
# Now can run without sudo (on newer kernels with cap_bpf)
```

2. **Run in a container**:
```bash
docker run --privileged --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  your-image python3 sniff_bcc.py
```

3. **Use systemd service with limited permissions**:
```ini
[Service]
User=root
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN
NoNewPrivileges=true
```

### Filtering Sensitive Data

Modify `sniff_bcc.py` to filter sensitive data:

```python
def parse_ssl_data(cpu, data, size):
    event = ct.cast(data, ct.POINTER(SSLData)).contents
    text_data = event.buf[:event.len].decode('utf-8', errors='ignore')
    
    # Filter out sensitive patterns
    if 'password' in text_data.lower():
        text_data = '[REDACTED: contains password]'
    
    if 'Authorization: Bearer' in text_data:
        # Redact token
        text_data = re.sub(r'Bearer\s+\S+', 'Bearer [REDACTED]', text_data)
    
    # ... rest of processing
```

## Performance Tuning

### 1. Adjust Buffer Sizes

In `sniff_bcc.py`:
```python
# Increase buffer size for high traffic
#define MAX_BUF_SIZE 8192  # Default: 4096
```

### 2. Filter at Kernel Level

Add filtering in eBPF program:
```c
// Only capture specific ports
if (data.fd != target_fd) {
    return 0;  // Skip
}

// Only capture specific processes
char target[] = "python3";
if (bpf_strcmp(data.comm, target) != 0) {
    return 0;
}
```

### 3. Use Ring Buffer (Kernel 5.8+)

For newer kernels, use ring buffer instead of perf buffer:
```python
# In BPF program
BPF_RINGBUF_OUTPUT(ssl_events, 1 << 24);  # 16MB buffer

# In Python
b["ssl_events"].open_ring_buffer(parse_ssl_data)
while True:
    b.ring_buffer_poll()
```

## Common Issues

### Issue: No events captured

**Possible causes**:
1. Wrong libssl path
2. No SSL traffic
3. Process not using libssl
4. eBPF program not attached

**Debug**:
```bash
# Check if uprobe attached
sudo cat /sys/kernel/debug/tracing/uprobe_events

# Monitor eBPF events
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Check which processes use libssl
lsof | grep libssl
```

### Issue: "libbpf: failed to load object"

**Solution**:
```bash
# Update to latest BCC
sudo apt update
sudo apt install --reinstall bpfcc-tools python3-bpfcc

# Or build from source
git clone https://github.com/iovisor/bcc.git
cd bcc
mkdir build && cd build
cmake ..
make
sudo make install
```

### Issue: High CPU usage

**Solutions**:
1. Add kernel-level filtering
2. Reduce buffer size
3. Increase perf buffer pages
4. Use sampling instead of tracing all events

```python
# Add to sniff_bcc.py
b.perf_buffer_poll(timeout=100)  # Poll less frequently
```

## Migration Checklist

- [ ] Install BCC on Linux system
- [ ] Test `sniff_bcc.py` captures SSL traffic
- [ ] Update `run_all.sh` to use new script
- [ ] Test full pipeline end-to-end
- [ ] Performance test with stress_test.py
- [ ] Add service for auto-start
- [ ] Document any custom modifications
- [ ] Update README with Linux-specific instructions

## Next Steps

1. **Choose your approach** (recommend: Option 1 - BCC Python)
2. **Set up Linux environment** (VM or native)
3. **Install dependencies**
4. **Test eBPF capture**
5. **Integrate with pipeline**
6. **Performance testing**
7. **Production deployment**

## Resources

- BCC Documentation: https://github.com/iovisor/bcc
- eBPF Tutorial: https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md
- Linux eBPF: https://ebpf.io/
- Kernel Requirements: https://github.com/iovisor/bcc/blob/master/INSTALL.md

## Support

For eBPF-specific issues:
1. Check BCC GitHub issues
2. Review kernel compatibility
3. Test with simple BCC examples first
4. Verify permissions and capabilities
