#!/bin/bash
#
# eBPF Setup Script for TrueIntent
# Installs dependencies and tests eBPF functionality
#

set -e

echo "=================================="
echo "TrueIntent eBPF Setup Script"
echo "=================================="
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ Error: This script must run on Linux"
    echo "   eBPF is not supported on $OSTYPE"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: Please run as root (use sudo)"
    exit 1
fi

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)

echo "→ Checking kernel version..."
if [ "$KERNEL_VERSION" -lt 4 ] || ([ "$KERNEL_VERSION" -eq 4 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
    echo "❌ Error: Kernel version too old (need >= 4.4)"
    echo "   Current: $(uname -r)"
    exit 1
fi
echo "✓ Kernel version OK: $(uname -r)"

# Install BCC
echo ""
echo "→ Installing BCC (BPF Compiler Collection)..."
apt update
apt install -y bpfcc-tools python3-bpfcc

# Install kernel headers
echo ""
echo "→ Installing kernel headers..."
apt install -y linux-headers-$(uname -r)

# Install build tools
echo ""
echo "→ Installing build tools..."
apt install -y clang llvm libelf-dev gcc make

# Install OpenSSL dev
echo ""
echo "→ Installing OpenSSL development files..."
apt install -y libssl-dev

# Verify BCC installation
echo ""
echo "→ Verifying BCC installation..."
if python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "✓ BCC Python module loaded successfully"
else
    echo "❌ Error: Failed to load BCC Python module"
    exit 1
fi

# Find libssl
echo ""
echo "→ Locating libssl..."
LIBSSL_PATH=$(ldconfig -p | grep libssl.so | head -1 | awk '{print $NF}')
if [ -z "$LIBSSL_PATH" ]; then
    echo "❌ Error: Could not find libssl.so"
    exit 1
fi
echo "✓ Found libssl at: $LIBSSL_PATH"

# Test eBPF capability
echo ""
echo "→ Testing eBPF capability..."
cat > /tmp/test_ebpf.py << 'EOF'
from bcc import BPF
try:
    b = BPF(text='int hello(void *ctx) { return 0; }')
    print("✓ eBPF program compiled successfully")
except Exception as e:
    print(f"❌ eBPF test failed: {e}")
    exit(1)
EOF

python3 /tmp/test_ebpf.py
rm /tmp/test_ebpf.py

# Make scripts executable
echo ""
echo "→ Making scripts executable..."
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
chmod +x "$SCRIPT_DIR/sniff_bcc.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/sniff_wrapper.py" 2>/dev/null || true
echo "✓ Scripts are executable"

# Summary
echo ""
echo "=================================="
echo "✓ Setup Complete!"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Test eBPF capture:"
echo "   sudo python3 sniff_bcc.py"
echo ""
echo "2. Start MCP server in another terminal:"
echo "   cd ../demo-ips && python3 server.py"
echo ""
echo "3. Send test request:"
echo "   curl -k -X POST https://127.0.0.1:8443/mcp \\"
echo "     -H 'X-API-Key: YOUR_KEY' \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ping\",\"arguments\":{\"host\":\"127.0.0.1\"}}}'"
echo ""
echo "4. Run full pipeline:"
echo "   cd .. && bash run_all.sh"
echo ""
