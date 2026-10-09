#!/bin/bash
# Full Pipeline Integration Test
# Tests eBPF → Parser → Policy Engine → Semantic Inspector → Audit Logger

set -e

echo "=========================================="
echo "  TrueIntent Full Pipeline Test"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_KEY="qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE"
SERVER_URL="https://127.0.0.1:8443/mcp"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

echo -e "${YELLOW}[INFO]${NC} Project root: $PROJECT_ROOT"
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}[ERROR]${NC} This test must run on Linux (eBPF requirement)"
    exit 1
fi

# Check privileges and choose sniffer mode
if [ "$EUID" -eq 0 ]; then 
    SNIFFER_CMD="python3 -u module1-interceptor/sniff_bcc_simple.py"
    echo -e "${GREEN}✓${NC} Root privilege active: using kernel eBPF uprobe sniffer"
else
    SNIFFER_CMD="python3 -u module1-interceptor/sniff.py"
    echo -e "${YELLOW}[INFO]${NC} Running as standard user: using TLS stream sniffer (run with sudo for kernel eBPF)"
fi

echo -e "${GREEN}[STEP 1]${NC} Checking dependencies..."

# Check for BCC
if ! python3 -c "import bcc" 2>/dev/null; then
    echo -e "${RED}[ERROR]${NC} BCC not installed. Run: sudo apt install python3-bpfcc"
    exit 1
fi
echo -e "${GREEN}✓${NC} BCC installed"

# Check for libssl
LIBSSL_PATH=$(ldconfig -p | grep libssl.so | awk '{print $NF}' | head -n1)
if [ -z "$LIBSSL_PATH" ]; then
    echo -e "${RED}[ERROR]${NC} libssl not found"
    exit 1
fi
echo -e "${GREEN}✓${NC} libssl found: $LIBSSL_PATH"

echo ""
echo -e "${GREEN}[STEP 2]${NC} Starting MCP server..."

# Start server in background
cd "$PROJECT_ROOT/demo-ips"
python3 server.py > /tmp/server.log 2>&1 &
SERVER_PID=$!
echo -e "${GREEN}✓${NC} Server started (PID: $SERVER_PID)"

# Wait for server to be ready
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}[ERROR]${NC} Server failed to start. Check /tmp/server.log"
    cat /tmp/server.log
    exit 1
fi

echo ""
echo -e "${GREEN}[STEP 3]${NC} Starting eBPF interceptor pipeline..."

# Start the full pipeline
cd "$PROJECT_ROOT"
$SNIFFER_CMD 2>/dev/null | \
  python3 -u module2-parser/parser.py 2>/dev/null | \
  python3 -u module3-policy/engine.py 2>/dev/null | \
  python3 -u module4-semantic/inspector.py > /tmp/pipeline.log 2>&1 &
PIPELINE_PID=$!
echo -e "${GREEN}✓${NC} Pipeline started (PID: $PIPELINE_PID)"

# Wait for pipeline to initialize
sleep 3

echo ""
echo -e "${GREEN}[STEP 4]${NC} Running test cases..."
echo ""

# Test counter
PASSED=0
FAILED=0

# Test 1: Benign request
echo -e "${YELLOW}[TEST 1]${NC} Benign request (ping tool)..."
RESPONSE=$(curl -sk -w "\n%{http_code}" -X POST "$SERVER_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -q "success"; then
    echo -e "${GREEN}✓ PASSED${NC} - Request allowed (200 OK)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ FAILED${NC} - Expected 200, got $HTTP_CODE"
    echo "Response: $BODY"
    FAILED=$((FAILED + 1))
fi

sleep 1

# Test 2: Command injection attempt
echo -e "${YELLOW}[TEST 2]${NC} Command injection (rm -rf)..."
RESPONSE=$(curl -sk -w "\n%{http_code}" -X POST "$SERVER_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"sudo rm -rf /"}}}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "403" ] || echo "$BODY" | grep -qi "blocked\|denied\|forbidden"; then
    echo -e "${GREEN}✓ PASSED${NC} - Malicious request blocked"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ FAILED${NC} - Malicious request NOT blocked (got $HTTP_CODE)"
    echo "Response: $BODY"
    FAILED=$((FAILED + 1))
fi

sleep 1

# Test 3: Path traversal attempt
echo -e "${YELLOW}[TEST 3]${NC} Path traversal (../../../etc/passwd)..."
RESPONSE=$(curl -sk -w "\n%{http_code}" -X POST "$SERVER_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"../../../etc/passwd"}}}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "403" ] || echo "$BODY" | grep -qi "blocked\|denied\|forbidden"; then
    echo -e "${GREEN}✓ PASSED${NC} - Path traversal blocked"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ FAILED${NC} - Path traversal NOT blocked (got $HTTP_CODE)"
    echo "Response: $BODY"
    FAILED=$((FAILED + 1))
fi

sleep 1

# Test 4: Hex-encoded malicious payload
echo -e "${YELLOW}[TEST 4]${NC} Hex-encoded obfuscation..."
RESPONSE=$(curl -sk -w "\n%{http_code}" -X POST "$SERVER_URL" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"\\x72\\x6d\\x20\\x2d\\x72\\x66"}}}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "403" ] || echo "$BODY" | grep -qi "blocked\|denied\|forbidden"; then
    echo -e "${GREEN}✓ PASSED${NC} - Obfuscated payload blocked"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ FAILED${NC} - Obfuscated payload NOT blocked (got $HTTP_CODE)"
    echo "Response: $BODY"
    FAILED=$((FAILED + 1))
fi

sleep 1

# Test 5: Rate limiting
echo -e "${YELLOW}[TEST 5]${NC} Rate limiting (50 concurrent requests)..."
RATE_LIMITED=$(python3 -c "
import urllib.request, ssl, concurrent.futures
ctx = ssl._create_unverified_context()
def req(i):
    r = urllib.request.Request('$SERVER_URL', data=b'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ping\",\"arguments\":{\"host\":\"127.0.0.1\"}}}', headers={'Content-Type': 'application/json', 'X-API-Key': '$API_KEY'})
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=5) as res:
            return res.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    codes = list(ex.map(req, range(50)))

print(1 if 429 in codes else 0)
" 2>/dev/null || echo 0)

if [ "$RATE_LIMITED" = "1" ]; then
    echo -e "${GREEN}✓ PASSED${NC} - Rate limiting triggered (429 Too Many Requests)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ FAILED${NC} - Rate limiting NOT triggered"
    FAILED=$((FAILED + 1))
fi

sleep 2

# Test 6: Invalid API key
echo -e "${YELLOW}[TEST 6]${NC} Authentication (invalid API key)..."
RESPONSE=$(curl -sk -w "\n%{http_code}" -X POST "$SERVER_URL" \
  -H "X-API-Key: INVALID_KEY_12345" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo -e "${GREEN}✓ PASSED${NC} - Invalid API key rejected ($HTTP_CODE)"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ FAILED${NC} - Invalid API key NOT rejected (got $HTTP_CODE)"
    FAILED=$((FAILED + 1))
fi

echo ""
echo -e "${GREEN}[STEP 5]${NC} Checking pipeline logs..."

# Check if pipeline captured traffic
if [ -f /tmp/pipeline.log ] && [ -s /tmp/pipeline.log ]; then
    EVENTS=$(wc -l < /tmp/pipeline.log)
    echo -e "${GREEN}✓${NC} Pipeline captured $EVENTS events"
else
    echo -e "${YELLOW}⚠${NC} Pipeline log empty or not found"
fi

echo ""
echo -e "${GREEN}[STEP 6]${NC} Checking audit logs..."

# Check audit logs
cd "$PROJECT_ROOT/module3-policy"
AUDIT_DIR="$HOME/.trueintent/logs"
if [ ! -d "$AUDIT_DIR" ] && [ -n "$SUDO_USER" ]; then
    USER_HOME=$(eval echo "~$SUDO_USER")
    AUDIT_DIR="$USER_HOME/.trueintent/logs"
fi

if [ -d "$AUDIT_DIR" ]; then
    AUDIT_FILES=$(ls "$AUDIT_DIR"/*.jsonl 2>/dev/null | wc -l)
    if [ $AUDIT_FILES -gt 0 ]; then
        echo -e "${GREEN}✓${NC} Audit logs created ($AUDIT_FILES files in $AUDIT_DIR)"
        
        # Show recent events
        echo ""
        echo "Recent audit events:"
        python3 audit_logger.py recent 5 2>/dev/null || true
    else
        echo -e "${YELLOW}⚠${NC} No audit log files found in $AUDIT_DIR"
    fi
else
    echo -e "${YELLOW}⚠${NC} Audit directory not found ($AUDIT_DIR)"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}[CLEANUP]${NC} Stopping services..."

# Stop pipeline
if kill -0 $PIPELINE_PID 2>/dev/null; then
    kill $PIPELINE_PID
    echo -e "${GREEN}✓${NC} Pipeline stopped"
fi

# Stop server
if kill -0 $SERVER_PID 2>/dev/null; then
    kill $SERVER_PID
    echo -e "${GREEN}✓${NC} Server stopped"
fi

# Wait for processes to terminate
sleep 1

echo ""
echo "=========================================="
echo "           TEST RESULTS"
echo "=========================================="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Logs available at:"
    echo "  - Server: /tmp/server.log"
    echo "  - Pipeline: /tmp/pipeline.log"
    exit 1
fi
