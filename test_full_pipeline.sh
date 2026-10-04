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

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[ERROR]${NC} Please run with sudo (eBPF requires root)"
    exit 1
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
sudo -u $SUDO_USER python3 -u module1-interceptor/sniff_bcc_simple.py 2>/dev/null | \
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
    ((PASSED++))
else
    echo -e "${RED}✗ FAILED${NC} - Expected 200, got $HTTP_CODE"
    echo "Response: $BODY"
    ((FAILED++))
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
    ((PASSED++))
else
    echo -e "${RED}✗ FAILED${NC} - Malicious request NOT blocked (got $HTTP_CODE)"
    echo "Response: $BODY"
    ((FAILED++))
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
    ((PASSED++))
else
    echo -e "${RED}✗ FAILED${NC} - Path traversal NOT blocked (got $HTTP_CODE)"
    echo "Response: $BODY"
    ((FAILED++))
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
    ((PASSED++))
else
    echo -e "${RED}✗ FAILED${NC} - Obfuscated payload NOT blocked (got $HTTP_CODE)"
    echo "Response: $BODY"
    ((FAILED++))
fi

sleep 1

# Test 5: Rate limiting
echo -e "${YELLOW}[TEST 5]${NC} Rate limiting (burst of 25 requests)..."
RATE_LIMITED=0
for i in {1..25}; do
    HTTP_CODE=$(curl -sk -w "%{http_code}" -o /dev/null -X POST "$SERVER_URL" \
      -H "X-API-Key: $API_KEY" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":'$i',"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}')
    
    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED=1
        break
    fi
done

if [ $RATE_LIMITED -eq 1 ]; then
    echo -e "${GREEN}✓ PASSED${NC} - Rate limiting triggered (429 Too Many Requests)"
    ((PASSED++))
else
    echo -e "${RED}✗ FAILED${NC} - Rate limiting NOT triggered"
    ((FAILED++))
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
    ((PASSED++))
else
    echo -e "${RED}✗ FAILED${NC} - Invalid API key NOT rejected (got $HTTP_CODE)"
    ((FAILED++))
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
if [ -d ~/.trueintent/audit ]; then
    AUDIT_FILES=$(ls ~/.trueintent/audit/*.json 2>/dev/null | wc -l)
    if [ $AUDIT_FILES -gt 0 ]; then
        echo -e "${GREEN}✓${NC} Audit logs created ($AUDIT_FILES files)"
        
        # Show recent events
        echo ""
        echo "Recent audit events:"
        python3 audit_logger.py recent 5 2>/dev/null || true
    else
        echo -e "${YELLOW}⚠${NC} No audit log files found"
    fi
else
    echo -e "${YELLOW}⚠${NC} Audit directory not found"
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
