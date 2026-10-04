#!/bin/bash
# ==============================================================================
# TrueIntent: Comprehensive Automated Pipeline & Test Suite Runner
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}  TrueIntent: Complete System Test Suite${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""

PASSED_COUNT=0
TOTAL_COUNT=7

run_test_step() {
    local step_num="$1"
    local step_name="$2"
    local command="$3"
    
    echo -e "${YELLOW}[STEP $step_num/$TOTAL_COUNT] $step_name...${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✓ PASS: $step_name${NC}\n"
        PASSED_COUNT=$((PASSED_COUNT + 1))
    else
        echo -e "${RED}✗ FAIL: $step_name${NC}\n"
        exit 1
    fi
}

# 1. Module 2 Parser Tests
run_test_step 1 "Module 2: Stream Parser & Reassembly Unit Tests" \
    "python3 module2-parser/test_parser.py"

# 2. Module 3 Policy Validation Tests
run_test_step 2 "Module 3: Policy Engine & Schema Validation Tests" \
    "python3 module3-policy/test_validation.py"

# 3. Module 4 Parity Tests
run_test_step 3 "Module 4: Semantic Inspector Baseline Parity Tests" \
    "python3 module4-semantic/test_parity.py"

# 4. Module 4 Evasion Tests
run_test_step 4 "Module 4: Enhanced Evasion & Obfuscation Tests" \
    "python3 module4-semantic/test_evasion.py"

# 5. Module 6 Adversarial Runner
run_test_step 5 "Module 6: Adversarial Attack Suite" \
    "python3 module6-adversarial/runner.py"

# 6. Module 7 Evaluation Harness
run_test_step 6 "Module 7: Automated Evaluation Benchmark Harness" \
    "python3 module7-evaluation/harness.py"

# 7. Pipeline Dataflow Integration Test (Benign + Malicious Payloads)
run_test_step 7 "Pipeline Integration: Multi-Stage Stream Dataflow" \
    "python3 -c \"
import subprocess, json

# Test 1: Benign call must be allowed by policy and clean by inspector
benign_event = json.dumps({
    'conn_id': 101, 'dir': 'write',
    'data': 'POST /mcp HTTP/1.1\r\n\r\n{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":1,\\\"method\\\":\\\"tools/call\\\",\\\"params\\\":{\\\"name\\\":\\\"ping\\\",\\\"arguments\\\":{\\\"host\\\":\\\"127.0.0.1\\\"}}}'
}) + '\n'

p1 = subprocess.Popen(['python3', 'module2-parser/parser.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p2 = subprocess.Popen(['python3', 'module3-policy/engine.py'], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p3 = subprocess.Popen(['python3', 'module4-semantic/inspector.py'], stdin=p2.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p1.stdin.write(benign_event)
p1.stdin.close()
out3, _ = p3.communicate(timeout=5)
p1.wait(); p2.wait()

res = json.loads(out3.strip())
assert res.get('policy_decision') == 'allow', f'Expected allow, got {res.get(\\\"policy_decision\\\")}'
assert res.get('semantic_decision') == 'clean', f'Expected clean, got {res.get(\\\"semantic_decision\\\")}'
print('  [✓] Benign request passed pipeline: policy_decision=allow, semantic_decision=clean')

# Test 2: Malicious call must be allowed by policy and flagged by inspector
malicious_event = json.dumps({
    'conn_id': 102, 'dir': 'write',
    'data': 'POST /mcp HTTP/1.1\r\n\r\n{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":2,\\\"method\\\":\\\"tools/call\\\",\\\"params\\\":{\\\"name\\\":\\\"execute_command\\\",\\\"arguments\\\":{\\\"cmd\\\":\\\"sudo rm -rf /\\\"}}}'
}) + '\n'

p1 = subprocess.Popen(['python3', 'module2-parser/parser.py'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p2 = subprocess.Popen(['python3', 'module3-policy/engine.py'], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p3 = subprocess.Popen(['python3', 'module4-semantic/inspector.py'], stdin=p2.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p1.stdin.write(malicious_event)
p1.stdin.close()
out3, _ = p3.communicate(timeout=5)
p1.wait(); p2.wait()

res2 = json.loads(out3.strip())
assert res2.get('policy_decision') == 'allow', f'Expected allow, got {res2.get(\\\"policy_decision\\\")}'
assert res2.get('semantic_decision') == 'flag', f'Expected flag, got {res2.get(\\\"semantic_decision\\\")}'
print('  [✓] Malicious request caught by IPS: policy_decision=allow, semantic_decision=flag')
\""

echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}  ALL $PASSED_COUNT/$TOTAL_COUNT TEST SUITES PASSED SUCCESSFULLY!${NC}"
echo -e "${GREEN}  The TrueIntent pipeline is fully functional and complete.${NC}"
echo -e "${GREEN}======================================================================${NC}"
