#!/bin/bash
# Test script for fixed pipeline

echo "==================================="
echo "  Pipeline Fix Test"
echo "==================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[INFO]${NC} This script tests the pipeline with fixes"
echo ""

# Test 1: Check if modules exist
echo -e "${YELLOW}[TEST 1]${NC} Checking if all modules exist..."
MISSING=0

if [ ! -f module1-interceptor/sniff_bcc_simple.py ]; then
    echo -e "${RED}✗${NC} sniff_bcc_simple.py not found"
    MISSING=1
else
    echo -e "${GREEN}✓${NC} sniff_bcc_simple.py found"
fi

if [ ! -f module2-parser/parser.py ]; then
    echo -e "${RED}✗${NC} parser.py not found"
    MISSING=1
else
    echo -e "${GREEN}✓${NC} parser.py found"
fi

if [ ! -f module3-policy/engine.py ]; then
    echo -e "${RED}✗${NC} engine.py not found"
    MISSING=1
else
    echo -e "${GREEN}✓${NC} engine.py found"
fi

if [ ! -f module4-semantic/inspector.py ]; then
    echo -e "${RED}✗${NC} inspector.py not found"
    MISSING=1
else
    echo -e "${GREEN}✓${NC} inspector.py found"
fi

if [ $MISSING -eq 1 ]; then
    echo -e "${RED}[ERROR]${NC} Missing modules! Are you in the right directory?"
    exit 1
fi

echo ""
echo -e "${GREEN}[SUCCESS]${NC} All modules found"
echo ""

# Test 2: Check Python syntax
echo -e "${YELLOW}[TEST 2]${NC} Checking Python syntax..."
python3 -m py_compile module2-parser/parser.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} parser.py syntax OK"
else
    echo -e "${RED}✗${NC} parser.py has syntax errors"
fi

python3 -m py_compile module3-policy/engine.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} engine.py syntax OK"
else
    echo -e "${RED}✗${NC} engine.py has syntax errors"
fi

python3 -m py_compile module4-semantic/inspector.py 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} inspector.py syntax OK"
else
    echo -e "${RED}✗${NC} inspector.py has syntax errors"
fi

echo ""
echo "==================================="
echo ""
echo -e "${GREEN}Ready to run full pipeline!${NC}"
echo ""
echo "Run this command:"
echo ""
echo -e "${YELLOW}sudo python3 -u module1-interceptor/sniff_bcc_simple.py 2>&1 | python3 -u module2-parser/parser.py 2>&1 | python3 -u module3-policy/engine.py 2>&1 | python3 -u module4-semantic/inspector.py${NC}"
echo ""
