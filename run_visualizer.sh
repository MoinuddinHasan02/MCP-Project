#!/bin/bash
# ==============================================================================
# TrueIntent Live Security Flow Visualizer Launcher
# ==============================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${FRONTEND_PORT:-8080}"

echo "======================================================================"
echo "  🛡️  TrueIntent: Live AI Agent Security Flow Visualizer"
echo "======================================================================"
echo "[*] Project Directory: $PROJECT_DIR"
echo "[*] Starting Visualizer Frontend on http://127.0.0.1:$PORT..."
echo ""

cd "$PROJECT_DIR"
python3 frontend/app.py
