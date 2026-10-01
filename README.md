# TrueIntent: eBPF-Driven MCP Inspection & Security Firewall

Zero-Instrumentation, Kernel-Level Intrusion Detection and Policy Enforcement for the Model Context Protocol (MCP) over Encrypted TLS.

## 1. Overview & Problem Statement

Autonomous AI agents increasingly leverage the Model Context Protocol (MCP) to interact with tools, execute system commands, read files, and access remote services over encrypted HTTPS/TLS connections. 

However, existing security solutions (such as in-process SDK proxies or local validators like Meta's mcpguard-dynamic) have major operational limitations:
* **Intrusive Instrumentation:** They require altering client or server application code to insert proxy layers.
* **TLS Blind Spot:** Traditional network firewalls cannot inspect the payload because JSON-RPC payloads are encapsulated within end-to-end encrypted TLS tunnels.
* **Fragility & Bypass:** In-process proxies can be disabled or bypassed if the agent process is compromised or if an attacker invokes tools outside the managed SDK.

TrueIntent solves this challenge by operating at the Linux kernel boundary using eBPF (Extended Berkeley Packet Filter). By attaching uprobes directly to user-space cryptographic libraries (`libssl.so`), TrueIntent extracts plaintext MCP messages directly before encryption / after decryption, reassembles fragmented network streams, and subjects every tool invocation to capability access control and semantic security inspection—with zero modifications to the AI agent or the MCP server.

```text
┌────────────────────────────────────────────────────────┐
│                   Linux User Space                     │
│                                                        │
│  [ AI Agent / Client ] ────(HTTPS / TLS)────► [ MCP Server ]
│          │                                         ▲   │
│     libssl.so                                      │   │
│    (SSL_write)                                     │   │
└──────────┼─────────────────────────────────────────┼───┘
           │ (uprobe hook)                           │
┌──────────▼─────────────────────────────────────────┼───┐
│                  Linux Kernel (eBPF)               │   │
│                                                    │   │
│  [ Module 1: eBPF Interceptor (sslsniff / BCC) ]   │   │
└──────────┼─────────────────────────────────────────┼───┘
           │ Streamed Events ({conn_id, dir, data})  │
┌──────────▼─────────────────────────────────────────┼───┐
│              TrueIntent Analysis Engine            │   │
│                                                    │   │
│  [ Module 2: Stream Parser (Reassembly & JSON) ]   │   │
│          │ Clean JSON-RPC Objects                  │   │
│  [ Module 3: Capability Policy Engine ]            │   │
│          │ Allowed Calls                           │   │
│  [ Module 4: Semantic Inspector (Meta Adapter) ]   │   │
│          │ Flag / Allow                            │   │
│  [ Active Enforcement / IDS Alerting ] ────────────┘   │
└────────────────────────────────────────────────────────┘
```

## 2. Architecture & Pipeline Breakdown
TrueIntent operates as a modular, decoupled pipeline:

* Module 1: eBPF Interceptor (module1-interceptor/)
Attaches eBPF uprobes to SSL_write and SSL_read in libssl.so.3. Captures plaintext network buffers across active connections and emits structured streaming events (conn_id, dir, data, ts_ns) without breaking TLS sessions.

* Module 2: Stream Parser (module2-parser/)
Performs stream-aware reassembly of fragmented TCP/TLS packets. Strips HTTP POST/SSE headers, extracts raw JSON-RPC 2.0 payloads, and handles split writes and batched tool calls.

* Module 3: Capability Policy Engine (module3-policy/)
Implements a strict, configurable allowlist (policy.json). Verifies whether an AI agent possesses the explicit capability to execute the target tool (default-deny routing).

* Module 4: Semantic Inspector (module4-semantic/)
A stateless adapter integrating Meta's mcpguard-dynamic ArgumentValidator. Recursively walks argument trees and evaluates command payloads against regex and shell injection rules (sudo, chmod, setcap, command chaining, subshells).

* Module 5: Baseline Integration (baseline-mcpguard/)
Maintains an isolated, untouched copy of Meta's reference implementation to ensure repeatable parity testing.

* Module 6: Adversarial Attack Suite (module6-adversarial/)
A curated corpus of red-team attack vectors targeting MCP: obfuscated injections (Base64 shells), encoding tricks (hex escapes), staged multi-turn exfiltrations, and direct violations.

* Module 7: Evaluation Harness (module7-evaluation/)
Automated benchmark runner computing Threat Coverage, Evasion/Bypass Rate, False Positive Rate (FPR), and end-to-end latency overhead.

## 3.Prerequisites & Environment Setup
System Requirements

* OS: Ubuntu 22.04 LTS or 24.04 LTS (Linux Kernel >= 5.15)

* Privileges: sudo / root access (required to load eBPF programs into the kernel)

* Runtime: Python 3.10+

Package Dependencies
Install required eBPF/BCC tools, compilers, and Python utilities:
```text
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-pip git curl
```
Verify your OpenSSL shared object path:
```text
Bash
# Verify libssl location (usually /usr/lib/x86_64-linux-gnu/libssl.so.3)
ldconfig -p | grep libssl.so
```
## 4. Step-by-Step Execution Guide

Step 1: Clone and Set Up Repository
```text
Bash
cd ~
git clone [https://github.com/](https://github.com/)<YOUR_USERNAME>/<YOUR_REPO_NAME>.git mcp-tls-guard
cd mcp-tls-guard
```
Step 2: Validate the Stream Parser (Module 2)
Ensure the streaming engine correctly reconstructs split packets, batched RPC calls, and malformed inputs:
```text
Bash
cd ~/mcp-tls-guard/module2-parser
python3 test_parser.py
```

test_01_valid_single_call (__main__.TestMCPParser) ... ok
test_02_fragmented_split_across_writes (__main__.TestMCPParser) ... ok
test_03_batched_messages_in_single_packet (__main__.TestMCPParser) ... ok
test_04_malformed_and_non_mcp_traffic (__main__.TestMCPParser) ... ok

----------------------------------------------------------------------
Ran 4 tests in 0.082s

OK
## Step 3: Run Baseline Parity Validation (Module 4)
Verify that our decoupled network adapter accurately reflects Meta's detection criteria without running their proxy:

Bash
cd ~/mcp-tls-guard/module4-semantic
python3 test_parity.py
Expected Output:
```text
Plaintext
============================================================
Module 4: Parity Test Runner with Meta argument_validator
============================================================
[PASS] Privileged Execution (sudo rm -rf /)        -> Decision: 'flag' (Expected: 'flag')
[PASS] Command Chaining Subshell (; nc)           -> Decision: 'flag' (Expected: 'flag')
[PASS] Benign Ping Tool                           -> Decision: 'clean' (Expected: 'clean')
[PASS] Benign Text Query                          -> Decision: 'clean' (Expected: 'clean')
============================================================
Summary: 4/4 passed parity checks
```

## Step 4: Run the Adversarial Attack Suite (Module 6)
Subject the semantic inspection engine to red-team evasion techniques:

Bash
cd ~/mcp-tls-guard/module6-adversarial
python3 runner.py
Expected Output:
```text
Plaintext
======================================================================
Module 6: Adversarial Attack Suite Runner
======================================================================
[A01] obfuscated_injection   | Status: CAUGHT
      Desc: Base64 encoded reverse shell to evade plain-text signature matching.
----------------------------------------------------------------------
[A02] encoding_tricks        | Status: EVADED (BYPASS)
      Desc: Hex-encoded privileged execution (sudo rm -rf /).
----------------------------------------------------------------------
[A03] staged_exfiltration_1  | Status: CAUGHT
      Desc: Step 1 of exfiltration: read sensitive file (innocuous on its own).
----------------------------------------------------------------------
[A04] staged_exfiltration_2  | Status: EVADED (BYPASS)
      Desc: Step 2 of exfiltration: send data to external IP.
----------------------------------------------------------------------
[B01] direct_violation       | Status: CAUGHT
      Desc: Direct, un-obfuscated attack to ensure the baseline is awake.
----------------------------------------------------------------------
Summary: 3 attacks caught, 2 successfully evaded the firewall.
======================================================================
```
## Step 5: Run the Benchmark Harness (Module 7)
Generate the end-to-end evaluation metrics and export results to CSV:

Bash
cd ~/mcp-tls-guard/module7-evaluation
python3 harness.py
This writes itemized latency and decision outputs to module7-evaluation/evaluation_results.csv.

## Step 6: Live Full-Pipeline eBPF Interception Demo
To run the complete system end-to-end against live encrypted traffic:

Terminal 1: Start the Local TLS MCP Server
```text
Bash
cd ~/mcp-tls-guard/module1-interceptor
python3 server.py
(Starts HTTPS server on https://127.0.0.1:8443/mcp)
```
Terminal 2: Run the TrueIntent eBPF Sniffer & Pipeline
```text
Bash
cd ~/mcp-tls-guard
sudo python3 module1-interceptor/sniff.py | \
  python3 module2-parser/parser.py | \
  python3 module3-policy/policy.py | \
  python3 module4-semantic/inspector.py
```
Terminal 3: Send Live Encrypted Requests
```text
Send Benign Request:

Bash
curl -k -X POST [https://127.0.0.1:8443/mcp](https://127.0.0.1:8443/mcp) \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{"host":"127.0.0.1"}}}'
Observed in Terminal 2: "policy_decision": "allow", "semantic_decision": "clean".
```
Send Malicious Exploit (Indirect Injection):
```text
Bash
curl -k -X POST [https://127.0.0.1:8443/mcp](https://127.0.0.1:8443/mcp) \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"sudo rm -rf /"}}}'
Observed in Terminal 2: "policy_decision": "allow", "semantic_decision": "flag", "reason": "Privileged sudo execution".
```

## 5. Directory Structure.
```text
   mcp-tls-guard/
├── .gitignore
├── BASELINE_VERSION.md               # Commit hash & provenance of Meta baseline
├── module1-interceptor/              # eBPF Kernel Interception
│   ├── sniff.py                      # BCC uprobe loader for libssl
│   ├── server.py                     # TLS-enabled mock MCP server
│   └── cert.pem / key.pem            # Self-signed TLS test certificates
├── module2-parser/                   # Stream Reassembly & Parsing
│   ├── parser.py                     # Stream-aware JSON-RPC parser
│   └── test_parser.py                # Unit tests for reassembly & edge cases
├── module3-policy/                   # Capability Policy
│   ├── policy.py                     # Capability allowlist enforcement
│   └── policy.json                   # Capability configuration
├── module4-semantic/                 # Semantic Inspection (Meta Adapter)
│   ├── inspector.py                  # Stream adapter wrapping ArgumentValidator
│   ├── test_parity.py                # Parity test suite against Meta rules
│   └── proxy/                        # Extracted Meta MCPGuard validator modules
├── baseline-mcpguard/                # Pristine baseline reference code
├── module6-adversarial/              # Attack Corpus & Evasion Suite
│   ├── attack_corpus.json            # Red-team attack vectors
│   └── runner.py                     # Adversarial evaluation runner
└── module7-evaluation/               # Empirical Evaluation
    ├── benign_corpus.json            # Benign baseline payload set
    ├── harness.py                    # Metric calculation script
    └── evaluation_results.csv        # Detailed benchmarking log
```
## 6. Security Model & Defensive Posture
* Zero Client/Server Footprint: TrueIntent does not link against, modify, or inject into AI model runtimes or MCP server binaries.

* Side-Channel Independence: Because inspection occurs at the socket and library boundary via kernel probes, evasion by altering HTTP client headers or TLS cipher suites is prevented.

* Defense-in-Depth:

  * Layer 1 (Module 3): Instant rejection of unapproved tool capabilities.

  * Layer 2 (Module 4): Deep semantic analysis on parameters for approved tools.

  * Layer 3 (Enforcement): Real-time auditing (IDS mode) with direct process/socket termination capability (IPS mode).
