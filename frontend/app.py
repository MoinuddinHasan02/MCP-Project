#!/usr/bin/env python3
"""
TrueIntent: Interactive Security Flow Visualizer & Frontend Server
===================================================================
A modern, standalone frontend that visualizes in real-time how AI agent
prompts, LLM-generated MCP tool calls, and security payloads travel through
the TrueIntent 4-layer eBPF/TLS inspection pipeline.
"""

import os
import sys
import json
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Add project root and modules to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'module3-policy'))
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'module4-semantic'))

try:
    import grok_agent
    from inspector import ThreatDetector, AdvancedDeobfuscator, notify_server_block
    from engine import PolicyAdapter
except ImportError as e:
    print(f"[ERROR] Failed to import core TrueIntent modules: {e}")
    sys.exit(1)

PORT = int(os.environ.get("FRONTEND_PORT", 8080))
MCP_SERVER_URL = "https://127.0.0.1:8443/mcp"
IPS_CONTROL_URL = "http://127.0.0.1:8444/ips-control"
MCP_API_KEY = "qucHMIbXHvj5JiVjPYSpkotBtDJeOe9e5OzreZPfrZE"

# SSL Context for local self-signed MCP server
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

detector = ThreatDetector()
deobfuscator = AdvancedDeobfuscator()
policy_adapter = PolicyAdapter(os.path.join(PROJECT_ROOT, 'module3-policy', 'policy.json'))


def check_service_status():
    """Checks reachability of the local MCP server, IPS control, and Grok config."""
    status = {
        "mcp_server": False,
        "ips_control": False,
        "grok_api": bool(grok_agent.GROK_API_KEY and grok_agent.GROK_API_KEY != "your_grok_api_key_here"),
        "grok_model": grok_agent.GROK_MODEL,
        "grok_base_url": grok_agent.GROK_BASE_URL
    }

    # Test MCP server on 8443
    try:
        req = urllib.request.Request(
            f"{MCP_SERVER_URL.rsplit('/', 1)[0]}/stats",
            headers={"X-API-Key": MCP_API_KEY}
        )
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=1.5) as res:
            status["mcp_server"] = res.status in [200, 401, 404]
    except Exception:
        status["mcp_server"] = False

    # Test IPS control on 8444
    try:
        req = urllib.request.Request(IPS_CONTROL_URL)
        with urllib.request.urlopen(req, timeout=1.5) as res:
            status["ips_control"] = True
    except urllib.error.HTTPError as e:
        status["ips_control"] = True
    except Exception:
        status["ips_control"] = False

    return status


def process_agent_flow(user_prompt, emit_func):
    """
    Executes a prompt through the live Grok agent loop and emits structured
    events for every stage, turn, and security evaluation layer.
    """
    flow_id = f"flow_{int(time.time()*1000)}"
    start_time = time.time()

    emit_func({
        "type": "flow_start",
        "flow_id": flow_id,
        "prompt": user_prompt,
        "timestamp": time.time()
    })

    conversation_history = [
        {"role": "system", "content": grok_agent.SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]

    current_turn = 0
    max_turns = 4
    all_turns_summary = []
    has_any_block = False
    blocked_details = []

    while current_turn < max_turns:
        current_turn += 1
        turn_id = f"{flow_id}_turn{current_turn}"

        emit_func({
            "type": "turn_start",
            "turn": current_turn,
            "turn_id": turn_id,
            "status": "querying_llm",
            "message": f"Querying Grok LLM ({grok_agent.GROK_MODEL})..."
        })

        # 1. Call Grok LLM
        t0 = time.time()
        try:
            response = grok_agent.call_grok_api(conversation_history)
            llm_duration = round((time.time() - t0) * 1000, 2)
        except Exception as e:
            emit_func({
                "type": "error",
                "message": f"Failed calling Grok API: {str(e)}",
                "turn": current_turn
            })
            return

        choice = response.get("choices", [{}])[0]
        message = choice.get("message", {})
        conversation_history.append(message)

        tool_calls = message.get("tool_calls", [])

        # If model returned pure text response without tools
        if not tool_calls:
            assistant_content = message.get("content", "")
            emit_func({
                "type": "final_text",
                "turn": current_turn,
                "text": assistant_content,
                "duration_ms": llm_duration
            })
            break

        # Process each tool call requested by the model
        for tool_call in tool_calls:
            call_id = tool_call.get("id", f"call_{int(time.time()*1000)}")
            fn = tool_call.get("function", {})
            tool_name = fn.get("name", "unknown")
            try:
                tool_args = json.loads(fn.get("arguments", "{}"))
            except Exception:
                tool_args = {}

            req_id = int(time.time() * 1000) % 1000000

            emit_func({
                "type": "tool_requested",
                "turn": current_turn,
                "call_id": call_id,
                "req_id": req_id,
                "tool_name": tool_name,
                "arguments": tool_args,
                "user_intent": user_prompt,
                "duration_ms": llm_duration
            })

            # =================================================================
            # LAYER 1: POLICY & CAPABILITY CHECK
            # =================================================================
            t_l1 = time.time()
            pol_action, pol_reason = policy_adapter.evaluate_tool_call(tool_name, tool_args)
            l1_duration = round((time.time() - t_l1) * 1000, 2)
            l1_passed = (pol_action != "block")

            emit_func({
                "type": "layer_eval",
                "layer": 1,
                "layer_name": "Policy & Capability Engine",
                "turn": current_turn,
                "req_id": req_id,
                "tool_name": tool_name,
                "status": "PASS" if l1_passed else "BLOCKED",
                "allowed": l1_passed,
                "reason": pol_reason,
                "duration_ms": l1_duration,
                "details": {"action": pol_action, "policy_reason": pol_reason}
            })

            # =================================================================
            # LAYER 2: DE-OBFUSCATION ENGINE
            # =================================================================
            t_l2 = time.time()
            deobf_args = {}
            has_obf = False
            for k, v in tool_args.items():
                if isinstance(v, str):
                    deobf_v = deobfuscator.deobfuscate(v)
                    deobf_args[k] = deobf_v
                    if deobf_v != v:
                        has_obf = True
            l2_duration = round((time.time() - t_l2) * 1000, 2)

            emit_func({
                "type": "layer_eval",
                "layer": 2,
                "layer_name": "De-obfuscation Engine",
                "turn": current_turn,
                "req_id": req_id,
                "tool_name": tool_name,
                "status": "UNMASKED" if has_obf else "CLEAN",
                "obfuscation_detected": has_obf,
                "duration_ms": l2_duration,
                "details": {
                    "has_obfuscation": has_obf,
                    "unmasked_arguments": deobf_args if has_obf else tool_args
                }
            })

            # =================================================================
            # LAYER 3: SEMANTIC THREAT INSPECTOR
            # =================================================================
            t_l3 = time.time()
            sem_decision, sem_reason, sem_details = detector.check_arguments(tool_args)
            l3_duration = round((time.time() - t_l3) * 1000, 2)
            l3_passed = (sem_decision != "flag")

            emit_func({
                "type": "layer_eval",
                "layer": 3,
                "layer_name": "Semantic Threat Inspector",
                "turn": current_turn,
                "req_id": req_id,
                "tool_name": tool_name,
                "status": "CLEAN" if l3_passed else "FLAGGED",
                "allowed": l3_passed,
                "reason": sem_reason,
                "duration_ms": l3_duration,
                "details": sem_details
            })

            # Determine whether security enforcement blocks this request
            is_blocked = (not l1_passed) or (not l3_passed)

            # =================================================================
            # LAYER 4: LOCAL MCP SERVER EXECUTION & IPS ENFORCEMENT
            # =================================================================
            t_l4 = time.time()
            mcp_packet = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": tool_args}
            }

            if is_blocked:
                has_any_block = True
                block_layer = "Layer 1 (Policy Engine)" if not l1_passed else "Layer 3 (Semantic Inspector)"
                block_cause = pol_reason if not l1_passed else sem_reason
                blocked_details.append({
                    "turn": current_turn,
                    "tool": tool_name,
                    "layer": block_layer,
                    "reason": block_cause
                })

                # Dispatched out-of-band block signal to IPS control (:8444)
                notify_server_block(req_id)
                l4_duration = round((time.time() - t_l4) * 1000, 2)

                emit_func({
                    "type": "layer_eval",
                    "layer": 4,
                    "layer_name": "Local MCP Server & IPS Enforcement",
                    "turn": current_turn,
                    "req_id": req_id,
                    "tool_name": tool_name,
                    "status": "TERMINATED_403",
                    "http_status": 403,
                    "allowed": False,
                    "duration_ms": l4_duration,
                    "wire_packet": mcp_packet,
                    "response": {
                        "error": "CRITICAL: Tool call terminated by TrueIntent eBPF Firewall (HTTP 403 Forbidden).",
                        "blocked": True,
                        "blocked_by": block_layer,
                        "reason": block_cause
                    }
                })

                tool_result = {
                    "status": "error",
                    "error": f"Security Violation: Tool execution blocked by TrueIntent firewall ({block_cause})",
                    "blocked": True
                }
            else:
                # Allowed: execute on live local MCP server over TLS
                mcp_body = json.dumps(mcp_packet).encode("utf-8")
                req = urllib.request.Request(
                    MCP_SERVER_URL,
                    data=mcp_body,
                    headers={
                        "Content-Type": "application/json",
                        "X-API-Key": MCP_API_KEY
                    }
                )

                try:
                    with urllib.request.urlopen(req, context=ssl_ctx, timeout=8) as response:
                        raw_body = response.read().decode("utf-8", errors="ignore")
                        l4_duration = round((time.time() - t_l4) * 1000, 2)
                        parsed = json.loads(raw_body)
                        tool_result = parsed.get("result", {})

                        emit_func({
                            "type": "layer_eval",
                            "layer": 4,
                            "layer_name": "Local MCP Server & IPS Enforcement",
                            "turn": current_turn,
                            "req_id": req_id,
                            "tool_name": tool_name,
                            "status": "EXECUTED_200",
                            "http_status": 200,
                            "allowed": True,
                            "duration_ms": l4_duration,
                            "wire_packet": mcp_packet,
                            "response": parsed
                        })
                except urllib.error.HTTPError as e:
                    raw_err = e.read().decode("utf-8", errors="ignore") if e.fp else ""
                    l4_duration = round((time.time() - t_l4) * 1000, 2)
                    is_403 = (e.code == 403)
                    if is_403:
                        has_any_block = True
                    emit_func({
                        "type": "layer_eval",
                        "layer": 4,
                        "layer_name": "Local MCP Server & IPS Enforcement",
                        "turn": current_turn,
                        "req_id": req_id,
                        "tool_name": tool_name,
                        "status": "TERMINATED_403" if is_403 else f"ERROR_{e.code}",
                        "http_status": e.code,
                        "allowed": not is_403,
                        "duration_ms": l4_duration,
                        "wire_packet": mcp_packet,
                        "response": {"error": f"HTTP {e.code}: {raw_err}"}
                    })
                    tool_result = {"error": f"HTTP {e.code}: {raw_err}", "blocked": is_403}
                except Exception as e:
                    l4_duration = round((time.time() - t_l4) * 1000, 2)
                    emit_func({
                        "type": "layer_eval",
                        "layer": 4,
                        "layer_name": "Local MCP Server & IPS Enforcement",
                        "turn": current_turn,
                        "req_id": req_id,
                        "tool_name": tool_name,
                        "status": "CONNECTION_FAILED",
                        "http_status": 0,
                        "allowed": False,
                        "duration_ms": l4_duration,
                        "wire_packet": mcp_packet,
                        "response": {"error": str(e)}
                    })
                    tool_result = {"error": str(e)}

            # Send tool execution result back to Grok conversation context
            conversation_history.append({
                "role": "tool",
                "tool_call_id": call_id,
                "name": tool_name,
                "content": json.dumps(tool_result)
            })

    total_duration = round((time.time() - start_time) * 1000, 2)

    # Extract final text message from history if any
    final_text = ""
    for msg in reversed(conversation_history):
        if msg.get("role") == "assistant" and msg.get("content"):
            final_text = msg.get("content")
            break

    emit_func({
        "type": "flow_complete",
        "flow_id": flow_id,
        "total_duration_ms": total_duration,
        "turns_completed": current_turn,
        "attack_detected": has_any_block,
        "blocked_details": blocked_details,
        "final_text": final_text
    })


class VisualizerHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Keep console output minimal and clean
        return

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/" or parsed.path == "/index.html":
            html_file = os.path.join(os.path.dirname(__file__), "index.html")
            if os.path.exists(html_file):
                with open(html_file, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()
            return

        elif parsed.path == "/api/status":
            status_data = check_service_status()
            body = json.dumps(status_data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif parsed.path == "/api/stream":
            query_params = urllib.parse.parse_qs(parsed.query)
            prompt = query_params.get("prompt", [""])[0]

            if not prompt:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Missing prompt query parameter"}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            def emit(event_dict):
                try:
                    payload = f"data: {json.dumps(event_dict)}\n\n"
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    pass

            try:
                process_agent_flow(prompt, emit)
            except Exception as e:
                emit({"type": "error", "message": str(e)})

            return

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/execute":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)

            try:
                data = json.loads(body_bytes.decode("utf-8"))
                prompt = data.get("prompt", "")
            except Exception:
                prompt = ""

            if not prompt:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON or missing prompt"}')
                return

            events_collector = []

            def emit(event_dict):
                events_collector.append(event_dict)

            try:
                process_agent_flow(prompt, emit)
                resp_body = json.dumps({"status": "success", "events": events_collector}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
            except Exception as e:
                err_resp = json.dumps({"status": "error", "error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(err_resp)
            return

        else:
            self.send_response(404)
            self.end_headers()


def run_visualizer_server():
    server_address = ("0.0.0.0", PORT)
    httpd = ThreadingHTTPServer(server_address, VisualizerHTTPHandler)
    print("\n" + "="*70)
    print("🚀 TrueIntent Security Flow Visualizer Frontend Active!")
    print("="*70)
    print(f"[*] Access the Live Visualizer at: http://127.0.0.1:{PORT}")
    print(f"[*] Target MCP Server:             {MCP_SERVER_URL}")
    print(f"[*] IPS Control Endpoint:         {IPS_CONTROL_URL}")
    print(f"[*] Grok Model Engine:             {grok_agent.GROK_MODEL}")
    print("="*70 + "\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down visualizer server...")
        httpd.server_close()


if __name__ == "__main__":
    run_visualizer_server()
