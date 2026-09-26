
import sys

import json

import os



class PolicyAdapter:

    def __init__(self, policy_path):

        # Load the policy rules

        self.policy = {}

        if os.path.exists(policy_path):

            with open(policy_path, 'r') as f:

                self.policy = json.load(f)

        else:

            sys.stderr.write(f"Warning: Policy file {policy_path} not found. Defaulting to block-all.\n")



    def evaluate_tool_call(self, tool_name, params):

        # Default-deny fallback: if tool isn't in policy, flag it

        allowed_tools = self.policy.get("allowed_tools", {})

        if tool_name not in allowed_tools:

            return "flag", f"Tool '{tool_name}' not found in policy (default-deny)"



        rule = allowed_tools[tool_name]

        action = rule.get("action", "block")



        if action == "block":

            return "block", f"Tool '{tool_name}' is explicitly blocked by policy"

            

        # If allowed, check for parameter restrictions (e.g., allowed paths)
        if action == "allow" and "allowed_paths" in rule:
            requested_path = params.get("path", "")
            if not any(requested_path.startswith(p) for p in rule["allowed_paths"]):
                return "block", f"Path '{requested_path}' is not in allowed_paths"

        return "allow", f"Tool '{tool_name}' execution permitted"

    def process_message(self, msg):
        # We only evaluate requests that are trying to use tools
        method = msg.get("method", "")
        payload = msg.get("mcp_payload", {})
        
        # Determine if this is a tool execution request
        is_tool_call = msg.get("msg_type") == "request" and ("tool" in method.lower() or msg.get("tool_name"))
        
        if is_tool_call:
            # Extract tool name (either from schema or directly from method)
            tool_name = msg.get("tool_name") or method
            params = payload.get("params", {}).get("arguments", {})
            
            decision, reason = self.evaluate_tool_call(tool_name, params)
            
            # Attach the engine's decision output to the message
            msg["policy_decision"] = decision
            msg["policy_reason"] = reason
        else:
            # Non-tool calls pass through
            msg["policy_decision"] = "allow"
            msg["policy_reason"] = "Not a tool execution request"
            
        return msg

if __name__ == "__main__":
    # Point to the exact location of the policy file
    policy_file = os.path.expanduser("~/mcp-tls-guard/module3-policy/policy.json")
    adapter = PolicyAdapter(policy_file)
    
    # Read messages piped in from Module 2
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            msg = json.loads(line)
            evaluated_msg = adapter.process_message(msg)
            print(json.dumps(evaluated_msg))
        except json.JSONDecodeError:
            sys.stderr.write("Failed to decode JSONmessage in adapter.\n")
