#!/usr/bin/env python3
"""
Policy engine wrapper with integrated audit logging
"""

import sys
import json
import os

# Import the original engine
from engine import PolicyAdapter, SchemaValidator

# Import audit logger
from audit_logger import get_audit_logger

# Initialize audit logger
audit_logger = get_audit_logger()

if __name__ == "__main__":
    # Point to the exact location of the policy file
    policy_file = os.path.expanduser("~/mcp-tls-guard/module3-policy/policy.json")
    
    # Also try relative path
    if not os.path.exists(policy_file):
        policy_file = os.path.join(os.path.dirname(__file__), "policy.json")
    
    adapter = PolicyAdapter(policy_file)
    
    # Read messages piped in from Module 2
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            msg = json.loads(line)
            evaluated_msg = adapter.process_message(msg)
            
            # Log policy decisions for blocked/flagged requests
            decision = evaluated_msg.get("policy_decision")
            if decision in ["block", "flag"]:
                client_ip = msg.get("client_ip", "unknown")
                tool_name = msg.get("tool_name", "unknown")
                reason = evaluated_msg.get("policy_reason", "")
                
                audit_logger.log_policy_decision(
                    client_ip,
                    tool_name,
                    decision,
                    reason
                )
            
            print(json.dumps(evaluated_msg))
            
        except json.JSONDecodeError:
            sys.stderr.write("Failed to decode JSON message in adapter.\n")
