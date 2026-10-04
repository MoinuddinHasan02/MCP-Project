import sys

import json

import os

import re

from pathlib import Path

from fnmatch import fnmatch



class SchemaValidator:

    """Validates JSON-RPC message structure and tool arguments against expected schemas"""

    

    def validate_jsonrpc_structure(self, msg):

        """Validate basic JSON-RPC 2.0 structure"""

        errors = []

        

        # Check for required JSON-RPC fields

        if not isinstance(msg, dict):

            return False, ["Message must be a JSON object"]

        

        jsonrpc_version = msg.get("jsonrpc")

        if jsonrpc_version != "2.0":

            errors.append(f"Invalid JSON-RPC version: {jsonrpc_version}, expected '2.0'")

        

        # Must have either 'method' (request) or 'result'/'error' (response)

        has_method = "method" in msg

        has_result = "result" in msg or "error" in msg

        

        if not has_method and not has_result:

            errors.append("Message must contain 'method' (request) or 'result'/'error' (response)")

        

        # Request must have 'id'

        if has_method and "id" not in msg:

            errors.append("Request message must contain 'id' field")

        

        return len(errors) == 0, errors

    

    def validate_tool_arguments(self, tool_name, arguments, arg_schema):

        """Validate tool arguments against schema from policy"""

        errors = []

        

        if not isinstance(arguments, dict):

            return False, ["Arguments must be a dictionary/object"]

        

        for arg_name, constraints in arg_schema.items():

            value = arguments.get(arg_name)

            

            # Check required arguments

            if constraints.get("required", False) and value is None:

                errors.append(f"Required argument '{arg_name}' is missing")

                continue

            

            if value is None:

                continue  # Optional argument not provided

            

            # Validate type

            expected_type = constraints.get("type")

            if expected_type:

                if expected_type == "string" and not isinstance(value, str):

                    errors.append(f"Argument '{arg_name}' must be a string, got {type(value).__name__}")

                elif expected_type == "number" and not isinstance(value, (int, float)):

                    errors.append(f"Argument '{arg_name}' must be a number, got {type(value).__name__}")

                elif expected_type == "boolean" and not isinstance(value, bool):

                    errors.append(f"Argument '{arg_name}' must be a boolean, got {type(value).__name__}")

                elif expected_type == "array" and not isinstance(value, list):

                    errors.append(f"Argument '{arg_name}' must be an array, got {type(value).__name__}")

            

            # Validate string constraints

            if isinstance(value, str):

                if "max_length" in constraints and len(value) > constraints["max_length"]:

                    errors.append(f"Argument '{arg_name}' exceeds max length {constraints['max_length']}")

                

                if "pattern" in constraints:

                    pattern = constraints["pattern"]

                    if not re.match(pattern, value):

                        errors.append(f"Argument '{arg_name}' does not match required pattern: {pattern}")

            

            # Validate numeric constraints

            if isinstance(value, (int, float)):

                if "min" in constraints and value < constraints["min"]:

                    errors.append(f"Argument '{arg_name}' is below minimum value {constraints['min']}")

                

                if "max" in constraints and value > constraints["max"]:

                    errors.append(f"Argument '{arg_name}' exceeds maximum value {constraints['max']}")

        

        return len(errors) == 0, errors



class PolicyAdapter:

    def __init__(self, policy_path):

        # Load the policy rules

        self.policy = {}

        self.validator = SchemaValidator()

        

        if os.path.exists(policy_path):

            with open(policy_path, 'r') as f:

                self.policy = json.load(f)

        else:

            sys.stderr.write(f"Warning: Policy file {policy_path} not found. Defaulting to block-all.\n")

    

    def canonicalize_path(self, path):

        """

        Resolve path to canonical form to prevent traversal attacks.

        Resolves symlinks and removes '..' components.

        """

        try:

            # Expand user home directory

            expanded = os.path.expanduser(path)

            # Get absolute path

            absolute = os.path.abspath(expanded)

            # Resolve symlinks and normalize

            canonical = os.path.realpath(absolute)

            return canonical

        except Exception as e:

            sys.stderr.write(f"Warning: Could not canonicalize path '{path}': {e}\n")

            return path  # Return original on error

    

    def check_path_allowed(self, requested_path, allowed_patterns, forbidden_patterns=None):

        """

        Check if a path is allowed based on patterns.

        Uses glob-style patterns and checks canonical paths.

        """

        canonical_path = self.canonicalize_path(requested_path)

        

        # First check forbidden paths (blacklist takes precedence)

        if forbidden_patterns:

            for forbidden_pattern in forbidden_patterns:

                if fnmatch(canonical_path, forbidden_pattern):

                    return False, f"Path matches forbidden pattern: {forbidden_pattern}"

        

        # Then check allowed paths (whitelist)

        for allowed_pattern in allowed_patterns:

            # Convert glob pattern to regex for better matching

            if fnmatch(canonical_path, allowed_pattern):

                return True, "Path allowed"

        

        return False, f"Path not in allowed patterns"



    def evaluate_tool_call(self, tool_name, params):

        # Default-deny fallback: if tool isn't in policy, flag it

        allowed_tools = self.policy.get("allowed_tools", {})

        if tool_name not in allowed_tools:

            return "flag", f"Tool '{tool_name}' not found in policy (default-deny)"



        rule = allowed_tools[tool_name]

        action = rule.get("action", "block")



        if action == "block":

            return "block", f"Tool '{tool_name}' is explicitly blocked by policy"

        

        # Validate arguments against schema if provided

        if "allowed_arguments" in rule:

            valid, errors = self.validator.validate_tool_arguments(

                tool_name, 

                params, 

                rule["allowed_arguments"]

            )

            if not valid:

                return "block", f"Argument validation failed: {'; '.join(errors)}"

        

        # If allowed, check for path restrictions

        if action == "allow":

            # Check path-based restrictions

            if "allowed_paths" in rule:

                requested_path = params.get("path", "")

                if requested_path:

                    forbidden_paths = rule.get("forbidden_paths", [])

                    allowed, reason = self.check_path_allowed(

                        requested_path, 

                        rule["allowed_paths"],

                        forbidden_paths

                    )

                    if not allowed:

                        return "block", reason

            

            # Check file size limits

            if "max_file_size" in rule:

                file_size = params.get("size", 0)

                if file_size > rule["max_file_size"]:

                    return "block", f"File size {file_size} exceeds limit {rule['max_file_size']}"

        

        return "allow", f"Tool '{tool_name}' execution permitted"

    def process_message(self, msg):
        # Identify the JSON-RPC payload: could be inside msg["mcp_payload"] or msg itself
        payload = msg.get("mcp_payload") if (isinstance(msg, dict) and isinstance(msg.get("mcp_payload"), dict)) else msg

        # Validate JSON-RPC structure of the payload
        valid_structure, structure_errors = self.validator.validate_jsonrpc_structure(payload)
        if not valid_structure:
            msg["policy_decision"] = "block"
            msg["policy_reason"] = f"Invalid message structure: {'; '.join(structure_errors)}"
            msg["validation_errors"] = structure_errors
            return msg

        # We only evaluate requests that are trying to use tools
        method = payload.get("method") or msg.get("method", "")
        tool_name = msg.get("tool_name") or (payload.get("params", {}).get("name") if isinstance(payload.get("params"), dict) else "") or method

        msg_type = msg.get("msg_type")
        if not msg_type:
            if "method" in payload and "id" in payload:
                msg_type = "request"
            elif "method" in payload:
                msg_type = "notification"
            else:
                msg_type = "response"

        # Determine if this is a tool execution request
        is_tool_call = (msg_type == "request") and ("tool" in method.lower() or bool(tool_name))

        if is_tool_call:
            params = payload.get("params", {}).get("arguments", {}) if isinstance(payload.get("params"), dict) else {}
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
    # Determine policy file location (try multiple paths)
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "policy.json"),  # Same directory as engine.py
        os.path.join(os.path.dirname(__file__), "policies", "defaults", "shell_server.json"),
        os.path.expanduser("~/try/module3-policy/policy.json"),
        os.path.expanduser("~/mcp-tls-guard/module3-policy/policy.json"),
    ]
    
    policy_file = None
    for path in possible_paths:
        if os.path.exists(path):
            policy_file = path
            sys.stderr.write(f"[Policy] Using policy file: {policy_file}\n")
            sys.stderr.flush()
            break
    
    if not policy_file:
        sys.stderr.write("[Policy] WARNING: No policy file found, using default-deny\n")
        sys.stderr.flush()
        policy_file = possible_paths[0]  # Use default even if doesn't exist
    
    adapter = PolicyAdapter(policy_file)
    
    sys.stderr.write("[Policy] Policy engine initialized\n")
    sys.stderr.write("[Policy] Waiting for parser output...\n")
    sys.stderr.flush()
    
    # Read messages piped in from Module 2
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        # Skip non-JSON lines (debug output from parser)
        if not line.startswith('{'):
            continue
            
        try:
            msg = json.loads(line)
            evaluated_msg = adapter.process_message(msg)
            print(json.dumps(evaluated_msg))
            sys.stdout.flush()  # Ensure output is sent immediately
        except json.JSONDecodeError as e:
            sys.stderr.write(f"[Policy] Failed to decode JSON: {e}\n")
            sys.stderr.flush()