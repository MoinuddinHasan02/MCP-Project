import sys
import json
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from proxy import argument_validator
except ImportError as e:
    sys.stderr.write(f"Error loading Meta's dependencies: {e}\n")
    sys.exit(1)

class MetaSemanticAdapter:
    def __init__(self):
        self.fake_policy_engine = MagicMock()
        self.validator = argument_validator.ArgumentValidator(self.fake_policy_engine)

    def _extract_strings(self, obj):
        """Recursively yields all string values from arguments."""
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from self._extract_strings(v)
        elif isinstance(obj, list):
            for item in obj:
                yield from self._extract_strings(item)

    def inspect(self, tool_name, arguments):
        try:
            # Check all argument values using Meta's injection scanner
            for val in self._extract_strings(arguments):
                result = self.validator.check_injection(val)
                if isinstance(result, dict) and result.get("action") == "DENY":
                    return "flag", f"Meta check_injection DENY: {result.get('reason')}"
            
            return "clean", "Passed Meta semantic inspection"
        except Exception as e:
            return "flag", f"Semantic inspection error: {type(e).__name__} - {str(e)}"

if __name__ == "__main__":
    adapter = MetaSemanticAdapter()
    
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            msg = json.loads(line)
            
            if msg.get("policy_decision") == "allow" and msg.get("msg_type") == "request":
                payload = msg.get("mcp_payload", {})
                tool_name = msg.get("tool_name", "")
                arguments = payload.get("params", {}).get("arguments", {})
                
                decision, reason = adapter.inspect(tool_name, arguments)
                msg["semantic_decision"] = decision
                msg["semantic_reason"] = reason
                
            elif msg.get("policy_decision") == "block":
                msg["semantic_decision"] = "skipped"
                msg["semantic_reason"] = "Execution already blocked by capability policy"
                
            print(json.dumps(msg))
            sys.stdout.flush()
            
        except json.JSONDecodeError:
            sys.stderr.write("Failed to decode JSON message in semantic adapter.\n")
