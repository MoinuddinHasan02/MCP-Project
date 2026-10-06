import sys
import re
import base64
import urllib.parse

class PayloadDeobfuscator:
    def __init__(self):
        self.hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2})+')
        self.b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

    def analyze(self, raw_payload, depth=0):
        if depth > 5:  
            return raw_payload
            
        current_payload = raw_payload

        if self.hex_pattern.search(current_payload):
            def replace_hex(match):
                raw_bytes = match.group(0).replace('\\x', '')
                try:
                    return bytes.fromhex(raw_bytes).decode('utf-8', errors='ignore')
                except ValueError:
                    return match.group(0)
            current_payload = self.hex_pattern.sub(replace_hex, current_payload)

        if '%' in current_payload:
            current_payload = urllib.parse.unquote(current_payload)

        for b64_match in self.b64_pattern.findall(current_payload):
            try:
                padded = b64_match + "=" * ((4 - len(b64_match) % 4) % 4)
                decoded = base64.b64decode(padded).decode('utf-8')
                if any(c in decoded for c in ['-', '/', ' ', '\\', '$', '|', '>']):
                     current_payload = current_payload.replace(b64_match, decoded)
            except Exception:
                pass

        if current_payload != raw_payload:
            return self.analyze(current_payload, depth + 1)
            
        return current_payload

if __name__ == "__main__":
    import json
    
    sys.stderr.write("[Parser] Stream parser initialized\n")
    sys.stderr.write("[Parser] Waiting for eBPF output...\n")
    sys.stderr.flush()
    
    deobfuscator = PayloadDeobfuscator()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        # Try to parse as JSON (from eBPF interceptor)
        try:
            ev = json.loads(line)
            
            # Extract the data field
            data = ev.get("data", "")
            
            # Look for MCP JSON-RPC payloads in the data
            # Typical pattern: POST /mcp HTTP/1.1\r\n...headers...\r\n\r\n{JSON}
            json_start = data.find('{"jsonrpc')
            if json_start != -1:
                json_data = data[json_start:]
                # Find end of JSON (look for closing brace)
                brace_count = 0
                json_end = -1
                for i, char in enumerate(json_data):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
                
                if json_end != -1:
                    mcp_payload = json_data[:json_end]
                    try:
                        mcp_json = json.loads(mcp_payload)
                        
                        # Deobfuscate arguments if present
                        if "params" in mcp_json and "arguments" in mcp_json["params"]:
                            args = mcp_json["params"]["arguments"]
                            for key, value in args.items():
                                if isinstance(value, str):
                                    args[key] = deobfuscator.analyze(value)
                        
                        # Output parsed message with MCP payload
                        output = {
                            "pid": ev.get("pid"),
                            "comm": ev.get("comm"),
                            "mcp_payload": mcp_json,
                            "client_ip": "127.0.0.1"  # Extract from data if needed
                        }
                        print(json.dumps(output))
                        sys.stdout.flush()
                        
                        sys.stderr.write(f"[Parser] Extracted MCP call: {mcp_json.get('method', 'unknown')}\n")
                        sys.stderr.flush()
                    except json.JSONDecodeError:
                        sys.stderr.write(f"[Parser] Invalid JSON in payload\n")
                        sys.stderr.flush()
        except json.JSONDecodeError:
            # Not JSON from eBPF, skip
            sys.stderr.write(f"[Parser] Skipping non-JSON line\n")
            sys.stderr.flush()
            continue
