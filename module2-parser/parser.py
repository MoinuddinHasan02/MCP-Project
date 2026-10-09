import sys
import json
import re
import base64
import urllib.parse


class PayloadDeobfuscator:
    def __init__(self):
        self.hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2})+')
        self.b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

    def analyze(self, raw_payload, depth=0):
        if depth > 5 or not isinstance(raw_payload, str):
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
            try:
                current_payload = urllib.parse.unquote(current_payload)
            except Exception:
                pass

        for b64_match in self.b64_pattern.findall(current_payload):
            try:
                padded = b64_match + "=" * ((4 - len(b64_match) % 4) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if any(c in decoded for c in ['-', '/', ' ', '\\', '$', '|', '>', 'sudo', 'rm', 'sh']):
                    current_payload = current_payload.replace(b64_match, decoded)
            except Exception:
                pass

        if current_payload != raw_payload:
            return self.analyze(current_payload, depth + 1)

        return current_payload


class MCPParser:
    def __init__(self):
        # Buffers keyed by (conn_id, dir)
        self.buffers = {}
        self.decoder = json.JSONDecoder()
        self.deobfuscator = PayloadDeobfuscator()

    def process_line(self, line):
        line = line.strip()
        if not line:
            return []

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return []

        if not isinstance(event, dict):
            return []

        # If the input is already a direct JSON-RPC message (e.g. from agent logger)
        if "jsonrpc" in event and ("method" in event or "result" in event or "error" in event):
            return [self._format_message(event, {})]

        conn_id = event.get('conn_id') or event.get('fd') or event.get('pid') or 'default'
        direction = event.get('dir') or event.get('direction') or 'write'
        key = (conn_id, direction)
        data = event.get('data', '')

        if not isinstance(data, str):
            return []

        if key not in self.buffers:
            self.buffers[key] = ""

        self.buffers[key] += data
        return self.extract_messages(key, event)

    def extract_messages(self, key, event):
        messages = []
        buffer = self.buffers.get(key, "")

        while buffer:
            # Strip leading whitespace
            buffer = buffer.lstrip(' \t\n\r')

            # Identify and strip HTTP headers (POST, GET, HTTP/1.x, etc.)
            http_match = re.match(r'^(?:POST|GET|PUT|DELETE|HEAD|HTTP/1\.[01]).*?\r\n\r\n', buffer, re.DOTALL)
            if http_match:
                buffer = buffer[http_match.end():].lstrip(' \t\n\r')
                continue

            if not buffer:
                break

            # If it looks like JSON, attempt to parse it
            if buffer.startswith('{'):
                try:
                    obj, idx = self.decoder.raw_decode(buffer)
                    if isinstance(obj, dict):
                        # Deobfuscate arguments if present
                        if "params" in obj and isinstance(obj["params"], dict) and "arguments" in obj["params"]:
                            args = obj["params"]["arguments"]
                            if isinstance(args, dict):
                                for k, v in args.items():
                                    if isinstance(v, str):
                                        args[k] = self.deobfuscator.analyze(v)

                        messages.append(self._format_message(obj, event, key))
                        buffer = buffer[idx:]
                    else:
                        buffer = buffer[1:]
                except json.JSONDecodeError:
                    # Check if fixing non-standard \x hex escapes allows decoding
                    sanitized = re.sub(r'(?<!\\)\\x([0-9a-fA-F]{2})', r'\\\\x\1', buffer)
                    if sanitized != buffer:
                        try:
                            obj, idx = self.decoder.raw_decode(sanitized)
                            if isinstance(obj, dict):
                                if "params" in obj and isinstance(obj["params"], dict) and "arguments" in obj["params"]:
                                    args = obj["params"]["arguments"]
                                    if isinstance(args, dict):
                                        for k, v in args.items():
                                            if isinstance(v, str):
                                                args[k] = self.deobfuscator.analyze(v)
                                messages.append(self._format_message(obj, event, key))
                                buffer = sanitized[idx:]
                                continue
                        except json.JSONDecodeError:
                            pass
                    # Incomplete JSON message; wait for the next chunk
                    break
            else:
                # Discard characters until the next potential JSON object or HTTP request
                next_brace = buffer.find('{')
                if next_brace != -1:
                    buffer = buffer[next_brace:]
                else:
                    buffer = ""

        self.buffers[key] = buffer
        return messages

    def _format_message(self, obj, event, key=None):
        method = obj.get("method", "")
        tool_name = ""
        if isinstance(obj.get("params"), dict):
            tool_name = obj["params"].get("name", "")

        msg_type = "response"
        if "method" in obj and "id" in obj:
            msg_type = "request"
        elif "method" in obj and "id" not in obj:
            msg_type = "notification"

        conn_id = event.get("conn_id") if event.get("conn_id") is not None else (key[0] if key and key[0] != 'default' else None)
        direction = event.get("dir") or event.get("direction") or (key[1] if key else "write")

        return {
            "ts_ns": event.get("ts_ns") or event.get("timestamp_ns"),
            "conn_id": conn_id,
            "dir": direction,
            "pid": event.get("pid"),
            "comm": event.get("comm"),
            "msg_type": msg_type,
            "method": method,
            "tool_name": tool_name,
            "mcp_payload": obj,
            "client_ip": event.get("client_ip", "127.0.0.1")
        }


if __name__ == "__main__":
    sys.stderr.write("[Parser] Stream parser initialized\n")
    sys.stderr.write("[Parser] Waiting for eBPF output...\n")
    sys.stderr.flush()

    parser = MCPParser()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            parsed_msgs = parser.process_line(line)
            for msg in parsed_msgs:
                mcp_obj = msg.get("mcp_payload", {})
                call_desc = msg.get("tool_name") or msg.get("method") or mcp_obj.get("method", "unknown")
                sys.stderr.write(f"[Parser] Extracted MCP call: {call_desc}\n")
                sys.stderr.flush()

                print(json.dumps(msg))
                sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"[Parser] Error processing line: {e}\n")
            sys.stderr.flush()