import sys

import json

import re



class MCPParser:

    def __init__(self):

        # Buffers keyed by a tuple of (conn_id, dir)

        self.buffers = {}

        self.decoder = json.JSONDecoder()



    def process_line(self, line):

        try:

            event = json.loads(line)

        except json.JSONDecodeError:

            return []

            

        conn_id = event.get('conn_id')

        direction = event.get('dir')

        key = (conn_id, direction)

        data = event.get('data', '')

        

        if key not in self.buffers:

            self.buffers[key] = ""

            

        self.buffers[key] += data

        return self.extract_messages(key, event)



    def extract_messages(self, key, event):

        messages = []

        buffer = self.buffers[key]

        

        while buffer:

            # Strip leading whitespace

            buffer = buffer.lstrip(' \t\n\r')

            

            # Identify and strip HTTP headers (POST, GET, HTTP/1.x)

            http_match = re.match(r'^(?:POST|GET|HTTP/1\.[01]).*?\r\n\r\n', buffer, re.DOTALL)
            if http_match:
                buffer = buffer[http_match.end():].lstrip(' \t\n\r')
                continue
                
            if not buffer:
                break
                
            # If it looks like JSON, attempt to parse it
            if buffer.startswith('{'):
                try:
                    obj, idx = self.decoder.raw_decode(buffer)
                    
                    # Extract explicit fields for Module 3
                    msg_type = "request" if "method" in obj and "id" in obj else "response"
                    if "method" in obj and "id" not in obj:
                        msg_type = "notification"
                        
                    # Create the structured internal object
                    structured_msg = {
                        "ts_ns": event.get("ts_ns"),
                        "conn_id": key[0],
                        "dir": key[1],
                        "msg_type": msg_type,
                        "method": obj.get("method", ""),
                        "tool_name": obj.get("params", {}).get("name", "") if isinstance(obj.get("params"), dict) else "",
                        "mcp_payload": obj
                    }
                    messages.append(structured_msg)
                    
                    # Advance the buffer past the parsed JSON object
                    buffer = buffer[idx:]
                except json.JSONDecodeError:
                    # Incomplete JSON message; wait for the next chunk
                    break
            else:
                # Log malformed bytes to stderr instead of failing silently
                sys.stderr.write(f"Discarding non-JSON byte: {repr(buffer[0])}\n")
                buffer = buffer[1:]
                
        # Save the remaining incomplete bytes back to the buffer state
        self.buffers[key] = buffer
        return messages

if __name__ == "__main__":
    parser = MCPParser()
    # Read from standard input in real-time
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parsed_msgs = parser.process_line(line)
        for msg in parsed_msgs:
            # Output the cleanly parsed MCP message as JSON
            print(json.dumps(msg))
