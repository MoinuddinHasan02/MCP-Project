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
    deobfuscator = PayloadDeobfuscator()
    for line in sys.stdin:
        line = line.strip()
        if line:
            decoded = deobfuscator.analyze(line)
            print(f"[PARSER] Analyzed: {decoded}")
            sys.stdout.flush()
