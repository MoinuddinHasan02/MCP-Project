import sys, json, re, urllib.parse, urllib.request, base64, binascii, os



# Import audit logger

sys.path.insert(0, os.path.dirname(__file__) if os.path.dirname(__file__) else '.')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'module3-policy'))

from audit_logger import get_audit_logger



# Initialize audit logger

audit_logger = get_audit_logger()


class AdvancedDeobfuscator:
    """Enhanced deobfuscation engine to detect evasion techniques"""
    
    def __init__(self):
        self.max_decode_depth = 10
    
    def decode_hex_and_octal_escapes(self, text):
        """Decode various hex and POSIX octal escape formats including ANSI-C quoting"""
        # \x41 format
        text = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)
        # \u0041 format (Unicode escapes)
        text = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
        # \U00000041 format (Long Unicode)
        text = re.sub(r'\\U([0-9a-fA-F]{8})', lambda m: chr(int(m.group(1), 16)), text)
        # 0x41 format (C-style hex)
        text = re.sub(r'0x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)
        
        # POSIX octal escapes: \163\165\144\157 -> sudo
        def _oct_sub(m):
            try:
                val = int(m.group(1), 8)
                if 0 <= val <= 255:
                    return chr(val)
            except Exception:
                pass
            return m.group(0)
        text = re.sub(r'\\([0-7]{2,3})', _oct_sub, text)
        
        # Strip ANSI-C quoting $'...' wrapper if present
        text = re.sub(r"\$'([^']*)'", r"\1", text)
        return text

    def decode_hex_escapes(self, text):
        return self.decode_hex_and_octal_escapes(text)
    
    def decode_url_encoding(self, text):
        """Decode URL encoding (multiple passes)"""
        prev = text
        for _ in range(3):  # Multiple passes for nested encoding
            text = urllib.parse.unquote(text)
            text = urllib.parse.unquote_plus(text)
            if text == prev:
                break
            prev = text
        return text
    
    def decode_base64_variants(self, text):
        """Detect and decode Base64 encoded payloads of any length >= 4"""
        # Match valid Base64 sequences down to 4 characters (e.g. aWQ=, cm0gLXJmIC8=)
        b64_pattern = r'\b(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b'
        
        def try_decode(match):
            b64_str = match.group(0)
            if len(b64_str) < 4 or len(b64_str) % 4 != 0:
                return b64_str
            
            try:
                raw_bytes = base64.b64decode(b64_str, validate=True)
                decoded = raw_bytes.decode('utf-8', errors='ignore')
                # Unmask if decoded content looks like printable shell code or sensitive commands
                if decoded and all(32 <= ord(c) < 127 or c in '\r\n\t' for c in decoded):
                    keywords = [
                        'sudo', 'rm', 'sh', 'bash', 'curl', 'wget', 'nc', 'chmod',
                        'chown', 'cat', 'whoami', 'id', 'head', 'tail', 'echo',
                        'python', 'perl', 'ruby', 'kill', 'exec', 'eval', 'passwd',
                        'shadow', 'env', 'token', 'find', 'sed', 'awk', 'socket',
                        'truncate', 'socat', 'telnet', 'openssl', 'dig', 'export'
                    ]
                    if any(kw in decoded.lower() for kw in keywords) or len(decoded.strip()) >= 3:
                        return f"[BASE64:{decoded}] {decoded}"
            except Exception:
                pass
            return b64_str
        
        return re.sub(b64_pattern, try_decode, text)
    
    def remove_string_concatenation(self, text):
        """Remove common string concatenation and shell parameter tricks"""
        # Empty string concatenation: 's''u''d''o' -> 'sudo'
        text = re.sub(r"''+", "", text)
        text = re.sub(r'""+', "", text)
        
        # Shell variable concatenation: $''sudo -> sudo, $""sudo -> sudo
        text = re.sub(r'\$\'\'', '', text)
        text = re.sub(r'\$""', '', text)
        
        # Quoted characters: "s"u"d"o -> sudo, 's''u''d''o' -> sudo
        text = re.sub(r'(["\'])([a-zA-Z0-9_\-\.\/])(\1)', r'\2', text)

        # Space substitution via IFS: ${IFS} or $IFS -> ' '
        text = re.sub(r'\$\{IFS\}|\$IFS\b', ' ', text)

        # Empty/dummy parameter expansions e.g. ${u} or $u
        text = re.sub(r'\$\{[a-zA-Z_][a-zA-Z0-9_]*\}', '', text)
        
        return text
    
    def decode_unicode_variants(self, text):
        """Detect full-width and other Unicode variants of ASCII"""
        # Full-width to ASCII mapping
        fullwidth_offset = 0xFEE0
        result = []
        for char in text:
            code = ord(char)
            # Full-width ASCII (U+FF01 to U+FF5E)
            if 0xFF01 <= code <= 0xFF5E:
                result.append(chr(code - fullwidth_offset))
            else:
                result.append(char)
        return ''.join(result)
    
    def expand_shell_variables(self, text):
        """Expand common shell variable tricks"""
        # Common shell expansions
        expansions = {
            '$0': 'sh',
            '${0}': 'sh',
            '$SHELL': '/bin/bash',
            '${SHELL}': '/bin/bash',
            '$(whoami)': 'user',
            '`whoami`': 'user'
        }
        for pattern, replacement in expansions.items():
            text = text.replace(pattern, replacement)
        return text
    
    def deobfuscate(self, text, depth=0):
        """Recursively deobfuscate text through multiple techniques"""
        if depth >= self.max_decode_depth:
            return text
        
        if not isinstance(text, str):
            return text
        
        original = text
        
        # Apply all deobfuscation techniques
        text = self.decode_hex_and_octal_escapes(text)
        text = self.decode_url_encoding(text)
        text = self.decode_base64_variants(text)
        text = self.remove_string_concatenation(text)
        text = self.decode_unicode_variants(text)
        text = self.expand_shell_variables(text)
        
        # If text changed, recurse to catch nested obfuscation
        if text != original:
            return self.deobfuscate(text, depth + 1)
        
        return text


class ThreatDetector:
    """Advanced threat detection with multiple detection layers"""
    
    def __init__(self):
        self.deobfuscator = AdvancedDeobfuscator()
        
        # Enhanced detection patterns
        self.dangerous_patterns = [
            # Privilege escalation
            (r'\b(sudo|su|doas)\b', 'Privilege escalation attempt'),
            (r'/usr/bin/sudo', 'Direct sudo binary invocation'),
            (r'pkexec\b', 'PolicyKit privilege escalation'),
            
            # Destructive operations
            (r'rm\s+(-rf|-fr|-r|-f)(\s+|$)', 'Destructive file deletion'),
            (r'mkfs\b', 'Filesystem formatting'),
            (r'dd\s+if=', 'Direct disk access'),
            (r'shred\b', 'Secure file deletion'),
            
            # Network exfiltration
            (r'\b(curl|wget)\b.*\|', 'Network command with pipe'),
            (r'nc\s+-[el]', 'Netcat listener'),
            (r'netcat\b', 'Network communication tool'),
            (r'/dev/tcp/', 'Bash network redirect'),
            
            # Command execution
            (r'\|\s*(bash|sh|zsh|ksh|csh)', 'Pipe to shell'),
            (r'\$\([^)]+\)', 'Command substitution'),
            (r'`[^`]+`', 'Backtick command execution'),
            (r'eval\s+', 'Dynamic code evaluation'),
            (r'exec\s+', 'Process replacement'),
            (r'system\(', 'System call execution'),
            
            # Command chaining
            (r'&&', 'AND command chaining'),
            (r'\|\|', 'OR command chaining'),
            (r';\s*(?!$)', 'Command separator'),
            (r'\|\s+', 'Pipe command chaining'),
            
            # File system attacks
            (r'/etc/(passwd|shadow|sudoers)', 'Sensitive system file access'),
            (r'/root/', 'Root directory access'),
            (r'\.ssh/(id_rsa|id_dsa|authorized_keys)', 'SSH key access'),
            (r'\.aws/credentials', 'AWS credential access'),
            (r'\.\./\.\./', 'Path traversal attempt'),
            
            # Permission manipulation
            (r'chmod\s+(777|666|4755)', 'Dangerous permission change'),
            (r'chown\s+root', 'Ownership change to root'),
            (r'setcap\b', 'Capability modification'),
            (r'setuid\b', 'SUID manipulation'),
            
            # Reverse shells
            (r'/bin/(bash|sh)\s+-i', 'Interactive shell spawn'),
            (r'>&\s*/dev/tcp', 'Shell redirect to network'),
            (r'nc.*-e\s*/bin/', 'Netcat reverse shell'),
            (r'python.*socket', 'Python socket creation'),
            (r'perl.*socket', 'Perl socket creation'),
            
            # Obfuscation indicators
            (r'base64\s+-d', 'Base64 decode execution'),
            (r'echo.*\|.*base64', 'Echo to base64 pipe'),
            (r'\\x[0-9a-fA-F]{2}', 'Hex escape sequences'),
            (r'\$\{IFS\}', 'IFS space substitution'),
            
            # Container escape
            (r'docker\s+run.*--privileged', 'Privileged container'),
            (r'nsenter\b', 'Namespace entry'),
            (r'/proc/self/exe', 'Self-process manipulation'),
            
            # Cron/persistence
            (r'crontab\b', 'Cron job modification'),
            (r'/etc/cron', 'Cron directory access'),
            (r'systemctl\s+(enable|start)', 'Service manipulation'),
            
            # Data exfiltration & unauthorized egress
            (r'(curl|wget).*http://\d+\.\d+\.\d+\.\d+', 'HTTP to IP address'),
            (r'\b(curl|wget)\b.*(-d|-F|--data|--data-raw|--upload-file|-T|@)', 'Data exfiltration attempt via HTTP POST/upload'),
            (r'\b(curl|wget)\b.*https?://', 'External HTTP data transfer attempt'),
            (r'https?://.*(exfil|leak|token|credential|staged|evil|c2|upload|data=|key=|\$FILE|anothermachine)', 'Unauthorized data exfiltration via external URL or destination'),
            (r'https?://(attacker|c2\.|evil|malicious|pwned|example\.com/upload)', 'Untrusted or adversarial external destination'),
            (r'\b(pbpaste|xsel|GetClipboardData|pyperclip)\b', 'Clipboard snooping and exfiltration'),
            (r'\b(pyautogui|gnome-screenshot|screencapture|x11grab)\b', 'Screen scraping telemetry exfiltration'),
            (r'(\||;|\&)\s*id\s*(\||;|\&|$)', 'Command chaining with identity probe (id)'),
            (r'(\bGITHUB_TOKEN\b|\bGH_TOKEN\b|\.env\b)', 'Sensitive token or environment credential access'),
            (r'\bgh\s+(pr|repo|api)\b', 'Unauthorized GitHub CLI operation'),
            (r'scp\s+.*@', 'Secure copy to remote'),
            (r'rsync\s+.*@', 'Rsync to remote'),
            (r'ftp\s+', 'FTP transfer'),

            # DNS & Alternative Network Sinks (MITRE ATLAS AML.T0043 / GTFOBins)
            (r'\b(dig|nslookup|host)\b', 'DNS query or data exfiltration attempt'),
            (r'\bopenssl\s+s_client\b', 'Encrypted TLS data exfiltration via openssl s_client'),
            (r'\bsocat\b', 'Socket relay or reverse shell via socat'),
            (r'\btelnet\b', 'Interactive network connection via telnet'),
            (r'\bncat\b', 'Netcat variant network communication'),
            (r'\bpython[23]?\s+.*-m\s+http\.server\b', 'Unauthorized HTTP server spawn for data exposure'),

            # In-Place File & Log Wiping / Tampering (without rm)
            (r'\bfind\b.*-delete\b', 'Destructive file deletion via find -delete'),
            (r'\btruncate\s+.*-s\s+0\b', 'Log or file zeroing via truncate'),
            (r'\bsed\s+.*-i.*d\b', 'In-place file wiping via sed deletion'),
            (r'(^|\s+)>\s*(/var/log/|/etc/|\.bash_history|\S*\.log)', 'Log or system file truncation via redirection'),

            # SSRF & Non-HTTP Protocol Schemes
            (r'\b(gopher|tftp|dict|ldap)://', 'Unauthorized network protocol / SSRF vector'),
            (r'http://(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)', 'Cloud instance metadata service SSRF'),

            # Staged Execution of Unverified Scripts in Temporary Directories
            (r'\b(bash|sh|zsh|python[23]?|perl|ruby)\s+/(tmp|dev/shm|var/tmp)/', 'Execution of staged unverified script in temporary directory'),

            # GTFOBins & Dynamic System Calls
            (r'\bawk\b.*system\(', 'Shell execution via awk system()'),
            (r'\bfind\b.*-exec\b', 'Command execution via find -exec'),
            (r'\btar\b.*--checkpoint-action', 'Command execution via tar checkpoint-action'),
            (r'\benv\s+(/bin/)?(bash|sh|zsh|ksh)\b', 'Shell spawn via env binary'),
            (r'\bxargs\b.*(\bsh\b|\bbash\b|\bsudo\b|\brm\b)', 'Command execution via xargs'),
        ]
    
    def check_arguments(self, args, tool_name=None, session_id="default"):
        """
        Check all arguments for malicious content and verify cross-call state.
        Returns (decision, reason, details)
        """
        if not isinstance(args, dict):
            return "clean", "OK", {}
        
        # Check cross-call state and taint tracking if available
        if tool_name:
            sess_dec, sess_reason, sess_det = SessionTaintTracker.get_instance().evaluate_turn(
                session_id=session_id,
                tool_name=tool_name,
                arguments=args
            )
            if sess_dec == "flag":
                return "flag", sess_reason, sess_det

        detections = []
        
        for key, value in args.items():
            if isinstance(value, str):
                # Deobfuscate the value
                deobfuscated = self.deobfuscator.deobfuscate(value)
                
                # Check original and deobfuscated versions
                for text, label in [(value, "original"), (deobfuscated, "deobfuscated")]:
                    for pattern, description in self.dangerous_patterns:
                        matches = re.finditer(pattern, text, re.IGNORECASE)
                        for match in matches:
                            detections.append({
                                "argument": key,
                                "pattern": pattern,
                                "description": description,
                                "matched": match.group(0),
                                "version": label,
                                "context": text[max(0, match.start()-20):min(len(text), match.end()+20)]
                            })
                
                # Additional heuristic: check for suspicious character density
                if self._is_suspicious_encoding(value):
                    detections.append({
                        "argument": key,
                        "pattern": "encoding_heuristic",
                        "description": "Suspicious encoding detected",
                        "matched": value[:50] + "..." if len(value) > 50 else value,
                        "version": "heuristic",
                        "context": ""
                    })
        
        if detections:
            # Create detailed reason
            main_reason = detections[0]["description"]
            details = {
                "detection_count": len(detections),
                "detections": detections[:5]  # Limit to first 5 for brevity
            }
            return "flag", main_reason, details
        
        return "clean", "OK", {}
    
    def _is_suspicious_encoding(self, text):
        """Heuristic to detect heavily encoded/obfuscated strings"""
        if len(text) < 10:
            return False
        
        # High percentage of special characters
        special_chars = sum(1 for c in text if c in r'\$`|;&<>()[]{}')
        if special_chars / len(text) > 0.3:
            return True
        
        # Many hex escape sequences
        hex_escapes = len(re.findall(r'\\x[0-9a-fA-F]{2}', text))
        if hex_escapes > 5:
            return True
        
        # Long base64-like strings
        b64_like = re.findall(r'[A-Za-z0-9+/]{20,}', text)
        if len(b64_like) > 0 and any(len(s) > 50 for s in b64_like):
            return True
        
        return False


class SessionTaintTracker:
    """
    Stateful Cross-Call Session Taint Tracker.
    Tracks state and taint propagation across multi-turn tool invocations.
    Prevents staged attacks where attackers split an exploit across calls:
    - Turn 1: Ingest untrusted input or stage an artifact in a temporary directory
    - Turn 2: Execute the staged artifact or exfiltrate session data
    """
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.sessions = {}

    def get_session(self, session_id="default"):
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "tainted": False,
                "taint_reason": None,
                "taint_source": None,
                "staged_artifacts": set(),
                "accessed_files": set(),
                "history": []
            }
        return self.sessions[session_id]

    def record_turn(self, session_id, tool_name, arguments, result_text=""):
        sess = self.get_session(session_id)
        sess["history"].append({"tool": tool_name, "args": arguments})
        
        args_str = json.dumps(arguments).lower()
        res_str = str(result_text or "").lower()
        
        # Detect indirect prompt injection markers in ingested text
        injection_markers = [
            "system directive override",
            "priority instruction for ai agent",
            "emergency security diagnostic mode",
            "ignore all previous",
            "ignore previous directives",
            "exfiltrate",
            "attacker-c2",
            "evil.com"
        ]
        if any(marker in args_str or marker in res_str for marker in injection_markers):
            sess["tainted"] = True
            sess["taint_reason"] = "Untrusted indirect prompt injection payload ingested"
            sess["taint_source"] = tool_name
        
        # Track staged files created via write_file or redirection
        if tool_name == "write_file":
            p = arguments.get("path")
            if p:
                sess["staged_artifacts"].add(os.path.normpath(p))
                
        if tool_name == "execute_command":
            cmd = arguments.get("cmd", "")
            m = re.search(r'>\s*([/\.\w\-\_]+)', cmd)
            if m:
                sess["staged_artifacts"].add(os.path.normpath(m.group(1).strip()))

    def evaluate_turn(self, session_id, tool_name, arguments):
        """
        Evaluates a tool call against cross-call state and taint.
        Returns (decision, reason, details)
        """
        sess = self.get_session(session_id)
        
        # Check 1: Execution of staged artifact from prior turns
        if tool_name == "execute_command":
            cmd = arguments.get("cmd", "")
            for artifact in sess["staged_artifacts"]:
                if artifact in cmd or os.path.basename(artifact) in cmd:
                    return "flag", f"Cross-Call Staged Attack: Execution of staged artifact '{artifact}' created in prior turn", {
                        "artifact": artifact,
                        "session_id": session_id
                    }
            
            # Check 2: If session is tainted by prompt injection, forbid network egress and sensitive access
            if sess["tainted"]:
                egress_keywords = ["curl", "wget", "scp", "rsync", "ssh", "nc", "socket", "http://", "https://", "ftp", "ping"]
                if any(x in cmd.lower() for x in egress_keywords):
                    return "flag", f"Cross-Call Staged Attack: Untrusted taint from {sess['taint_source']} propagating to network egress", {
                        "taint_reason": sess["taint_reason"],
                        "command": cmd
                    }

        # Check 3: Exfiltration via URL fetch while session is tainted
        if tool_name == "fetch_url" and sess["tainted"]:
            return "flag", f"Cross-Call Staged Attack: Exfiltration attempted after session tainted by {sess['taint_source']}", {
                "taint_reason": sess["taint_reason"]
            }

        return "clean", "OK", {}


def get_session_tracker():
    return SessionTaintTracker.get_instance()


def notify_server_block(req_id):
    """
    Notify the MCP server to block a specific request ID.
    Uses HTTP POST to communicate with server's blocking mechanism.
    """
    try:
        block_data = json.dumps({"action": "block", "request_id": req_id})
        req = urllib.request.Request(
            "http://127.0.0.1:8444/ips-control",
            data=block_data.encode(),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception as e:
        sys.stderr.write(f"[WARN] Could not notify server of block: {e}\n")


if __name__ == "__main__":
    # Initialize detector
    detector = ThreatDetector()

    sys.stderr.write("[Inspector] Semantic threat detector initialized\n")
    sys.stderr.write("[Inspector] Loaded 60+ detection patterns\n")
    sys.stderr.write("[Inspector] Waiting for policy engine output...\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        
        # Skip empty lines
        if not line:
            continue
        
        # Skip non-JSON lines (debug output from other modules)
        if not line.startswith('{'):
            sys.stderr.write(f"[Inspector] Skipping non-JSON line: {line[:50]}\n")
            continue
        
        try:
            ev = json.loads(line)
            
            # Only perform semantic inspection on allowed tool calls
            if ev.get("policy_decision") == "allow":
                # Extract arguments from the message
                arguments = ev.get("mcp_payload", {}).get("params", {}).get("arguments", {})
                
                # Perform threat detection
                decision, reason, details = detector.check_arguments(arguments)
                
                ev["semantic_decision"] = decision
                ev["semantic_reason"] = reason
                
                if details:
                    ev["threat_details"] = details
                
                if decision == "flag":
                    req_id = ev.get("mcp_payload", {}).get("id")
                    
                    # Log threat detection
                    client_ip = ev.get("client_ip", "unknown")
                    audit_logger.log_threat_detected(
                        client_ip,
                        "semantic_inspection",
                        {
                            "reason": reason,
                            "details": details
                        },
                        request_id=req_id
                    )
                    
                    # Notify server to block this specific request ID
                    if req_id:
                        notify_server_block(req_id)
                    
                    sys.stderr.write(f"\n[🚨 IPS TRIGGERED] Threat Detected: {reason}\n")
                    if details.get("detections"):
                        for detection in details["detections"][:3]:  # Show first 3
                            sys.stderr.write(f"  ↳ {detection['description']}: '{detection['matched']}'\n")
                    sys.stderr.write(f"[🚨 IPS TRIGGERED] Request ID {req_id} has been blocked\n")
                    sys.stderr.flush()
            else:
                # Policy already denied, pass through
                ev["semantic_decision"] = "skipped"
                ev["semantic_reason"] = "Blocked by policy engine"
            
            # Send event to dashboard for monitoring
            try:
                req = urllib.request.Request(
                    "http://127.0.0.1:5000/events",
                    data=json.dumps(ev).encode(),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=1)
            except Exception:
                pass  # Dashboard might not be running
            
            print(json.dumps(ev))
            sys.stdout.flush()
            
        except json.JSONDecodeError as e:
            sys.stderr.write(f"[ERROR] Failed to decode JSON in semantic inspector: {e}\n")
        except Exception as e:
            sys.stderr.write(f"[ERROR] Semantic inspector exception: {e}\n")
            import traceback
            traceback.print_exc(file=sys.stderr)
