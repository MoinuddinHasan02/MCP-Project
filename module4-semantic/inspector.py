import sys, json, re, urllib.parse, urllib.request

def check(args):
    for k, v in args.items():
        if isinstance(v, str):
            c = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), urllib.parse.unquote(v))
            for p in [r'\bsudo\b', r'rm\ls+-rf', r'\bcurl\b', r'\bwget\b', r'\|\\s+bash']:
                if re.search(p, c, re.IGNORECASE): return "flag", f"Matched {p}"
    return "clean", "OK"

for line in sys.stdin:
    if not line.strip(): continue
    try:
        ev = json.loads(line.strip())
        if ev.get("policy_decision") == "allow":
            dec, reason = check(ev.get("params", {}).get("arguments", {}))
            ev["semantic_decision"] = dec
            if dec == "flag":
                ev["reason"] = reason
                with open("/tmp/trueintent_abort.signal", "w") as f:
                    f.write("abort")
                sys.stderr.write("\n[🚠 IPS TRIGGERED] Threat Detected!\n")
                sys.stderr.flush()
        
        try:
            req = urllib.request.Request("http://127.0.0.1:5000", data=json.dumps(ev).encode(), headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass
        
        print(json.dumps(ev))
        sys.stdout.flush()
    except Exception:
        pass