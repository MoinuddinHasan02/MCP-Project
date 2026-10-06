#!/usr/bin/env python3
"""
Wrapper for the compiled sslsniff C binary
Parses output and feeds to the pipeline
"""

import sys
import os
import subprocess
import signal
import json

def parse_sslsniff_output(line):
    """
    Parse output from sslsniff binary
    Expected format: [timestamp] [pid] [direction] [fd] data
    """
    try:
        # Example line format from sslsniff:
        # [1234567890.123] [12345] [write] [42] {"jsonrpc":"2.0"...}
        
        # Simple parsing - adjust based on actual sslsniff output format
        if line.startswith('['):
            parts = line.split('] ', 4)
            if len(parts) >= 5:
                timestamp = parts[0][1:]
                pid = parts[1][1:]
                direction = parts[2][1:]
                fd = parts[3][1:]
                data = parts[4].strip()
                
                # Output structured data
                output = {
                    "timestamp": timestamp,
                    "pid": pid,
                    "direction": direction,
                    "fd": fd,
                    "data": data
                }
                
                return json.dumps(output)
    except Exception:
        pass
    
    # If parsing fails, return raw line
    return line

def main():
    sys.stderr.write("[*] TrueIntent eBPF Wrapper\n")
    sys.stderr.write("[*] Starting sslsniff binary...\n")
    
    # Find the sslsniff binary
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sslsniff_path = os.path.join(script_dir, 'sslsniff')
    
    if not os.path.exists(sslsniff_path):
        sys.stderr.write(f"[ERROR] sslsniff binary not found at: {sslsniff_path}\n")
        sys.stderr.write("[HINT] Run: cd module1-interceptor && ./build.sh\n")
        sys.exit(1)
    
    # Check if running as root
    if os.geteuid() != 0:
        sys.stderr.write("[ERROR] This program must be run as root (sudo)\n")
        sys.exit(1)
    
    try:
        # Start sslsniff process
        process = subprocess.Popen(
            [sslsniff_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        sys.stderr.write(f"[*] sslsniff started (PID: {process.pid})\n")
        sys.stderr.write("[*] Intercepting SSL/TLS traffic...\n")
        sys.stderr.flush()
        
        # Handle Ctrl+C
        def signal_handler(sig, frame):
            sys.stderr.write("\n[*] Stopping sslsniff...\n")
            process.terminate()
            process.wait()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Read and parse output
        for line in process.stdout:
            line = line.strip()
            if line:
                parsed = parse_sslsniff_output(line)
                print(parsed)
                sys.stdout.flush()
        
        # Check for errors
        process.wait()
        if process.returncode != 0:
            stderr_output = process.stderr.read()
            sys.stderr.write(f"[ERROR] sslsniff exited with code {process.returncode}\n")
            sys.stderr.write(f"[ERROR] {stderr_output}\n")
    
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to run sslsniff: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
