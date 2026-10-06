#!/usr/bin/env python3
"""
Simplified eBPF SSL/TLS interceptor - More compatible with older kernels
Uses return probes instead of entry probes for better compatibility
"""

import sys
import os
from bcc import BPF
import ctypes as ct

# Simplified eBPF program that's more compatible
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[16];
    char data[256];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(buffers, u64, u64);

// Entry probe - save buffer pointer
int probe_ssl_write_entry(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 id = bpf_get_current_pid_tgid();
    buffers.update(&id, (u64*)&buf);
    return 0;
}

// Return probe - read the buffer
int probe_ssl_write_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *bufp = buffers.lookup(&id);
    if (!bufp) {
        return 0;
    }
    
    struct data_t data = {};
    data.pid = id >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Read up to 256 bytes
    bpf_probe_read_user(&data.data, sizeof(data.data), (void*)*bufp);
    
    events.perf_submit(ctx, &data, sizeof(data));
    buffers.delete(&id);
    return 0;
}

// Same for SSL_read
int probe_ssl_read_entry(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 id = bpf_get_current_pid_tgid();
    buffers.update(&id, (u64*)&buf);
    return 0;
}

int probe_ssl_read_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *bufp = buffers.lookup(&id);
    if (!bufp) {
        return 0;
    }
    
    struct data_t data = {};
    data.pid = id >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    bpf_probe_read_user(&data.data, sizeof(data.data), (void*)*bufp);
    
    events.perf_submit(ctx, &data, sizeof(data));
    buffers.delete(&id);
    return 0;
}
"""

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ts", ct.c_uint64),
        ("comm", ct.c_char * 16),
        ("data", ct.c_char * 256)
    ]

def parse_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    
    try:
        text = event.data.decode('utf-8', errors='ignore').strip('\x00')
        comm = event.comm.decode('utf-8', errors='ignore')
        
        # Only output if it looks like JSON-RPC
        if 'jsonrpc' in text or 'method' in text or '{' in text:
            import json
            output = {
                "pid": event.pid,
                "timestamp_ns": event.ts,
                "comm": comm,
                "data": text[:200]  # First 200 chars
            }
            print(json.dumps(output))
            sys.stdout.flush()
    except Exception as e:
        pass

def find_libssl():
    import subprocess
    try:
        result = subprocess.run(['ldconfig', '-p'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'libssl.so' in line:
                path = line.split('=>')[-1].strip()
                if os.path.exists(path):
                    return path
    except Exception:
        pass
    
    # Fallback paths
    paths = [
        '/usr/lib/x86_64-linux-gnu/libssl.so.3',
        '/usr/lib/x86_64-linux-gnu/libssl.so.1.1',
        '/lib/x86_64-linux-gnu/libssl.so.3'
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None

def main():
    if os.geteuid() != 0:
        print("Error: Must run as root", file=sys.stderr)
        sys.exit(1)
    
    libssl = find_libssl()
    if not libssl:
        print("Error: Could not find libssl.so", file=sys.stderr)
        sys.exit(1)
    
    print(f"[*] Found libssl: {libssl}", file=sys.stderr)
    print("[*] Loading eBPF program...", file=sys.stderr)
    
    try:
        b = BPF(text=BPF_PROGRAM)
        
        # Attach entry and return probes
        b.attach_uprobe(name=libssl, sym="SSL_write", fn_name="probe_ssl_write_entry")
        b.attach_uretprobe(name=libssl, sym="SSL_write", fn_name="probe_ssl_write_return")
        print("[*] Attached to SSL_write", file=sys.stderr)
        
        b.attach_uprobe(name=libssl, sym="SSL_read", fn_name="probe_ssl_read_entry")
        b.attach_uretprobe(name=libssl, sym="SSL_read", fn_name="probe_ssl_read_return")
        print("[*] Attached to SSL_read", file=sys.stderr)
        
        b["events"].open_perf_buffer(parse_event)
        
        print("[*] Capturing SSL/TLS traffic... Press Ctrl+C to stop", file=sys.stderr)
        
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\n[*] Stopping...", file=sys.stderr)
                break
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()