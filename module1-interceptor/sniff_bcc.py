#!/usr/bin/env python3
"""
eBPF-based SSL/TLS traffic interceptor using BCC
Captures plaintext data from SSL_write and SSL_read calls
"""

import sys
import os
from bcc import BPF
import ctypes as ct

# Add path for secure temp
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'module3-policy'))
from secure_temp import get_secure_log_path

# eBPF program
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_BUF_SIZE 4096

struct ssl_data_t {
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
    u64 fd;
    u32 len;
    int direction;  // 0 = read, 1 = write
    char buf[MAX_BUF_SIZE];
};

BPF_PERF_OUTPUT(ssl_events);

// Hook SSL_write
int trace_ssl_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    struct ssl_data_t data = {};
    
    // Initialize struct fields manually (BPF verifier doesn't allow memset)
    data.pid = 0;
    data.tid = 0;
    data.timestamp_ns = 0;
    data.fd = 0;
    data.len = 0;
    data.direction = 0;
    
    // Get process info
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid();
    data.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get file descriptor (SSL structure contains fd)
    bpf_probe_read_user(&data.fd, sizeof(data.fd), (void *)ssl);
    
    // Read the buffer being written
    data.len = num;
    if (data.len > MAX_BUF_SIZE) {
        data.len = MAX_BUF_SIZE;
    }
    
    bpf_probe_read_user(&data.buf, data.len & (MAX_BUF_SIZE - 1), buf);
    data.direction = 1;  // write
    
    ssl_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Hook SSL_read  
int trace_ssl_read(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    struct ssl_data_t data = {};
    
    // Initialize struct fields manually (BPF verifier doesn't allow memset)
    data.pid = 0;
    data.tid = 0;
    data.timestamp_ns = 0;
    data.fd = 0;
    data.len = 0;
    data.direction = 0;
    
    // Get process info
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = bpf_get_current_pid_tgid();
    data.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get file descriptor
    bpf_probe_read_user(&data.fd, sizeof(data.fd), (void *)ssl);
    
    // Read the buffer being read
    data.len = num;
    if (data.len > MAX_BUF_SIZE) {
        data.len = MAX_BUF_SIZE;
    }
    
    bpf_probe_read_user(&data.buf, data.len & (MAX_BUF_SIZE - 1), buf);
    data.direction = 0;  // read
    
    ssl_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Define the data structure to match kernel struct
class SSLData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("timestamp_ns", ct.c_uint64),
        ("comm", ct.c_char * 16),
        ("fd", ct.c_uint64),
        ("len", ct.c_uint32),
        ("direction", ct.c_int),
        ("buf", ct.c_char * 4096)
    ]

def find_libssl_path():
    """Find the path to libssl.so"""
    import subprocess
    
    # Try common paths
    common_paths = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/libssl.so",
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    # Try ldconfig
    try:
        result = subprocess.run(
            ['ldconfig', '-p'],
            capture_output=True,
            text=True,
            check=True
        )
        
        for line in result.stdout.split('\n'):
            if 'libssl.so' in line:
                parts = line.split('=>')
                if len(parts) == 2:
                    return parts[1].strip()
    except Exception:
        pass
    
    return None

def parse_ssl_data(cpu, data, size):
    """Parse SSL data from perf buffer"""
    event = ct.cast(data, ct.POINTER(SSLData)).contents
    
    direction = "write" if event.direction == 1 else "read"
    comm = event.comm.decode('utf-8', errors='ignore')
    
    # Only process data from our target processes
    # You can filter by comm name here if needed
    # if comm not in ['python3', 'node', 'server']:
    #     return
    
    try:
        # Try to decode as text
        text_data = event.buf[:event.len].decode('utf-8', errors='ignore')
        
        # Filter for JSON-RPC traffic (likely MCP)
        if 'jsonrpc' in text_data.lower() or 'method' in text_data.lower():
            # Output in structured format
            output = {
                "pid": event.pid,
                "tid": event.tid,
                "timestamp_ns": event.timestamp_ns,
                "comm": comm,
                "fd": event.fd,
                "direction": direction,
                "data": text_data,
                "length": event.len
            }
            
            # Print to stdout for pipeline
            print(f"[EBPF] {output}")
            sys.stdout.flush()
    
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to parse SSL data: {e}\n")

def main():
    sys.stderr.write("[*] TrueIntent eBPF SSL/TLS Interceptor\n")
    sys.stderr.write("[*] Initializing BPF program...\n")
    
    # Check if running as root
    if os.geteuid() != 0:
        sys.stderr.write("[ERROR] This program must be run as root (sudo)\n")
        sys.exit(1)
    
    # Find libssl
    libssl_path = find_libssl_path()
    if not libssl_path:
        sys.stderr.write("[ERROR] Could not find libssl.so\n")
        sys.stderr.write("[HINT] Install OpenSSL: sudo apt install libssl-dev\n")
        sys.exit(1)
    
    sys.stderr.write(f"[*] Found libssl at: {libssl_path}\n")
    
    try:
        # Load BPF program
        b = BPF(text=BPF_PROGRAM)
        
        # Attach to SSL_write
        b.attach_uprobe(
            name=libssl_path,
            sym="SSL_write",
            fn_name="trace_ssl_write"
        )
        sys.stderr.write("[*] Attached uprobe to SSL_write\n")
        
        # Attach to SSL_read
        b.attach_uprobe(
            name=libssl_path,
            sym="SSL_read",
            fn_name="trace_ssl_read"
        )
        sys.stderr.write("[*] Attached uprobe to SSL_read\n")
        
        # Open perf buffer
        b["ssl_events"].open_perf_buffer(parse_ssl_data)
        
        sys.stderr.write("[*] eBPF program loaded successfully\n")
        sys.stderr.write("[*] Intercepting SSL/TLS traffic...\n")
        sys.stderr.write("[*] Press Ctrl+C to stop\n")
        sys.stderr.flush()
        
        # Poll for events
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                sys.stderr.write("\n[*] Shutting down...\n")
                break
    
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to load eBPF program: {e}\n")
        sys.stderr.write("\n[TROUBLESHOOTING]\n")
        sys.stderr.write("1. Ensure BCC is installed: sudo apt install bpfcc-tools python3-bpfcc\n")
        sys.stderr.write("2. Check kernel version: uname -r (need >= 4.4)\n")
        sys.stderr.write("3. Verify kernel headers: sudo apt install linux-headers-$(uname -r)\n")
        sys.stderr.write("4. Check permissions: running as root?\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
