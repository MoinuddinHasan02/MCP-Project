from bcc import BPF
import time
import sys
import datetime

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_PERF_OUTPUT(alerts);

struct alert_data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

static __always_inline void check_and_block(void *ctx, const char *filename) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't' && comm[3] == 'h') {
        char ex_name[16] = {0};
        bpf_probe_read_user_str(&ex_name, sizeof(ex_name), filename);

        if (ex_name[0] == '/' && ex_name[1] == 'b' && ex_name[2] == 'i' && ex_name[3] == 'n' && ex_name[4] == '/' && ex_name[5] == 's' && ex_name[6] == 'h') {
            struct alert_data_t data = {0};
            data.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            bpf_send_signal(9); // SIGKILL
            alerts.perf_submit(ctx, &data, sizeof(data));
        }
    }
}

int kprobe____x64_sys_execve(struct pt_regs *ctx) {
    struct pt_regs *regs;
    bpf_probe_read_kernel(&regs, sizeof(regs), &ctx->di);
    const char *filename;
    bpf_probe_read_kernel(&filename, sizeof(filename), &regs->di);
    check_and_block(ctx, filename);
    return 0;
}

int kprobe__sys_execve(struct pt_regs *ctx, const char __user *filename) {
    check_and_block(ctx, filename);
    return 0;
}
"""

try:
    b = BPF(text=bpf_text)
    print("[+] eBPF Policy Loaded: Monitoring & streaming alerts...")
except Exception as e:
    print(f"[-] Failed to load eBPF program: {e}")
    sys.exit(1)

def print_alert(cpu, data, size):
    event = b["alerts"].event(data)
    comm_str = event.comm.decode('utf-8', errors='ignore').strip('\x00')
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Print clean alert to stdout
    print(f"[{timestamp}] [!!!] INTRUSION PREVENTED: Process '{comm_str}' (PID: {event.pid}) attempted shell execution.")
    sys.stdout.flush()

b["alerts"].open_perf_buffer(print_alert)

try:
    while True:
        b.perf_buffer_poll()
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\n[-] Exiting Policy module.")
