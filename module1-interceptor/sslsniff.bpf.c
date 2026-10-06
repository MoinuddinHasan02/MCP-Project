
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_tracing.h>

#include "common.h"



char LICENSE[] SEC("license") = "GPL";



struct {

    __uint(type, BPF_MAP_TYPE_RINGBUF);

    __uint(max_entries, 16 * 1024 * 1024);

} events SEC(".maps");



struct {

    __uint(type, BPF_MAP_TYPE_ARRAY);

    __uint(max_entries, STAT_MAX);

    __type(key, __u32);

    __type(value, __u64);

} stats SEC(".maps");



struct call_args {

    __u64 ssl, buf, lenp, num;

    __u32 dir, ex;

};



struct {

    __uint(type, BPF_MAP_TYPE_LRU_HASH);

    __uint(max_entries, 10240);

    __type(key, __u64);

    __type(value, struct call_args);

} active_calls SEC(".maps");



struct conn_key  { __u32 pid; __u32 pad; __u64 ssl; };

struct conn_info { __u64 conn_id; __s32 fd; __s32 pad; };



struct {

    __uint(type, BPF_MAP_TYPE_LRU_HASH);

    __uint(max_entries, 65536);

    __type(key, struct conn_key);

    __type(value, struct conn_info);
} conns SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline struct conn_info *get_conn(__u32 pid, __u64 ssl)
{
    struct conn_key k = { .pid = pid, .ssl = ssl };
    struct conn_info *ci = bpf_map_lookup_elem(&conns, &k);
    if (ci)
        return ci;

    __u32 idx = STAT_NEXT_CONN;
    __u64 *ctr = bpf_map_lookup_elem(&stats, &idx);
    if (!ctr)
        return NULL;
    struct conn_info fresh = { .conn_id = __sync_fetch_and_add(ctr, 1) + 1, .fd = -1 };
    bpf_map_update_elem(&conns, &k, &fresh, BPF_NOEXIST);
    return bpf_map_lookup_elem(&conns, &k);
}

static __always_inline void emit(__u64 ssl, const void *buf, __u32 total, __u8 dir)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct conn_info *ci = get_conn(id >> 32, ssl);
    __u64 conn_id = ci ? ci->conn_id : 0;
    __s32 fd      = ci ? ci->fd : -1;

    #pragma unroll
    for (int i = 0; i < MAX_CHUNKS; i++) {
        __u32 off = i * MAX_DATA;
        if (off >= total)
            break;

        __u32 n = total - off;
        
        /* THE DEFINITIVE FIX: Force bounds to max 4095 using a bitwise mask. 
           Since MAX_DATA is 4096, this proves to the verifier it will fit. */
        n &= 4095; 

        struct ssl_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            bump(STAT_DROPPED);
            return;
        }
        e->ts_ns     = bpf_ktime_get_ns();
        e->conn_id   = conn_id;
        e->ssl_ptr   = ssl;
        e->pid       = id >> 32;
        e->tid       = (__u32)id;
        e->fd        = fd;
        e->total_len = total;
        e->chunk     = i;
        e->dir       = dir;
        __builtin_memset(e->pad, 0, sizeof(e->pad));
        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        if (bpf_probe_read_user(e->data, n, (const char *)buf + off)) {
            bpf_ringbuf_discard(e, 0);
            bump(STAT_READ_FAIL);
            return;
      }
        e->data_len = n;
        bpf_ringbuf_submit(e, 0);
    }
}

static __always_inline int enter(void *ssl, const void *buf, __u64 num,
                                 __u64 lenp, __u32 dir, __u32 ex)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct call_args a = { .ssl = (__u64)ssl, .buf = (__u64)buf, .lenp = lenp,
                           .num = num, .dir = dir, .ex = ex };
    bpf_map_update_elem(&active_calls, &id, &a, BPF_ANY);
    return 0;
}

static __always_inline int leave(int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct call_args *a = bpf_map_lookup_elem(&active_calls, &id);
    if (!a)
        return 0;

    __u32 len = 0;
    if (a->ex) {
        if (ret == 1 && a->lenp) {
            __u64 done = 0;
            bpf_probe_read_user(&done, sizeof(done), (void *)a->lenp);
            len = done > (1u << 30) ? (1u << 30) : (__u32)done;
        }
    } else if (ret > 0) {
        len = ret;
    }
    if (len)
        emit(a->ssl, (const void *)a->buf, len, a->dir);
    bpf_map_delete_elem(&active_calls, &id);
    return 0;
}

SEC("uprobe")
int BPF_KPROBE(ssl_write_enter, void *ssl, const void *buf, int num)
{ return enter(ssl, buf, num, 0, DIR_WRITE, 0); }
SEC("uretprobe")
int BPF_KRETPROBE(ssl_write_leave, int ret) { return leave(ret); }

SEC("uprobe")
int BPF_KPROBE(ssl_read_enter, void *ssl, void *buf, int num)
{ return enter(ssl, buf, num, 0, DIR_READ, 0); }
SEC("uretprobe")
int BPF_KRETPROBE(ssl_read_leave, int ret) { return leave(ret); }

SEC("uprobe")
int BPF_KPROBE(ssl_write_ex_enter, void *ssl, const void *buf, size_t num,
               size_t *written)
{ return enter(ssl, buf, num, (__u64)written, DIR_WRITE, 1); }
SEC("uretprobe")
int BPF_KRETPROBE(ssl_write_ex_leave, int ret) { return leave(ret); }

SEC("uprobe")
int BPF_KPROBE(ssl_read_ex_enter, void *ssl, void *buf, size_t num,
               size_t *readbytes)
{ return enter(ssl, buf, num, (__u64)readbytes, DIR_READ, 1); }
SEC("uretprobe")
int BPF_KRETPROBE(ssl_read_ex_leave, int ret) { return leave(ret); }

SEC("uprobe")
int BPF_KPROBE(ssl_set_fd_enter, void *ssl, int fd)
{
    struct conn_info *ci = get_conn(bpf_get_current_pid_tgid() >> 32, (__u64)ssl);
    if (ci)
        ci->fd = fd;
    return 0;
}

SEC("uprobe")
int BPF_KPROBE(ssl_free_enter, void *ssl)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct conn_key k = { .pid = id >> 32, .ssl = (__u64)ssl };
    struct conn_info *ci = bpf_map_lookup_elem(&conns, &k);
    if (!ci)
        return 0;

    struct ssl_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        __builtin_memset(e, 0, __builtin_offsetof(struct ssl_event, data));
        e->ts_ns   = bpf_ktime_get_ns();
        e->conn_id = ci->conn_id;
        e->ssl_ptr = (__u64)ssl;
        e->pid     = id >> 32;
        e->tid     = (__u32)id;
        e->fd      = ci->fd;
        e->dir     = DIR_CLOSE;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    } else {
        bump(STAT_DROPPED);
    }
    bpf_map_delete_elem(&conns, &k);return 0;
}
