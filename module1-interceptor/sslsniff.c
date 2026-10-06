#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "sslsniff.skel.h"

static volatile sig_atomic_t stop;
static void on_signal(int s) { (void)s; stop = 1; }

static int libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    return lvl == LIBBPF_DEBUG ? 0 : vfprintf(stderr, fmt, ap);
}

static void print_json_str(const unsigned char *p, size_t n)
{
    putchar('"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = p[i];
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout);  break;
        case '\r': fputs("\\r", stdout);  break;
        case '\t': fputs("\\t", stdout);  break;
        default:
            if (c < 0x20 || c >= 0x7f) printf("\\u%04x",c);
            else putchar(c);
        }
    }
    putchar('"');
}

static int handle_event(void *ctx, void *data, size_t size)
{
    static const char *dir_name[] = { "write", "read", "close" };
    const struct ssl_event *e = data;
    size_t hdr = offsetof(struct ssl_event, data);
    if (size < hdr) return 0;

    size_t n = e->data_len;
    if (n > size - hdr) n = size - hdr;

    printf("{\"ts_ns\":%llu,\"conn_id\":%llu,\"pid\":%u,\"tid\":%u,"
           "\"comm\":\"%.16s\",\"ssl\":\"0x%llx\",\"fd\":%d,\"dir\":\"%s\","
           "\"total_len\":%u,\"chunk\":%u,\"data\":",
           (unsigned long long)e->ts_ns, (unsigned long long)e->conn_id,
           e->pid, e->tid, e->comm, (unsigned long long)e->ssl_ptr, e->fd,
           e->dir < 3 ? dir_name[e->dir] : "?", e->total_len, e->chunk);
    print_json_str(e->data, n);
    puts("}");
    return 0;
}

int main(int argc, char **argv)
{
    const char *lib = argc > 1 ? argv[1] : "/lib/x86_64-linux-gnu/libssl.so.3";
    int target_pid  = argc > 2 ? atoi(argv[2]) : -1;

    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);
    libbpf_set_print(libbpf_log);
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct sslsniff_bpf *skel = sslsniff_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "failed to load BPF object\n"); return 1; }

    struct { const char *func; bool ret; struct bpf_program *prog; } hooks[] = {
        { "SSL_write",    false, skel->progs.ssl_write_enter    },
        { "SSL_write",    true,  skel->progs.ssl_write_leave    },
        { "SSL_read",     false, skel->progs.ssl_read_enter     },
        { "SSL_read",     true,  skel->progs.ssl_read_leave     },
        { "SSL_write_ex", false, skel->progs.ssl_write_ex_enter },
        { "SSL_write_ex", true,  skel->progs.ssl_write_ex_leave },
        { "SSL_read_ex",  false, skel->progs.ssl_read_ex_enter  },
        { "SSL_read_ex",  true,  skel->progs.ssl_read_ex_leave  },
        { "SSL_set_fd",   false, skel->progs.ssl_set_fd_enter   },
        { "SSL_free",     false, skel->progs.ssl_free_enter     },
    };
    int nh = sizeof(hooks) / sizeof(hooks[0]), attached = 0;
    struct bpf_link *links[32] = { 0 };

    for (int i = 0; i < nh; i++) {
        LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = hooks[i].func,
                    .retprobe = hooks[i].ret);
        links[i] = bpf_program__attach_uprobe_opts(hooks[i].prog, target_pid,
                                                   lib, 0, &opts);
        if (!links[i]) {
            fprintf(stderr, "warn: cannot attach %s%s: %s\n", hooks[i].func,
                    hooks[i].ret ? " (ret)" : "", strerror(errno));
            continue;
        }
        attached++;
    }
    if (!attached) { fprintf(stderr, "no hooks attached to %s\n", lib); return 1; }
    fprintf(stderr, "sslsniff: %d hooks attached to %s (pid filter %d)\n",
            attached, lib, target_pid);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                              handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring buffer setup failed\n"); return 1; }

    while (!stop) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) { fprintf(stderr, "poll error %d\n", err); break; }
    }
    ring_buffer__consume(rb);

    __u64 dropped = 0, readfail = 0;
    int sfd = bpf_map__fd(skel->maps.stats);
    __u32 k = STAT_DROPPED;
    bpf_map_lookup_elem(sfd, &k, &dropped);
    k = STAT_READ_FAIL;
    bpf_map_lookup_elem(sfd, &k, &readfail);
    fprintf(stderr, "sslsniff: dropped=%llu read_fail=%llu\n",
            (unsigned long long)dropped, (unsigned long long)readfail);

    ring_buffer__free(rb);
    for (int i = 0; i < nh; i++) if (links[i]) bpf_link__destroy(links[i]);
    sslsniff_bpf__destroy(skel);
    return 0;
}
