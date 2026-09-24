#ifndef COMMON_H

#define COMMON_H

#ifndef __VMLINUX_H__

#include <linux/types.h>

#endif

#define MAX_DATA   4096

#define MAX_CHUNKS 8

enum dir_t { DIR_WRITE = 0, DIR_READ = 1, DIR_CLOSE = 2 };

enum stat_idx { STAT_DROPPED, STAT_READ_FAIL, STAT_NEXT_CONN, STAT_MAX };

struct ssl_event {

    __u64 ts_ns;

    __u64 conn_id;

    __u64 ssl_ptr;

    __u32 pid;

    __u32 tid;

    __s32 fd;

    __u32 total_len;

    __u32 chunk;

    __u32 data_len;

    __u8  dir;

    __u8  pad[7];

    char  comm[16];

    __u8  data[MAX_DATA];

};

#endif


