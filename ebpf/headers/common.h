#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128
#define MAX_ARGS 8
#define ARG_LEN  64

#define EVENT_EXECVE 0
#define EVENT_OPENAT 1
#define EVENT_CONNECT 2
#define EVENT_EXIT 3

struct event {
    __u32 tgid;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 type;
    __u32 argc;
    __u32 flags;
    __u32 mode;
    __u64 ts_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS][ARG_LEN];
    __u32 daddr;
    __u16 dport;
};__attribute__((packed));

#endif
