#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

#define EVENT_EXECVE 0
#define EVENT_OPENAT 1
#define EVENT_CONNECT 2

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 type;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __u32 daddr;
    __u16 dport;
};

#endif