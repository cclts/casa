#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

#include "execve.c"
#include "openat.c"
#include "connect.c"