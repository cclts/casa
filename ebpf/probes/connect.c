#ifndef AF_INET
#define AF_INET 2
#endif
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_CONNECT;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->tgid = pid_tgid >> 32;
    e->pid = pid_tgid & 0xffffffff;
    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xffffffff;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    struct sockaddr_in sa = {};
    int ret = bpf_probe_read_user(&sa, sizeof(sa), addr);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    if (sa.sin_family == AF_INET) {
        e->daddr = sa.sin_addr.s_addr;
        e->dport = sa.sin_port;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}