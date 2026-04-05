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

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVENT_CONNECT;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), addr);

    if (sa.sin_family == AF_INET) {
        e->daddr = sa.sin_addr.s_addr;
        e->dport = sa.sin_port;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}