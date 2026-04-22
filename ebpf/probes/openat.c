#include <bpf/bpf_core_read.h>

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    __builtin_memset(e, 0, sizeof(*e)); 
    
    e->type = EVENT_OPENAT;
    e->ts_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->tgid = pid_tgid >> 32;
    e->pid = pid_tgid & 0xffffffff;
        
    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xffffffff;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
