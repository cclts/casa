# CASA

CASA monitors the `openclaw-gateway` process tree, derives session-level context from observed events, and evaluates weighted CEL rules to produce `audit.log` and `alert.log`.

## Validated Environment

This project is sensitive to runtime version changes, especially OpenClaw itself.

### 1. OpenClaw Version

This is the most important compatibility point.

CASA currently depends on OpenClaw runtime behavior for:

- CLI session boundary detection
- `openclaw-gateway` process-tree tracking
- expected child-process patterns
- routine-noise filtering

Validated baseline:

```text
OpenClaw 2026.3.24 (cff6dc9)
```

### 2. Kernel + eBPF Toolchain

This is the second most important compatibility point.

Validated baseline:

```text
Kernel: 6.17.0-20-generic
Architecture: aarch64
bpftool: v7.7.0
libbpf: v1.7
clang: 20.1.8
llc: 20.1.8
bpffs: /sys/fs/bpf mounted
kernel.unprivileged_bpf_disabled = 2
Environment: Ubuntu VM on VMware Fusion
```

### 3. Runtime Versions

Validated baseline:

```text
Node: v24.14.1
Go: go1.24.0 linux/arm64
```

## Build and Run

### Prerequisites

Before running CASA evaluation on Linux, make sure:

- OpenClaw is already installed
- OpenClaw onboarding is already completed
- a working LLM provider and API key are already configured for OpenClaw

`setup.sh` only prepares CASA build dependencies. It does not install or configure OpenClaw for you.

Example:

```bash
openclaw --version
openclaw onboard --install-daemon
```

Without a configured provider/API key, OpenClaw CLI prompts may fail and evaluation results will not be meaningful.

### Setup

```bash
./setup.sh
```

After `setup.sh`, verify:

```bash
go version
openclaw --version
```

### Build

```bash
make
```

### Run

```bash
make run 2>&1 | stdbuf -oL tee trace.log
```

### Reload Rules

CASA writes its pid file to `CASA_PID_PATH` and supports rule reload with `SIGHUP`.

```bash
kill -HUP $(cat /var/run/casa.pid)
```

## Derived Context

Rules evaluate against three context groups.

### Execution

```text
execution.suspicious_path_exec
execution.deep_chain
execution.shell_in_chain
execution.network_tool_in_chain
execution.interpreter_in_chain
execution.container_runtime_in_chain
execution.memfd_or_deleted_exec
```

### Capability

```text
capability.has_dangerous_caps
capability.dangerous_count
capability.seccomp_disabled
```

### History

```text
history.connect_then_exec
history.sensitive_then_network
history.sensitive_then_execve
history.burst_open
history.burst_connect
history.burst_exec
history.write_then_exec_same_path
history.opened_deleted_path
```

## Rule Configuration

Default rule file:

```text
user/config/rules.json
```

Top-level JSON shape:

```json
{
  "analysis": {
    "lineage_max_depth": 4
  },
  "thresholds": {
    "log": 5,
    "alert": 10
  },
  "rules": [
    {
      "name": "shell_download_execute",
      "description": "Shell chain with download and execution behavior",
      "expr": "history.connect_then_exec && execution.shell_in_chain",
      "weight": 4,
      "enabled": true
    }
  ]
}
```

### Analysis Fields

```text
analysis.lineage_max_depth
analysis.recent_event_limit
analysis.max_per_process_artifacts
analysis.deep_chain_threshold
analysis.burst_open_threshold
analysis.burst_connect_threshold
analysis.burst_exec_threshold
analysis.burst_window_seconds
analysis.sensitive_history_window_seconds
analysis.suspicious_path_patterns
analysis.sensitive_path_prefixes
analysis.sensitive_path_patterns
analysis.shell_names
analysis.network_tool_names
analysis.interpreter_names
analysis.container_runtime_names
analysis.dangerous_capability_names
```

### Thresholds

```text
thresholds.log
thresholds.alert
```

### Rule Fields

```text
rules[].name
rules[].description
rules[].expr
rules[].weight
rules[].enabled
```

## CEL Input Shape

```json
{
  "session_id": 123,
  "execution": {
    "suspicious_path_exec": true,
    "deep_chain": true,
    "shell_in_chain": true,
    "network_tool_in_chain": false,
    "interpreter_in_chain": false,
    "container_runtime_in_chain": false,
    "memfd_or_deleted_exec": false
  },
  "capability": {
    "has_dangerous_caps": false,
    "dangerous_count": 0,
    "seccomp_disabled": true
  },
  "history": {
    "connect_then_exec": true,
    "sensitive_then_network": false,
    "sensitive_then_execve": false,
    "burst_open": false,
    "burst_connect": false,
    "burst_exec": false,
    "write_then_exec_same_path": false,
    "opened_deleted_path": false
  }
}
```

## Rule Semantics

- each enabled rule is compiled at reload time
- rules evaluate against derived context, not raw events directly
- each rule can trigger at most once per session
- score accumulates across the session
- only newly triggered rules add new score
- only newly triggered rules appear in `audit.log` and `alert.log`


## Environment Variables

### Log and Rule Paths

```bash
CASA_EVENTS_LOG_PATH     # default: user/logs/events.log
CASA_EVENTS_LOG          # alias for CASA_EVENTS_LOG_PATH

CASA_SESSIONS_LOG_PATH   # default: user/logs/sessions.log
CASA_SESSIONS_LOG        # alias for CASA_SESSIONS_LOG_PATH

CASA_AUDIT_LOG_PATH      # default: user/logs/audit.log
CASA_ALERT_LOG_PATH      # default: user/logs/alert.log

CASA_RULES_PATH          # default: user/config/rules.json
```

### Runtime Paths

```bash
CASA_BPF_PATH            # default: ebpf/build/probes.o
CASA_PID_PATH            # default: /var/run/casa.pid
```

### Example

```bash
CASA_RULES_PATH=/path/to/rules.json \
CASA_EVENTS_LOG_PATH=/tmp/events.log \
CASA_SESSIONS_LOG_PATH=/tmp/sessions.log \
CASA_AUDIT_LOG_PATH=/tmp/audit.log \
CASA_ALERT_LOG_PATH=/tmp/alert.log \
make run
```

## Pipeline Model

High-level flow:

```text
eBPF events
  -> process-tree tracking
  -> CLI session tracking
  -> derived context
  -> CEL rules
  -> logs
```

CASA distinguishes three scopes:

- `events.log`: events inside the tracked `openclaw-gateway` tree
- `session`: one OpenClaw CLI invocation window
- `context`: derived session-level features used by rules

## Logs

1. `events.log`
  - contains events from the tracked `openclaw-gateway` tree
  - does not carry `session_id`
  - does not carry decision output
2. `sessions.log`
  - lifecycle-oriented session snapshots
  - does not carry decision output
  - current reasons:
    - `periodic_flush`
    - `session_closed`
    - `shutdown`
3. `audit.log`
  - contains the triggering event and decision payload
  - written when total score reaches `thresholds.log`
4. `alert.log`
  - same structure as `audit.log`
  - written when total score reaches `thresholds.alert`
