# CASA

CASA monitors the `openclaw-gateway` process tree, derives session-level context from accepted events, and evaluates weighted CEL rules to produce `audit.log` and `alert.log`.

## ⚠️ Critical Requirement

CASA is highly sensitive to **OpenClaw version** and **Linux kernel + eBPF toolchain**.

If OpenClaw runtime behavior changes, CASA may lose:

- CLI session boundary detection
- `openclaw-gateway` tree tracking
- routine-noise filtering
- expected child-process patterns

Validated baseline:

```text
OpenClaw 2026.3.24 (cff6dc9)
Kernel 6.17.0-20-generic
Architecture aarch64
bpftool v7.7.0
libbpf v1.7
clang 20.1.8
llc 20.1.8
Node v24.14.1
Go go1.24.0 linux/arm64
Environment Ubuntu VM on VMware Fusion
```

Before evaluation, verify:

```bash
openclaw --version
go version
uname -r
```

OpenClaw must already be:

- installed
- onboarded
- configured with a working LLM provider and API key

Without a working provider/API key, OpenClaw prompts may fail and CASA evaluation will not be meaningful.

The bundled `user/config/rules.json` is only a baseline template. For a real evaluation environment, **you must configure at least:**

- `analysis.llm_provider_urls`

If your environment also includes non-security communication services, configure as needed:

- `analysis.channel_urls`
- `analysis.known_cidrs`

## ❗ Quick Start

1. Install OpenClaw and complete onboarding.
2. Configure a working LLM provider/API key for OpenClaw.
3. Run:

```bash
./setup.sh
```

4. Verify:

```bash
openclaw --version
go version
```

5. Build and run:

```bash
make
make run
```

Optional:

- reload rules with `kill -HUP $(cat /var/run/casa.pid)`
- configure `channel_urls` or `known_cidrs` if your evaluation environment has non-security network traffic that should be excluded from CASA network-derived rules
- do not rely on the bundled `rules.json` unchanged; fill in `analysis.llm_provider_urls` for your actual provider


## 📊 Evaluation

For evaluation usage and scripts, see the files under `evaluation/`.

## Logs

- `events.log`
  accepted events that entered session/context processing
- `sessions.log`
  raw session snapshots
- `audit.log`
  rule hits once total score reaches `thresholds.log`
- `alert.log`
  rule hits once total score reaches `thresholds.alert`

Current `sessions.log` reasons:

- `periodic_flush`
- `session_closed`
- `shutdown`

## Rule Configuration

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
analysis.llm_provider_urls
analysis.channel_urls
analysis.known_cidrs
analysis.configured_connect_refresh_seconds
```

### Configured Connect Ignore

- `analysis.llm_provider_urls`
  required for real evaluation; LLM API endpoints used by OpenClaw itself
- `analysis.channel_urls`
  optional non-security communication endpoints that should not affect network-derived rules
- `analysis.known_cidrs`
  optional known network ranges for services that are not reliably covered by DNS resolution or may use hard-coded IPs
- `analysis.configured_connect_refresh_seconds`
  periodic DNS refresh interval for configured URLs

CASA resolves configured URLs at startup and can refresh them periodically. `known_cidrs` is matched directly without DNS.

These settings are environment-specific. CASA supports them, but evaluation users should configure `channel_urls` and `known_cidrs` for their own environment.

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

## Derived Context

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
