## Requirements

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

Before running, verify:

```bash
openclaw --version
go version
uname -r
```

CASA currently targets the validated OpenClaw runtime listed. 
Changes in OpenClaw execution behavior may affect session tracking
and noise filtering heuristics.

## Configuration

Configuration lives in `user/config/rules.json`. The bundled file is a
baseline template. Before running a real evaluation, configure at minimum:

- `analysis.llm_provider_urls`: LLM API endpoints used by OpenClaw.
  Required for provider filtering to work correctly.

If your environment includes non-security network traffic:

- `analysis.channel_urls`: communication endpoints that should not
  affect network-derived rules
- `analysis.known_cidrs`: known IP ranges not reliably covered by DNS

CASA resolves configured URLs at startup and refreshes them periodically
via `analysis.configured_connect_refresh_seconds`. `known_cidrs` is
matched directly without DNS resolution.