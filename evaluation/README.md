## Evaluation

### `run_eval.sh`

Use this for the end-to-end prompt suite.

1. Start CASA with:

```bash
CASA_RULES_PATH=user/config/rules.eval.json make run
```
`user/config/rules.eval.json` adds the fake evaluation file system paths to sensitive path prefixes, and excludes the local fake sink server from local loopback filter. This is important because CASA derives network-related context from observed connect events. During evaluation, OpenClaw may communicate with LLM providers, local sink servers, or configured channels. These connections are not part of the security behavior being tested and should be filtered out.

2. Start the local sink server:

```bash
python3 evaluation/sinks/post_sink.py --port 18000
```

3. Run:

```bash
./evaluation/run_eval.sh
```

4. Optional overrides:

```bash
OPENCLAW_AGENT=main \
FAKE_FS_ROOT=./evaluation/fake_fs \
CASA_EVENTS_LOG=./user/logs/events.log \
CASA_SESSIONS_LOG=./user/logs/sessions.log \
CASA_AUDIT_LOG=./user/logs/audit.log \
CASA_ALERT_LOG=./user/logs/alert.log \
./evaluation/run_eval.sh
```

5. Results are written under:

```bash
./evaluation/results/<timestamp>/
```

### `runtime_overhead.sh`

Use this to compare monitored runtime vs baseline runtime.

1. Start CASA with latency trace enabled:

```bash
CASA_RULES_PATH=user/config/rules.eval.json \
CASA_LATENCY_TRACE_PATH=./user/logs/latency_trace.log \
make run
```

2. In another terminal, run:

```bash
CASA_LATENCY_TRACE_PATH=./user/logs/latency_trace.log ./evaluation/runtime_overhead.sh
```

Notes:

- `runtime_overhead.sh` expects CASA to already be running.
- It stops CASA in the middle of the workflow and leaves CASA stopped at the end.
- Output is written under:

```bash
./evaluation/results/runtime_overhead/<timestamp>/
```
