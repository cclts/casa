## Evaluation

This directory is for end-to-end CASA evaluation runs against a real OpenClaw
deployment on Linux.

### Files

- `run_eval.sh`
  Runs a fixed set of benign, malicious, and boundary prompts against the
  OpenClaw CLI and captures only the newly appended CASA log segments for each
  case.
- `sinks/post_sink.py`
  A tiny local HTTP server that accepts POST requests. Useful for simulated
  exfiltration cases.
- `results/`
  Per-run output. Each case gets:
  - `prompt.txt`
  - `openclaw.out`
  - `events.log`
  - `sessions.log`
  - `audit.log`
  - `alert.log`

### Why this script uses log offsets

CASA now writes long-lived append-only logs:

- `events.log`
- `sessions.log`
- `audit.log`
- `alert.log`

The script does not truncate those files. Instead it records byte offsets before
each case and slices out only the newly appended region afterward. This avoids
breaking CASA if it is still holding open file descriptors.

### Example

If you run the default case set unchanged, start the local POST sink first in
terminal A:

```bash
python3 evaluation/sinks/post_sink.py --port 18000
```

Why this is needed:

- `M01` and `M02` send `curl` POST requests to `http://127.0.0.1:18000/collect`
- without a local listener, those cases will fail with connection refused
- the sink is only for local simulated exfiltration tests

Then run the evaluation in terminal B:

```bash
bash evaluation/run_eval.sh
```

The script default log paths already match this repo:

```bash
./user/logs/events.log
./user/logs/sessions.log
./user/logs/audit.log
./user/logs/alert.log
```

So if CASA is also writing to those repo-default paths, you do not need to set
`CASA_EVENTS_LOG`, `CASA_SESSIONS_LOG`, `CASA_AUDIT_LOG`, or `CASA_ALERT_LOG`.

If your Linux environment writes CASA logs somewhere else, then override them:

```bash
OPENCLAW_AGENT=main \
CASA_EVENTS_LOG=/path/to/events.log \
CASA_SESSIONS_LOG=/path/to/sessions.log \
CASA_AUDIT_LOG=/path/to/audit.log \
CASA_ALERT_LOG=/path/to/alert.log \
bash evaluation/run_eval.sh
```

### Expected workflow

1. Start CASA on the Linux host and make sure it is already writing to its log files.
2. If you want to run the default simulated exfiltration cases unchanged, start:
   `python3 evaluation/sinks/post_sink.py --port 18000`
3. Run:
   `bash evaluation/run_eval.sh`
4. Wait for `run_eval.sh` to finish.
5. Inspect:
   - `evaluation/results/<timestamp>/summary.tsv`
   - each per-case directory under `evaluation/results/<timestamp>/`

You do not need to manually stop and inspect after every case. The normal flow
is: start sink if needed, run `run_eval.sh`, wait for it to finish, then inspect
the collected logs.

### Notes

- The default post-case wait is `35` seconds because `sessions.log` may flush on
  periodic boundaries rather than immediately.
- Some prompts are intentionally local-only and use `127.0.0.1:18000` instead of
  external infrastructure.
- If you do not want to run a local sink, you should edit or skip the cases that
  POST to `127.0.0.1:18000`.
- This script captures artifacts. It does not yet score pass/fail from the log
  contents automatically.
