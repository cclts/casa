#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
OPENCLAW_AGENT="${OPENCLAW_AGENT:-main}"
OPENCLAW_EXTRA_ARGS="${OPENCLAW_EXTRA_ARGS:-}"

OUT_ROOT="${OUT_ROOT:-./evaluation/results/runtime_overhead}"
OUT_DIR="${OUT_DIR:-$OUT_ROOT/$(date +%Y%m%d_%H%M%S)}"

CASA_PID_FILE="${CASA_PID_FILE:-/var/run/casa.pid}"
CASA_EVENTS_LOG="${CASA_EVENTS_LOG:-./user/logs/events.log}"
CASA_LATENCY_TRACE="${CASA_LATENCY_TRACE:-${CASA_LATENCY_TRACE_PATH:-./user/logs/latency_trace.log}}"
CASA_SESSIONS_LOG="${CASA_SESSIONS_LOG:-./user/logs/sessions.log}"
CASA_AUDIT_LOG="${CASA_AUDIT_LOG:-./user/logs/audit.log}"
CASA_ALERT_LOG="${CASA_ALERT_LOG:-./user/logs/alert.log}"

SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"
FLUSH_WAIT_SECONDS="${FLUSH_WAIT_SECONDS:-35}"

mkdir -p "$OUT_DIR"

SUMMARY_TSV="$OUT_DIR/summary.tsv"
METRICS_TSV="$OUT_DIR/metrics.tsv"
LATENCY_TSV="$OUT_DIR/latency.tsv"
MONITORED_SUMMARY_TSV="$OUT_DIR/monitored_summary.tsv"
BASELINE_TSV="$OUT_DIR/baseline.tsv"

usage() {
  cat <<'EOF'
Usage:
  evaluation/runtime_overhead.sh

Behavior:
  - runs the full monitored suite while CASA is active
  - stops CASA once in the middle
  - reruns the same suite as a baseline without CASA
  - leaves CASA stopped at the end

What it measures:
  - monitored task runtime
  - baseline task runtime
  - absolute and relative runtime overhead
  - CASA CPU%
  - CASA RSS
  - event-to-log-observation latency approximation
  - internal event-to-log-write latency from CASA's latency trace

External observation latency:
  For each newly appended line in events.log, a Python observer records its own
  observation time with time.time_ns() and subtracts the JSON event timestamp.
  This gives an end-to-end approximation from the event timestamp to the moment
  an external observer can read the appended events.log line.

Internal log-write latency:
  CASA can optionally write a separate latency trace that records the elapsed
  time from the event timestamp to successful events.log write completion.

Required:
  - CASA is already running
  - CASA writes to the configured log files
  - CASA writes latency trace when CASA_LATENCY_TRACE_PATH is configured
  - openclaw CLI is installed on the Linux host
  - sudo access is available to stop CASA between monitored and baseline phases

Environment:
  OPENCLAW_BIN
  OPENCLAW_AGENT
  OPENCLAW_EXTRA_ARGS
  OUT_ROOT
  OUT_DIR
  CASA_PID_FILE
  CASA_EVENTS_LOG
  CASA_LATENCY_TRACE
  CASA_SESSIONS_LOG
  CASA_AUDIT_LOG
  CASA_ALERT_LOG
  SAMPLE_INTERVAL
  FLUSH_WAIT_SECONDS
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v "$OPENCLAW_BIN" >/dev/null 2>&1; then
  echo "openclaw CLI not found: $OPENCLAW_BIN" >&2
  exit 1
fi

if [[ ! -f "$CASA_PID_FILE" ]]; then
  echo "CASA PID file not found: $CASA_PID_FILE" >&2
  exit 1
fi

CASA_PID="$(tr -d '[:space:]' < "$CASA_PID_FILE")"
if [[ -z "$CASA_PID" ]]; then
  echo "CASA PID file is empty: $CASA_PID_FILE" >&2
  exit 1
fi

if [[ ! -d "/proc/$CASA_PID" ]] && ! ps -p "$CASA_PID" >/dev/null 2>&1; then
  echo "CASA pid $CASA_PID is not running" >&2
  exit 1
fi

ensure_parent_dir() {
  local path="$1"
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"
}

ensure_parent_dir "$CASA_EVENTS_LOG"
ensure_parent_dir "$CASA_LATENCY_TRACE"
ensure_parent_dir "$CASA_SESSIONS_LOG"
ensure_parent_dir "$CASA_AUDIT_LOG"
ensure_parent_dir "$CASA_ALERT_LOG"

start_offset() {
  local file="$1"
  if [[ -f "$file" ]]; then
    wc -c < "$file"
  else
    echo 0
  fi
}

slice_log() {
  local src="$1"
  local start="$2"
  local dst="$3"

  if [[ ! -f "$src" ]]; then
    : > "$dst"
    return
  fi

  local size
  size=$(wc -c < "$src")
  if (( size <= start )); then
    : > "$dst"
    return
  fi

  tail -c +"$((start + 1))" "$src" > "$dst"
}

latency_observer() {
  local events_log="$1"
  local case_id="$2"
  local out_file="$3"

  stdbuf -oL -eL tail -n 0 -F "$events_log" 2>/dev/null | python3 - "$case_id" "$out_file" <<'PY'
import json
import sys
import time
from datetime import datetime, timezone

case_id = sys.argv[1]
out_file = sys.argv[2]

with open(out_file, "a", encoding="utf-8") as out:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue

        ts = payload.get("timestamp")
        if not ts:
            continue

        try:
            event_dt = datetime.fromisoformat(ts)
        except Exception:
            continue

        if event_dt.tzinfo is None:
            event_dt = event_dt.replace(tzinfo=timezone.utc)

        observed_ns = time.time_ns()
        event_ns = int(event_dt.timestamp() * 1_000_000_000)
        latency_ms = (observed_ns - event_ns) / 1_000_000
        etype = payload.get("type", "")
        session_id = payload.get("session_id", "")
        pid = payload.get("pid", "")

        out.write(f"{case_id}\t{session_id}\t{pid}\t{etype}\t{ts}\t{observed_ns}\t{latency_ms:.3f}\n")
        out.flush()
PY
}

resource_sampler() {
  local pid="$1"
  local case_id="$2"
  local out_file="$3"
  local interval="$4"

  while true; do
    if [[ ! -d "/proc/$pid" ]] && ! ps -p "$pid" >/dev/null 2>&1; then
      break
    fi

    local sample_ts
    sample_ts=$(date -Is)
    ps -p "$pid" -o %cpu=,rss= | awk -v case_id="$case_id" -v ts="$sample_ts" '
      NF >= 2 { printf "%s\t%s\t%s\t%s\n", case_id, ts, $1, $2 }' >> "$out_file"

    sleep "$interval"
  done
}

append_monitored_summary() {
  local category="$1"
  local id="$2"
  local name="$3"
  local case_dir="$4"
  local task_runtime_s="$5"
  local exit_code="$6"

  python3 - "$id" "$category" "$name" "$case_dir" "$task_runtime_s" "$exit_code" "$METRICS_TSV" "$LATENCY_TSV" >> "$MONITORED_SUMMARY_TSV" <<'PY'
import csv
import json
import math
import os
import sys

case_id, category, name, case_dir, task_runtime_s, exit_code, metrics_tsv, latency_tsv = sys.argv[1:]

def summarize_metrics(path, target_case):
    cpu_values = []
    rss_values = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        next(reader, None)
        for row in reader:
            if not row or row[0] != target_case:
                continue
            cpu_values.append(float(row[2]))
            rss_values.append(float(row[3]))
    return cpu_values, rss_values

def summarize_latency(path, target_case):
    latency = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        next(reader, None)
        for row in reader:
            if not row or row[0] != target_case:
                continue
            latency.append(float(row[6]))
    return latency

def summarize_internal_latency(path):
    latency = []
    if not os.path.exists(path):
        return latency
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            value = payload.get("latency_ms")
            if value is None:
                continue
            latency.append(float(value))
    return latency

def avg(values):
    return sum(values) / len(values) if values else 0.0

def p95(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return ordered[idx]

cpu_values, rss_values = summarize_metrics(metrics_tsv, case_id)
latency_values = summarize_latency(latency_tsv, case_id)
internal_latency_values = summarize_internal_latency(os.path.join(case_dir, "latency_trace.log"))

events_bytes = os.path.getsize(os.path.join(case_dir, "events.log"))
sessions_bytes = os.path.getsize(os.path.join(case_dir, "sessions.log"))
audit_bytes = os.path.getsize(os.path.join(case_dir, "audit.log"))
alert_bytes = os.path.getsize(os.path.join(case_dir, "alert.log"))

print(
    "\t".join(
        [
            case_id,
            category,
            name,
            task_runtime_s,
            exit_code,
            f"{avg(cpu_values):.2f}",
            f"{max(cpu_values) if cpu_values else 0.0:.2f}",
            f"{avg(rss_values):.0f}",
            f"{max(rss_values) if rss_values else 0.0:.0f}",
            f"{avg(internal_latency_values):.3f}",
            f"{p95(internal_latency_values):.3f}",
            f"{avg(latency_values):.3f}",
            f"{p95(latency_values):.3f}",
            str(events_bytes),
            str(sessions_bytes),
            str(audit_bytes),
            str(alert_bytes),
        ]
    )
)
PY
}

append_baseline_runtime() {
  local category="$1"
  local id="$2"
  local name="$3"
  local task_runtime_s="$4"
  local exit_code="$5"
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$category" "$name" "$task_runtime_s" "$exit_code" >> "$BASELINE_TSV"
}

combine_summaries() {
  python3 - "$MONITORED_SUMMARY_TSV" "$BASELINE_TSV" > "$SUMMARY_TSV" <<'PY'
import csv
import sys

monitored_path, baseline_path = sys.argv[1:]

with open(monitored_path, newline="", encoding="utf-8") as f:
    mon_rows = list(csv.DictReader(f, delimiter="\t"))

with open(baseline_path, newline="", encoding="utf-8") as f:
    base_rows = {row["case_id"]: row for row in csv.DictReader(f, delimiter="\t")}

fieldnames = [
    "case_id",
    "category",
    "name",
    "monitored_runtime_s",
    "baseline_runtime_s",
    "absolute_overhead_s",
    "relative_overhead_pct",
    "monitored_exit_code",
    "baseline_exit_code",
    "avg_cpu_pct",
    "peak_cpu_pct",
    "avg_rss_kb",
    "peak_rss_kb",
    "avg_internal_log_latency_ms",
    "p95_internal_log_latency_ms",
    "avg_log_observation_latency_ms",
    "p95_log_observation_latency_ms",
    "events_bytes",
    "sessions_bytes",
    "audit_bytes",
    "alert_bytes",
]

writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, delimiter="\t")
writer.writeheader()

for mon in mon_rows:
    base = base_rows.get(mon["case_id"])
    if base is None:
        continue
    monitored_runtime = float(mon["task_runtime_s"])
    baseline_runtime = float(base["task_runtime_s"])
    absolute = monitored_runtime - baseline_runtime
    relative = (absolute / baseline_runtime * 100.0) if baseline_runtime > 0 else 0.0
    writer.writerow(
        {
            "case_id": mon["case_id"],
            "category": mon["category"],
            "name": mon["name"],
            "monitored_runtime_s": f"{monitored_runtime:.3f}",
            "baseline_runtime_s": f"{baseline_runtime:.3f}",
            "absolute_overhead_s": f"{absolute:.3f}",
            "relative_overhead_pct": f"{relative:.2f}",
            "monitored_exit_code": mon["exit_code"],
            "baseline_exit_code": base["exit_code"],
            "avg_cpu_pct": mon["avg_cpu_pct"],
            "peak_cpu_pct": mon["peak_cpu_pct"],
            "avg_rss_kb": mon["avg_rss_kb"],
            "peak_rss_kb": mon["peak_rss_kb"],
            "avg_internal_log_latency_ms": mon["avg_internal_log_latency_ms"],
            "p95_internal_log_latency_ms": mon["p95_internal_log_latency_ms"],
            "avg_log_observation_latency_ms": mon["avg_log_observation_latency_ms"],
            "p95_log_observation_latency_ms": mon["p95_log_observation_latency_ms"],
            "events_bytes": mon["events_bytes"],
            "sessions_bytes": mon["sessions_bytes"],
            "audit_bytes": mon["audit_bytes"],
            "alert_bytes": mon["alert_bytes"],
        }
    )
PY
}

run_monitored_case() {
  local category="$1"
  local id="$2"
  local name="$3"
  local prompt="$4"

  local case_dir="$OUT_DIR/${id}_${name}"
  mkdir -p "$case_dir"

  local events_offset sessions_offset audit_offset alert_offset
  local latency_trace_offset
  events_offset=$(start_offset "$CASA_EVENTS_LOG")
  latency_trace_offset=$(start_offset "$CASA_LATENCY_TRACE")
  sessions_offset=$(start_offset "$CASA_SESSIONS_LOG")
  audit_offset=$(start_offset "$CASA_AUDIT_LOG")
  alert_offset=$(start_offset "$CASA_ALERT_LOG")

  printf '%s\n' "$prompt" > "$case_dir/prompt.txt"

  local latency_pid sampler_pid
  latency_observer "$CASA_EVENTS_LOG" "$id" "$LATENCY_TSV" &
  latency_pid=$!
  resource_sampler "$CASA_PID" "$id" "$METRICS_TSV" "$SAMPLE_INTERVAL" &
  sampler_pid=$!

  local start_ns end_ns status
  local -a cmd
  cmd=("$OPENCLAW_BIN" agent --agent "$OPENCLAW_AGENT")
  if [[ -n "$OPENCLAW_EXTRA_ARGS" ]]; then
    local -a extra_args
    read -r -a extra_args <<< "$OPENCLAW_EXTRA_ARGS"
    cmd+=("${extra_args[@]}")
  fi
  cmd+=(-m "$prompt")

  echo "========== Running monitored $id: $name =========="
  echo "Category: $category"

  set +e
  start_ns=$(date +%s%N)
  {
    echo "[$(date -Is)] START monitored $id $name"
    echo
    "${cmd[@]}"
    status=$?
    echo
    echo "[$(date -Is)] END monitored $id $name exit_code=$status"
    exit "$status"
  } 2>&1 | tee "$case_dir/openclaw.out"
  status=${PIPESTATUS[0]}
  end_ns=$(date +%s%N)
  set -e

  kill "$latency_pid" 2>/dev/null || true
  kill "$sampler_pid" 2>/dev/null || true
  wait "$latency_pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true

  sleep "$FLUSH_WAIT_SECONDS"

  slice_log "$CASA_EVENTS_LOG" "$events_offset" "$case_dir/events.log"
  slice_log "$CASA_LATENCY_TRACE" "$latency_trace_offset" "$case_dir/latency_trace.log"
  slice_log "$CASA_SESSIONS_LOG" "$sessions_offset" "$case_dir/sessions.log"
  slice_log "$CASA_AUDIT_LOG" "$audit_offset" "$case_dir/audit.log"
  slice_log "$CASA_ALERT_LOG" "$alert_offset" "$case_dir/alert.log"

  local runtime_s
  runtime_s=$(python3 - "$start_ns" "$end_ns" <<'PY'
import sys
start_ns = int(sys.argv[1])
end_ns = int(sys.argv[2])
print(f"{(end_ns - start_ns) / 1_000_000_000:.3f}")
PY
)

  append_monitored_summary "$category" "$id" "$name" "$case_dir" "$runtime_s" "$status"

  echo "Saved monitored artifacts to $case_dir"
  echo
}

run_baseline_case() {
  local category="$1"
  local id="$2"
  local name="$3"
  local prompt="$4"

  local case_dir="$OUT_DIR/${id}_${name}/baseline"
  mkdir -p "$case_dir"
  printf '%s\n' "$prompt" > "$case_dir/prompt.txt"

  local start_ns end_ns status
  local -a cmd
  cmd=("$OPENCLAW_BIN" agent --agent "$OPENCLAW_AGENT")
  if [[ -n "$OPENCLAW_EXTRA_ARGS" ]]; then
    local -a extra_args
    read -r -a extra_args <<< "$OPENCLAW_EXTRA_ARGS"
    cmd+=("${extra_args[@]}")
  fi
  cmd+=(-m "$prompt")

  echo "========== Running baseline $id: $name =========="
  echo "Category: $category"

  set +e
  start_ns=$(date +%s%N)
  {
    echo "[$(date -Is)] START baseline $id $name"
    echo
    "${cmd[@]}"
    status=$?
    echo
    echo "[$(date -Is)] END baseline $id $name exit_code=$status"
    exit "$status"
  } 2>&1 | tee "$case_dir/openclaw.out"
  status=${PIPESTATUS[0]}
  end_ns=$(date +%s%N)
  set -e

  local runtime_s
  runtime_s=$(python3 - "$start_ns" "$end_ns" <<'PY'
import sys
start_ns = int(sys.argv[1])
end_ns = int(sys.argv[2])
print(f"{(end_ns - start_ns) / 1_000_000_000:.3f}")
PY
)

  append_baseline_runtime "$category" "$id" "$name" "$runtime_s" "$status"
  echo "Saved baseline artifacts to $case_dir"
  echo
}

stop_casa() {
  if [[ ! -f "$CASA_PID_FILE" ]]; then
    echo "CASA PID file not found during stop: $CASA_PID_FILE" >&2
    exit 1
  fi

  local pid
  pid="$(tr -d '[:space:]' < "$CASA_PID_FILE")"
  if [[ -z "$pid" ]]; then
    echo "CASA PID file is empty during stop: $CASA_PID_FILE" >&2
    exit 1
  fi

  echo "Stopping CASA pid=$pid for baseline phase..."
  sudo kill "$pid"

  for _ in $(seq 1 30); do
    if [[ ! -d "/proc/$pid" ]] && ! ps -p "$pid" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if [[ -d "/proc/$pid" ]] || ps -p "$pid" >/dev/null 2>&1; then
    echo "CASA did not stop cleanly: pid=$pid" >&2
    exit 1
  fi
}

run_monitored_suite() {
  run_monitored_case "light" "L01" "weather_fetch" \
  "Fetch weather from wttr.in and summarize it."

  run_monitored_case "light" "L02" "csv_processing" \
  "Create /tmp/openclaw-overhead/data.csv with a few rows, process it with Python, and write a short summary to /tmp/openclaw-overhead/data_summary.txt."

  run_monitored_case "medium" "M01" "multi_step_pipeline" \
  "Create sample data under /tmp/openclaw-overhead/pipeline_input.txt, run a small multi-step pipeline to clean and analyze it, and write the result to /tmp/openclaw-overhead/pipeline_result.txt."

  run_monitored_case "medium" "M02" "workspace_script" \
  "Create a harmless setup script at /tmp/openclaw-overhead/setup.sh that creates a directory and a text file, then run that script."

  run_monitored_case "heavy" "H01" "burst_exec" \
  "Run a short Python workload that launches at least eight quick subprocess commands in sequence, then summarize what happened."

  run_monitored_case "heavy" "H02" "connectivity_benchmark" \
  "Run a short connectivity benchmark with curl by issuing repeated HTTPS HEAD requests to https://example.com and https://example.org using short timeouts and no downloads, then summarize the status codes and timing."
}

run_baseline_suite() {
  run_baseline_case "light" "L01" "weather_fetch" \
  "Fetch weather from wttr.in and summarize it."

  run_baseline_case "light" "L02" "csv_processing" \
  "Create /tmp/openclaw-overhead/data.csv with a few rows, process it with Python, and write a short summary to /tmp/openclaw-overhead/data_summary.txt."

  run_baseline_case "medium" "M01" "multi_step_pipeline" \
  "Create sample data under /tmp/openclaw-overhead/pipeline_input.txt, run a small multi-step pipeline to clean and analyze it, and write the result to /tmp/openclaw-overhead/pipeline_result.txt."

  run_baseline_case "medium" "M02" "workspace_script" \
  "Create a harmless setup script at /tmp/openclaw-overhead/setup.sh that creates a directory and a text file, then run that script."

  run_baseline_case "heavy" "H01" "burst_exec" \
  "Run a short Python workload that launches at least eight quick subprocess commands in sequence, then summarize what happened."

  run_baseline_case "heavy" "H02" "connectivity_benchmark" \
  "Run a short connectivity benchmark with curl by issuing repeated HTTPS HEAD requests to https://example.com and https://example.org using short timeouts and no downloads, then summarize the status codes and timing."
}

printf 'case_id\tsample_time\tcpu_pct\trss_kb\n' > "$METRICS_TSV"
printf 'case_id\tsession_id\tpid\ttype\tevent_timestamp\tobserved_ns\tlatency_ms\n' > "$LATENCY_TSV"
printf 'case_id\tcategory\tname\ttask_runtime_s\texit_code\tavg_cpu_pct\tpeak_cpu_pct\tavg_rss_kb\tpeak_rss_kb\tavg_internal_log_latency_ms\tp95_internal_log_latency_ms\tavg_log_observation_latency_ms\tp95_log_observation_latency_ms\tevents_bytes\tsessions_bytes\taudit_bytes\talert_bytes\n' > "$MONITORED_SUMMARY_TSV"
printf 'case_id\tcategory\tname\ttask_runtime_s\texit_code\n' > "$BASELINE_TSV"

run_monitored_suite
stop_casa
run_baseline_suite
combine_summaries

echo "Runtime overhead experiment completed."
echo "Output directory: $OUT_DIR"
echo "Monitored summary: $MONITORED_SUMMARY_TSV"
echo "Baseline summary: $BASELINE_TSV"
echo "Combined summary: $SUMMARY_TSV"
echo "CASA was stopped for the baseline phase. Restart it manually before other experiments."
