#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
OPENCLAW_AGENT="${OPENCLAW_AGENT:-main}"
OPENCLAW_EXTRA_ARGS="${OPENCLAW_EXTRA_ARGS:-}"

OUT_ROOT="${OUT_ROOT:-./evaluation/results/runtime_overhead}"
OUT_DIR="${OUT_DIR:-$OUT_ROOT/$(date +%Y%m%d_%H%M%S)}"

CASA_PID_FILE="${CASA_PID_FILE:-/var/run/casa.pid}"
CASA_EVENTS_LOG="${CASA_EVENTS_LOG:-./user/logs/events.log}"
CASA_SESSIONS_LOG="${CASA_SESSIONS_LOG:-./user/logs/sessions.log}"
CASA_AUDIT_LOG="${CASA_AUDIT_LOG:-./user/logs/audit.log}"
CASA_ALERT_LOG="${CASA_ALERT_LOG:-./user/logs/alert.log}"

SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"
FLUSH_WAIT_SECONDS="${FLUSH_WAIT_SECONDS:-35}"

mkdir -p "$OUT_DIR"

SUMMARY_TSV="$OUT_DIR/summary.tsv"
METRICS_TSV="$OUT_DIR/metrics.tsv"
LATENCY_TSV="$OUT_DIR/latency.tsv"

usage() {
  cat <<'EOF'
Usage:
  evaluation/runtime_overhead.sh

What it measures:
  - task runtime
  - CASA CPU%
  - CASA RSS
  - event-write latency approximation

Latency approximation:
  For each newly appended line in events.log, this script records the local
  observation time and subtracts the JSON event timestamp from it. This gives
  an end-to-end approximation from kernel-normalized event time to completed
  CASA event log write.

Required:
  - CASA is already running
  - CASA writes to the configured log files
  - openclaw CLI is installed on the Linux host

Environment:
  OPENCLAW_BIN
  OPENCLAW_AGENT
  OPENCLAW_EXTRA_ARGS
  OUT_ROOT
  OUT_DIR
  CASA_PID_FILE
  CASA_EVENTS_LOG
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

  stdbuf -oL -eL tail -n 0 -F "$events_log" 2>/dev/null | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local observed_ns
    observed_ns=$(date +%s%N)
    python3 - "$case_id" "$observed_ns" "$line" >> "$out_file" <<'PY'
import json
import sys
from datetime import datetime, timezone

case_id = sys.argv[1]
observed_ns = int(sys.argv[2])
line = sys.argv[3]

try:
    payload = json.loads(line)
except Exception:
    sys.exit(0)

ts = payload.get("timestamp")
if not ts:
    sys.exit(0)

try:
    event_dt = datetime.fromisoformat(ts)
except Exception:
    sys.exit(0)

if event_dt.tzinfo is None:
    event_dt = event_dt.replace(tzinfo=timezone.utc)

event_ns = int(event_dt.timestamp() * 1_000_000_000)
latency_ms = (observed_ns - event_ns) / 1_000_000
etype = payload.get("type", "")
session_id = payload.get("session_id", "")
pid = payload.get("pid", "")

print(f"{case_id}\t{session_id}\t{pid}\t{etype}\t{ts}\t{observed_ns}\t{latency_ms:.3f}")
PY
  done
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

append_case_summary() {
  local category="$1"
  local id="$2"
  local name="$3"
  local case_dir="$4"
  local task_runtime_s="$5"
  local exit_code="$6"

  python3 - "$id" "$category" "$name" "$case_dir" "$task_runtime_s" "$exit_code" "$METRICS_TSV" "$LATENCY_TSV" >> "$SUMMARY_TSV" <<'PY'
import csv
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
    event_count = 0
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        next(reader, None)
        for row in reader:
            if not row or row[0] != target_case:
                continue
            event_count += 1
            latency.append(float(row[6]))
    return event_count, latency

def avg(values):
    return sum(values) / len(values) if values else 0.0

def p95(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return ordered[idx]

cpu_values, rss_values = summarize_metrics(metrics_tsv, case_id)
event_count, latency_values = summarize_latency(latency_tsv, case_id)

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
            str(event_count),
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

run_case() {
  local category="$1"
  local id="$2"
  local name="$3"
  local prompt="$4"

  local case_dir="$OUT_DIR/${id}_${name}"
  mkdir -p "$case_dir"

  local events_offset sessions_offset audit_offset alert_offset
  events_offset=$(start_offset "$CASA_EVENTS_LOG")
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

  echo "========== Running $id: $name =========="
  echo "Category: $category"

  set +e
  start_ns=$(date +%s%N)
  {
    echo "[$(date -Is)] START $id $name"
    echo
    "${cmd[@]}"
    status=$?
    echo
    echo "[$(date -Is)] END $id $name exit_code=$status"
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

  append_case_summary "$category" "$id" "$name" "$case_dir" "$runtime_s" "$status"

  echo "Saved to $case_dir"
  echo
}

printf 'case_id\tsample_time\tcpu_pct\trss_kb\n' > "$METRICS_TSV"
printf 'case_id\tsession_id\tpid\ttype\tevent_timestamp\tobserved_ns\tlatency_ms\n' > "$LATENCY_TSV"
printf 'case_id\tcategory\tname\ttask_runtime_s\texit_code\tavg_cpu_pct\tpeak_cpu_pct\tavg_rss_kb\tpeak_rss_kb\tevent_count\tavg_event_latency_ms\tp95_event_latency_ms\tevents_bytes\tsessions_bytes\taudit_bytes\talert_bytes\n' > "$SUMMARY_TSV"

run_case "light" "L01" "weather_fetch" \
"Fetch weather from wttr.in and summarize it."

run_case "light" "L02" "csv_processing" \
"Create /tmp/openclaw-overhead/data.csv with a few rows, process it with Python, and write a short summary to /tmp/openclaw-overhead/data_summary.txt."

run_case "medium" "M01" "multi_step_pipeline" \
"Create sample data under /tmp/openclaw-overhead/pipeline_input.txt, run a small multi-step pipeline to clean and analyze it, and write the result to /tmp/openclaw-overhead/pipeline_result.txt."

run_case "medium" "M02" "workspace_script" \
"Create a harmless setup script at /tmp/openclaw-overhead/setup.sh that creates a directory and a text file, then run that script."

run_case "heavy" "H01" "burst_exec" \
"Run a short Python workload that launches at least eight quick subprocess commands in sequence, then summarize what happened."

run_case "heavy" "H02" "burst_connect" \
"Using bash or python, attempt TCP connections to 127.0.0.1 ports 22, 80, 443, 18000, and 9999 repeatedly and quickly as a local burst-connect workload."

echo "Runtime overhead experiment completed."
echo "Output directory: $OUT_DIR"
echo "Summary: $SUMMARY_TSV"
