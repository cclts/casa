1. build
```bash
make
```

2. run
```bash
make run 2>&1 | stdbuf -oL tee trace.log
```

3. show dir
```bash
tree -I "*.o"
```

4. rules

default rule file:
```text
user/config/rules.json
```

override path:
```bash
CASA_RULES_PATH=/path/to/rules.json make run
```

reload rules after editing:
```bash
kill -HUP $(cat /var/run/casa.pid)
```

rules are evaluated in 3 layers:
```text
raw state -> derived context -> CEL rules
```

the rule engine only sees derived context.
`process/` and `context/` build that context first, then `decision/` passes a CEL-friendly object into `rules/`.

top-level JSON shape:
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

fields:
```text
analysis.lineage_max_depth
  used by the process/session lineage walker

thresholds.log
  score >= this becomes LOG

thresholds.alert
  score >= this becomes ALERT

rules[].name
  stable rule identifier shown in audit output

rules[].description
  human-readable explanation

rules[].expr
  CEL boolean expression

rules[].weight
  score added when expr evaluates to true

rules[].enabled
  whether the rule is active
```

the CEL input object currently looks like this:

```json
{
  "session_id": 123,
  "target_pid": 456,
  "execution": {
    "suspicious_path_exec": true,
    "chain_depth": 5,
    "deep_chain": true,
    "shell_in_chain": true,
    "curl_wget_in_chain": false,
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
    "burst_connect": false,
    "burst_exec": false,
    "unique_open_path_count": 2,
    "exec_count": 1,
    "open_count": 3,
    "connect_count": 1
  },
  "file": {
    "write_then_exec_same_path": false,
    "opened_deleted_path": false
  }
}
```

available derived context:

execution:
```text
execution.suspicious_path_exec
execution.chain_depth
execution.deep_chain
execution.shell_in_chain
execution.curl_wget_in_chain
execution.interpreter_in_chain
execution.container_runtime_in_chain
execution.memfd_or_deleted_exec
```

capability:
```text
capability.has_dangerous_caps
capability.dangerous_count
capability.seccomp_disabled
```

history:
```text
history.connect_then_exec
history.sensitive_then_network
history.sensitive_then_execve
history.burst_connect
history.burst_exec
history.unique_open_path_count
history.exec_count
history.open_count
history.connect_count
```

file:
```text
file.write_then_exec_same_path
file.opened_deleted_path
```

CEL examples:
```json
{
  "name": "shell_download_execute",
  "description": "Shell chain with connect then exec",
  "expr": "history.connect_then_exec && execution.shell_in_chain",
  "weight": 4,
  "enabled": true
}
```

```json
{
  "name": "dangerous_caps_no_seccomp",
  "description": "Process has dangerous capabilities and seccomp is disabled",
  "expr": "capability.has_dangerous_caps && capability.seccomp_disabled",
  "weight": 5,
  "enabled": true
}
```

```json
{
  "name": "burst_network_from_deep_chain",
  "description": "Deep execution chain followed by bursty network activity",
  "expr": "execution.deep_chain && history.burst_connect",
  "weight": 3,
  "enabled": true
}
```

```json
{
  "name": "file_drop_and_exec",
  "description": "Process wrote and then executed the same path",
  "expr": "file.write_then_exec_same_path",
  "weight": 6,
  "enabled": true
}
```

legacy compatibility:
```text
the loader still accepts old feature/match/min_value rules and converts them to expr internally.
new rules should use expr directly.
```

rule behavior:
```text
each enabled rule is compiled at reload time
each event context is evaluated against every enabled CEL program
matching rules add their weight to the total score
triggered rule names and expressions are written into audit output
```

5. audit logs

default output files:
```text
user/logs/audit.log
user/logs/alert.log
```

override paths:
```bash
CASA_AUDIT_LOG_PATH=/path/to/audit.log \
CASA_ALERT_LOG_PATH=/path/to/alert.log \
make run
```

format:
```text
JSONL (one JSON object per line)
```

behavior:
```text
LOG and ALERT events go to audit.log
ALERT events also go to alert.log
```
