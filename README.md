1. build
```
make
```
2. run
```
make run 2>&1 | stdbuf -oL tee trace.log
```
3. show dir
```
tree -I "*.o|*.mod|*.sum"
```

4. risk rules
default rule file:
```
user/config/risk_rules.json
```

override path:
```bash
CARE_RULES_PATH=/path/to/risk_rules.json make run
```

reload rules after editing:
```bash
kill -HUP <care-go-pid>
```

5. audit logs
default output files:
```text
user/logs/audit.log
user/logs/alert.log
```

override paths:
```bash
CARE_AUDIT_LOG_PATH=/path/to/audit.log \
CARE_ALERT_LOG_PATH=/path/to/alert.log \
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
