# CASA Pipeline

```mermaid
flowchart TD
    A["eBPF probes<br/>execve / openat / connect / exit"] --> B["ringbuf -> user/internal/ebpf.ToEvent()"]
    B --> C["pipeline.Run(...)"]

    C --> D["auditMonitor.RecordEvent(e)<br/>stage raw event"]
    D --> E{"event type"}

    E -->|EXECVE| F["tracker.Propagate(pid, ppid, transparent)<br/>sessionTracker.ObserveExecve(e)"]
    E -->|EXIT| G["log [RAW EXIT]"]
    E -->|OPENAT / CONNECT| H["no tracker mutation"]

    F --> I{"tracker.Exists(pid) or tracker.Exists(ppid)?"}
    G --> I
    H --> I

    I -->|no| J["auditMonitor.DiscardEvent(e)"]
    J --> K{"EXIT?"}
    K -->|yes| L["sessionTracker.ObserveExit(e)<br/>tracker.Remove(pid)"]
    K -->|no| M["drop from session/context path"]

    I -->|yes| N["sessionTracker.Resolve(e)"]
    N --> O{"active/closing CLI session<br/>and event belongs to tracked tree?"}
    O -->|no| P["auditMonitor.DiscardEvent(e)"]
    P --> Q{"EXIT?"}
    Q -->|yes| L
    Q -->|no| M

    O -->|yes| R["securityStore.Ensure(pid)<br/>except EXIT"]
    R --> S{"ShouldIngestIntoContext(e) or EXIT?"}
    S -->|no| T["auditMonitor.DiscardEvent(e)<br/>keep only raw event log"]
    S -->|yes| U["process.BuildLineage(pid)"]

    U --> V["contextManager.ObserveAndBuild(session.ID, session.SessionPID, lineage, e, depth)"]
    V --> W["contextManager.SnapshotSession(session.ID)"]
    W --> X["decisionEngine.Evaluate(context)"]
    X --> Y["auditMonitor.Record(e, context, rawSession, result)"]
    Y --> Z{"EXIT?"}
    Z -->|yes| L
    Z -->|no| AA["next event"]

    L --> AB["session may enter closing state<br/>janitor expires after grace period"]
    AB --> AC["[SESSION] end log"]
```

## Notes

- `SessionTracker` now treats a session as a CLI invocation time window, not a process-membership graph.
- `Tracker` maintains whether a pid/ppid is still inside the `openclaw-gateway` tree.
- `BuildLineage(...)` is only used for context derivation, not for session resolution.
- `EXIT` events always try to reach `sessionTracker.ObserveExit(...)` even if they are dropped by earlier gates.
- The janitor goroutine closes sessions after the configured grace period elapses.
