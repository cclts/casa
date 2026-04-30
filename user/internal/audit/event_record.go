package audit

import (
	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/event"
)

func buildEventLogRecord(e event.Event, ctx context.Context) EventLogRecord {
	record := EventLogRecord{
		Timestamp: e.TimeHuman,
		SessionID: ctx.SessionID,
		PID:       e.PID,
		PPID:      e.PPID,
		UID:       e.UID,
		Type:      e.Type.String(),
		Comm:      e.Comm,
		Depth:     targetExecutionDepth(ctx),
	}
	populateEventLogFields(&record, e)
	return record
}

func populateEventLogFields(record *EventLogRecord, e event.Event) {
	switch e.Type {
	case event.EventExecve:
		record.Path = stringPtr(e.Path)
		args := append([]string(nil), e.Args...)
		record.Args = &args
	case event.EventOpenat:
		record.Path = stringPtr(e.Path)
		record.Flags = uint32Ptr(e.Flags)
		record.Mode = uint32Ptr(e.Mode)
	case event.EventConnect:
		record.Addr = stringPtr(e.Addr)
		record.Port = uint16Ptr(e.Port)
	case event.EventExit:
		// EXIT only keeps the common core fields.
	}
}

func buildEventRecord(e event.Event) EventRecord {
	record := EventRecord{
		Type: e.Type.String(),
		PID:  e.PID,
		PPID: e.PPID,
		UID:  e.UID,
		Comm: e.Comm,
	}
	populateEventRecordFields(&record, e)
	return record
}

func populateEventRecordFields(record *EventRecord, e event.Event) {
	switch e.Type {
	case event.EventExecve:
		record.Path = stringPtr(e.Path)
		args := append([]string(nil), e.Args...)
		record.Args = &args
	case event.EventOpenat:
		record.Path = stringPtr(e.Path)
		record.Flags = uint32Ptr(e.Flags)
		record.Mode = uint32Ptr(e.Mode)
	case event.EventConnect:
		record.Addr = stringPtr(e.Addr)
		record.Port = uint16Ptr(e.Port)
	case event.EventExit:
	}
}

func stringPtr(v string) *string {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}

func targetExecutionDepth(ctx context.Context) int {
	for _, item := range ctx.ExecutionChains {
		if item.PID == ctx.TargetPID {
			return item.ChainDepth
		}
	}
	return 0
}
