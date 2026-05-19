package telemetry

import (
	stdcontext "context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cclts/casa/user/internal/audit"
	ctxpkg "github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
	"github.com/cclts/casa/user/internal/rules"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

type Manager struct {
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider

	mu       sync.Mutex
	sessions map[process.SessionID]*sessionTrace
}

type sessionTrace struct {
	ctx       stdcontext.Context
	span      trace.Span
	id        process.SessionID
	pid       uint32
	createdAt time.Time
	closedAt  time.Time

	acceptedEvents int
	connectCount   int
	openatCount    int
	execveCount    int
	exitCount      int

	ruleHitsTotal int
	auditEmitted  bool
	alertEmitted  bool
	finalScore    int
	finalAction   decision.Action
}

type AnalysisInput struct {
	Session *process.Session
	Event   event.Event
	Context ctxpkg.ContextSnapshot
	Result  decision.Result
	Audit   audit.RecordOutcome
}

// NewManager initializes a session-oriented tracer manager.
func NewManager(ctx stdcontext.Context, cfg Config) (*Manager, error) {
	if !cfg.Enabled() {
		return &Manager{}, nil
	}

	clientOptions := []otlptracehttp.Option{}
	if strings.HasPrefix(cfg.Endpoint, "http://") || strings.HasPrefix(cfg.Endpoint, "https://") {
		clientOptions = append(clientOptions, otlptracehttp.WithEndpointURL(cfg.Endpoint))
	} else {
		clientOptions = append(clientOptions, otlptracehttp.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Insecure {
		clientOptions = append(clientOptions, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("create otlp trace exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
		)),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return &Manager{
		tracer:   provider.Tracer("github.com/cclts/casa/user/internal/pipeline"),
		provider: provider,
		sessions: make(map[process.SessionID]*sessionTrace),
	}, nil
}

// RecordAnalysis records the accepted event and any rule/audit/alert side effects.
func (m *Manager) RecordAnalysis(input AnalysisInput) {
	if m == nil || m.provider == nil || input.Session == nil {
		return
	}

	m.mu.Lock()
	sessionTrace := m.getOrCreateSessionTraceLocked(input.Session)
	sessionTrace.observe(input.Event, input.Result, input.Audit)
	m.applySessionAttributesLocked(sessionTrace)
	m.mu.Unlock()

	m.recordEventSpan(sessionTrace, input.Event)
	if len(input.Result.Triggered) > 0 {
		for _, rule := range input.Result.Triggered {
			m.recordRuleMatchSpan(sessionTrace, input.Event, input.Context, input.Result, rule)
		}
	}
	if input.Audit.AuditEmitted {
		m.recordAuditSpan(sessionTrace, input.Event, input.Result)
	}
	if input.Audit.AlertEmitted {
		m.recordAlertSpan(sessionTrace, input.Event, input.Result)
	}
}

// CloseSession ends the root span for one session.
func (m *Manager) CloseSession(id process.SessionID, closedAt time.Time) {
	if m == nil || m.provider == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sessionTrace, ok := m.sessions[id]
	if !ok {
		return
	}
	sessionTrace.closedAt = closedAt
	m.applySessionAttributesLocked(sessionTrace)
	sessionTrace.span.End(trace.WithTimestamp(closedAt))
	delete(m.sessions, id)
}

// Shutdown ends all active session spans and flushes the provider.
func (m *Manager) Shutdown(ctx stdcontext.Context) error {
	if m == nil || m.provider == nil {
		return nil
	}

	now := time.Now()

	m.mu.Lock()
	for id, sessionTrace := range m.sessions {
		if sessionTrace.closedAt.IsZero() {
			sessionTrace.closedAt = now
		}
		m.applySessionAttributesLocked(sessionTrace)
		sessionTrace.span.End(trace.WithTimestamp(now))
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	return m.provider.Shutdown(ctx)
}

func (m *Manager) getOrCreateSessionTraceLocked(sess *process.Session) *sessionTrace {
	if existing, ok := m.sessions[sess.ID]; ok {
		return existing
	}

	ctx, span := m.tracer.Start(
		stdcontext.Background(),
		fmt.Sprintf("session %d", sess.ID),
		trace.WithTimestamp(sess.CreatedAt),
		trace.WithAttributes(
			attribute.Int64("casa.session.id", int64(sess.ID)),
			attribute.Int64("casa.session.pid", int64(sess.SessionPID)),
			attribute.String("casa.session.created_at", sess.CreatedAt.Format(time.RFC3339Nano)),
		),
	)
	state := &sessionTrace{
		ctx:       ctx,
		span:      span,
		id:        sess.ID,
		pid:       sess.SessionPID,
		createdAt: sess.CreatedAt,
	}
	m.sessions[sess.ID] = state
	return state
}

func (m *Manager) applySessionAttributesLocked(sessionTrace *sessionTrace) {
	if sessionTrace == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.Int64("casa.session.id", int64(sessionTrace.id)),
		attribute.Int64("casa.session.pid", int64(sessionTrace.pid)),
		attribute.String("casa.session.created_at", sessionTrace.createdAt.Format(time.RFC3339Nano)),
		attribute.Int("casa.session.final_score", sessionTrace.finalScore),
		attribute.String("casa.session.final_action", string(sessionTrace.finalAction)),
		attribute.Int("casa.session.rule_hits_total", sessionTrace.ruleHitsTotal),
		attribute.Bool("casa.session.audit_emitted", sessionTrace.auditEmitted),
		attribute.Bool("casa.session.alert_emitted", sessionTrace.alertEmitted),
		attribute.Int("casa.session.event_count.accepted", sessionTrace.acceptedEvents),
		attribute.Int("casa.session.event_count.connect", sessionTrace.connectCount),
		attribute.Int("casa.session.event_count.openat", sessionTrace.openatCount),
		attribute.Int("casa.session.event_count.execve", sessionTrace.execveCount),
		attribute.Int("casa.session.event_count.exit", sessionTrace.exitCount),
	}
	if !sessionTrace.closedAt.IsZero() {
		attrs = append(attrs, attribute.String("casa.session.closed_at", sessionTrace.closedAt.Format(time.RFC3339Nano)))
	}
	sessionTrace.span.SetAttributes(attrs...)
}

func (m *Manager) recordEventSpan(sessionTrace *sessionTrace, e event.Event) {
	_, span := m.tracer.Start(
		sessionTrace.ctx,
		eventSpanName(e),
		trace.WithTimestamp(e.Time),
		trace.WithAttributes(eventAttributes(sessionTrace.id, e)...),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	span.End(trace.WithTimestamp(e.Time))
}

func (m *Manager) recordRuleMatchSpan(sessionTrace *sessionTrace, e event.Event, snapshot ctxpkg.ContextSnapshot, result decision.Result, rule rules.TriggeredRule) {
	attrs := append(eventAttributes(sessionTrace.id, e), ruleMatchAttributes(snapshot, result, rule)...)
	_, span := m.tracer.Start(
		sessionTrace.ctx,
		fmt.Sprintf("rule matched: %s", rule.Name),
		trace.WithTimestamp(e.Time),
		trace.WithAttributes(attrs...),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	span.End(trace.WithTimestamp(e.Time))
}

func (m *Manager) recordAuditSpan(sessionTrace *sessionTrace, e event.Event, result decision.Result) {
	attrs := append(eventAttributes(sessionTrace.id, e), recordOutcomeAttributes("casa.audit", result)...)
	_, span := m.tracer.Start(
		sessionTrace.ctx,
		"audit emitted",
		trace.WithTimestamp(e.Time),
		trace.WithAttributes(attrs...),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	span.End(trace.WithTimestamp(e.Time))
}

func (m *Manager) recordAlertSpan(sessionTrace *sessionTrace, e event.Event, result decision.Result) {
	attrs := append(eventAttributes(sessionTrace.id, e), recordOutcomeAttributes("casa.alert", result)...)
	_, span := m.tracer.Start(
		sessionTrace.ctx,
		"alert emitted",
		trace.WithTimestamp(e.Time),
		trace.WithAttributes(attrs...),
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	span.End(trace.WithTimestamp(e.Time))
}

func (s *sessionTrace) observe(e event.Event, result decision.Result, auditOutcome audit.RecordOutcome) {
	s.acceptedEvents++
	switch e.Type {
	case event.EventConnect:
		s.connectCount++
	case event.EventOpenat:
		s.openatCount++
	case event.EventExecve:
		s.execveCount++
	case event.EventExit:
		s.exitCount++
	}
	s.ruleHitsTotal += len(result.Triggered)
	s.finalScore = result.Score
	s.finalAction = maxAction(s.finalAction, result.Action)
	s.auditEmitted = s.auditEmitted || auditOutcome.AuditEmitted
	s.alertEmitted = s.alertEmitted || auditOutcome.AlertEmitted
}

func maxAction(current, next decision.Action) decision.Action {
	if actionSeverity(next) > actionSeverity(current) {
		return next
	}
	return current
}

func actionSeverity(action decision.Action) int {
	switch action {
	case decision.ActionAlert:
		return 3
	case decision.ActionLog:
		return 2
	case decision.ActionIgnore:
		return 1
	default:
		return 0
	}
}

func eventSpanName(e event.Event) string {
	switch e.Type {
	case event.EventConnect:
		return "event: connect remote host"
	case event.EventOpenat:
		return "event: open file"
	case event.EventExecve:
		return "event: exec process"
	case event.EventExit:
		return "event: process exit"
	default:
		return "event: process event"
	}
}

func eventAttributes(sessionID process.SessionID, e event.Event) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Int64("casa.session.id", int64(sessionID)),
		attribute.String("casa.event.type", e.Type.String()),
		attribute.String("casa.event.timestamp", e.Time.Format(time.RFC3339Nano)),
		attribute.Int64("process.pid", int64(e.PID)),
		attribute.Int64("process.parent_pid", int64(e.PPID)),
		attribute.Int64("thread.id", int64(e.TID)),
		attribute.Int64("user.id", int64(e.UID)),
	}
	if e.Comm != "" {
		attrs = append(attrs, attribute.String("process.command", e.Comm))
	}
	switch e.Type {
	case event.EventExecve:
		if e.Path != "" {
			attrs = append(attrs, attribute.String("process.executable.path", e.Path))
		}
		if len(e.Args) > 0 {
			attrs = append(attrs, attribute.StringSlice("process.args", e.Args))
		}
	case event.EventOpenat:
		if e.Path != "" {
			attrs = append(attrs, attribute.String("file.path", e.Path))
		}
		attrs = append(attrs,
			attribute.Int64("file.flags", int64(e.Flags)),
			attribute.Int64("file.mode", int64(e.Mode)),
		)
	case event.EventConnect:
		if e.Addr != "" {
			attrs = append(attrs,
				attribute.String("server.address", e.Addr),
				attribute.Int64("server.port", int64(e.Port)),
			)
		}
	}
	return attrs
}

func ruleMatchAttributes(snapshot ctxpkg.ContextSnapshot, result decision.Result, rule rules.TriggeredRule) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("casa.rule.name", rule.Name),
		attribute.String("casa.rule.expr", rule.Expr),
		attribute.Int("casa.rule.weight", rule.Weight),
		attribute.Int("casa.rule.triggered_rule_count", len(result.Triggered)),
		attribute.StringSlice("casa.decision.triggered_rule_names", triggeredRuleNames(result.Triggered)),
		attribute.Int("casa.decision.score", result.Score),
		attribute.String("casa.decision.action", string(result.Action)),
		attribute.Int("casa.decision.log_threshold", result.LogThreshold),
		attribute.Int("casa.decision.alert_threshold", result.AlertThreshold),
		attribute.Bool("casa.execution.suspicious_path_exec", snapshot.Execution.SuspiciousPathExec),
		attribute.Bool("casa.execution.deep_chain", snapshot.Execution.DeepChain),
		attribute.Bool("casa.execution.shell_in_chain", snapshot.Execution.ShellInChain),
		attribute.Bool("casa.execution.network_tool_in_chain", snapshot.Execution.NetworkToolInChain),
		attribute.Bool("casa.execution.interpreter_in_chain", snapshot.Execution.InterpreterInChain),
		attribute.Bool("casa.execution.container_runtime_in_chain", snapshot.Execution.ContainerRuntimeInChain),
		attribute.Bool("casa.execution.memfd_or_deleted_exec", snapshot.Execution.MemfdOrDeletedExec),
		attribute.Bool("casa.capability.has_dangerous_caps", snapshot.Capability.HasDangerousCaps),
		attribute.Int("casa.capability.dangerous_count", snapshot.Capability.DangerousCount),
		attribute.Bool("casa.capability.seccomp_disabled", snapshot.Capability.SeccompDisabled),
		attribute.Bool("casa.history.connect_then_exec", snapshot.History.ConnectThenExec),
		attribute.Bool("casa.history.sensitive_then_network", snapshot.History.SensitiveThenNetwork),
		attribute.Bool("casa.history.sensitive_then_execve", snapshot.History.SensitiveThenExecve),
		attribute.Bool("casa.history.burst_open", snapshot.History.BurstOpen),
		attribute.Bool("casa.history.burst_connect", snapshot.History.BurstConnect),
		attribute.Bool("casa.history.burst_exec", snapshot.History.BurstExec),
		attribute.Bool("casa.history.write_then_exec_same_path", snapshot.History.WriteThenExecSamePath),
		attribute.Bool("casa.history.opened_deleted_path", snapshot.History.OpenedDeletedPath),
	}
	return attrs
}

func recordOutcomeAttributes(prefix string, result decision.Result) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(prefix+".kind", strings.TrimPrefix(prefix, "casa.")),
		attribute.Int("casa.decision.score", result.Score),
		attribute.String("casa.decision.action", string(result.Action)),
		attribute.Int("casa.decision.log_threshold", result.LogThreshold),
		attribute.Int("casa.decision.alert_threshold", result.AlertThreshold),
		attribute.Int(prefix+".triggered_rule_count", len(result.Triggered)),
		attribute.StringSlice(prefix+".triggered_rule_names", triggeredRuleNames(result.Triggered)),
	}
}

func triggeredRuleNames(items []rules.TriggeredRule) []string {
	if len(items) == 0 {
		return nil
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}
	return names
}
