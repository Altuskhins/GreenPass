// Package mobilebridge exposes a stable single-session wrapper around the
// sing-box core for the GreenPass plugin.
//
// The wrapper mirrors the VlessCore C-ABI contract used by GreenPass:
//
//   - StartSingle(configJson) starts exactly one core instance. Any previously
//     running instance is stopped first. Returns nil on success, error on failure.
//   - StopSingle() stops the active instance (idempotent, safe when nothing runs).
//   - SingleRunning() reports whether the instance is currently running.
//   - StatusJSON()/LogsJSON()/LastLog()/LastError() return lifecycle + log state.
//
// The config JSON is a standard sing-box config (inbounds/outbounds/route/...).
// The plugin owns the lifecycle; mobilebridge only serializes start/stop and
// captures state transitions + a best-effort log ring so the plugin can poll
// diagnostics through the same surface it already uses for the xray core.
package mobilebridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// Lifecycle states reported via StatusJSON and used by GreenPass diagnostics.
const (
	StateStarting = "starting"
	StateRunning  = "running"
	StateStopping = "stopping"
	StateStopped  = "stopped"
	StateError    = "error"
)

const (
	// maxLogEntries bounds the in-memory log/state ring surfaced to the plugin.
	maxLogEntries = 200
)

// statusSnapshot is the JSON shape returned by StatusJSON. It mirrors the
// olcRTC bridge status so GreenPass can reuse the same diagnostic plumbing.
type statusSnapshot struct {
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
	StartedAt int64  `json:"started_at,omitempty"`
	StoppedAt int64  `json:"stopped_at,omitempty"`
	Version   string `json:"version,omitempty"`
}

// logEntry is one ring entry; logs and state transitions share the ring.
type logEntry struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	State     string `json:"state,omitempty"`
}

var (
	mu sync.Mutex

	// Single-session state. Only one core runs at a time; StartSingle stops
	// any previous instance before starting the new one.
	currentBox    *box.Box
	currentCancel context.CancelFunc
	currentState  string = StateStopped
	currentMsg    string
	startedAt     time.Time
	stoppedAt     time.Time

	// Diagnostics ring + last-log/last-error slots.
	logMu   sync.Mutex
	logRing []logEntry
	lastLog string
	lastErr string
	logSubs []chan logEntry
)

// version is the bridge build version; overridden via -ldflags in the build script.
var version = "1.0.0"

// Version returns the bridge build version.
func Version() string {
	mu.Lock()
	defer mu.Unlock()
	return version
}

// SetVersion overrides the bridge build version (used by build scripts / tests).
func SetVersion(v string) {
	mu.Lock()
	defer mu.Unlock()
	version = v
}

// StatusJSON returns the latest core lifecycle status as a JSON object.
func StatusJSON() string {
	mu.Lock()
	snapshot := statusSnapshot{
		State:   currentState,
		Message: currentMsg,
		Version: version,
	}
	if !startedAt.IsZero() {
		snapshot.StartedAt = startedAt.Unix()
	}
	if !stoppedAt.IsZero() {
		snapshot.StoppedAt = stoppedAt.Unix()
	}
	mu.Unlock()
	out, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Sprintf(`{"state":"%s","error":%q}`, StateError, err.Error())
	}
	return string(out)
}

// LogsJSON returns the latest log entries as a JSON array (oldest first).
func LogsJSON() string {
	logMu.Lock()
	entries := make([]logEntry, len(logRing))
	copy(entries, logRing)
	logMu.Unlock()
	if entries == nil {
		return "[]"
	}
	out, err := json.Marshal(entries)
	if err != nil {
		return "[]"
	}
	return string(out)
}

// LastLog returns the latest log or state message observed by mobilebridge.
func LastLog() string {
	logMu.Lock()
	defer logMu.Unlock()
	return lastLog
}

// LastError returns the latest error observed by mobilebridge.
func LastError() string {
	logMu.Lock()
	defer logMu.Unlock()
	return lastErr
}

// SubscribeLogs returns a channel that receives every new log entry until it is
// closed by the caller via UnsubscribeLogs. Used by tests; not exposed via C-ABI.
func SubscribeLogs() chan logEntry {
	ch := make(chan logEntry, 32)
	logMu.Lock()
	logSubs = append(logSubs, ch)
	logMu.Unlock()
	return ch
}

// UnsubscribeLogs removes and closes a previously returned channel.
func UnsubscribeLogs(ch chan logEntry) {
	logMu.Lock()
	defer logMu.Unlock()
	for i, sub := range logSubs {
		if sub == ch {
			logSubs = append(logSubs[:i], logSubs[i+1:]...)
			close(ch)
			return
		}
	}
}

// ValidateConfig parses and structurally validates a sing-box JSON config
// without starting anything. Returns nil on success.
func ValidateConfig(configJson string) error {
	ctx := baseContext()
	_, err := parseConfig(ctx, configJson)
	return err
}

// StartSingle starts exactly one core instance from a sing-box JSON config.
// Any previously running instance is stopped first. Returns nil on success or
// an error describing why the start failed (config parse, registry, lifecycle).
func StartSingle(configJson string) error {
	ctx, cancel := context.WithCancel(baseContext())

	options, err := parseConfig(ctx, configJson)
	if err != nil {
		cancel()
		setState(StateError, E.Cause(err, "decode config").Error())
		return err
	}

	// Stop any currently running instance before starting a new one. This keeps
	// the single-session invariant: at most one *box.Box is alive at a time.
	_ = StopSingle()

	setState(StateStarting, "")

	instance, err := box.New(box.Options{
		Context:           ctx,
		Options:           options,
		PlatformLogWriter: bridgeLogWriter{},
	})
	if err != nil {
		cancel()
		setState(StateError, E.Cause(err, "create core").Error())
		return err
	}

	mu.Lock()
	currentBox = instance
	currentCancel = cancel
	mu.Unlock()
	// Start() runs the full lifecycle internally (preStart + start + postStart).
	// Do NOT call PreStart() first: Start() re-enters preStart() and would
	// double-start DNS/inbound managers, panicking with "already started".
	if err := instance.Start(); err != nil {
		finishStopWithError(E.Cause(err, "start").Error(), cancel)
		return err
	}

	setState(StateRunning, "")
	return nil
}

// StopSingle stops the active instance (if any). Safe to call when nothing is
// running; repeated stops are treated as success.
func StopSingle() error {
	mu.Lock()
	instance := currentBox
	cancel := currentCancel
	if instance == nil {
		mu.Unlock()
		return nil
	}
	// Mark stopping before the (possibly blocking) Close so StatusJSON reflects intent.
	currentState = StateStopping
	currentMsg = ""
	mu.Unlock()

	setState(StateStopping, "")

	if cancel != nil {
		cancel()
	}
	err := instance.Close()

	mu.Lock()
	currentBox = nil
	currentCancel = nil
	stoppedAt = time.Now()
	if err != nil && !errors.Is(err, context.Canceled) {
		currentState = StateError
		currentMsg = E.Cause(err, "stop").Error()
	} else {
		currentState = StateStopped
		currentMsg = ""
	}
	mu.Unlock()

	if err != nil && !errors.Is(err, context.Canceled) {
		rememberError(E.Cause(err, "stop").Error())
		return err
	}
	return nil
}

// SingleRunning reports whether the single session is currently running.
func SingleRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return currentBox != nil && currentState == StateRunning
}

// --- internals ---------------------------------------------------------------

func baseContext() context.Context {
	// include.Context wires every protocol/dns/service registry sing-box needs.
	// No platform interface: GreenPass drives a local SOCKS inbound and a remote
	// outbound; there is no TUN/VPN surface to protect, so a stub-free context is
	// sufficient and avoids pulling sing-tun platform hooks into the .so.
	return include.Context(context.Background())
}

// bridgeLogWriter receives the messages emitted by sing-box itself.  The core
// normally writes those to stderr, which is not retained by ExteraGram; keeping
// them in the existing C-ABI log ring makes failed TLS/DNS/transport attempts
// visible through GreenPass's "Copy logs" action.
type bridgeLogWriter struct{}

func (bridgeLogWriter) WriteMessage(level boxlog.Level, message string) {
	// Trace/debug events are extremely noisy on a mobile client and quickly
	// crowd out the connection failure that matters.  Info and above retain
	// lifecycle, outbound, DNS, TLS and handshake diagnostics.
	if level > boxlog.LevelInfo {
		return
	}
	rememberLog(boxlog.FormatLevel(level), strings.TrimSpace(message), "")
}

func parseConfig(ctx context.Context, configJson string) (option.Options, error) {
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configJson))
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config")
	}
	return options, nil
}

// finishStopWithError is called when PreStart/Start fail. sing-box's Box already
// calls Close() internally on those failures, so we only clear our bookkeeping,
// cancel the context, and record the error state — we must NOT close the box.
func finishStopWithError(msg string, cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
	mu.Lock()
	currentBox = nil
	currentCancel = nil
	currentState = StateError
	currentMsg = msg
	stoppedAt = time.Now()
	mu.Unlock()
	rememberError(msg)
}

func setState(state, msg string) {
	mu.Lock()
	currentState = state
	currentMsg = msg
	mu.Unlock()
	rememberLog(stateToLevel(state), msg, state)
}

func stateToLevel(state string) string {
	if state == StateError {
		return "error"
	}
	return "info"
}

// firstNonEmpty returns the first non-empty string among values.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func rememberLog(level, message, state string) {
	if level == "" && message == "" && state == "" {
		return
	}
	entry := logEntry{
		Timestamp: time.Now().UnixMilli(),
		Level:     strings.ToLower(firstNonEmpty(level, "info")),
		Message:   message,
		State:     state,
	}
	logMu.Lock()
	lastLog = formatEntry(entry)
	if level == "error" || state == StateError {
		lastErr = message
	}
	logRing = append(logRing, entry)
	if len(logRing) > maxLogEntries {
		logRing = logRing[len(logRing)-maxLogEntries:]
	}
	subs := logSubs
	logMu.Unlock()
	for _, sub := range subs {
		select {
		case sub <- entry:
		default:
			// Drop if subscriber is slow; diagnostics are best-effort.
		}
	}
}

func rememberError(message string) {
	rememberLog("error", message, StateError)
}

func formatEntry(e logEntry) string {
	if e.State != "" && e.Message != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Level, e.State, e.Message)
	}
	if e.State != "" {
		return fmt.Sprintf("[%s] %s", e.Level, e.State)
	}
	return fmt.Sprintf("[%s] %s", e.Level, e.Message)
}
