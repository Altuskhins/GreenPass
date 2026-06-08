// Package mobilebridge exposes a gomobile-friendly Android API over olcRTC.
//
// Build with:
//
//	gomobile bind -target=android -androidapi 23 -o build/combined-tunnel.aar ./mobilebridge
package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	olcmobile "github.com/openlibrecommunity/olcrtc/mobile"
)

const (
	defaultCarrier  = "telemost"
	defaultClientID = "android"

	stateStarting  = "starting"
	stateHandshake = "handshake"
	stateRunning   = "running"
	stateReady     = "ready"
	stateStopping  = "stopping"
	stateStopped   = "stopped"
	stateError     = "error"

	maxCoreLogEntries     = 100
	persistentLogMaxBytes = 262144
)

// Listener receives logs and lifecycle state changes from mobilebridge.
//
// Implement this interface in Kotlin/Java and install it with SetListener.
type Listener interface {
	OnLog(sessionId string, level string, message string)
	OnState(sessionId string, state string, message string)
}

// SocketProtector protects sockets from Android VPN routing.
type SocketProtector interface {
	Protect(fd int) bool
}

type sessionRunner interface {
	Start() error
	Stop() error
	IsRunning() bool
}

type session struct {
	id     string
	cancel context.CancelFunc
	runner sessionRunner
}

type olcRTCConfig struct {
	Engine string `json:"engine"`

	Carrier   string `json:"carrier"`
	Provider  string `json:"provider"`
	Transport string `json:"transport"`

	RoomID   string `json:"room_id"`
	ClientID string `json:"client_id"`
	DeviceID string `json:"device_id"`
	KeyHex   string `json:"key_hex"`

	SocksPort       int    `json:"socks_port"`
	SocksUser       string `json:"socks_user"`
	SocksPass       string `json:"socks_pass"`
	SocksListenHost string `json:"socks_listen_host"`

	DNSServer string `json:"dns_server"`

	VP8FPS       int `json:"vp8_fps"`
	VP8BatchSize int `json:"vp8_batch_size"`

	LivenessIntervalMillis int `json:"liveness_interval_millis"`
	LivenessTimeoutMillis  int `json:"liveness_timeout_millis"`
	LivenessFailures       int `json:"liveness_failures"`

	WaitReadyTimeoutMillis int `json:"wait_ready_timeout_millis"`

	LogPath string `json:"log_path"`
}

type startWithTransportFunc func(
	carrierName string,
	transportName string,
	roomID string,
	clientID string,
	keyHex string,
	socksPort int,
	socksUser string,
	socksPass string,
) error

var (
	mu       sync.RWMutex
	sessions = make(map[string]*session)
	listener Listener

	lastMu    sync.RWMutex
	lastLog   string
	lastError string

	diagnosticsMu sync.RWMutex
	coreStatus    = statusSnapshot{State: stateStopped}
	coreLogs      = make([]logEntry, 0, maxCoreLogEntries)

	persistentLogMu   sync.Mutex
	persistentLogPath string

	mobileStartWithTransport = startWithTransportFunc(olcmobile.StartWithTransport)
	mobileWaitReady          = olcmobile.WaitReady
	mobileStop               = olcmobile.Stop
	mobileIsRunning          = olcmobile.IsRunning
	mobileSetDebug           = olcmobile.SetDebug
	mobileSetDNS             = olcmobile.SetDNS
	mobileSetSocksListenHost = olcmobile.SetSocksListenHost
	mobileSetVP8Options      = olcmobile.SetVP8Options
	mobileSetLivenessOptions = olcmobile.SetLivenessOptions
)

type statusSnapshot struct {
	State           string `json:"state"`
	Message         string `json:"message,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	UpdatedAtMillis int64  `json:"updated_at_millis"`
	Running         bool   `json:"running"`
}

type logEntry struct {
	TimestampMillis int64  `json:"timestamp_millis"`
	SessionID       string `json:"session_id,omitempty"`
	Level           string `json:"level"`
	Message         string `json:"message"`
	State           string `json:"state,omitempty"`
}

func init() {
	setGlobalLogHandler()
}

// SetListener installs a log/state callback listener.
func SetListener(l Listener) {
	mu.Lock()
	listener = l
	mu.Unlock()
}

// SetSocketProtector installs the Android socket protector used by olcRTC.
func SetSocketProtector(p SocketProtector) {
	olcmobile.SetProtector(p)
}

// SetLogLevel changes olcRTC/mobilebridge log verbosity.
//
// Supported levels are debug, info, warn/warning, error.
func SetLogLevel(newLevel string) {
	switch strings.ToLower(strings.TrimSpace(newLevel)) {
	case "debug":
		mobileSetDebug(true)
	case "", "info", "warn", "warning", "error":
		mobileSetDebug(false)
	default:
		emitLog("", "warn", fmt.Sprintf("unknown log level %q, keeping previous level", newLevel))
	}
}

// Version returns the build version or "dev" when no VCS metadata is present.
func Version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && setting.Value != "" {
				if len(setting.Value) > 8 {
					return setting.Value[:8]
				}
				return setting.Value
			}
		}
	}
	return "dev"
}

// LastLog returns the latest log or state message observed by mobilebridge.
func LastLog() string {
	lastMu.RLock()
	defer lastMu.RUnlock()
	return lastLog
}

// LastError returns the latest error observed by mobilebridge.
func LastError() string {
	lastMu.RLock()
	defer lastMu.RUnlock()
	return lastError
}

// StatusJSON returns the latest core lifecycle status as a JSON object.
func StatusJSON() string {
	diagnosticsMu.RLock()
	snapshot := coreStatus
	diagnosticsMu.RUnlock()
	data, err := json.Marshal(snapshot)
	if err != nil {
		return `{"state":"error","message":"status serialization failed","running":false}`
	}
	return string(data)
}

// LogsJSON returns the latest core log entries as a JSON array.
func LogsJSON() string {
	diagnosticsMu.RLock()
	entries := append([]logEntry(nil), coreLogs...)
	diagnosticsMu.RUnlock()
	data, err := json.Marshal(entries)
	if err != nil {
		return `[]`
	}
	return string(data)
}

// ValidateConfig parses and validates an olcRTC client JSON config.
func ValidateConfig(configJson string) error {
	_, err := parseOlcRTCJSON(configJson)
	return err
}

// Start validates an olcRTC client JSON config and starts a background session.
func Start(configJson string) (string, error) {
	cfg, err := parseOlcRTCJSON(configJson)
	if err != nil {
		return "", err
	}
	setPersistentLogPath(cfg.LogPath)
	_, cancel := context.WithCancel(context.Background())
	return startRunner(cancel, &olcRTCRunner{cfg: cfg})
}

// StartOlcRTC starts an olcRTC Telemost client session.
//
// This compatibility helper uses clientID "android". Prefer Start with JSON and
// an explicit client_id when the server expects a specific client identifier.
func StartOlcRTC(roomID string, keyHex string, socksPort int, socksUser string, socksPass string) (string, error) {
	return StartOlcRTCWithClient(defaultCarrier, "", roomID, defaultClientID, keyHex, socksPort, socksUser, socksPass)
}

// StartOlcRTCWithClient starts an olcRTC session with explicit carrier, transport, and clientID.
func StartOlcRTCWithClient(
	carrier string,
	transport string,
	roomID string,
	clientID string,
	keyHex string,
	socksPort int,
	socksUser string,
	socksPass string,
) (string, error) {
	cfg := olcRTCConfig{
		Carrier:   carrier,
		Transport: transport,
		RoomID:    roomID,
		ClientID:  clientID,
		KeyHex:    keyHex,
		SocksPort: socksPort,
		SocksUser: socksUser,
		SocksPass: socksPass,
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		return "", err
	}
	setPersistentLogPath(cfg.LogPath)
	_, cancel := context.WithCancel(context.Background())
	return startRunner(cancel, &olcRTCRunner{cfg: cfg})
}

// StartFromUrl is kept for ABI compatibility.
func StartFromUrl(configUrl string) (string, error) {
	if strings.TrimSpace(configUrl) == "" {
		return "", errors.New("configUrl is required")
	}
	return "", errors.New("turnable URLs are no longer supported; pass olcRTC JSON to Start")
}

// Stop gracefully stops a running session.
//
// Repeated stops are treated as success so Android lifecycle code can call this
// from multiple callbacks without special casing.
func Stop(sessionId string) error {
	if strings.TrimSpace(sessionId) == "" {
		return errors.New("sessionId is required")
	}

	mu.Lock()
	s, ok := sessions[sessionId]
	if ok {
		delete(sessions, sessionId)
	}
	mu.Unlock()

	if !ok {
		return nil
	}

	emitState(sessionId, stateStopping, "")
	s.cancel()
	err := s.runner.Stop()
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "not running") {
		emitState(sessionId, stateError, err.Error())
		return fmt.Errorf("stop session %s: %w", sessionId, err)
	}

	emitState(sessionId, stateStopped, "")
	return nil
}

// StopAll gracefully stops all running sessions.
func StopAll() error {
	mu.RLock()
	ids := make([]string, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, id)
	}
	mu.RUnlock()

	var err error
	for _, id := range ids {
		err = errors.Join(err, Stop(id))
	}
	return err
}

// IsRunning reports whether a session exists and its olcRTC client is active.
func IsRunning(sessionId string) bool {
	mu.RLock()
	s := sessions[sessionId]
	mu.RUnlock()
	return s != nil && s.runner.IsRunning()
}

// Single-session helpers backing the clean C-ABI (StartCore/StopCore) used by the
// GreenPass plugin. Only one session is active at a time; StartSingle stops any
// current session first.
var (
	singleStartMu sync.Mutex
	singleMu      sync.Mutex
	singleID      string
)

// StartSingle starts exactly one session from an olcRTC JSON config. Any
// previously running session is stopped first. Returns nil on success or an error.
func StartSingle(configJson string) error {
	singleStartMu.Lock()
	defer singleStartMu.Unlock()

	cfg, err := parseOlcRTCJSON(configJson)
	if err != nil {
		singleMu.Lock()
		singleID = ""
		singleMu.Unlock()
		return err
	}
	setPersistentLogPath(cfg.LogPath)
	emitLog("", "info", "StartSingle config accepted")

	_ = StopSingle()

	cancelCtx, cancel := context.WithCancel(context.Background())
	id := uuid.NewString()
	runner := &olcRTCRunner{cfg: cfg, sessionID: id}

	singleMu.Lock()
	singleID = id
	singleMu.Unlock()

	mu.Lock()
	sessions[id] = &session{id: id, cancel: cancel, runner: runner}
	mu.Unlock()

	emitState(id, stateStarting, "")
	if err := startRunnerSafely(runner); err != nil {
		cancel()
		_ = runner.Stop()
		mu.Lock()
		delete(sessions, id)
		mu.Unlock()
		singleMu.Lock()
		if singleID == id {
			singleID = ""
		}
		singleMu.Unlock()
		emitState(id, stateError, err.Error())
		return fmt.Errorf("start session: %w", err)
	}

	if cancelCtx.Err() != nil {
		_ = runner.Stop()
		mu.Lock()
		delete(sessions, id)
		mu.Unlock()
		return context.Canceled
	}

	emitState(id, stateRunning, "")
	return nil
}

// StopSingle stops the active session (if any). Safe to call when nothing is running.
func StopSingle() error {
	singleMu.Lock()
	singleID = ""
	singleMu.Unlock()
	return StopAll()
}

// SingleRunning reports whether the single session is currently running.
func SingleRunning() bool {
	singleMu.Lock()
	id := singleID
	singleMu.Unlock()
	if id == "" {
		return false
	}
	return IsRunning(id)
}

func startRunner(cancel context.CancelFunc, runner sessionRunner) (string, error) {
	id := uuid.NewString()
	if olcRunner, ok := runner.(*olcRTCRunner); ok {
		olcRunner.sessionID = id
	}

	emitState(id, stateStarting, "")
	if err := startRunnerSafely(runner); err != nil {
		cancel()
		emitState(id, stateError, err.Error())
		return "", fmt.Errorf("start session: %w", err)
	}

	mu.Lock()
	sessions[id] = &session{id: id, cancel: cancel, runner: runner}
	mu.Unlock()

	emitState(id, stateRunning, "")
	return id, nil
}

func startRunnerSafely(runner sessionRunner) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return runner.Start()
}

func parseOlcRTCJSON(configJSON string) (olcRTCConfig, error) {
	if strings.TrimSpace(configJSON) == "" {
		return olcRTCConfig{}, errors.New("configJson is required")
	}

	var selector struct {
		Engine string        `json:"engine"`
		OlcRTC *olcRTCConfig `json:"olcrtc"`
	}
	if err := json.Unmarshal([]byte(configJSON), &selector); err != nil {
		return olcRTCConfig{}, fmt.Errorf("parse config JSON: %w", err)
	}

	engineName := strings.ToLower(strings.TrimSpace(selector.Engine))
	if engineName == "" {
		engineName = "olcrtc"
	}
	if engineName != "olcrtc" {
		if engineName == "turnable" {
			return olcRTCConfig{}, errors.New("turnable engine is no longer supported")
		}
		return olcRTCConfig{}, fmt.Errorf("unsupported engine %q", selector.Engine)
	}

	cfg := olcRTCConfig{}
	if selector.OlcRTC != nil {
		cfg = *selector.OlcRTC
	} else if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return olcRTCConfig{}, fmt.Errorf("parse olcRTC config JSON: %w", err)
	}
	cfg.Engine = "olcrtc"
	if err := cfg.normalizeAndValidate(); err != nil {
		return olcRTCConfig{}, err
	}
	return cfg, nil
}

func (c *olcRTCConfig) normalizeAndValidate() error {
	c.Carrier = strings.TrimSpace(firstNonEmpty(c.Carrier, c.Provider, defaultCarrier))
	c.Transport = strings.TrimSpace(c.Transport)
	c.RoomID = strings.TrimSpace(c.RoomID)
	c.ClientID = strings.TrimSpace(firstNonEmpty(c.ClientID, c.DeviceID))
	c.KeyHex = strings.TrimSpace(c.KeyHex)
	c.SocksListenHost = strings.TrimSpace(c.SocksListenHost)
	c.DNSServer = strings.TrimSpace(c.DNSServer)
	c.LogPath = strings.TrimSpace(c.LogPath)

	if c.Carrier == "" {
		return errors.New("carrier is required")
	}
	if c.RoomID == "" {
		return errors.New("room_id is required")
	}
	if c.ClientID == "" {
		return errors.New("client_id is required")
	}
	if c.KeyHex == "" {
		return errors.New("key_hex is required")
	}
	if c.SocksPort <= 0 || c.SocksPort > 65535 {
		return fmt.Errorf("invalid socks_port %d", c.SocksPort)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func maskKeyHex(keyHex string) string {
	trimmed := strings.TrimSpace(keyHex)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 12 {
		return "***"
	}
	return trimmed[:6] + "..." + trimmed[len(trimmed)-6:]
}

type olcRTCRunner struct {
	cfg       olcRTCConfig
	sessionID string
}

func (r *olcRTCRunner) Start() error {
	emitLog(
		r.sessionID,
		"info",
		fmt.Sprintf(
			"runner start carrier=%s transport=%s room=%s client=%s key=%s socks_port=%d",
			r.cfg.Carrier,
			r.cfg.Transport,
			r.cfg.RoomID,
			r.cfg.ClientID,
			maskKeyHex(r.cfg.KeyHex),
			r.cfg.SocksPort,
		),
	)
	if r.cfg.DNSServer != "" {
		emitLog(r.sessionID, "info", fmt.Sprintf("set dns %s", r.cfg.DNSServer))
		mobileSetDNS(r.cfg.DNSServer)
	}
	if r.cfg.SocksListenHost != "" {
		emitLog(r.sessionID, "info", fmt.Sprintf("set socks listen host %s", r.cfg.SocksListenHost))
		mobileSetSocksListenHost(r.cfg.SocksListenHost)
	}
	if r.cfg.VP8FPS > 0 || r.cfg.VP8BatchSize > 0 {
		emitLog(r.sessionID, "info", fmt.Sprintf("set vp8 fps=%d batch=%d", r.cfg.VP8FPS, r.cfg.VP8BatchSize))
		mobileSetVP8Options(r.cfg.VP8FPS, r.cfg.VP8BatchSize)
	}
	if r.cfg.LivenessIntervalMillis > 0 || r.cfg.LivenessTimeoutMillis > 0 || r.cfg.LivenessFailures > 0 {
		emitLog(
			r.sessionID,
			"info",
			fmt.Sprintf(
				"set liveness interval=%d timeout=%d failures=%d",
				r.cfg.LivenessIntervalMillis,
				r.cfg.LivenessTimeoutMillis,
				r.cfg.LivenessFailures,
			),
		)
		mobileSetLivenessOptions(
			r.cfg.LivenessIntervalMillis,
			r.cfg.LivenessTimeoutMillis,
			r.cfg.LivenessFailures,
		)
	}

	emitLog(r.sessionID, "info", "mobileStartWithTransport enter")
	if err := mobileStartWithTransport(
		r.cfg.Carrier,
		r.cfg.Transport,
		r.cfg.RoomID,
		r.cfg.ClientID,
		r.cfg.KeyHex,
		r.cfg.SocksPort,
		r.cfg.SocksUser,
		r.cfg.SocksPass,
	); err != nil {
		emitLog(r.sessionID, "error", fmt.Sprintf("mobileStartWithTransport error: %v", err))
		return err
	}
	emitLog(r.sessionID, "info", "mobileStartWithTransport returned")
	emitState(r.sessionID, stateHandshake, "waiting for WebRTC and local SOCKS")
	if r.cfg.WaitReadyTimeoutMillis > 0 {
		emitLog(r.sessionID, "info", fmt.Sprintf("WaitReady enter timeout_ms=%d", r.cfg.WaitReadyTimeoutMillis))
		if err := mobileWaitReady(r.cfg.WaitReadyTimeoutMillis); err != nil {
			emitLog(r.sessionID, "error", fmt.Sprintf("WaitReady error: %v", err))
			mobileStop()
			return err
		}
		emitLog(r.sessionID, "info", "WaitReady returned")
		emitState(r.sessionID, stateReady, "local SOCKS ready")
	}
	return nil
}

func (r *olcRTCRunner) Stop() error {
	emitLog(r.sessionID, "info", "mobileStop enter")
	mobileStop()
	emitLog(r.sessionID, "info", "mobileStop returned")
	return nil
}

func (r *olcRTCRunner) IsRunning() bool {
	return mobileIsRunning()
}

func setGlobalLogHandler() {
	olcmobile.SetLogWriter(&olcRTCLogWriter{})
	log.SetOutput(&stdLogBridge{})
}

func emitLog(sessionID, level, message string) {
	rememberLog(level, message)
	rememberDiagnosticLog(sessionID, level, message, "")
	mu.RLock()
	l := listener
	mu.RUnlock()
	if l != nil {
		l.OnLog(sessionID, level, message)
	}
}

func emitState(sessionID, state, message string) {
	rememberState(state, message)
	rememberDiagnosticState(sessionID, state, message)
	mu.RLock()
	l := listener
	mu.RUnlock()
	if l != nil {
		l.OnState(sessionID, state, message)
	}
}

func rememberDiagnosticLog(sessionID, level, message, state string) {
	text := strings.TrimSpace(message)
	if text == "" {
		return
	}
	entry := logEntry{
		TimestampMillis: time.Now().UnixMilli(),
		SessionID:       strings.TrimSpace(sessionID),
		Level:           strings.ToLower(strings.TrimSpace(level)),
		Message:         text,
		State:           strings.TrimSpace(state),
	}
	if entry.Level == "" {
		entry.Level = "info"
	}
	diagnosticsMu.Lock()
	coreLogs = append(coreLogs, entry)
	if len(coreLogs) > maxCoreLogEntries {
		coreLogs = append([]logEntry(nil), coreLogs[len(coreLogs)-maxCoreLogEntries:]...)
	}
	diagnosticsMu.Unlock()
	if shouldPersistLogEntry(entry) {
		writePersistentLog(entry)
	}
}

func rememberDiagnosticState(sessionID, state, message string) {
	statusState := strings.ToLower(strings.TrimSpace(state))
	if statusState == stateRunning {
		statusState = stateReady
	}
	if statusState == "" {
		return
	}
	text := strings.TrimSpace(message)
	diagnosticsMu.Lock()
	coreStatus = statusSnapshot{
		State:           statusState,
		Message:         text,
		SessionID:       strings.TrimSpace(sessionID),
		UpdatedAtMillis: time.Now().UnixMilli(),
		Running:         statusState == stateReady,
	}
	diagnosticsMu.Unlock()
	logMessage := text
	if logMessage == "" {
		logMessage = statusState
	}
	rememberDiagnosticLog(sessionID, "state", logMessage, statusState)
}

func rememberLog(logLevel, message string) {
	text := strings.TrimSpace(message)
	if text == "" {
		return
	}
	lastMu.Lock()
	lastLog = fmt.Sprintf("%s: %s", strings.ToLower(strings.TrimSpace(logLevel)), text)
	if strings.EqualFold(strings.TrimSpace(logLevel), "error") {
		lastError = text
	}
	lastMu.Unlock()
}

func setPersistentLogPath(logPath string) {
	trimmed := strings.TrimSpace(logPath)
	persistentLogMu.Lock()
	persistentLogPath = trimmed
	persistentLogMu.Unlock()
	if trimmed != "" {
		writePersistentLog(logEntry{
			TimestampMillis: time.Now().UnixMilli(),
			Level:           "info",
			Message:         "persistent log enabled",
		})
	}
}

func shouldPersistLogEntry(entry logEntry) bool {
	level := strings.ToLower(strings.TrimSpace(entry.Level))
	state := strings.ToLower(strings.TrimSpace(entry.State))
	message := strings.TrimSpace(entry.Message)
	if level == "error" || level == "warn" || level == "warning" || state != "" {
		return true
	}
	if strings.Contains(message, " tunnel to ") && strings.Contains(message, "sid=") {
		return false
	}
	return true
}

func writePersistentLog(entry logEntry) {
	persistentLogMu.Lock()
	logPath := persistentLogPath
	persistentLogMu.Unlock()
	if strings.TrimSpace(logPath) == "" {
		return
	}
	if entry.TimestampMillis == 0 {
		entry.TimestampMillis = time.Now().UnixMilli()
	}
	if strings.TrimSpace(entry.Level) == "" {
		entry.Level = "info"
	}
	record := map[string]any{
		"ms":      entry.TimestampMillis,
		"ts":      time.UnixMilli(entry.TimestampMillis).Format("2006-01-02 15:04:05"),
		"level":   strings.ToLower(strings.TrimSpace(entry.Level)),
		"message": strings.TrimSpace(entry.Message),
	}
	if strings.TrimSpace(entry.SessionID) != "" {
		record["session_id"] = strings.TrimSpace(entry.SessionID)
	}
	if strings.TrimSpace(entry.State) != "" {
		record["state"] = strings.TrimSpace(entry.State)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	persistentLogMu.Lock()
	defer persistentLogMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return
	}
	rotatePersistentLogLocked(logPath)
	fileHandle, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer fileHandle.Close()
	_, _ = fileHandle.Write(append(data, '\n'))
	_ = fileHandle.Sync()
}

func rotatePersistentLogLocked(logPath string) {
	info, err := os.Stat(logPath)
	if err != nil || info.Size() <= persistentLogMaxBytes {
		return
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		return
	}
	tailSize := persistentLogMaxBytes / 2
	if len(data) > tailSize {
		data = data[len(data)-tailSize:]
	}
	_ = os.WriteFile(logPath, append([]byte("...truncated...\n"), data...), 0o600)
}

func rememberState(state, message string) {
	text := strings.TrimSpace(message)
	if text == "" {
		text = strings.TrimSpace(state)
	} else {
		text = fmt.Sprintf("%s: %s", strings.TrimSpace(state), text)
	}
	if text == "" {
		return
	}
	lastMu.Lock()
	lastLog = text
	if strings.EqualFold(strings.TrimSpace(state), stateError) {
		lastError = text
	}
	lastMu.Unlock()
}

type olcRTCLogWriter struct{}

func (w *olcRTCLogWriter) WriteLog(msg string) {
	emitLog("", "info", msg)
}

type stdLogBridge struct{}

func (b *stdLogBridge) Write(p []byte) (int, error) {
	emitLog("", "info", strings.TrimSpace(string(p)))
	return len(p), nil
}

// sleepForTests gives lifecycle tests a stable synchronization point without
// exporting test-only API to gomobile.
func sleepForTests() {
	time.Sleep(10 * time.Millisecond)
}
