package mobilebridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	if err := ValidateConfig(validOlcRTCConfigJSON()); err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}

	if err := ValidateConfig(`{"engine":"turnable"}`); err == nil {
		t.Fatal("ValidateConfig() expected an error for turnable")
	}
	if err := ValidateConfig(`{"engine":"olcrtc","room_id":"room","key_hex":"key","socks_port":1080}`); err == nil {
		t.Fatal("ValidateConfig() expected an error for missing client_id")
	}
}

func TestStartStopLifecycleWithMock(t *testing.T) {
	runtime := installMockRuntime()
	defer runtime.restore()
	defer func() { _ = StopAll() }()

	sessionID, err := Start(validOlcRTCConfigJSON())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if sessionID == "" {
		t.Fatal("Start() returned an empty session id")
	}
	if !IsRunning(sessionID) {
		t.Fatal("IsRunning() = false, want true")
	}
	if runtime.last.carrier != "jitsi" ||
		runtime.last.transport != "datachannel" ||
		runtime.last.roomID != "room-id" ||
		runtime.last.clientID != "client-id" ||
		runtime.last.socksPort != 10808 {
		t.Fatalf("Start args = %+v", runtime.last)
	}
	if runtime.waitTimeout != 2500 {
		t.Fatalf("WaitReady timeout = %d, want 2500", runtime.waitTimeout)
	}

	if err := Stop(sessionID); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if IsRunning(sessionID) {
		t.Fatal("IsRunning() = true after Stop")
	}
}

func TestRepeatedStopDoesNotFail(t *testing.T) {
	runtime := installMockRuntime()
	defer runtime.restore()
	defer func() { _ = StopAll() }()

	sessionID, err := Start(validOlcRTCConfigJSON())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if err := Stop(sessionID); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := Stop(sessionID); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
}

func TestStartFromUrlRejected(t *testing.T) {
	if _, err := StartFromUrl("turnable://example"); err == nil {
		t.Fatal("StartFromUrl() expected an error")
	}
}

func TestStartFailsWhenWaitReadyFails(t *testing.T) {
	runtime := installMockRuntime()
	defer runtime.restore()
	runtime.waitErr = errors.New("not ready")

	if _, err := Start(validOlcRTCConfigJSON()); err == nil {
		t.Fatal("Start() expected WaitReady error")
	}
	if runtime.running {
		t.Fatal("runtime should be stopped after WaitReady failure")
	}
}

func TestStatusJSONTracksLifecycle(t *testing.T) {
	emitState("session-1", stateStarting, "initializing")

	var status struct {
		State           string `json:"state"`
		Message         string `json:"message"`
		SessionID       string `json:"session_id"`
		UpdatedAtMillis int64  `json:"updated_at_millis"`
		Running         bool   `json:"running"`
	}
	if err := json.Unmarshal([]byte(StatusJSON()), &status); err != nil {
		t.Fatalf("StatusJSON() returned invalid JSON: %v", err)
	}
	if status.State != stateStarting || status.Message != "initializing" || status.SessionID != "session-1" {
		t.Fatalf("starting status = %+v", status)
	}
	if status.UpdatedAtMillis <= 0 {
		t.Fatalf("UpdatedAtMillis = %d, want positive", status.UpdatedAtMillis)
	}
	if status.Running {
		t.Fatal("Running = true while starting")
	}

	emitState("session-1", stateRunning, "SOCKS ready")
	if err := json.Unmarshal([]byte(StatusJSON()), &status); err != nil {
		t.Fatalf("StatusJSON() returned invalid ready JSON: %v", err)
	}
	if status.State != stateReady || !status.Running {
		t.Fatalf("ready status = %+v", status)
	}
}

func TestLogsJSONKeepsLatestHundredEntries(t *testing.T) {
	for index := 0; index < 105; index++ {
		emitLog("session-ring", "info", fmt.Sprintf("ring-%03d", index))
	}

	var entries []struct {
		TimestampMillis int64  `json:"timestamp_millis"`
		SessionID       string `json:"session_id"`
		Level           string `json:"level"`
		Message         string `json:"message"`
	}
	if err := json.Unmarshal([]byte(LogsJSON()), &entries); err != nil {
		t.Fatalf("LogsJSON() returned invalid JSON: %v", err)
	}
	if len(entries) != 100 {
		t.Fatalf("len(LogsJSON()) = %d, want 100", len(entries))
	}
	if entries[0].Message != "ring-005" || entries[99].Message != "ring-104" {
		t.Fatalf("ring boundaries = %q .. %q", entries[0].Message, entries[99].Message)
	}
	for _, entry := range entries {
		if entry.TimestampMillis <= 0 || entry.SessionID != "session-ring" || entry.Level != "info" {
			t.Fatalf("invalid log entry = %+v", entry)
		}
	}
}

type mockRuntime struct {
	running     bool
	waitErr     error
	waitTimeout int
	last        mockStartArgs
	restore     func()
}

type mockStartArgs struct {
	carrier   string
	transport string
	roomID    string
	clientID  string
	keyHex    string
	socksPort int
	socksUser string
	socksPass string
}

func installMockRuntime() *mockRuntime {
	runtime := &mockRuntime{}

	previousStart := mobileStartWithTransport
	previousWaitReady := mobileWaitReady
	previousStop := mobileStop
	previousIsRunning := mobileIsRunning
	previousSetDebug := mobileSetDebug
	previousSetDNS := mobileSetDNS
	previousSetSocksListenHost := mobileSetSocksListenHost
	previousSetVP8Options := mobileSetVP8Options
	previousSetLivenessOptions := mobileSetLivenessOptions

	mu.Lock()
	previousSessions := sessions
	sessions = make(map[string]*session)
	mu.Unlock()

	mobileStartWithTransport = func(
		carrierName string,
		transportName string,
		roomID string,
		clientID string,
		keyHex string,
		socksPort int,
		socksUser string,
		socksPass string,
	) error {
		runtime.running = true
		runtime.last = mockStartArgs{
			carrier:   carrierName,
			transport: transportName,
			roomID:    roomID,
			clientID:  clientID,
			keyHex:    keyHex,
			socksPort: socksPort,
			socksUser: socksUser,
			socksPass: socksPass,
		}
		return nil
	}
	mobileWaitReady = func(timeoutMillis int) error {
		runtime.waitTimeout = timeoutMillis
		return runtime.waitErr
	}
	mobileStop = func() {
		runtime.running = false
	}
	mobileIsRunning = func() bool {
		return runtime.running
	}
	mobileSetDebug = func(bool) {}
	mobileSetDNS = func(string) {}
	mobileSetSocksListenHost = func(string) {}
	mobileSetVP8Options = func(int, int) {}
	mobileSetLivenessOptions = func(int, int, int) {}

	runtime.restore = func() {
		_ = StopAll()
		mobileStartWithTransport = previousStart
		mobileWaitReady = previousWaitReady
		mobileStop = previousStop
		mobileIsRunning = previousIsRunning
		mobileSetDebug = previousSetDebug
		mobileSetDNS = previousSetDNS
		mobileSetSocksListenHost = previousSetSocksListenHost
		mobileSetVP8Options = previousSetVP8Options
		mobileSetLivenessOptions = previousSetLivenessOptions
		mu.Lock()
		sessions = previousSessions
		mu.Unlock()
	}

	return runtime
}

func validOlcRTCConfigJSON() string {
	return `{
		"engine": "olcrtc",
		"carrier": "jitsi",
		"transport": "datachannel",
		"room_id": "room-id",
		"client_id": "client-id",
		"key_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"socks_port": 10808,
		"socks_user": "u",
		"socks_pass": "p",
		"wait_ready_timeout_millis": 2500
	}`
}
