package mobilebridge

import (
	"strings"
	"testing"
	"time"

	boxlog "github.com/sagernet/sing-box/log"
)

// minimalValidConfig is the smallest sing-box config that actually starts a
// local mixed inbound (SOCKS+HTTP) bound to an ephemeral port and a direct
// outbound. It exercises the real box.New -> PreStart -> Start -> Close path.
const minimalValidConfig = `{
  "log": {"disabled": true},
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ]
}`

func TestValidateConfig_RejectsGarbage(t *testing.T) {
	err := ValidateConfig(`{not json`)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestValidateConfig_AcceptsMinimal(t *testing.T) {
	if err := ValidateConfig(minimalValidConfig); err != nil {
		t.Fatalf("expected nil for minimal valid config, got: %v", err)
	}
}

func TestStartStopSingle_Lifecycle(t *testing.T) {
	// Ensure clean slate.
	_ = StopSingle()

	if err := StartSingle(minimalValidConfig); err != nil {
		t.Fatalf("StartSingle failed: %v\nstatus=%s", err, StatusJSON())
	}

	if !SingleRunning() {
		t.Fatalf("expected running after start; status=%s", StatusJSON())
	}

	st := StatusJSON()
	if !strings.Contains(st, `"state":"running"`) {
		t.Fatalf("expected state running in status, got: %s", st)
	}

	if err := StopSingle(); err != nil {
		t.Fatalf("StopSingle failed: %v", err)
	}

	// After stop, running must be false and state stopped (or error).
	if SingleRunning() {
		t.Fatalf("expected not running after stop; status=%s", StatusJSON())
	}
	st2 := StatusJSON()
	if !strings.Contains(st2, `"state":"stopped"`) && !strings.Contains(st2, `"state":"error"`) {
		t.Fatalf("expected state stopped or error after stop, got: %s", st2)
	}
}

func TestStopSingle_IdempotentWhenNothingRunning(t *testing.T) {
	_ = StopSingle()
	if err := StopSingle(); err != nil {
		t.Fatalf("double StopSingle should be safe, got: %v", err)
	}
}

func TestStartSingle_ReplacesPreviousInstance(t *testing.T) {
	_ = StopSingle()
	if err := StartSingle(minimalValidConfig); err != nil {
		t.Fatalf("first StartSingle failed: %v", err)
	}
	if !SingleRunning() {
		t.Fatalf("expected running after first start; status=%s", StatusJSON())
	}
	// Starting again must stop the previous instance and start a new one.
	if err := StartSingle(minimalValidConfig); err != nil {
		t.Fatalf("second StartSingle failed: %v", err)
	}
	if !SingleRunning() {
		t.Fatalf("expected running after second start; status=%s", StatusJSON())
	}
	_ = StopSingle()
}

func TestLogsJSON_ReturnsArray(t *testing.T) {
	_ = StopSingle()
	_ = StartSingle(minimalValidConfig)
	_ = StopSingle()
	got := LogsJSON()
	if !strings.HasPrefix(got, "[") {
		t.Fatalf("expected JSON array, got: %s", got)
	}
}

func TestBridgeLogWriter_RetainsCoreMessages(t *testing.T) {
	bridgeLogWriter{}.WriteMessage(boxlog.LevelError, "TLS handshake failed")
	if !strings.Contains(LogsJSON(), "TLS handshake failed") {
		t.Fatalf("core log message was not retained: %s", LogsJSON())
	}
}

func TestStatusJSON_HasState(t *testing.T) {
	got := StatusJSON()
	if !strings.Contains(got, `"state"`) {
		t.Fatalf("expected state field, got: %s", got)
	}
}

// TestSubscribeLogs_ReceiveEntries verifies the diagnostics ring is observable.
func TestSubscribeLogs_ReceiveEntries(t *testing.T) {
	_ = StopSingle()
	ch := SubscribeLogs()
	defer UnsubscribeLogs(ch)
	_ = StartSingle(minimalValidConfig)
	_ = StopSingle()

	// State transitions starting/running/stopping/stopped should arrive.
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a log entry via subscription")
	}
}
