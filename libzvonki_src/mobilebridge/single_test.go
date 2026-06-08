package mobilebridge

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestStartSingleStopSingleWithMock(t *testing.T) {
	runtime := installMockRuntime()
	defer runtime.restore()
	defer func() { _ = StopSingle() }()

	if err := StartSingle(validOlcRTCConfigJSON()); err != nil {
		t.Fatalf("StartSingle() error = %v", err)
	}
	if !SingleRunning() {
		t.Fatal("SingleRunning() = false after StartSingle, want true")
	}
	if err := StopSingle(); err != nil {
		t.Fatalf("StopSingle() error = %v", err)
	}
	if SingleRunning() {
		t.Fatal("SingleRunning() = true after StopSingle, want false")
	}
}

func TestStartSingleReplacesPrevious(t *testing.T) {
	runtime := installMockRuntime()
	defer runtime.restore()
	defer func() { _ = StopSingle() }()

	if err := StartSingle(validOlcRTCConfigJSON()); err != nil {
		t.Fatalf("first StartSingle() error = %v", err)
	}
	if err := StartSingle(validOlcRTCConfigJSON()); err != nil {
		t.Fatalf("second StartSingle() should stop-then-start, error = %v", err)
	}
	if !SingleRunning() {
		t.Fatal("SingleRunning() = false after restart, want true")
	}
}

func TestConcurrentStartSingleSerializesReplacement(t *testing.T) {
	runtime := installMockRuntime()
	defer runtime.restore()
	defer func() { _ = StopSingle() }()

	var stateMu sync.Mutex
	active := false
	stopCalls := 0
	firstStopEntered := make(chan struct{})
	releaseFirstStop := make(chan struct{})

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
		stateMu.Lock()
		defer stateMu.Unlock()
		if active {
			return errors.New("olcRTC already running")
		}
		active = true
		return nil
	}
	mobileWaitReady = func(int) error {
		return nil
	}
	mobileStop = func() {
		stateMu.Lock()
		stopCalls++
		call := stopCalls
		stateMu.Unlock()
		if call == 1 {
			close(firstStopEntered)
			<-releaseFirstStop
		}
		stateMu.Lock()
		active = false
		stateMu.Unlock()
	}
	mobileIsRunning = func() bool {
		stateMu.Lock()
		defer stateMu.Unlock()
		return active
	}

	if err := StartSingle(validOlcRTCConfigJSON()); err != nil {
		t.Fatalf("initial StartSingle() error = %v", err)
	}

	results := make(chan error, 2)
	go func() {
		results <- StartSingle(validOlcRTCConfigJSON())
	}()
	select {
	case <-firstStopEntered:
	case <-time.After(time.Second):
		t.Fatal("replacement did not begin stopping the previous session")
	}

	go func() {
		results <- StartSingle(validOlcRTCConfigJSON())
	}()
	time.Sleep(50 * time.Millisecond)
	close(releaseFirstStop)

	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent StartSingle() error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent StartSingle() timed out")
		}
	}
}
