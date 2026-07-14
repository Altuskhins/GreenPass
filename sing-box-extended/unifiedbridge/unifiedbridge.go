package unifiedbridge

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	olcrtc "combinedtunnel/mobilebridge"
	singbox "singboxextended/mobilebridge"
	qwdtt "singboxextended/qwdttbridge"
)

const (
	EngineSingBox = "singbox"
	EngineOlcRTC  = "olcrtc"
	EngineQWDTT   = "qwdtt"
)

var (
	mu                  sync.Mutex
	lastEngine          = EngineSingBox
	qwdttStartSerial    uint64
	qwdttStartingSerial uint64
)

func configEngine(configJSON string) string {
	var header struct {
		Engine string `json:"engine"`
	}
	if json.Unmarshal([]byte(configJSON), &header) == nil {
		switch strings.ToLower(strings.TrimSpace(header.Engine)) {
		case EngineOlcRTC:
			return EngineOlcRTC
		case EngineQWDTT:
			return EngineQWDTT
		}
	}
	return EngineSingBox
}

func Start(configJSON string) error {
	engine := configEngine(configJSON)
	if engine == EngineQWDTT {
		// Validate before replacing a working qWDTT session.
		if err := qwdtt.ValidateConfig(configJSON); err != nil {
			return err
		}
	}

	mu.Lock()
	if qwdttStartingSerial != 0 {
		if err := qwdtt.StopSingle(); err != nil {
			mu.Unlock()
			return err
		}
		qwdttStartingSerial = 0
	}
	current := currentEngineLocked()
	if current != "" && current != engine {
		if err := stopEngineLocked(current); err != nil {
			mu.Unlock()
			return err
		}
	}
	lastEngine = engine
	if engine == EngineQWDTT {
		// qWDTT may wait for a server-issued WireGuard config. Do not hold the
		// unified lock, otherwise Stop cannot cancel that wait.
		qwdttStartSerial++
		serial := qwdttStartSerial
		qwdttStartingSerial = serial
		mu.Unlock()
		err := qwdtt.StartSingle(configJSON)
		mu.Lock()
		if qwdttStartingSerial == serial {
			qwdttStartingSerial = 0
		}
		mu.Unlock()
		return err
	}
	defer mu.Unlock()
	if engine == EngineOlcRTC {
		return olcrtc.StartSingle(configJSON)
	}
	return singbox.StartSingle(configJSON)
}

func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	qwdttStartingSerial = 0
	return stopLocked()
}

func stopLocked() error {
	qwdttErr := qwdtt.StopSingle()
	singErr := singbox.StopSingle()
	olcErr := olcrtc.StopSingle()
	if qwdttErr != nil {
		return qwdttErr
	}
	if singErr != nil {
		return singErr
	}
	return olcErr
}

func currentEngineLocked() string {
	if qwdtt.SingleRunning() {
		return EngineQWDTT
	}
	if olcrtc.SingleRunning() {
		return EngineOlcRTC
	}
	if singbox.SingleRunning() {
		return EngineSingBox
	}
	return ""
}

func stopEngineLocked(engine string) error {
	if engine == EngineQWDTT {
		return qwdtt.StopSingle()
	}
	if engine == EngineOlcRTC {
		return olcrtc.StopSingle()
	}
	if engine == EngineSingBox {
		return singbox.StopSingle()
	}
	return stopLocked()
}

func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return qwdtt.SingleRunning() || singbox.SingleRunning() || olcrtc.SingleRunning()
}

func CurrentEngine() string {
	mu.Lock()
	defer mu.Unlock()
	if qwdtt.SingleRunning() {
		return EngineQWDTT
	}
	if olcrtc.SingleRunning() {
		return EngineOlcRTC
	}
	if singbox.SingleRunning() {
		return EngineSingBox
	}
	return lastEngine
}

func ValidateConfig(configJSON string) error {
	if configEngine(configJSON) == EngineOlcRTC {
		return olcrtc.ValidateConfig(configJSON)
	}
	if configEngine(configJSON) == EngineQWDTT {
		return qwdtt.ValidateConfig(configJSON)
	}
	return singbox.ValidateConfig(configJSON)
}

func Version() string {
	return fmt.Sprintf("greenpass sing-box/%s olcrtc/%s qwdtt/%s", singbox.Version(), olcrtc.Version(), qwdtt.Version())
}

func LastLog() string {
	if CurrentEngine() == EngineQWDTT {
		return qwdtt.LastLog()
	}
	if CurrentEngine() == EngineOlcRTC {
		return olcrtc.LastLog()
	}
	return singbox.LastLog()
}

func LastError() string {
	if CurrentEngine() == EngineQWDTT {
		return qwdtt.LastError()
	}
	if CurrentEngine() == EngineOlcRTC {
		return olcrtc.LastError()
	}
	return singbox.LastError()
}

func StatusJSON() string {
	if CurrentEngine() == EngineQWDTT {
		return qwdtt.StatusJSON()
	}
	if CurrentEngine() == EngineOlcRTC {
		return olcrtc.StatusJSON()
	}
	return singbox.StatusJSON()
}

func LogsJSON() string {
	if CurrentEngine() == EngineQWDTT {
		return qwdtt.LogsJSON()
	}
	if CurrentEngine() == EngineOlcRTC {
		return olcrtc.LogsJSON()
	}
	return singbox.LogsJSON()
}
