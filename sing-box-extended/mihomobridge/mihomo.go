// Package mihomobridge runs Mihomo inside the shared GreenPass Go runtime.
package mihomobridge

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
)

const (
	maxConfigBytes = 2 * 1024 * 1024
	maxLogEntries  = 200
)

type startConfig struct {
	Engine    string   `json:"engine"`
	Config    string   `json:"config,omitempty"`
	Links     []string `json:"links,omitempty"`
	WorkDir   string   `json:"work_dir"`
	MixedPort int      `json:"mixed_port"`
	Username  string   `json:"username,omitempty"`
	Password  string   `json:"password,omitempty"`
}

type statusSnapshot struct {
	State     string `json:"state"`
	Message   string `json:"message,omitempty"`
	StartedAt int64  `json:"started_at,omitempty"`
	StoppedAt int64  `json:"stopped_at,omitempty"`
	Version   string `json:"version,omitempty"`
}

type logEntry struct {
	Timestamp int64  `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	State     string `json:"state,omitempty"`
}

var (
	mu        sync.Mutex
	running   bool
	state     = "stopped"
	stateMsg  string
	startedAt time.Time
	stoppedAt time.Time

	logOnce sync.Once
	logMu   sync.Mutex
	logRing []logEntry
	lastLog string
	lastErr string
)

func parseEnvelope(configJSON string) (startConfig, error) {
	var in startConfig
	if len(configJSON) > maxConfigBytes {
		return in, fmt.Errorf("configuration is too large")
	}
	if err := json.Unmarshal([]byte(configJSON), &in); err != nil {
		return in, fmt.Errorf("decode mihomo envelope: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(in.Engine), "mihomo") {
		return in, fmt.Errorf("engine must be mihomo")
	}
	if strings.TrimSpace(in.Config) == "" && len(in.Links) == 0 {
		return in, fmt.Errorf("mihomo config or links are required")
	}
	if in.MixedPort < 1 || in.MixedPort > 65535 {
		return in, fmt.Errorf("invalid mixed port")
	}
	if (in.Username == "") != (in.Password == "") || strings.ContainsAny(in.Username+in.Password, ":\r\n") {
		return in, fmt.Errorf("invalid SOCKS credentials")
	}
	if strings.TrimSpace(in.WorkDir) == "" {
		return in, fmt.Errorf("work directory is required")
	}
	return in, nil
}

func rawConfig(in startConfig) (*config.RawConfig, error) {
	workDir, err := filepath.Abs(filepath.Clean(in.WorkDir))
	if err != nil {
		return nil, fmt.Errorf("resolve work directory: %w", err)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("create work directory: %w", err)
	}
	constant.SetHomeDir(workDir)

	var raw *config.RawConfig
	if strings.TrimSpace(in.Config) != "" {
		raw, err = config.UnmarshalRawConfig([]byte(in.Config))
		if err != nil {
			return nil, fmt.Errorf("parse mihomo config: %w", err)
		}
	} else {
		proxies, convertErr := convert.ConvertsV2Ray([]byte(strings.Join(in.Links, "\n")))
		if convertErr != nil {
			return nil, fmt.Errorf("convert proxy links: %w", convertErr)
		}
		if len(proxies) == 0 {
			return nil, fmt.Errorf("mihomo did not recognize these proxy links")
		}
		raw = config.DefaultRawConfig()
		raw.Proxy = proxies
		names := make([]string, 0, len(proxies))
		usedNames := make(map[string]bool, len(proxies))
		for index, proxy := range proxies {
			name, _ := proxy["name"].(string)
			name = strings.TrimSpace(name)
			if name == "" {
				name = fmt.Sprintf("Proxy %d", index+1)
			}
			base := name
			for suffix := 2; usedNames[name]; suffix++ {
				name = fmt.Sprintf("%s #%d", base, suffix)
			}
			proxy["name"] = name
			usedNames[name] = true
			names = append(names, name)
		}
		group := map[string]any{"name": "GREENPASS", "type": "select", "proxies": names}
		if len(names) > 1 {
			group["type"] = "url-test"
			group["url"] = "https://cp.cloudflare.com/generate_204"
			group["interval"] = 180
			group["tolerance"] = 50
		}
		raw.ProxyGroup = []map[string]any{group}
		raw.Rule = []string{"MATCH,GREENPASS"}
	}

	// GreenPass owns the only local listener. Imported configs may define TUN,
	// controllers or LAN listeners; none of those belong inside ExteraGram.
	raw.Port = 0
	raw.SocksPort = 0
	raw.RedirPort = 0
	raw.TProxyPort = 0
	raw.ShadowSocksConfig = ""
	raw.VmessConfig = ""
	raw.MixedPort = in.MixedPort
	raw.AllowLan = false
	raw.BindAddress = "127.0.0.1"
	raw.Authentication = nil
	raw.SkipAuthPrefixes = nil
	raw.LanAllowedIPs = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
	raw.LanDisAllowedIPs = nil
	if in.Username != "" {
		raw.Authentication = []string{in.Username + ":" + in.Password}
	}
	raw.Interface = ""
	raw.RoutingMark = 0
	raw.ExternalController = ""
	raw.ExternalControllerRoutingMark = 0
	raw.ExternalControllerTLS = ""
	raw.ExternalControllerUnix = ""
	raw.ExternalControllerPipe = ""
	raw.ExternalUI = ""
	raw.ExternalUIURL = ""
	raw.ExternalUIName = ""
	raw.ExternalDohServer = ""
	raw.Secret = ""
	raw.Listeners = nil
	raw.Tunnels = nil
	raw.Tun.Enable = false
	raw.TuicServer.Enable = false
	raw.IPTables.Enable = false
	raw.DNS.Listen = ""
	raw.NTP.WriteToSystem = false
	return raw, nil
}

func prepare(configJSON string) (*config.Config, error) {
	in, err := parseEnvelope(configJSON)
	if err != nil {
		return nil, err
	}
	raw, err := rawConfig(in)
	if err != nil {
		return nil, err
	}
	cfg, err := config.ParseRawConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("decode mihomo config: %w", err)
	}
	return cfg, nil
}

func apply(cfg *config.Config) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("mihomo panic: %v", recovered)
		}
	}()
	hub.ApplyConfig(cfg)
	return nil
}

func Start(configJSON string) error {
	mu.Lock()
	defer mu.Unlock()
	startLogCollector()
	clearLastError()

	cfg, err := prepare(configJSON)
	if err != nil {
		setStateLocked("error", err.Error())
		return err
	}
	if running {
		executor.Shutdown()
		running = false
	}
	setStateLocked("starting", "")
	if err := apply(cfg); err != nil {
		setStateLocked("error", err.Error())
		return err
	}
	running = true
	startedAt = time.Now()
	setStateLocked("running", "")
	return nil
}

func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return nil
	}
	setStateLocked("stopping", "")
	executor.Shutdown()
	running = false
	stoppedAt = time.Now()
	setStateLocked("stopped", "")
	return nil
}

func ValidateConfig(configJSON string) error {
	mu.Lock()
	defer mu.Unlock()
	_, err := prepare(configJSON)
	return err
}

func SingleRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

func Version() string { return constant.Version }

func StatusJSON() string {
	mu.Lock()
	snapshot := statusSnapshot{State: state, Message: stateMsg, Version: Version()}
	if !startedAt.IsZero() {
		snapshot.StartedAt = startedAt.Unix()
	}
	if !stoppedAt.IsZero() {
		snapshot.StoppedAt = stoppedAt.Unix()
	}
	mu.Unlock()
	out, _ := json.Marshal(snapshot)
	return string(out)
}

func LogsJSON() string {
	logMu.Lock()
	entries := append([]logEntry(nil), logRing...)
	logMu.Unlock()
	if entries == nil {
		return "[]"
	}
	out, _ := json.Marshal(entries)
	return string(out)
}

func LastLog() string {
	logMu.Lock()
	defer logMu.Unlock()
	return lastLog
}

func LastError() string {
	logMu.Lock()
	defer logMu.Unlock()
	return lastErr
}

func startLogCollector() {
	logOnce.Do(func() {
		sub := log.Subscribe()
		go func() {
			for event := range sub {
				if event.LogLevel < log.INFO {
					continue
				}
				rememberLog(event.Type(), strings.TrimSpace(event.Payload), "")
			}
		}()
	})
}

func setStateLocked(nextState, message string) {
	state = nextState
	stateMsg = message
	level := "info"
	if nextState == "error" {
		level = "error"
	}
	rememberLog(level, message, nextState)
}

func rememberLog(level, message, state string) {
	if level == "" && message == "" && state == "" {
		return
	}
	entry := logEntry{Timestamp: time.Now().UnixMilli(), Level: strings.ToLower(level), Message: message, State: state}
	logMu.Lock()
	if state != "" {
		lastLog = fmt.Sprintf("[%s] %s", entry.Level, state)
	} else {
		lastLog = fmt.Sprintf("[%s] %s", entry.Level, message)
	}
	if entry.Level == "error" || state == "error" {
		lastErr = message
	}
	logRing = append(logRing, entry)
	if len(logRing) > maxLogEntries {
		logRing = logRing[len(logRing)-maxLogEntries:]
	}
	logMu.Unlock()
}

func clearLastError() {
	logMu.Lock()
	lastErr = ""
	logMu.Unlock()
}
