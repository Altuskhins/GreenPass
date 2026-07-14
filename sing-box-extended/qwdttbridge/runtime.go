// qWDTT/WDTT transport bridge for the unified GreenPass core.
//
// The generated upstream_*.go sources implement the original TURN + DTLS +
// WRAP/RTP transport. This file keeps that transport in the same Go runtime as
// sing-box, then turns the server-issued WireGuard configuration into a local
// sing-box SOCKS endpoint.
package qwdttbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	singbox "singboxextended/mobilebridge"
)

const (
	EngineName    = "qwdtt"
	bridgeVersion = "qwdtt/wdtt-compatible"
)

type rawConfig struct {
	Engine                 string          `json:"engine"`
	Peer                   string          `json:"peer"`
	Server                 string          `json:"server"`
	DTLSHost               string          `json:"dtls_host"`
	DTLSPort               int             `json:"dtls_port"`
	ServerPort             int             `json:"server_port"`
	Hashes                 json.RawMessage `json:"hashes"`
	VKHashes               json.RawMessage `json:"vk_hashes"`
	VKHash                 string          `json:"vk_hash"`
	Password               string          `json:"password"`
	Pass                   string          `json:"pass"`
	Workers                int             `json:"workers"`
	LocalPort              int             `json:"local_port"`
	Port                   int             `json:"port"`
	DeviceID               string          `json:"device_id"`
	ClientID               string          `json:"client_id"`
	SocksListenHost        string          `json:"socks_listen_host"`
	SocksPort              int             `json:"socks_port"`
	TurnHost               string          `json:"turn_host"`
	TurnPort               string          `json:"turn_port"`
	VKAnonPath             string          `json:"vk_anon_path"`
	WaitReadyTimeoutMillis int             `json:"wait_ready_timeout_millis"`
}

type bridgeConfig struct {
	peer       string
	hashes     []string
	password   string
	workers    int
	localPort  int
	deviceID   string
	socksHost  string
	socksPort  int
	turnHost   string
	turnPort   string
	vkAnonPath string
	waitReady  time.Duration
}

type wireGuardConfig struct {
	privateKey   string
	addresses    []string
	publicKey    string
	preSharedKey string
	allowedIPs   []string
	mtu          int
	keepalive    int
	localPort    int
}

type transportSession struct {
	cancel      context.CancelFunc
	localConn   net.PacketConn
	dispatcher  *Dispatcher
	workersDone chan struct{}
	stopOnce    sync.Once
}

type coreSession struct {
	transport *transportSession
}

type statusSnapshot struct {
	State           string `json:"state"`
	Message         string `json:"message,omitempty"`
	UpdatedAtMillis int64  `json:"updated_at_millis"`
	Running         bool   `json:"running"`
}

var (
	lifecycleMu  sync.Mutex
	stateMu      sync.RWMutex
	active       *coreSession
	state        = statusSnapshot{State: "stopped", UpdatedAtMillis: time.Now().UnixMilli()}
	lastLog      string
	lastError    string
	resolverOnce sync.Once
	pendingStart context.CancelFunc
	startSerial  uint64
)

// CaptchaResultChan and its helpers live here because qWDTT's original
// executable defined them in main.go, which is intentionally not imported by
// the embedded library.
var CaptchaResultChan = make(chan string, 1)
var captchaModeValue atomic.Value

func init() {
	captchaModeValue.Store("auto")
}

func normalizeCaptchaMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "auto", "rjs", "wv":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "auto"
	}
}

func setCaptchaMode(mode string) string {
	normalized := normalizeCaptchaMode(mode)
	captchaModeValue.Store(normalized)
	return normalized
}

func getCaptchaMode() string {
	mode, _ := captchaModeValue.Load().(string)
	if mode == "" {
		return "auto"
	}
	return mode
}

func drainCaptchaResult() {
	select {
	case <-CaptchaResultChan:
	default:
	}
}

func setStatus(next, message string) {
	stateMu.Lock()
	state = statusSnapshot{
		State:           next,
		Message:         message,
		UpdatedAtMillis: time.Now().UnixMilli(),
		Running:         next == "running",
	}
	if message != "" {
		lastLog = message
	}
	if next == "starting" || next == "running" {
		lastError = ""
	} else if next == "error" {
		lastError = message
	}
	stateMu.Unlock()
}

func configString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var values []string
	if json.Unmarshal(raw, &values) == nil {
		return strings.Join(values, ",")
	}
	return ""
}

func normalizePeer(value string, defaultPort int) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("peer is required")
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value, nil
	}
	host := strings.Trim(value, "[]")
	if host == "" {
		return "", errors.New("peer host is required")
	}
	if defaultPort <= 0 || defaultPort > 65535 {
		defaultPort = 56000
	}
	return net.JoinHostPort(host, strconv.Itoa(defaultPort)), nil
}

func normalizeConfig(configJSON string) (bridgeConfig, error) {
	var raw rawConfig
	if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
		return bridgeConfig{}, fmt.Errorf("parse qWDTT config JSON: %w", err)
	}
	if engine := strings.TrimSpace(raw.Engine); engine != "" && !strings.EqualFold(engine, EngineName) {
		return bridgeConfig{}, fmt.Errorf("unsupported engine %q", engine)
	}
	defaultPort := raw.DTLSPort
	if defaultPort <= 0 {
		defaultPort = raw.ServerPort
	}
	peerValue := raw.Peer
	if strings.TrimSpace(peerValue) == "" {
		peerValue = raw.Server
	}
	if strings.TrimSpace(peerValue) == "" {
		peerValue = raw.DTLSHost
	}
	peer, err := normalizePeer(peerValue, defaultPort)
	if err != nil {
		return bridgeConfig{}, err
	}
	hashText := configString(raw.Hashes)
	if hashText == "" {
		hashText = configString(raw.VKHashes)
	}
	if hashText == "" {
		hashText = raw.VKHash
	}
	hashes := ParseHashes(hashText)
	if len(hashes) == 0 {
		return bridgeConfig{}, errors.New("VK call hash is required")
	}
	password := strings.TrimSpace(raw.Password)
	if password == "" {
		password = strings.TrimSpace(raw.Pass)
	}
	if password == "" {
		return bridgeConfig{}, errors.New("password is required")
	}
	deviceID := strings.TrimSpace(raw.DeviceID)
	if deviceID == "" {
		deviceID = strings.TrimSpace(raw.ClientID)
	}
	if deviceID == "" {
		return bridgeConfig{}, errors.New("device_id is required")
	}
	socksPort := raw.SocksPort
	if socksPort <= 0 || socksPort > 65535 {
		return bridgeConfig{}, fmt.Errorf("invalid socks_port %d", socksPort)
	}
	workers := raw.Workers
	if workers <= 0 {
		workers = 18
	}
	if workers < workersPerGroup {
		workers = workersPerGroup
	}
	if workers > 108 {
		workers = 108
	}
	localPort := raw.LocalPort
	if localPort <= 0 {
		localPort = raw.Port
	}
	if localPort < 0 || localPort > 65535 {
		return bridgeConfig{}, fmt.Errorf("invalid local_port %d", localPort)
	}
	waitMillis := raw.WaitReadyTimeoutMillis
	if waitMillis <= 0 {
		waitMillis = 60000
	}
	if waitMillis < 15000 {
		waitMillis = 15000
	}
	if waitMillis > 120000 {
		waitMillis = 120000
	}
	socksHost := strings.TrimSpace(raw.SocksListenHost)
	if socksHost == "" {
		socksHost = "127.0.0.1"
	}
	anonPath := strings.TrimSpace(raw.VKAnonPath)
	if anonPath == "" {
		anonPath = "vkcalls"
	}
	return bridgeConfig{
		peer:       peer,
		hashes:     hashes,
		password:   password,
		workers:    workers,
		localPort:  localPort,
		deviceID:   deviceID,
		socksHost:  socksHost,
		socksPort:  socksPort,
		turnHost:   strings.TrimSpace(raw.TurnHost),
		turnPort:   strings.TrimSpace(raw.TurnPort),
		vkAnonPath: anonPath,
		waitReady:  time.Duration(waitMillis) * time.Millisecond,
	}, nil
}

func parseWireGuardConfig(raw string, localPort int) (wireGuardConfig, error) {
	values := map[string]map[string]string{
		"interface": {},
		"peer":      {},
	}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		switch strings.ToLower(line) {
		case "[interface]":
			section = "interface"
			continue
		case "[peer]":
			section = "peer"
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			continue
		}
		values[section][strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return wireGuardConfig{}, err
	}
	privateKey := values["interface"]["privatekey"]
	publicKey := values["peer"]["publickey"]
	addresses := splitList(values["interface"]["address"])
	if privateKey == "" || publicKey == "" || len(addresses) == 0 {
		return wireGuardConfig{}, errors.New("server returned incomplete WireGuard config")
	}
	allowedIPs := splitList(values["peer"]["allowedips"])
	if len(allowedIPs) == 0 {
		allowedIPs = []string{"0.0.0.0/0"}
	}
	mtu, _ := strconv.Atoi(values["interface"]["mtu"])
	if mtu < 576 || mtu > 1500 {
		mtu = 1280
	}
	keepalive, _ := strconv.Atoi(values["peer"]["persistentkeepalive"])
	if keepalive <= 0 || keepalive > 65535 {
		keepalive = 25
	}
	if localPort <= 0 || localPort > 65535 {
		return wireGuardConfig{}, errors.New("invalid local qWDTT port")
	}
	return wireGuardConfig{
		privateKey:   privateKey,
		addresses:    addresses,
		publicKey:    publicKey,
		preSharedKey: values["peer"]["presharedkey"],
		allowedIPs:   allowedIPs,
		mtu:          mtu,
		keepalive:    keepalive,
		localPort:    localPort,
	}, nil
}

func splitList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func buildSingBoxConfig(config bridgeConfig, wg wireGuardConfig) (string, error) {
	peer := map[string]any{
		"address":                       "127.0.0.1",
		"port":                          wg.localPort,
		"public_key":                    wg.publicKey,
		"allowed_ips":                   wg.allowedIPs,
		"persistent_keepalive_interval": wg.keepalive,
	}
	if wg.preSharedKey != "" {
		peer["pre_shared_key"] = wg.preSharedKey
	}
	payload := map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type":        "mixed",
			"tag":         "qwdtt-in",
			"listen":      config.socksHost,
			"listen_port": config.socksPort,
		}},
		"endpoints": []any{map[string]any{
			"type":        "wireguard",
			"tag":         "qwdtt-wg",
			"mtu":         wg.mtu,
			"address":     wg.addresses,
			"private_key": wg.privateKey,
			"peers":       []any{peer},
		}},
		"route": map[string]any{
			"final": "qwdtt-wg",
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func startTransport(parent context.Context, config bridgeConfig) (*transportSession, wireGuardConfig, error) {
	resolverOnce.Do(setupGlobalResolver)
	setCaptchaMode("auto")
	setVkAuthMode("anonymous")
	setVkAnonPath(config.vkAnonPath)
	wrapKey, err := deriveWrapKey(config.password)
	if err != nil {
		return nil, wireGuardConfig{}, err
	}
	peer, err := net.ResolveUDPAddr("udp", config.peer)
	if err != nil {
		return nil, wireGuardConfig{}, fmt.Errorf("resolve qWDTT peer: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)
	localConn, err := listenUDP(net.JoinHostPort("127.0.0.1", strconv.Itoa(config.localPort)))
	if err != nil {
		cancel()
		return nil, wireGuardConfig{}, fmt.Errorf("listen local qWDTT UDP: %w", err)
	}
	udpAddr, ok := localConn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.Port <= 0 {
		_ = localConn.Close()
		cancel()
		return nil, wireGuardConfig{}, errors.New("invalid local qWDTT UDP listener")
	}
	actualPort := udpAddr.Port
	if conn, ok := localConn.(*net.UDPConn); ok {
		_ = conn.SetReadBuffer(socketBufSize)
		_ = conn.SetWriteBuffer(socketBufSize)
	}
	stats := NewStats()
	dispatcher := NewDispatcher(ctx, localConn, stats)
	session := &transportSession{
		cancel:      cancel,
		localConn:   localConn,
		dispatcher:  dispatcher,
		workersDone: make(chan struct{}),
	}
	transport := &TurnParams{
		Host:    config.turnHost,
		Port:    config.turnPort,
		Hashes:  config.hashes,
		WrapKey: wrapKey,
	}
	configCh := make(chan string, 1)
	var workers sync.WaitGroup
	var pauseFlag int32
	var previousReady <-chan struct{}
	workerID := 1
	groups := (config.workers + workersPerGroup - 1) / workersPerGroup
	for index := 0; index < groups; index++ {
		var waitReady <-chan struct{}
		var signalReady chan<- struct{}
		if index > 0 {
			waitReady = previousReady
		}
		if index < groups-1 {
			nextReady := make(chan struct{})
			signalReady = nextReady
			previousReady = nextReady
		}
		start := index * workersPerGroup
		end := start + workersPerGroup
		if end > config.workers {
			end = config.workers
		}
		ids := make([]int, 0, end-start)
		for position := start; position < end; position++ {
			ids = append(ids, workerID)
			workerID++
		}
		groupID := index + 1
		workers.Add(1)
		go func(groupID, hashIndex int, ids []int, waitReady <-chan struct{}, signalReady chan<- struct{}) {
			defer workers.Done()
			WorkerGroup(ctx, groupID, hashIndex, transport, peer, dispatcher, strconv.Itoa(actualPort), groupID == 1, configCh, ids, &pauseFlag, config.deviceID, config.password, stats, waitReady, signalReady)
		}(groupID, index, ids, waitReady, signalReady)
	}
	go func() {
		workers.Wait()
		close(session.workersDone)
	}()
	timer := time.NewTimer(config.waitReady)
	defer timer.Stop()
	select {
	case wireGuardText := <-configCh:
		wg, parseErr := parseWireGuardConfig(wireGuardText, actualPort)
		if parseErr != nil {
			session.stop()
			return nil, wireGuardConfig{}, parseErr
		}
		return session, wg, nil
	case <-session.workersDone:
		if err := ctx.Err(); err != nil {
			session.stop()
			return nil, wireGuardConfig{}, fmt.Errorf("qWDTT start cancelled: %w", err)
		}
		session.stop()
		return nil, wireGuardConfig{}, errors.New("qWDTT workers stopped before WireGuard config was received")
	case <-ctx.Done():
		session.stop()
		return nil, wireGuardConfig{}, fmt.Errorf("qWDTT start cancelled: %w", ctx.Err())
	case <-timer.C:
		session.stop()
		return nil, wireGuardConfig{}, errors.New("qWDTT timeout waiting for WireGuard config")
	}
}

func (session *transportSession) stop() {
	if session == nil {
		return
	}
	session.stopOnce.Do(func() {
		session.cancel()
		_ = session.localConn.Close()
		session.dispatcher.Shutdown()
		select {
		case <-session.workersDone:
		case <-time.After(3 * time.Second):
		}
	})
}

func monitorTransport(session *transportSession) {
	<-session.workersDone
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	if active == nil || active.transport != session {
		return
	}
	active = nil
	singErr := singbox.StopSingle()
	session.stop()
	if singErr != nil {
		setStatus("error", "qWDTT transport stopped: "+singErr.Error())
		return
	}
	setStatus("error", "qWDTT transport stopped unexpectedly")
}

func stopLocked() error {
	session := active
	active = nil
	if session == nil {
		setStatus("stopped", "")
		return nil
	}
	setStatus("stopping", "stopping qWDTT")
	singErr := singbox.StopSingle()
	session.transport.stop()
	if singErr != nil {
		setStatus("error", singErr.Error())
		return singErr
	}
	setStatus("stopped", "")
	return nil
}

// StartSingle starts qWDTT and its server-issued WireGuard endpoint in the
// existing sing-box runtime. It never spawns a process or loads a second Go
// shared library.
func StartSingle(configJSON string) error {
	config, err := normalizeConfig(configJSON)
	if err != nil {
		setStatus("error", err.Error())
		return err
	}
	lifecycleMu.Lock()
	startSerial++
	serial := startSerial
	if pendingStart != nil {
		pendingStart()
		pendingStart = nil
	}
	if err := stopLocked(); err != nil {
		lifecycleMu.Unlock()
		return err
	}
	startCtx, cancelStart := context.WithCancel(context.Background())
	pendingStart = cancelStart
	setStatus("starting", "qWDTT: requesting WireGuard config")
	lifecycleMu.Unlock()

	transport, wg, err := startTransport(startCtx, config)
	if err != nil {
		cancelStart()
		lifecycleMu.Lock()
		if startSerial == serial {
			pendingStart = nil
			setStatus("error", err.Error())
		}
		lifecycleMu.Unlock()
		return err
	}
	singboxConfig, err := buildSingBoxConfig(config, wg)
	if err != nil {
		transport.stop()
		cancelStart()
		lifecycleMu.Lock()
		if startSerial == serial {
			pendingStart = nil
			setStatus("error", err.Error())
		}
		lifecycleMu.Unlock()
		return err
	}

	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	if startSerial != serial || startCtx.Err() != nil {
		cancelStart()
		transport.stop()
		return context.Canceled
	}
	pendingStart = nil
	if err := singbox.StartSingle(singboxConfig); err != nil {
		cancelStart()
		transport.stop()
		setStatus("error", err.Error())
		return err
	}
	active = &coreSession{transport: transport}
	setStatus("running", "qWDTT: local SOCKS ready")
	go monitorTransport(transport)
	return nil
}

// StopSingle stops both the local WireGuard SOCKS endpoint and qWDTT transport.
func StopSingle() error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	startSerial++
	if pendingStart != nil {
		pendingStart()
		pendingStart = nil
	}
	return stopLocked()
}

func SingleRunning() bool {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	return active != nil && singbox.SingleRunning()
}

func ValidateConfig(configJSON string) error {
	_, err := normalizeConfig(configJSON)
	return err
}

func Version() string {
	return bridgeVersion
}

func LastLog() string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return lastLog
}

func LastError() string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return lastError
}

func StatusJSON() string {
	stateMu.RLock()
	snapshot := state
	stateMu.RUnlock()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return `{"state":"error","message":"status encode failed"}`
	}
	return string(encoded)
}

func LogsJSON() string {
	stateMu.RLock()
	message := lastLog
	failure := lastError
	stateName := state.State
	stateMu.RUnlock()
	entries := []map[string]string{}
	if message != "" {
		entries = append(entries, map[string]string{"level": "info", "message": message})
	}
	if failure != "" && failure != message {
		entries = append(entries, map[string]string{"level": "error", "message": failure})
	}
	if len(entries) == 0 {
		entries = append(entries, map[string]string{"level": "info", "message": "qWDTT: " + stateName})
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}
