package qwdttbridge

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestStartTransportRejectsBeforeWorkersExist(t *testing.T) {
	started := time.Now()
	_, _, err := startTransport(context.Background(), bridgeConfig{})
	if err == nil {
		t.Fatal("expected invalid password error")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("early validation waited for workers: %v", elapsed)
	}
}

func TestStartingClearsStaleError(t *testing.T) {
	setStatus("error", "old failure")
	setStatus("starting", "starting again")
	if got := LastError(); got != "" {
		t.Fatalf("LastError after new start = %q", got)
	}
}

func TestNormalizeConfigAcceptsOfficialFields(t *testing.T) {
	config, err := normalizeConfig(`{
        "engine":"qwdtt",
        "peer":"203.0.113.10",
        "hashes":["hash-a","hash-b"],
        "password":"secret",
        "device_id":"greenpass-device",
        "socks_port":10804
    }`)
	if err != nil {
		t.Fatalf("normalizeConfig: %v", err)
	}
	if config.peer != "203.0.113.10:56000" {
		t.Fatalf("peer = %q", config.peer)
	}
	if len(config.hashes) != 2 || config.workers != 18 {
		t.Fatalf("hashes=%v workers=%d", config.hashes, config.workers)
	}
}

func TestNormalizeConfigPreservesPartialWorkerGroup(t *testing.T) {
	config, err := normalizeConfig(`{
        "engine":"qwdtt",
        "peer":"203.0.113.10",
        "hashes":"hash-a",
        "password":"secret",
        "device_id":"greenpass-device",
        "workers":16,
        "socks_port":10804
    }`)
	if err != nil {
		t.Fatalf("normalizeConfig: %v", err)
	}
	if config.workers != 16 {
		t.Fatalf("workers = %d, want 16", config.workers)
	}
}

func TestServerWireGuardConfigUsesEmbeddedQWDTTUDP(t *testing.T) {
	serverConfig := `[Interface]
PrivateKey = private-key
Address = 10.66.66.9/32
DNS = 8.8.8.8
MTU = 1280

[Peer]
PublicKey = public-key
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:9000
PersistentKeepalive = 25`
	wg, err := parseWireGuardConfig(serverConfig, 19000)
	if err != nil {
		t.Fatalf("parseWireGuardConfig: %v", err)
	}
	if wg.localPort != 19000 || wg.privateKey != "private-key" || wg.publicKey != "public-key" {
		t.Fatalf("unexpected WireGuard config: %+v", wg)
	}
	config := bridgeConfig{socksHost: "127.0.0.1", socksPort: 10804}
	raw, err := buildSingBoxConfig(config, wg)
	if err != nil {
		t.Fatalf("buildSingBoxConfig: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("unmarshal generated config: %v", err)
	}
	endpoint := parsed["endpoints"].([]any)[0].(map[string]any)
	peer := endpoint["peers"].([]any)[0].(map[string]any)
	if peer["address"] != "127.0.0.1" || int(peer["port"].(float64)) != 19000 {
		t.Fatalf("endpoint peer = %#v", peer)
	}
}
