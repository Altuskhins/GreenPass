package unifiedbridge

import "testing"

const minimalSingBoxConfig = `{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 0}],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}`

func TestConfigEngine(t *testing.T) {
	if got := configEngine(minimalSingBoxConfig); got != EngineSingBox {
		t.Fatalf("sing-box config detected as %q", got)
	}
	if got := configEngine(`{"engine":"olcrtc"}`); got != EngineOlcRTC {
		t.Fatalf("olcrtc config detected as %q", got)
	}
	if got := configEngine(`{"engine":"qwdtt"}`); got != EngineQWDTT {
		t.Fatalf("qwdtt config detected as %q", got)
	}
}

func TestValidateOlcRTCConfig(t *testing.T) {
	config := `{
		"engine":"olcrtc",
		"carrier":"jitsi",
		"transport":"datachannel",
		"room_id":"room-id",
		"client_id":"client-id",
		"key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"socks_port":10808
	}`
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("validate olcRTC config: %v", err)
	}
}

func TestValidateQWDTTConfig(t *testing.T) {
	config := `{
		"engine":"qwdtt",
		"peer":"203.0.113.10:56000",
		"hashes":"vk-hash-1,vk-hash-2",
		"password":"secret",
		"device_id":"greenpass-test",
		"socks_port":10804
	}`
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("validate qwdtt config: %v", err)
	}
}

func TestSingBoxLifecycleThroughUnifiedBridge(t *testing.T) {
	_ = Stop()
	if err := ValidateConfig(minimalSingBoxConfig); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := Start(minimalSingBoxConfig); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !IsRunning() || CurrentEngine() != EngineSingBox {
		t.Fatalf("running=%v engine=%q", IsRunning(), CurrentEngine())
	}
	if err := Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
}
