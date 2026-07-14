//go:build with_wireguard

package unifiedbridge

import "testing"

const minimalAWGConfig = `{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 0}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "endpoints": [{
    "type": "wireguard",
    "tag": "awg-out",
    "address": ["10.8.0.2/32"],
    "private_key": "QGg8AFRn6qKfTB7cT3FWH1WGx3np+OKzlNuQUrqIBmI=",
    "peers": [{
      "address": "192.0.2.1",
      "port": 443,
      "public_key": "3nk7jdnkcL95Fc/z+GCiH7jOovEKhFkLIGPT+U/uLEQ=",
      "allowed_ips": ["0.0.0.0/0"]
    }],
    "amnezia": {
      "jc": 2, "jmin": 15, "jmax": 54,
      "s1": 551, "s2": 360,
      "h1": 1574660735, "h2": 1131225120,
      "h3": 1223379570, "h4": 116431299
    }
  }],
  "route": {"final": "awg-out", "auto_detect_interface": true}
}`

func TestValidateAWG20Config(t *testing.T) {
	if err := ValidateConfig(minimalAWGConfig); err != nil {
		t.Fatalf("validate AWG 2.0 config: %v", err)
	}
	if err := Start(minimalAWGConfig); err != nil {
		t.Fatalf("start AWG 2.0 config: %v", err)
	}
	if err := Stop(); err != nil {
		t.Fatalf("stop AWG 2.0 config: %v", err)
	}
}
