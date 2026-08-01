package mihomobridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
)

func TestValidateVLESSLinkEnvelope(t *testing.T) {
	payload, err := json.Marshal(startConfig{
		Engine:    "mihomo",
		Links:     []string{"vless://3179dce2-2ff9-413c-85b4-c1d53ed41668@example.com:443?security=tls&type=ws&host=example.com&path=%2Fws#test"},
		WorkDir:   filepath.Join(t.TempDir(), "mihomo"),
		MixedPort: 10804,
		Username:  "greenpass",
		Password:  "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(string(payload)); err != nil {
		t.Fatalf("validate Mihomo envelope: %v", err)
	}
}

func TestStartAcceptsAuthenticatedLoopbackSOCKS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	payload, err := json.Marshal(startConfig{
		Engine:    "mihomo",
		Links:     []string{"vless://3179dce2-2ff9-413c-85b4-c1d53ed41668@example.com:443?security=tls&type=ws&host=example.com&path=%2Fws#test"},
		WorkDir:   filepath.Join(t.TempDir(), "mihomo"),
		MixedPort: port,
		Username:  "greenpass",
		Password:  "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Start(string(payload)); err != nil {
		t.Fatalf("start Mihomo: %v", err)
	}
	t.Cleanup(func() {
		_ = Stop()
		_ = cachefile.Cache().Close()
	})

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatalf("dial mixed listener: %v", err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 2 {
		t.Fatalf("SOCKS method reply=%v err=%v", reply, err)
	}
	user, password := []byte("greenpass"), []byte("secret")
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err = conn.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS auth reply=%v err=%v", reply, err)
	}
}
