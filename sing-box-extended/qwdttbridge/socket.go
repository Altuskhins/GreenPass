package qwdttbridge

import (
	"context"
	"net"
)

// qWDTT's Android executable used a Linux-specific SO_REUSEADDR helper. The
// embedded core needs the same behavior on Android and must remain testable on
// Windows, where syscall's socket handle type differs. A normal ListenConfig
// is sufficient because the unified core owns the port for the whole session.
func listenUDP(addr string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", addr)
}
