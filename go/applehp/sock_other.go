//go:build !unix

package applehp

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ListenUDP binds an IPv4 UDP socket with an enlarged receive buffer.
func ListenUDP(bindIP string, port int, _ bool, rcvBuf int) (*net.UDPConn, error) {
	ip := net.IPv4zero
	if bindIP != "" {
		parsed := net.ParseIP(bindIP).To4()
		if parsed == nil {
			return nil, fmt.Errorf("applehp: invalid IPv4 UDP bind address %q", bindIP)
		}
		ip = parsed
	}
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	if rcvBuf > 0 {
		_ = uc.SetReadBuffer(rcvBuf)
	}
	return uc, nil
}

// DialTCPWithLocal dials an IPv4 TCP connection, optionally pinning the source
// local IPv4 address.
func DialTCPWithLocal(ctx context.Context, localIP, remoteAddr string, timeout time.Duration) (*net.TCPConn, error) {
	d := net.Dialer{Timeout: timeout}
	if localIP != "" {
		ip := net.ParseIP(localIP).To4()
		if ip == nil {
			return nil, fmt.Errorf("applehp: invalid IPv4 local TCP address %q", localIP)
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	conn, err := d.DialContext(ctx, "tcp4", remoteAddr)
	if err != nil {
		return nil, err
	}
	tc := conn.(*net.TCPConn)
	_ = tc.SetNoDelay(true)
	return tc, nil
}
