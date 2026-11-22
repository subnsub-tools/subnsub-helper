//go:build unix

package applehp

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ListenUDP binds an IPv4 UDP socket with SO_REUSEADDR, optional SO_REUSEPORT,
// and an enlarged receive buffer for macOS High Performance media bursts.
func ListenUDP(bindIP string, port int, reusePort bool, rcvBuf int) (*net.UDPConn, error) {
	ip := net.IPv4zero
	if bindIP != "" {
		parsed := net.ParseIP(bindIP).To4()
		if parsed == nil {
			return nil, fmt.Errorf("applehp: invalid IPv4 UDP bind address %q", bindIP)
		}
		ip = parsed
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					sockErr = err
					return
				}
				if reusePort {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						sockErr = err
						return
					}
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UDPConn)
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
