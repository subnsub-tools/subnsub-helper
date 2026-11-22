package applehp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort        = 5900
	defaultUDPRcvBuf   = 4 * 1024 * 1024
	defaultWarmupDwell = 1400 * time.Millisecond
)

// UDPBindError reports a failure binding either the ctrl (5900) or video (5901)
// local UDP socket before the handshake begins.
type UDPBindError struct {
	Role string
	Addr string
	Err  error
}

func (e *UDPBindError) Error() string {
	return fmt.Sprintf("applehp: bind UDP %s (%s): %v", e.Role, e.Addr, e.Err)
}

func (e *UDPBindError) Unwrap() error { return e.Err }

// Config describes connection, UDP binding, and stream negotiation parameters.
type Config struct {
	Host         string
	Port         int
	Username     string
	Password     string
	AuthMode     string // "srp" (default, auto-falls back to nonsrp) or "nonsrp"
	LocalTCPAddr string
	UDPBindAddr  string
	UDPCtrlPort  int
	UDPVideoPort int
	ReusePort    bool
	WarmupTCP    bool
	WarmupDwell  time.Duration
	Curtain      bool
	Width        int
	Height       int
	HiDPIScale   float64
	// How the display's modes are written for the host (displayForm), as the
	// handshake wrote them.
	form          int
	HDR           bool
	Codec         string // "avc" (default), "hevc", or "both"
	TilesPerFrame int
	AudioEnabled  bool
	// MaxBitrate caps the bandwidth the media offer declares, in bits a
	// second; zero leaves the protocol's own ceilings.
	MaxBitrate  int
	SessionMode string // "auto" (default), "share", or "alt"
	Logf        func(format string, args ...any)
}

// DefaultConfig returns sensible defaults for browser-compatible H.264 probing.
func DefaultConfig() Config {
	return Config{
		Port:        defaultPort,
		AuthMode:    "srp",
		WarmupTCP:   true,
		WarmupDwell: defaultWarmupDwell,
		Curtain:     false,
		Width:       1920,
		Height:      1080,
		HiDPIScale:  1.0,
		Codec:       "avc",
		SessionMode: "auto",
	}
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func (c Config) withDefaults() Config {
	if c.Port <= 0 {
		c.Port = defaultPort
	}
	if c.AuthMode == "" {
		c.AuthMode = "srp"
	}
	if c.UDPCtrlPort <= 0 {
		c.UDPCtrlPort = c.Port
	}
	if c.UDPVideoPort <= 0 {
		c.UDPVideoPort = c.Port + 1
	}
	if c.Width <= 0 {
		c.Width = 1920
	}
	if c.Height <= 0 {
		c.Height = 1080
	}
	if c.HiDPIScale <= 0 {
		c.HiDPIScale = 1.0
	}
	if c.Codec == "" {
		c.Codec = "avc"
	}
	if c.TilesPerFrame <= 0 {
		if strings.EqualFold(c.Codec, "avc") {
			c.TilesPerFrame = 1
		} else {
			c.TilesPerFrame = 4
		}
	}
	if c.SessionMode == "" {
		c.SessionMode = "auto"
	}
	if c.WarmupTCP && c.WarmupDwell <= 0 {
		c.WarmupDwell = defaultWarmupDwell
	}
	return c
}

// ResolveIPv4 resolves host explicitly to an IPv4 address string so TCP and UDP
// share the IPv4 address family expected by Apple HP media transport.
func ResolveIPv4(host string) (string, error) {
	return validateIPv4Addr(host)
}

// Session represents an active negotiated Apple High Performance Screen Sharing session.
type Session struct {
	cfg Config
	// The block cipher of the encrypted input event (stream.go sendEvent),
	// and the record key it was made from.
	eventMu       sync.Mutex
	eventKey      cipher.Block
	eventKeyOf    []byte
	destIP        string
	ctrlDestPort  int
	videoDestPort int

	tcp       *net.TCPConn
	br        *bufio.Reader
	ctrlConn  *net.UDPConn
	videoConn *net.UDPConn

	Cipher                *RecordCipher
	Keys                  NegotiationKeys
	AuthUsed              string
	SessionSelectDetected bool
	ConsoleUser           string

	ServerW, ServerH     int
	CanvasW, CanvasH     int
	CanvasTiles          int
	VideoSSRC, AudioSSRC uint32
	VideoDec             *SRTPDecryptor
	AudioDec             *SRTPDecryptor
	CtrlEnc              *SRTCPEncryptor
	CtrlDec              *SRTCPDecryptor
	AudioEnc             *SRTPEncryptor
	LeftoverMsgs         [][]byte

	rxEncBuf   []byte
	altSession bool
	closeOnce  sync.Once
	// The session's Run, while there is one (stream.go).
	runMu sync.Mutex
	run   *runState
}

// LocalTCPAddr returns the established TCP client address.
func (s *Session) LocalTCPAddr() string {
	if s.tcp == nil {
		return ""
	}
	return s.tcp.LocalAddr().String()
}

// RemoteTCPAddr returns the connected TCP server address.
func (s *Session) RemoteTCPAddr() string {
	if s.tcp == nil {
		return ""
	}
	return s.tcp.RemoteAddr().String()
}

// CtrlLocalAddr returns the bound UDP ctrl socket address.
func (s *Session) CtrlLocalAddr() string {
	if s.ctrlConn == nil {
		return ""
	}
	return s.ctrlConn.LocalAddr().String()
}

// VideoLocalAddr returns the bound UDP video socket address.
func (s *Session) VideoLocalAddr() string {
	if s.videoConn == nil {
		return ""
	}
	return s.videoConn.LocalAddr().String()
}

// Close tears down the control TCP socket with SO_LINGER=0 (RST, matching native
// Screen Sharing so ScreensharingAgent exits immediately) and closes UDP sockets.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if s.tcp != nil {
			_ = s.tcp.SetLinger(0)
			_ = s.tcp.Close()
		}
		if s.ctrlConn != nil {
			_ = s.ctrlConn.Close()
		}
		if s.videoConn != nil {
			_ = s.videoConn.Close()
		}
	})
	return nil
}

// Connect binds UDP media sockets, performs optional TCP warmup + punch loop,
// authenticates, activates enc1103, and completes the 0x1c media negotiation.
func Connect(ctx context.Context, cfg Config) (*Session, error) {
	cfg = cfg.withDefaults()
	destIP, err := ResolveIPv4(cfg.Host)
	if err != nil {
		return nil, err
	}

	ctrlConn, err := ListenUDP(cfg.UDPBindAddr, cfg.UDPCtrlPort, cfg.ReusePort, defaultUDPRcvBuf)
	if err != nil {
		bindAddr := cfg.UDPBindAddr
		if bindAddr == "" {
			bindAddr = "0.0.0.0"
		}
		return nil, &UDPBindError{Role: "ctrl", Addr: net.JoinHostPort(bindAddr, fmt.Sprintf("%d", cfg.UDPCtrlPort)), Err: err}
	}
	videoConn, err := ListenUDP(cfg.UDPBindAddr, cfg.UDPVideoPort, cfg.ReusePort, defaultUDPRcvBuf)
	if err != nil {
		_ = ctrlConn.Close()
		bindAddr := cfg.UDPBindAddr
		if bindAddr == "" {
			bindAddr = "0.0.0.0"
		}
		return nil, &UDPBindError{Role: "video", Addr: net.JoinHostPort(bindAddr, fmt.Sprintf("%d", cfg.UDPVideoPort)), Err: err}
	}

	cleanupSockets := true
	defer func() {
		if cleanupSockets {
			_ = ctrlConn.Close()
			_ = videoConn.Close()
		}
	}()

	cfg.logf("UDP bound ctrl=%s video=%s target=%s:%d/%d",
		ctrlConn.LocalAddr(), videoConn.LocalAddr(), destIP, cfg.UDPCtrlPort, cfg.UDPVideoPort)

	remoteAddr := net.JoinHostPort(destIP, fmt.Sprintf("%d", cfg.Port))

	if cfg.WarmupTCP {
		cfg.logf("warmup TCP -> %s (dwell=%s)", remoteAddr, cfg.WarmupDwell)
		if err := WarmupTCP(ctx, cfg.LocalTCPAddr, remoteAddr, cfg.WarmupDwell); err != nil {
			cfg.logf("warmup TCP warning: %v", err)
		}
	}

	punchStop := make(chan struct{})
	var punchWG sync.WaitGroup
	punchWG.Add(1)
	go func() {
		defer punchWG.Done()
		punchLoop(punchStop, ctrlConn, videoConn, destIP, cfg.UDPCtrlPort, cfg.UDPVideoPort)
	}()
	defer func() {
		close(punchStop)
		punchWG.Wait()
	}()

	// A caller that gives up (ctx) closes the connection under whatever read
	// the handshake is in: its reads wait on the host, not on ctx.
	var held struct {
		mu sync.Mutex
		tc *net.TCPConn
	}
	hold := func(c *net.TCPConn) {
		held.mu.Lock()
		held.tc = c
		held.mu.Unlock()
	}
	stopAbort := context.AfterFunc(ctx, func() {
		held.mu.Lock()
		if held.tc != nil {
			_ = held.tc.SetLinger(0)
			_ = held.tc.Close()
		}
		held.mu.Unlock()
	})
	defer stopAbort()

	tc, br, ecbKey, authUsed, err := connectAndAuth(ctx, cfg, remoteAddr)
	if err != nil {
		return nil, err
	}
	hold(tc)
	cleanupTCP := true
	defer func() {
		if cleanupTCP && tc != nil {
			_ = tc.SetLinger(0)
			_ = tc.Close()
		}
	}()

	srvW, srvH, err := doClientServerInit(tc, br)
	if err != nil {
		return nil, err
	}
	cfg.logf("auth=%s ServerInit=%dx%d", authUsed, srvW, srvH)

	ssDetected, consoleUser, err := peekSessionSelect(tc, br)
	if err != nil {
		return nil, err
	}
	altSession := false
	if ssDetected {
		cfg.logf("SessionSelect prompt detected (console_user=%q, mode=%s)", consoleUser, cfg.SessionMode)
		mode := cfg.SessionMode
		if mode == "auto" {
			mode = "share"
		}
		if mode == "alt" {
			altSession = true
			_ = tc.SetLinger(0)
			_ = tc.Close()
			tc = nil
			tc, br, ecbKey, authUsed, err = connectAndAuth(ctx, cfg, remoteAddr)
			if err != nil {
				return nil, fmt.Errorf("applehp: alt-session reconnect auth: %w", err)
			}
			hold(tc)
			srvW, srvH, err = doClientServerInit(tc, br)
			if err != nil {
				return nil, fmt.Errorf("applehp: alt-session ServerInit: %w", err)
			}
			ssDetected2, cu2, err := peekSessionSelect(tc, br)
			if err != nil {
				return nil, err
			}
			if !ssDetected2 {
				return nil, errors.New("applehp: alt-session prompt disappeared on second connection")
			}
			consoleUser = cu2
		}
		if err := handleSessionSelect(tc, br, mode, consoleUser, cfg.Username, cfg.Password, ecbKey); err != nil {
			return nil, err
		}
	}

	// Plaintext prelude.
	prelude := append(BuildViewerInfo(DefaultViewerOSVer), Apple0x12Followup()...)
	if _, err := writeFull(tc, prelude); err != nil {
		return nil, fmt.Errorf("applehp: send ViewerInfo: %w", err)
	}
	if err := sleepCtx(ctx, 100*time.Millisecond); err != nil {
		return nil, err
	}
	if cfg.Curtain || altSession {
		cfg.form = int(hostForm.Load())
		vd := displayConfig(cfg.Width, cfg.Height, cfg.HiDPIScale, cfg.HDR, cfg.form)
		if _, err := writeFull(tc, vd); err != nil {
			return nil, fmt.Errorf("applehp: send VirtualDisplay: %w", err)
		}
	}
	if _, err := writeFull(tc, BuildSetEncodings(HPEncodings)); err != nil {
		return nil, fmt.Errorf("applehp: send plaintext SetEncodings: %w", err)
	}

	cipher, encBuf, err := readUntilEnc1103(tc, br, ecbKey)
	if err != nil {
		return nil, err
	}
	if _, err := writeFull(tc, BuildPostEncryptionToggle()); err != nil {
		return nil, fmt.Errorf("applehp: send PostEncryptionToggle: %w", err)
	}
	if err := sleepCtx(ctx, 200*time.Millisecond); err != nil {
		return nil, err
	}
	encBuf, _, err = drainCipherBuffer(tc, br, cipher, encBuf, 350*time.Millisecond)
	if err != nil {
		return nil, err
	}
	cfg.logf("enc1103 active")

	// Encrypted phase: SetEncodings + 0x1c offer + FBURequest.
	videoOffer, audioOffer, videoSSRC, audioSSRC, err := CreateOffers(OfferOptions{
		Codec:         cfg.Codec,
		TilesPerFrame: cfg.TilesPerFrame,
		AudioEnabled:  cfg.AudioEnabled,
		LTRP:          false,
		MaxBitrate:    cfg.MaxBitrate,
	})
	if err != nil {
		return nil, err
	}
	keys, err := RandomNegotiationKeys()
	if err != nil {
		return nil, err
	}
	if err := cipher.EncryptAndSend(tc, BuildSetEncodings(HPEncodings)); err != nil {
		return nil, fmt.Errorf("applehp: send encrypted SetEncodings: %w", err)
	}
	msg1c := Build0x1c(audioOffer, videoOffer, keys, true, altSession)
	if err := cipher.EncryptAndSend(tc, msg1c); err != nil {
		return nil, fmt.Errorf("applehp: send 0x1c: %w", err)
	}
	if err := cipher.EncryptAndSend(tc, BuildFBURequest(false, 0, 0, 0xffff, 0xffff)); err != nil {
		return nil, fmt.Errorf("applehp: send FBURequest: %w", err)
	}

	var leftover [][]byte
	cw, ch, ct, encBuf, err := readVideoAnswer(ctx, tc, br, cipher, encBuf, msg1c, &leftover, cfg.logf)
	if err != nil {
		return nil, err
	}
	cfg.logf("0x1c canvas=%dx%d tiles=%d videoSSRC=0x%08x", cw, ch, ct, videoSSRC)

	videoDec, err := NewSRTPDecryptor(keys.VideoKeyS[:])
	if err != nil {
		return nil, err
	}
	audioDec, err := NewSRTPDecryptor(keys.AudioKeyS[:])
	if err != nil {
		return nil, err
	}
	ctrlEnc, err := NewSRTCPEncryptor(keys.VideoKeyV[:])
	if err != nil {
		return nil, err
	}
	ctrlDec, err := NewSRTCPDecryptor(keys.VideoKeyS[:])
	if err != nil {
		return nil, err
	}
	audioEnc, err := NewSRTPEncryptor(keys.AudioKeyV[:], audioSSRC)
	if err != nil {
		return nil, err
	}

	sess := &Session{
		cfg:                   cfg,
		destIP:                destIP,
		ctrlDestPort:          cfg.UDPCtrlPort,
		videoDestPort:         cfg.UDPVideoPort,
		tcp:                   tc,
		br:                    br,
		ctrlConn:              ctrlConn,
		videoConn:             videoConn,
		Cipher:                cipher,
		Keys:                  keys,
		AuthUsed:              authUsed,
		SessionSelectDetected: ssDetected,
		ConsoleUser:           consoleUser,
		ServerW:               srvW,
		ServerH:               srvH,
		CanvasW:               cw,
		CanvasH:               ch,
		CanvasTiles:           ct,
		VideoSSRC:             videoSSRC,
		AudioSSRC:             audioSSRC,
		VideoDec:              videoDec,
		AudioDec:              audioDec,
		CtrlEnc:               ctrlEnc,
		CtrlDec:               ctrlDec,
		AudioEnc:              audioEnc,
		LeftoverMsgs:          leftover,
		rxEncBuf:              encBuf,
		altSession:            altSession,
	}

	// Send initial SR+RR so AVConference registers our SSRC on the ctrl port.
	sess.SendRTCPFeedback(nil)

	cleanupSockets = false
	cleanupTCP = false
	return sess, nil
}

func connectAndAuth(ctx context.Context, cfg Config, remoteAddr string) (*net.TCPConn, *bufio.Reader, []byte, string, error) {
	tryAuth := func(mode string) (*net.TCPConn, *bufio.Reader, []byte, error) {
		tc, err := DialTCPWithLocal(ctx, cfg.LocalTCPAddr, remoteAddr, 15*time.Second)
		if err != nil {
			return nil, nil, nil, err
		}
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
		br := bufio.NewReaderSize(tc, 64*1024)
		rw := struct {
			io.Reader
			io.Writer
		}{br, tc}
		_, secTypes, err := DoHandshake(rw)
		if err != nil {
			_ = tc.Close()
			return nil, nil, nil, err
		}
		if !bytes.Contains(secTypes, []byte{SecTypeAppleRSA}) {
			_ = tc.Close()
			return nil, nil, nil, fmt.Errorf("applehp: server did not offer Apple RSA security type 33 (offered %v)", secTypes)
		}
		var ecbKey []byte
		if mode == "nonsrp" {
			ecbKey, err = AuthNonSRP(rw, cfg.Username, cfg.Password)
		} else {
			ecbKey, err = AuthSRP(rw, cfg.Username, cfg.Password)
		}
		if err != nil {
			_ = tc.Close()
			return nil, nil, nil, err
		}
		_ = tc.SetDeadline(time.Time{})
		return tc, br, ecbKey, nil
	}

	primary := strings.ToLower(cfg.AuthMode)
	if primary == "nonsrp" {
		tc, br, key, err := tryAuth("nonsrp")
		if err == nil {
			return tc, br, key, "nonsrp", nil
		}
		if errors.Is(err, ErrAuthRejected) {
			return nil, nil, nil, "", err
		}
		cfg.logf("nonsrp auth failed (%v); falling back to srp", err)
		tc, br, key, err2 := tryAuth("srp")
		return tc, br, key, "srp", err2
	}

	tc, br, key, err := tryAuth("srp")
	if err == nil {
		return tc, br, key, "srp", nil
	}
	if !errors.Is(err, ErrSRPFallback) {
		return nil, nil, nil, "", err
	}
	cfg.logf("srp fallback triggered (%v); retrying nonsrp", err)
	tc, br, key, err2 := tryAuth("nonsrp")
	return tc, br, key, "nonsrp", err2
}

func doClientServerInit(tc *net.TCPConn, br *bufio.Reader) (int, int, error) {
	_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
	defer tc.SetDeadline(time.Time{})
	if _, err := writeFull(tc, []byte{0xc1}); err != nil {
		return 0, 0, fmt.Errorf("applehp: send ClientInit: %w", err)
	}
	var head [24]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return 0, 0, fmt.Errorf("applehp: read ServerInit: %w", err)
	}
	nameLen := binary.BigEndian.Uint32(head[20:24])
	if nameLen > 65536 {
		return 0, 0, fmt.Errorf("applehp: ServerInit name too long (%d)", nameLen)
	}
	if nameLen > 0 {
		discard := make([]byte, nameLen)
		if _, err := io.ReadFull(br, discard); err != nil {
			return 0, 0, fmt.Errorf("applehp: read ServerInit name: %w", err)
		}
	}
	w := int(binary.BigEndian.Uint16(head[0:2]))
	h := int(binary.BigEndian.Uint16(head[2:4]))
	return w, h, nil
}

func peekSessionSelect(tc *net.TCPConn, br *bufio.Reader) (bool, string, error) {
	_ = tc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	peek, err := br.Peek(4)
	_ = tc.SetReadDeadline(time.Time{})
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false, "", nil
		}
		return false, "", fmt.Errorf("applehp: peek SessionSelect: %w", err)
	}
	if !bytes.Equal(peek, sessionSelectMagic) {
		return false, "", nil
	}
	var ssi [76]byte
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(br, ssi[:])
	_ = tc.SetReadDeadline(time.Time{})
	if err != nil {
		return false, "", fmt.Errorf("applehp: read SessionSelect prompt: %w", err)
	}
	cu := ssi[0x0c:]
	if z := bytes.IndexByte(cu, 0); z >= 0 {
		cu = cu[:z]
	}
	return true, string(cu), nil
}

func handleSessionSelect(tc *net.TCPConn, br *bufio.Reader, mode, consoleUser, username, password string, ecbKey []byte) error {
	var body []byte
	var err error
	if mode == "alt" {
		body, err = BuildSessionSelectCmd2(username, password, ecbKey)
		if err != nil {
			return err
		}
	} else {
		body = BuildSessionSelectCmd0(consoleUser)
	}
	if _, err := writeFull(tc, body); err != nil {
		return fmt.Errorf("applehp: send SessionSelect cmd=%s: %w", mode, err)
	}
	_ = tc.SetReadDeadline(time.Now().Add(60 * time.Second))
	var ack [64 * 1024]byte
	n, err := br.Read(ack[:])
	_ = tc.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		return fmt.Errorf("applehp: wait SessionSelect ack: %w", err)
	}
	return nil
}

func readUntilEnc1103(tc *net.TCPConn, br *bufio.Reader, ecbKey []byte) (*RecordCipher, []byte, error) {
	var buf []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if br.Buffered() == 0 {
			_ = tc.SetReadDeadline(time.Now().Add(1 * time.Second))
		}
		tmp := make([]byte, 64*1024)
		n, err := br.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if blob, tailPos, found := scanFor1103(buf); found {
				_ = tc.SetReadDeadline(time.Time{})
				cipher, err := NewRecordCipher(blob, ecbKey)
				if err != nil {
					return nil, nil, err
				}
				tail := append([]byte(nil), buf[tailPos:]...)
				_, consumed := cipher.DecryptStream(tail)
				return cipher, tail[consumed:], nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			_ = tc.SetReadDeadline(time.Time{})
			return nil, nil, fmt.Errorf("applehp: waiting for enc1103: %w", err)
		}
	}
	_ = tc.SetReadDeadline(time.Time{})
	return nil, nil, errors.New("applehp: timed out waiting for enc1103 (server may be rate-limiting; wait 10-15s)")
}

func scanFor1103(buf []byte) ([]byte, int, bool) {
	pos := 0
	for pos < len(buf) {
		b := buf[pos]
		if b == MsgServerMiscStatus {
			if pos+8 > len(buf) {
				return nil, 0, false
			}
			pos += 8
			continue
		}
		if b == MsgServerFramebufferUpdate {
			if pos+4 > len(buf) {
				return nil, 0, false
			}
			nRects := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
			p := pos + 4
			for i := 0; i < nRects; i++ {
				if p+12 > len(buf) {
					return nil, 0, false
				}
				enc := int32(binary.BigEndian.Uint32(buf[p+8 : p+12]))
				p += 12
				switch enc {
				case EncAppleRekey:
					if p+36 > len(buf) {
						return nil, 0, false
					}
					blob := append([]byte(nil), buf[p:p+36]...)
					return blob, p + 36, true
				case EncAppleMediaInit, EncAppleMVS:
					if p+2 > len(buf) {
						return nil, 0, false
					}
					sz := int(binary.BigEndian.Uint16(buf[p : p+2]))
					if p+2+sz > len(buf) {
						return nil, 0, false
					}
					p += 2 + sz
				default:
					return nil, 0, false
				}
			}
			pos = p
			continue
		}
		break
	}
	return nil, 0, false
}

func drainCipherBuffer(tc *net.TCPConn, br *bufio.Reader, cipher *RecordCipher, encBuf []byte, quietWait time.Duration) ([]byte, [][]byte, error) {
	var all [][]byte
	if len(encBuf) > 0 {
		msgs, consumed := cipher.DecryptStream(encBuf)
		all = append(all, msgs...)
		encBuf = encBuf[consumed:]
	}
	tmp := make([]byte, 64*1024)
	for {
		if br.Buffered() == 0 {
			_ = tc.SetReadDeadline(time.Now().Add(quietWait))
		}
		n, err := br.Read(tmp)
		if n > 0 {
			encBuf = append(encBuf, tmp[:n]...)
			msgs, consumed := cipher.DecryptStream(encBuf)
			all = append(all, msgs...)
			encBuf = encBuf[consumed:]
		}
		if err != nil {
			_ = tc.SetReadDeadline(time.Time{})
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return encBuf, all, nil
			}
			return encBuf, all, err
		}
	}
}

func readVideoAnswer(
	ctx context.Context,
	tc *net.TCPConn,
	br *bufio.Reader,
	cipher *RecordCipher,
	encBuf []byte,
	msg1c []byte,
	leftover *[][]byte,
	logf func(string, ...any),
) (cw, ch, ct int, rem []byte, err error) {
	const retryLimit = 16
	for attempt := 0; attempt <= retryLimit; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, 200*time.Millisecond); err != nil {
				return 0, 0, 0, encBuf, err
			}
			if err := cipher.EncryptAndSend(tc, msg1c); err != nil {
				return 0, 0, 0, encBuf, err
			}
			logf("0x1c re-query %d/%d", attempt, retryLimit)
		}

		// Wait up to 3s on first attempt, 1s on retries for encrypted 0x1c answer.
		wait := 1 * time.Second
		if attempt == 0 {
			wait = 3 * time.Second
		}
		deadline := time.Now().Add(wait)
		tmp := make([]byte, 64*1024)
		for time.Now().Before(deadline) {
			if br.Buffered() == 0 {
				_ = tc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			}
			n, rerr := br.Read(tmp)
			if n > 0 {
				encBuf = append(encBuf, tmp[:n]...)
				msgs, consumed := cipher.DecryptStream(encBuf)
				encBuf = encBuf[consumed:]
				for _, m := range msgs {
					w, h, t, ok := ExtractCanvasDims(m)
					if ok && cw == 0 {
						cw, ch, ct = w, h, t
					} else if leftover != nil {
						*leftover = append(*leftover, m)
					}
				}
				if cw > 0 && ch > 0 {
					_ = tc.SetReadDeadline(time.Time{})
					return cw, ch, ct, encBuf, nil
				}
			}
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					if cw > 0 && ch > 0 {
						_ = tc.SetReadDeadline(time.Time{})
						return cw, ch, ct, encBuf, nil
					}
					continue
				}
				_ = tc.SetReadDeadline(time.Time{})
				return 0, 0, 0, encBuf, fmt.Errorf("applehp: read 0x1c answer: %w", rerr)
			}
		}
	}
	_ = tc.SetReadDeadline(time.Time{})
	return 0, 0, 0, encBuf, errors.New("applehp: host returned degenerate 0x0 canvas after 0x1c retries")
}

func punchLoop(stop <-chan struct{}, ctrlConn, videoConn *net.UDPConn, destIP string, ctrlPort, videoPort int) {
	ip := net.ParseIP(destIP)
	if ip == nil {
		return
	}
	ctrlDst := &net.UDPAddr{IP: ip, Port: ctrlPort}
	videoDst := &net.UDPAddr{IP: ip, Port: videoPort}
	oneByte := []byte{0x00}
	sendPunch := func() {
		if ctrlConn != nil {
			_, _ = ctrlConn.WriteToUDP(oneByte, ctrlDst)
		}
		if videoConn != nil {
			_, _ = videoConn.WriteToUDP(oneByte, videoDst)
		}
	}
	sendPunch()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			sendPunch()
		}
	}
}

// SendRTCPFeedback transmits an encrypted SR+RR compound RTCP packet (and
// optional legacy FIR for targetSSRC when non-zero) to the host ctrl UDP port.
func (s *Session) SendRTCPFeedback(firTargetSSRC *uint32) {
	if s.ctrlConn == nil || s.CtrlEnc == nil {
		return
	}
	ip := net.ParseIP(s.destIP)
	if ip == nil {
		return
	}
	dst := &net.UDPAddr{IP: ip, Port: s.ctrlDestPort}

	s.runMu.Lock()
	own := s.VideoSSRC
	s.runMu.Unlock()
	stats := s.VideoDec.StateSnapshot()
	sources := make([]uint32, 0, len(stats))
	for ssrc := range stats {
		sources = append(sources, ssrc)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i] < sources[j] })

	pkt := append(BuildEmptySR(own), BuildRR(own, sources, stats)...)
	if firTargetSSRC != nil && *firTargetSSRC != 0 {
		pkt = append(pkt, BuildAVPFFIR(own, *firTargetSSRC, 1)...)
		pkt = append(pkt, BuildPLI(own, *firTargetSSRC)...)
		pkt = append(pkt, BuildLegacyFIR(*firTargetSSRC)...)
	}
	if enc, err := s.CtrlEnc.Protect(pkt); err == nil {
		_, _ = s.ctrlConn.WriteToUDP(enc, dst)
	}
}

// ProbeReport summarizes live media reception and H.264 depacketization metrics.
type ProbeReport struct {
	LocalTCP         string
	RemoteTCP        string
	CtrlUDP          string
	VideoUDP         string
	AuthUsed         string
	SessionSelect    bool
	ConsoleUser      string
	ServerW, ServerH int
	CanvasW, CanvasH int
	CanvasTiles      int
	FirstVideoSrc    string
	FirstPacketDelay time.Duration
	FirstKeyDelay    time.Duration
	VideoPackets     int
	SRTPOK           int
	SRTPFailed       int
	SSRCs            map[uint32]int
	SPSLen           int
	PPSLen           int
	SPSProfile       uint8
	SPSLevel         uint8
	SPSMaxRef        uint32
	PatchedMaxRef    uint32
	FramesTotal      int
	Keyframes        int
	BytesDecrypted   int64
	Duration         time.Duration
}

// CollectProbeStats receives SRTP UDP media for `duration`, depacketizes H.264
// access units, inspects and patches SPS max_num_ref_frames, optionally dumps an
// Annex-B .h264 bitstream to dumpPath, and returns a ProbeReport.
func (s *Session) CollectProbeStats(ctx context.Context, duration time.Duration, dumpPath string) (*ProbeReport, error) {
	if duration <= 0 {
		duration = 8 * time.Second
	}
	start := time.Now()
	report := &ProbeReport{
		LocalTCP:      s.LocalTCPAddr(),
		RemoteTCP:     s.RemoteTCPAddr(),
		CtrlUDP:       s.CtrlLocalAddr(),
		VideoUDP:      s.VideoLocalAddr(),
		AuthUsed:      s.AuthUsed,
		SessionSelect: s.SessionSelectDetected,
		ConsoleUser:   s.ConsoleUser,
		ServerW:       s.ServerW,
		ServerH:       s.ServerH,
		CanvasW:       s.CanvasW,
		CanvasH:       s.CanvasH,
		CanvasTiles:   s.CanvasTiles,
	}

	var dumpFile *os.File
	if dumpPath != "" {
		f, err := os.Create(dumpPath)
		if err != nil {
			return nil, fmt.Errorf("applehp: create %s: %w", dumpPath, err)
		}
		dumpFile = f
		defer dumpFile.Close()
	}

	// Keep ctrl socket drained in background so audio/RTCP packets do not fill buffers.
	ctrlDone := make(chan struct{})
	go func() {
		defer close(ctrlDone)
		buf := make([]byte, 4096)
		for {
			_ = s.ctrlConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			_, _, err := s.ctrlConn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
						if time.Since(start) >= duration {
							return
						}
						continue
					}
				}
				return
			}
		}
	}()
	defer func() { <-ctrlDone }()

	type pktEntry struct {
		seq     uint16
		payload []byte
	}
	type tsGroup struct {
		ssrc    uint32
		ts      uint32
		packets []pktEntry
	}

	var (
		curGroup    *tsGroup
		rawSPS      []byte
		patchedSPS  []byte
		rawPPS      []byte
		sentParams  bool
		awaitKey    = true
		primarySSRC uint32
		firSent     bool
	)
	startCode := []byte{0x00, 0x00, 0x00, 0x01}

	flushGroup := func(g *tsGroup) {
		if g == nil || len(g.packets) == 0 {
			return
		}
		sort.Slice(g.packets, func(i, j int) bool {
			return int16(g.packets[i].seq-g.packets[j].seq) < 0
		})
		payloads := make([][]byte, 0, len(g.packets))
		for _, p := range g.packets {
			if len(p.payload) > 0 && p.payload[0] == AppleAVCConfigMarker {
				if sps, pps, ok := ParseAVCConfig(p.payload); ok {
					rawSPS = sps
					rawPPS = pps
					if info, ok2 := ParseSPSInfo(sps); ok2 {
						report.SPSProfile = info.ProfileIDC
						report.SPSLevel = info.LevelIDC
						report.SPSMaxRef = info.MaxNumRefFrames
					}
					if ps, patched := PatchAVCSPSMaxRefFrames(sps, 10); patched {
						patchedSPS = ps
						if info2, ok2 := ParseSPSInfo(ps); ok2 {
							report.PatchedMaxRef = info2.MaxNumRefFrames
						}
					} else {
						patchedSPS = sps
						report.PatchedMaxRef = report.SPSMaxRef
					}
					report.SPSLen = len(rawSPS)
					report.PPSLen = len(rawPPS)
					sentParams = false
				}
			}
			payloads = append(payloads, p.payload)
		}
		nalus := ReassembleH264(payloads)
		if len(nalus) == 0 {
			return
		}
		isKey := AUIsKeyframe(nalus)
		report.FramesTotal++
		if isKey {
			report.Keyframes++
			if report.FirstKeyDelay == 0 {
				report.FirstKeyDelay = time.Since(start)
			}
			awaitKey = false
		}
		if dumpFile != nil && !awaitKey {
			if isKey && !sentParams && len(patchedSPS) > 0 && len(rawPPS) > 0 {
				_, _ = dumpFile.Write(startCode)
				_, _ = dumpFile.Write(patchedSPS)
				_, _ = dumpFile.Write(startCode)
				_, _ = dumpFile.Write(rawPPS)
				sentParams = true
			}
			for _, nal := range nalus {
				_, _ = dumpFile.Write(startCode)
				_, _ = dumpFile.Write(nal)
			}
		}
	}

	buf := make([]byte, 65536)
	lastFeedback := time.Now()
	endTime := start.Add(duration)
	for time.Now().Before(endTime) {
		select {
		case <-ctx.Done():
			flushGroup(curGroup)
			report.SSRCs = s.VideoDec.SSRCCounts()
			report.Duration = time.Since(start)
			return report, ctx.Err()
		default:
		}

		if time.Since(lastFeedback) >= 1*time.Second {
			var firTarget *uint32
			if !firSent && report.Keyframes == 0 && primarySSRC != 0 && time.Since(start) >= 1500*time.Millisecond {
				firTarget = &primarySSRC
				firSent = true
			}
			s.SendRTCPFeedback(firTarget)
			lastFeedback = time.Now()
		}

		_ = s.videoConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, srcAddr, err := s.videoConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		if n <= 1 {
			continue
		}
		report.VideoPackets++
		if report.FirstVideoSrc == "" && srcAddr != nil {
			report.FirstVideoSrc = srcAddr.String()
			report.FirstPacketDelay = time.Since(start)
		}

		_, payload, ssrc, seq, ts, marker, ok := s.VideoDec.Decrypt(buf[:n])
		if !ok {
			report.SRTPFailed++
			continue
		}
		report.SRTPOK++
		report.BytesDecrypted += int64(len(payload))
		if primarySSRC == 0 {
			primarySSRC = ssrc
		}
		if curGroup != nil && (curGroup.ssrc != ssrc || curGroup.ts != ts) {
			flushGroup(curGroup)
			curGroup = nil
		}
		if curGroup == nil {
			curGroup = &tsGroup{ssrc: ssrc, ts: ts}
		}
		cp := make([]byte, len(payload))
		copy(cp, payload)
		curGroup.packets = append(curGroup.packets, pktEntry{seq: seq, payload: cp})
		if marker {
			flushGroup(curGroup)
			curGroup = nil
		}
	}
	flushGroup(curGroup)
	report.SSRCs = s.VideoDec.SSRCCounts()
	report.Duration = time.Since(start)
	return report, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
