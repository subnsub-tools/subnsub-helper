package applehp

// MockHost stands in for a Mac's Screen Sharing in tests: it takes the
// sign-in, the rekey and the media offer as this package sends them, then
// streams the frames it was given and records what the viewer sends back.
// It follows this client, not the Mac: passing against it shows the client
// and what is built on it agree with each other, nothing more.

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// MockPointer and MockKey are what a viewer sent.
type MockPointer struct {
	Mask byte
	X, Y int
}

type MockKey struct {
	Down   bool
	Keysym uint32
}

type MockHost struct {
	Username, Password string
	// The display, in points and in pixels.
	Width, Height int
	BackingW      int
	BackingH      int
	// The stream: parameter sets, then access units (each a list of NAL
	// units, the first a key frame), sent round and round at FPS.
	SPS, PPS []byte
	Frames   [][][]byte
	FPS      int
	// Audio payloads, one every AudioEvery, round and round; none sends none.
	Audio      [][]byte
	AudioEvery time.Duration
	// Where the viewer's media sockets are; zero is the listener's port and
	// the one after it, as a viewer that was told nothing else binds.
	ClientCtrlPort, ClientVideoPort int

	ln   net.Listener
	rsa  *rsa.PrivateKey
	once sync.Once

	mu       sync.Mutex
	pointers []MockPointer
	keys     []MockKey
	cuts     []string
	modes    []bool
	resizes  [][2]int
	offers   int
	arms     int
	sessions int
	live     *mockSession
}

type mockSession struct {
	conn   net.Conn
	cipher *RecordCipher
	stop   chan struct{}
	once   sync.Once
}

func (s *mockSession) end() { s.once.Do(func() { close(s.stop); s.conn.Close() }) }

// Listen starts the host on addr ("127.0.0.1:0" for any port).
func (m *MockHost) Listen(addr string) error {
	if m.Width == 0 {
		m.Width, m.Height = 1280, 720
	}
	if m.BackingW == 0 {
		m.BackingW, m.BackingH = m.Width, m.Height
	}
	if m.FPS <= 0 {
		m.FPS = 30
	}
	if m.AudioEvery <= 0 {
		m.AudioEvery = 10 * time.Millisecond
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	m.rsa = k
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	m.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return nil
}

func (m *MockHost) Port() int { return m.ln.Addr().(*net.TCPAddr).Port }

func (m *MockHost) Close() {
	m.once.Do(func() {
		if m.ln != nil {
			m.ln.Close()
		}
		m.mu.Lock()
		s := m.live
		m.mu.Unlock()
		if s != nil {
			s.end()
		}
	})
}

// What the viewer has sent so far.
func (m *MockHost) Pointers() []MockPointer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]MockPointer(nil), m.pointers...)
}

func (m *MockHost) Keys() []MockKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]MockKey(nil), m.keys...)
}

// Modes is each SetMode the viewer sent: true to control, false to observe.
func (m *MockHost) Modes() []bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]bool(nil), m.modes...)
}

func (m *MockHost) CutTexts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.cuts...)
}

func (m *MockHost) Resizes() [][2]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][2]int(nil), m.resizes...)
}

// Counts answers how many media offers, armings and signed-in sessions
// there have been.
func (m *MockHost) Counts() (offers, arms, sessions int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.offers, m.arms, m.sessions
}

// SendClipboard puts text on the "host's" clipboard for the session there is.
func (m *MockHost) SendClipboard(text string) error {
	m.mu.Lock()
	s := m.live
	m.mu.Unlock()
	if s == nil {
		return errors.New("no session")
	}
	var arc []byte
	put := func(b []byte) {
		arc = binary.BigEndian.AppendUint32(arc, uint32(len(b)))
		arc = append(arc, b...)
	}
	arc = binary.BigEndian.AppendUint32(arc, 1)
	put([]byte("public.utf8-plain-text"))
	arc = binary.BigEndian.AppendUint32(arc, 0)
	arc = binary.BigEndian.AppendUint32(arc, 1)
	put([]byte("public.mime-type"))
	put([]byte("text/plain;charset=utf-8"))
	put([]byte(text))
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write(arc)
	zw.Flush()
	msg := make([]byte, 16, 16+zb.Len())
	msg[0] = MsgServerClipboardSend
	binary.BigEndian.PutUint32(msg[8:12], uint32(len(arc)))
	binary.BigEndian.PutUint32(msg[12:16], uint32(zb.Len()))
	msg = append(msg, zb.Bytes()...)
	return s.cipher.EncryptAndSend(s.conn, msg)
}

func (m *MockHost) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	ecbKey, err := m.signIn(conn)
	if err != nil {
		return
	}
	// ClientInit, ServerInit.
	var ci [1]byte
	if _, err := io.ReadFull(conn, ci[:]); err != nil {
		return
	}
	var si [24]byte
	binary.BigEndian.PutUint16(si[0:2], uint16(m.Width))
	binary.BigEndian.PutUint16(si[2:4], uint16(m.Height))
	conn.Write(si[:])
	// The cleartext prelude, up to the encodings.
	for {
		t, body, err := readClear(conn)
		if err != nil {
			return
		}
		if t == MsgClientVirtualDisplay {
			// A display of the session's own, at the size it asks for.
			if w, h, ok := m.noteResize(body); ok {
				m.mu.Lock()
				m.Width, m.Height, m.BackingW, m.BackingH = w, h, w, h
				m.mu.Unlock()
			}
		}
		if t == MsgClientSetEncodings {
			break
		}
	}
	// The rekey, and the word that the viewer took it.
	cbcKey := make([]byte, 16)
	cbcIV := make([]byte, 16)
	rand.Read(cbcKey)
	rand.Read(cbcIV)
	wrap, _ := aes.NewCipher(ecbKey[:16])
	var rekey [36]byte
	binary.BigEndian.PutUint32(rekey[0:4], 1)
	wrap.Encrypt(rekey[4:20], cbcKey)
	wrap.Encrypt(rekey[20:36], cbcIV)
	fbu := make([]byte, 4+12+36)
	binary.BigEndian.PutUint16(fbu[2:4], 1)
	binary.BigEndian.PutUint32(fbu[12:16], uint32(EncAppleRekey))
	copy(fbu[16:], rekey[:])
	conn.Write(fbu)
	if t, _, err := readClear(conn); err != nil || t != MsgClientSetEncryption {
		return
	}
	cipher, err := NewRecordCipher(rekey[:], ecbKey[:16])
	if err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	s := &mockSession{conn: conn, cipher: cipher, stop: make(chan struct{})}
	m.mu.Lock()
	if m.live != nil {
		m.live.end()
	}
	m.live = s
	m.sessions++
	m.mu.Unlock()
	defer s.end()

	var media chan struct{}
	offered := false
	stopMedia := func() {
		if media != nil {
			close(media)
			media = nil
		}
	}
	defer stopMedia()
	for {
		var rl [2]byte
		if _, err := io.ReadFull(conn, rl[:]); err != nil {
			return
		}
		ct := make([]byte, binary.BigEndian.Uint16(rl[:]))
		if _, err := io.ReadFull(conn, ct); err != nil {
			return
		}
		msg, ok := cipher.DecryptRecord(ct)
		if !ok || len(msg) == 0 {
			return
		}
		switch msg[0] {
		case MsgClientMediaNegotiation:
			if len(msg) < 0x80 {
				return
			}
			as := int(binary.BigEndian.Uint16(msg[10:12]))
			vo := 0x80 + as
			if len(msg) < vo+0x5c {
				return
			}
			audioKey := append([]byte(nil), msg[0x52:0x80]...)
			videoKey := append([]byte(nil), msg[vo+0x2e:vo+0x5c]...)
			m.mu.Lock()
			m.offers++
			first := !offered
			offered = true
			bw, bh := m.BackingW, m.BackingH
			m.mu.Unlock()
			cipher.EncryptAndSend(conn, mockAnswer(bw, bh))
			if first {
				cipher.EncryptAndSend(conn, m.metadata())
			}
			stopMedia()
			media = make(chan struct{})
			go m.stream(conn.RemoteAddr().(*net.TCPAddr).IP, videoKey, audioKey, media)
		case MsgClientVirtualDisplay:
			if w, h, ok := m.noteResize(msg); ok {
				// The new size is said; pictures stop until it is offered for.
				stopMedia()
				m.mu.Lock()
				m.Width, m.Height, m.BackingW, m.BackingH = w, h, w, h
				m.mu.Unlock()
				cipher.EncryptAndSend(conn, m.layoutUpdate())
			}
		case MsgClientAutoFBUpdate:
			m.mu.Lock()
			m.arms++
			m.mu.Unlock()
		case msgClientEncryptedEvent:
			// As Screen Sharing reads it (stream.go sendEvent): one block
			// under the record key, a key and the pointer each marked.
			if len(msg) >= 18 {
				var p [16]byte
				if b, err := aes.NewCipher(cipher.CBCKey); err == nil {
					b.Decrypt(p[:], msg[2:18])
				}
				m.mu.Lock()
				if p[0] == 0xff {
					m.keys = append(m.keys, MockKey{p[1] != 0, binary.BigEndian.Uint32(p[2:6])})
				}
				if p[10] == 0xff {
					m.pointers = append(m.pointers, MockPointer{p[11], int(binary.BigEndian.Uint16(p[12:14])), int(binary.BigEndian.Uint16(p[14:16]))})
				}
				m.mu.Unlock()
			}
		case MsgClientPointerEvent:
			if len(msg) >= 6 {
				m.mu.Lock()
				m.pointers = append(m.pointers, MockPointer{msg[1], int(binary.BigEndian.Uint16(msg[2:4])), int(binary.BigEndian.Uint16(msg[4:6]))})
				m.mu.Unlock()
			}
		case MsgClientKeyEvent:
			if len(msg) >= 8 {
				m.mu.Lock()
				m.keys = append(m.keys, MockKey{msg[1] != 0, binary.BigEndian.Uint32(msg[4:8])})
				m.mu.Unlock()
			}
		case MsgClientSetMode:
			if len(msg) >= 4 {
				m.mu.Lock()
				m.modes = append(m.modes, msg[3] == 1)
				m.mu.Unlock()
			}
		case MsgClientCutText:
			if len(msg) >= 8 {
				n := int(binary.BigEndian.Uint32(msg[4:8]))
				if 8+n <= len(msg) {
					r := make([]rune, n)
					for i, c := range msg[8 : 8+n] {
						r[i] = rune(c)
					}
					m.mu.Lock()
					m.cuts = append(m.cuts, string(r))
					m.mu.Unlock()
				}
			}
		}
	}
}

// readClear reads one of the viewer's cleartext messages.
func readClear(r io.Reader) (byte, []byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	rest := 0
	switch h[0] {
	case MsgClientViewerInfo, MsgClientVirtualDisplay:
		rest = int(binary.BigEndian.Uint16(h[2:4]))
	case MsgClientSetEncryption:
		rest = 4
		if h[3] == 1 {
			rest = 8
		}
	case MsgClientSetEncodings:
		rest = 4 * int(binary.BigEndian.Uint16(h[2:4]))
	default:
		return 0, nil, errors.New("mock host: unexpected cleartext message")
	}
	b := make([]byte, 4+rest)
	copy(b, h[:])
	if _, err := io.ReadFull(r, b[4:]); err != nil {
		return 0, nil, err
	}
	return h[0], b, nil
}

// noteResize reads a display configuration and records the size it asks
// for, where it asks for a display that can change size.
func (m *MockHost) noteResize(msg []byte) (int, int, bool) {
	const d = 0x0c
	if len(msg) < d+0x9c+28 {
		return 0, 0, false
	}
	if binary.BigEndian.Uint32(msg[d+0x7a:d+0x7e])&1 == 0 {
		return 0, 0, false
	}
	cur := int(binary.BigEndian.Uint16(msg[d+0x92 : d+0x94]))
	e := d + 0x9c + 28*cur
	if e+28 > len(msg) {
		return 0, 0, false
	}
	w := int(binary.BigEndian.Uint32(msg[e+8 : e+12]))
	h := int(binary.BigEndian.Uint32(msg[e+12 : e+16]))
	m.mu.Lock()
	m.resizes = append(m.resizes, [2]int{w, h})
	m.mu.Unlock()
	return w, h, true
}

// mockAnswer is the answer to a media offer as macOS 15 sends it: a framebuffer update with one
// 0x3f2 rectangle holding a plist for each stream, the audio one (no size) before the video one.
func mockAnswer(w, h int) []byte {
	plist := func(blob []byte) []byte {
		var zb bytes.Buffer
		zw := zlib.NewWriter(&zb)
		zw.Write(blob)
		zw.Close()
		pl, _ := EncodePlistDict(map[string]any{
			"avcMediaStreamNegotiatorMediaBlob": zb.Bytes(),
		})
		return pl
	}
	audio := plist(appendFieldVarint(nil, 1, 1))
	inner := appendFieldVarint(nil, 4, uint64(w))
	inner = appendFieldVarint(inner, 5, uint64(h))
	inner = appendFieldVarint(inner, 6, 1)
	video := plist(appendFieldBytes(nil, 5, inner))
	body := []byte{0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}
	body = binary.BigEndian.AppendUint16(body, uint16(len(audio)))
	body = binary.BigEndian.AppendUint16(body, uint16(len(video)))
	body = append(body, make([]byte, 6)...)
	body = append(append(body, audio...), video...)
	msg := []byte{0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	msg = binary.BigEndian.AppendUint32(msg, uint32(EncAppleMediaInit))
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(body)))
	return append(msg, body...)
}

func (m *MockHost) layoutRect() []byte {
	m.mu.Lock()
	sw, sh, bw, bh := m.Width, m.Height, m.BackingW, m.BackingH
	m.mu.Unlock()
	body := make([]byte, 20+56)
	binary.BigEndian.PutUint16(body[0:2], 5)
	binary.BigEndian.PutUint16(body[2:4], uint16(sw))
	binary.BigEndian.PutUint16(body[4:6], uint16(sh))
	binary.BigEndian.PutUint16(body[6:8], uint16(bw))
	binary.BigEndian.PutUint16(body[8:10], uint16(bh))
	binary.BigEndian.PutUint16(body[18:20], 1)
	r := make([]byte, 12, 14+len(body))
	binary.BigEndian.PutUint32(r[8:12], uint32(EncAppleLayout))
	r = binary.BigEndian.AppendUint16(r, uint16(len(body)))
	return append(r, body...)
}

func (m *MockHost) layoutUpdate() []byte {
	u := []byte{0, 0, 0, 1}
	return append(u, m.layoutRect()...)
}

// metadata is what a host says once the stream is agreed: its layout, the
// vendor keys, and a cursor (a red 2 by 2, half transparent) stored and
// then shown again by its id alone.
func (m *MockHost) metadata() []byte {
	u := []byte{0, 0, 0, 4}
	u = append(u, m.layoutRect()...)
	ks := make([]byte, 12+22)
	binary.BigEndian.PutUint32(ks[8:12], uint32(EncAppleKeysyms))
	copy(ks[12:], []byte{0, 0x14, 0, 1, 0, 4, 0x10, 0x08, 0xfd, 0, 0x10, 0x08, 0xfd, 1, 0x10, 0x08, 0xfd, 2, 0x10, 0x08, 0xfd, 3})
	u = append(u, ks...)
	const w, h = 2, 2
	raw := make([]byte, w*h*5)
	for i := 0; i < w*h; i++ {
		raw[i*4+2] = 0xff // BGRA: red
		raw[w*h*4+i] = 0x80
	}
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write(raw)
	zw.Flush()
	cur := make([]byte, 12, 20+zb.Len())
	binary.BigEndian.PutUint16(cur[0:2], 1)
	binary.BigEndian.PutUint16(cur[2:4], 1)
	binary.BigEndian.PutUint16(cur[4:6], w)
	binary.BigEndian.PutUint16(cur[6:8], h)
	binary.BigEndian.PutUint32(cur[8:12], uint32(EncAppleCursor))
	cur = binary.BigEndian.AppendUint32(cur, 1000)
	cur = binary.BigEndian.AppendUint32(cur, uint32(zb.Len()))
	cur = append(cur, zb.Bytes()...)
	u = append(u, cur...)
	sel := make([]byte, 12+8)
	binary.BigEndian.PutUint32(sel[8:12], uint32(EncAppleCursor))
	binary.BigEndian.PutUint32(sel[12:16], 1000)
	return append(u, sel...)
}

// stream sends the frames and the audio until stop closes.
func (m *MockHost) stream(to net.IP, videoKey, audioKey []byte, stop chan struct{}) {
	m.mu.Lock()
	cp, vp := m.ClientCtrlPort, m.ClientVideoPort
	m.mu.Unlock()
	if cp == 0 {
		cp = m.Port()
	}
	if vp == 0 {
		vp = cp + 1
	}
	vs, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: to, Port: vp})
	if err != nil {
		return
	}
	defer vs.Close()
	as, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: to, Port: cp})
	if err != nil {
		return
	}
	defer as.Close()
	var sb [8]byte
	rand.Read(sb[:])
	venc, err := NewSRTPEncryptor(videoKey, binary.BigEndian.Uint32(sb[0:4])|1)
	if err != nil {
		return
	}
	aenc, err := NewSRTPEncryptor(audioKey, binary.BigEndian.Uint32(sb[4:8])|1)
	if err != nil {
		return
	}
	stamp := func(e *SRTPEncryptor, ts uint32) {
		e.mu.Lock()
		e.ts = ts
		e.mu.Unlock()
	}
	if len(m.Audio) > 0 {
		go func() {
			t := time.NewTicker(m.AudioEvery)
			defer t.Stop()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				case <-t.C:
					stamp(aenc, uint32(i)*480)
					as.Write(aenc.Encrypt(m.Audio[i%len(m.Audio)], 101, false))
				}
			}
		}()
	}
	if len(m.Frames) == 0 {
		<-stop
		return
	}
	avcc := []byte{1, m.SPS[1], m.SPS[2], m.SPS[3], 0xff, 0xe1}
	avcc = binary.BigEndian.AppendUint16(avcc, uint16(len(m.SPS)))
	avcc = append(avcc, m.SPS...)
	avcc = append(avcc, 1)
	avcc = binary.BigEndian.AppendUint16(avcc, uint16(len(m.PPS)))
	avcc = append(avcc, m.PPS...)
	cfg := append([]byte{AppleAVCConfigMarker, 0, 0, 0}, []byte("avc1avcC")...)
	cfg = append(cfg, avcc...)
	const mtu = 1100
	t := time.NewTicker(time.Second / time.Duration(m.FPS))
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		au := m.Frames[i%len(m.Frames)]
		ts := uint32(i) * uint32(90000/m.FPS)
		var pkts [][]byte
		if i%len(m.Frames) == 0 {
			pkts = append(pkts, cfg)
		}
		for _, nal := range au {
			if len(nal) == 0 {
				continue
			}
			if len(nal) <= mtu {
				pkts = append(pkts, nal)
				continue
			}
			ind := nal[0]&0xe0 | H264NALFUA
			typ := nal[0] & 0x1f
			rest := nal[1:]
			for first := true; len(rest) > 0; first = false {
				n := min(len(rest), mtu)
				fh := typ
				if first {
					fh |= 0x80
				}
				if n == len(rest) {
					fh |= 0x40
				}
				pkts = append(pkts, append([]byte{ind, fh}, rest[:n]...))
				rest = rest[n:]
			}
		}
		for k, p := range pkts {
			stamp(venc, ts)
			vs.Write(venc.Encrypt(p, 123, k == len(pkts)-1))
			// A burst of a key frame's packets all at once overruns a
			// loopback receiver's buffer in a test under load.
			if k%32 == 31 {
				time.Sleep(time.Millisecond)
			}
		}
	}
}

// signIn is the sign-in this package's client performs, from the server's
// side: the security type, the key, SRP-6a over a modulus of the right size
// (a made-up one: the arithmetic is the same and a test need not be slow).
func (m *MockHost) signIn(conn net.Conn) ([]byte, error) {
	var mod [512]byte
	mod[0] = 0xff
	for i := 1; i < 511; i++ {
		mod[i] = byte(i*17 + 3)
	}
	mod[511] = 0xfb
	N := new(big.Int).SetBytes(mod[:])
	g := big.NewInt(5)
	salt := bytes.Repeat([]byte{0x42}, 32)
	const iters uint64 = 100
	dk, err := pbkdf2.Key(sha512.New, m.Password, salt, int(iters), srpPBKDF2Len)
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(sha512Concat(salt, sha512Concat([]byte(":"), dk)))
	x.Mod(x, N)
	v := new(big.Int).Exp(g, x, N)
	var bb [32]byte
	rand.Read(bb[:])
	bPriv := new(big.Int).SetBytes(bb[:])
	k := new(big.Int).SetBytes(sha512Concat(mod[:], padBigIntBE(g, srpModulusLen)))
	B := new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, bPriv, N))
	B.Mod(B, N)

	conn.Write([]byte(ProtocolVersion))
	var ver [12]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return nil, err
	}
	conn.Write([]byte{1, SecTypeAppleRSA})
	var init [15]byte
	if _, err := io.ReadFull(conn, init[:]); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&m.rsa.PublicKey)
	if err != nil {
		return nil, err
	}
	pk := make([]byte, 4+6+len(der))
	binary.BigEndian.PutUint32(pk[0:4], uint32(6+len(der)))
	binary.BigEndian.PutUint32(pk[6:10], uint32(len(der)))
	copy(pk[10:], der)
	conn.Write(pk)

	read := func() ([]byte, error) {
		var l [4]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(l[:])
		if n > 1<<16 {
			return nil, errors.New("mock host: message too long")
		}
		b := make([]byte, n)
		_, err := io.ReadFull(conn, b)
		return b, err
	}
	refuse := func() ([]byte, error) {
		conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1})
		return nil, ErrAuthRejected
	}
	c1, err := read()
	if err != nil {
		return nil, err
	}
	if len(c1) < 10 {
		return nil, errors.New("mock host: short identity")
	}
	el := int(binary.BigEndian.Uint16(c1[8:10]))
	if 10+el > len(c1) {
		return nil, errors.New("mock host: short identity")
	}
	ident, err := rsa.DecryptPKCS1v15(rand.Reader, m.rsa, c1[10:10+el])
	if err != nil || len(ident) < 8 {
		return refuse()
	}
	ul := int(binary.BigEndian.Uint32(ident[4:8]))
	if 8+ul > len(ident) {
		return refuse()
	}
	userOK := string(ident[8:8+ul]) == m.Username

	// Laid out as macOS 15 lays it out (see parseSRPChallenge); the header goes on once the
	// rest is known.
	caps := []byte("mda=SHA-512")
	s1 := []byte{0x00}
	s1 = binary.BigEndian.AppendUint16(s1, srpModulusLen)
	s1 = append(s1, mod[:]...)
	s1 = binary.BigEndian.AppendUint16(s1, 1)
	s1 = append(s1, 5, byte(len(salt)))
	s1 = append(s1, salt...)
	Bb := padBigIntBE(B, srpModulusLen)
	s1 = binary.BigEndian.AppendUint16(s1, uint16(len(Bb)))
	s1 = append(s1, Bb...)
	s1 = binary.BigEndian.AppendUint64(s1, iters)
	s1 = binary.BigEndian.AppendUint16(s1, uint16(len(caps)))
	s1 = append(s1, caps...)
	head := []byte{0x00, 0x00, 0x00, 0x02}
	head = binary.BigEndian.AppendUint16(head, uint16(len(s1)+4))
	head = binary.BigEndian.AppendUint32(head, uint32(len(s1)))
	s1 = append(head, s1...)
	conn.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s1))))
	conn.Write(s1)

	c2, err := read()
	if err != nil {
		return nil, err
	}
	if len(c2) < 14 {
		return nil, errors.New("mock host: short proof")
	}
	sl := int(binary.BigEndian.Uint32(c2[10:14]))
	if 14+sl > len(c2) || sl < 3 {
		return nil, errors.New("mock host: short proof")
	}
	sd := c2[14 : 14+sl]
	al := int(binary.BigEndian.Uint16(sd[0:2]))
	if 3+al > len(sd) {
		return nil, errors.New("mock host: short proof")
	}
	Ab := sd[2 : 2+al]
	ml := int(sd[2+al])
	if 3+al+ml > len(sd) {
		return nil, errors.New("mock host: short proof")
	}
	m1 := sd[3+al : 3+al+ml]
	A := new(big.Int).SetBytes(Ab)
	u := new(big.Int).SetBytes(sha512Concat(Ab, Bb))
	S := new(big.Int).Exp(new(big.Int).Mod(new(big.Int).Mul(A, new(big.Int).Exp(v, u, N)), N), bPriv, N)
	K := sha512Concat(padBigIntBE(S, srpModulusLen))
	hN := sha512.Sum512(mod[:])
	hG := sha512.Sum512(padBigIntBE(g, srpModulusLen))
	var hx [64]byte
	for i := range hx {
		hx[i] = hN[i] ^ hG[i]
	}
	he := sha512.Sum512(nil)
	if !userOK || !bytes.Equal(m1, sha512Concat(hx[:], he[:], salt, Ab, Bb, K)) {
		return refuse()
	}
	key := sha256.Sum256(K)
	conn.Write([]byte{0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0})
	return key[:], nil
}
