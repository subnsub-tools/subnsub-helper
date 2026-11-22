package applehp

import (
	"context"
	"crypto/aes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	// ProtocolVersion is Apple Screen Sharing's RFB version banner.
	ProtocolVersion = "RFB 003.889\n"

	// SecTypeAppleRSA is RFB security type 33 (0x21), carrying Apple RSA1+SRP
	// or legacy RSA1+AES authentication.
	SecTypeAppleRSA byte = 0x21

	srpHashLen    = 64
	srpModulusLen = 512
	srpPBKDF2Len  = 128
	rsaBlockLen   = 256
	ardCredLen    = 64
)

var (
	// ErrSRPFallback indicates the server rejected or bypassed the SRP-6a path
	// (e.g. older macOS host) and non-SRP RSA1+AES should be attempted on a new TCP connection.
	ErrSRPFallback = errors.New("applehp: server fell back from SRP to legacy auth")

	// ErrAuthRejected indicates invalid credentials or server-side auth denial.
	ErrAuthRejected = errors.New("applehp: authentication rejected")
)

// DoHandshake exchanges the RFB 003.889 banner and reads the advertised security types.
func DoHandshake(rw io.ReadWriter) (string, []byte, error) {
	var banner [12]byte
	if _, err := io.ReadFull(rw, banner[:]); err != nil {
		return "", nil, fmt.Errorf("applehp: read protocol banner: %w", err)
	}
	if !strings.HasPrefix(string(banner[:]), "RFB ") {
		return "", nil, fmt.Errorf("applehp: unexpected protocol banner %q", string(banner[:]))
	}
	if _, err := writeFull(rw, []byte(ProtocolVersion)); err != nil {
		return "", nil, fmt.Errorf("applehp: write protocol banner: %w", err)
	}
	var countBuf [1]byte
	if _, err := io.ReadFull(rw, countBuf[:]); err != nil {
		return "", nil, fmt.Errorf("applehp: read security-type count: %w", err)
	}
	count := int(countBuf[0])
	if count == 0 {
		var reasonLen [4]byte
		if _, err := io.ReadFull(rw, reasonLen[:]); err == nil {
			n := binary.BigEndian.Uint32(reasonLen[:])
			if n > 0 && n <= 4096 {
				reason := make([]byte, n)
				if _, err := io.ReadFull(rw, reason); err == nil {
					return "", nil, fmt.Errorf("applehp: server refused handshake: %s", string(reason))
				}
			}
		}
		return "", nil, errors.New("applehp: server returned empty security-type list")
	}
	secTypes := make([]byte, count)
	if _, err := io.ReadFull(rw, secTypes); err != nil {
		return "", nil, fmt.Errorf("applehp: read security types: %w", err)
	}
	return string(banner[:]), secTypes, nil
}

// WarmupTCP performs Apple Screen Sharing's pre-session TCP probe (connect,
// banner exchange, close, dwell) so screensharingd registers the peer before
// the main control connection opens.
func WarmupTCP(ctx context.Context, localIP, remoteAddr string, dwell time.Duration) error {
	tc, err := DialTCPWithLocal(ctx, localIP, remoteAddr, 10*time.Second)
	if err != nil {
		return err
	}
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	_, _, herr := DoHandshake(tc)
	_ = tc.Close()
	if herr != nil {
		return herr
	}
	if dwell > 0 {
		t := time.NewTimer(dwell)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

func rsa1FetchPublicKey(rw io.ReadWriter) (*rsa.PublicKey, error) {
	initReq := []byte{
		SecTypeAppleRSA,
		0x00, 0x00, 0x00, 0x0a,
		0x01, 0x00, 'R', 'S', 'A', '1',
		0x00, 0x00, 0x00, 0x00,
	}
	if _, err := writeFull(rw, initReq); err != nil {
		return nil, fmt.Errorf("applehp: send RSA1 init: %w", err)
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(rw, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("applehp: read RSA1 pubkey length: %w", err)
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen < 6 || pktLen > 65536 {
		return nil, fmt.Errorf("applehp: invalid RSA1 pubkey packet length %d", pktLen)
	}
	pkt := make([]byte, pktLen)
	if _, err := io.ReadFull(rw, pkt); err != nil {
		return nil, fmt.Errorf("applehp: read RSA1 pubkey: %w", err)
	}
	keyLen := binary.BigEndian.Uint32(pkt[2:6])
	if keyLen == 0 || uint64(6)+uint64(keyLen) > uint64(len(pkt)) {
		return nil, fmt.Errorf("applehp: invalid DER public key length %d", keyLen)
	}
	der := pkt[6 : 6+keyLen]
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		pkcs1Pub, err2 := x509.ParsePKCS1PublicKey(der)
		if err2 != nil {
			return nil, fmt.Errorf("applehp: parse server RSA public key: %w", err)
		}
		return pkcs1Pub, nil
	}
	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("applehp: unexpected server public key type %T", pubAny)
	}
	return rsaPub, nil
}

type srpChallenge struct {
	N          *big.Int
	Nb         []byte // 512 bytes big-endian
	g          *big.Int
	salt       []byte
	B          *big.Int
	Bb         []byte // 512 bytes big-endian
	iterations uint64
	cap        []byte
}

// AuthSRP performs Apple's Type-33 RSA1+SRP-6a (RFC 5054 4096-bit MODP, SHA-512,
// PBKDF2-HMAC-SHA512) authentication and returns the 16-byte enc1103 wrap key.
func AuthSRP(rw io.ReadWriter, username, password string) ([]byte, error) {
	pub, err := rsa1FetchPublicKey(rw)
	if err != nil {
		return nil, err
	}
	userBytes := []byte(username)
	inner := make([]byte, 4+len(userBytes)+3)
	binary.BigEndian.PutUint32(inner[0:4], uint32(len(userBytes)))
	copy(inner[4:], userBytes)
	payload := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint32(payload[0:4], uint32(len(inner)))
	copy(payload[4:], inner)

	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, payload)
	if err != nil {
		return nil, fmt.Errorf("applehp: RSA encrypt SRP identity: %w", err)
	}
	if len(enc) != rsaBlockLen {
		return nil, fmt.Errorf("applehp: expected %dB RSA ciphertext, got %d", rsaBlockLen, len(enc))
	}

	c2s1 := make([]byte, 4+650)
	binary.BigEndian.PutUint32(c2s1[0:4], 650)
	binary.LittleEndian.PutUint16(c2s1[4:6], 1)
	copy(c2s1[6:10], "RSA1")
	c2s1[10] = 0x00
	c2s1[11] = 0x02
	binary.BigEndian.PutUint16(c2s1[12:14], uint16(len(enc)))
	copy(c2s1[14:14+len(enc)], enc)
	if _, err := writeFull(rw, c2s1); err != nil {
		return nil, fmt.Errorf("applehp: send SRP c2s1: %w", err)
	}

	var s2c1LenBuf [4]byte
	if _, err := io.ReadFull(rw, s2c1LenBuf[:]); err != nil {
		return nil, fmt.Errorf("applehp: read SRP challenge length: %w", err)
	}
	s2c1Len := binary.BigEndian.Uint32(s2c1LenBuf[:])
	if s2c1Len > 32768 {
		return nil, fmt.Errorf("applehp: SRP challenge too large (%dB)", s2c1Len)
	}
	s2c1 := make([]byte, s2c1Len)
	if _, err := io.ReadFull(rw, s2c1); err != nil {
		return nil, fmt.Errorf("applehp: read SRP challenge: %w", err)
	}
	if s2c1Len < 1000 {
		return nil, ErrSRPFallback
	}

	ch, err := parseSRPChallenge(s2c1)
	if err != nil {
		return nil, err
	}

	A, Ab, M1, K, err := solveSRP(ch, password)
	if err != nil {
		return nil, err
	}
	_ = A

	var civ [16]byte
	if _, err := io.ReadFull(rand.Reader, civ[:]); err != nil {
		return nil, err
	}
	sd := make([]byte, 0, 2+srpModulusLen+1+srpHashLen+2+len(ch.cap)+1+16)
	sd = binary.BigEndian.AppendUint16(sd, srpModulusLen)
	sd = append(sd, Ab...)
	sd = append(sd, srpHashLen)
	sd = append(sd, M1...)
	sd = binary.BigEndian.AppendUint16(sd, uint16(len(ch.cap)))
	sd = append(sd, ch.cap...)
	sd = append(sd, 16)
	sd = append(sd, civ[:]...)

	payLen := 1076
	if need := 14 + len(sd); need > payLen {
		payLen = need
	}
	c2s2 := make([]byte, 4+payLen)
	binary.BigEndian.PutUint32(c2s2[0:4], uint32(payLen))
	binary.LittleEndian.PutUint16(c2s2[4:6], 1)
	copy(c2s2[6:10], "RSA1")
	c2s2[10] = 0x00
	c2s2[11] = 0x02
	binary.BigEndian.PutUint16(c2s2[12:14], uint16(len(sd)+4))
	binary.BigEndian.PutUint32(c2s2[14:18], uint32(len(sd)))
	copy(c2s2[18:], sd)
	if _, err := writeFull(rw, c2s2); err != nil {
		return nil, fmt.Errorf("applehp: send SRP proof: %w", err)
	}

	var m2LenBuf [4]byte
	if _, err := io.ReadFull(rw, m2LenBuf[:]); err != nil {
		return nil, fmt.Errorf("applehp: read SRP M2 length: %w", err)
	}
	m2Len := binary.BigEndian.Uint32(m2LenBuf[:])
	if m2Len > 32768 {
		return nil, fmt.Errorf("applehp: SRP M2 too large (%dB)", m2Len)
	}
	if m2Len > 0 {
		m2 := make([]byte, m2Len)
		if _, err := io.ReadFull(rw, m2); err != nil {
			return nil, fmt.Errorf("applehp: read SRP M2: %w", err)
		}
	}
	var resBuf [4]byte
	if _, err := io.ReadFull(rw, resBuf[:]); err != nil {
		return nil, fmt.Errorf("applehp: read SRP SecurityResult: %w", err)
	}
	res := binary.BigEndian.Uint32(resBuf[:])
	if res != 0 {
		return nil, fmt.Errorf("%w: SRP result=%d", ErrAuthRejected, res)
	}
	sum := sha256.Sum256(K)
	return sum[:16], nil
}

func parseSRPChallenge(s2c1 []byte) (*srpChallenge, error) {
	if len(s2c1) < 12+srpModulusLen+16 {
		return nil, fmt.Errorf("applehp: SRP challenge truncated (%dB)", len(s2c1))
	}
	// A 10-byte header (u16 0, u16 step = 2, u16 payload_len + 4, u32 payload_len), then the
	// control byte, then N as a u16 length and its bytes: what macOS 15 sends, on Apple silicon
	// and on Intel alike (2026-11-22, Mac14,12 and Macmini8,1). The specification has a 9-byte
	// header; the last word of the header is the length of what follows it, which settles which.
	var head int
	switch {
	case binary.BigEndian.Uint32(s2c1[6:10]) == uint32(len(s2c1)-10):
		head = 10
	case binary.BigEndian.Uint32(s2c1[5:9]) == uint32(len(s2c1)-9):
		head = 9
	default:
		return nil, errors.New("applehp: SRP challenge framing not recognised")
	}
	nLen := int(binary.BigEndian.Uint16(s2c1[head+1 : head+3]))
	p := head + 3
	var Nb []byte
	switch {
	case nLen == srpModulusLen+1 && s2c1[p] == 0x00:
		p++
		Nb = append([]byte(nil), s2c1[p:p+srpModulusLen]...)
		p += srpModulusLen
	case nLen == srpModulusLen:
		Nb = append([]byte(nil), s2c1[p:p+srpModulusLen]...)
		p += srpModulusLen
	default:
		return nil, fmt.Errorf("applehp: unexpected SRP modulus length %d (marker=0x%02x)", nLen, s2c1[p])
	}

	if p+2 > len(s2c1) {
		return nil, errors.New("applehp: SRP challenge truncated at gLen")
	}
	gLen := int(binary.BigEndian.Uint16(s2c1[p : p+2]))
	p += 2
	if gLen == 0 || p+gLen+1 > len(s2c1) {
		return nil, errors.New("applehp: SRP challenge invalid gLen")
	}
	g := new(big.Int).SetBytes(s2c1[p : p+gLen])
	p += gLen

	saltLen := int(s2c1[p])
	p++
	if p+saltLen+2 > len(s2c1) {
		return nil, errors.New("applehp: SRP challenge truncated at salt")
	}
	salt := append([]byte(nil), s2c1[p:p+saltLen]...)
	p += saltLen

	bLen := int(binary.BigEndian.Uint16(s2c1[p : p+2]))
	p += 2
	if bLen == 0 || p+bLen+10 > len(s2c1) {
		return nil, errors.New("applehp: SRP challenge truncated at B")
	}
	B := new(big.Int).SetBytes(s2c1[p : p+bLen])
	Bb := padBigIntBE(B, srpModulusLen)
	p += bLen

	iterations := binary.BigEndian.Uint64(s2c1[p : p+8])
	p += 8
	if iterations == 0 || iterations > 1_000_000 {
		return nil, fmt.Errorf("applehp: SRP iteration count %d out of range", iterations)
	}

	capLen := int(binary.BigEndian.Uint16(s2c1[p : p+2]))
	p += 2
	if p+capLen > len(s2c1) {
		return nil, errors.New("applehp: SRP challenge truncated at cap")
	}
	capBytes := append([]byte(nil), s2c1[p:p+capLen]...)

	return &srpChallenge{
		N:          new(big.Int).SetBytes(Nb),
		Nb:         Nb,
		g:          g,
		salt:       salt,
		B:          B,
		Bb:         Bb,
		iterations: iterations,
		cap:        capBytes,
	}, nil
}

func solveSRP(ch *srpChallenge, password string) (A *big.Int, Ab, M1, K []byte, err error) {
	gPad := padBigIntBE(ch.g, srpModulusLen)
	kBytes := sha512Concat(ch.Nb, gPad)
	k := new(big.Int).SetBytes(kBytes)

	var aRand [64]byte
	if _, err = io.ReadFull(rand.Reader, aRand[:]); err != nil {
		return nil, nil, nil, nil, err
	}
	nMinus1 := new(big.Int).Sub(ch.N, big.NewInt(1))
	a := new(big.Int).SetBytes(aRand[:])
	a.Mod(a, nMinus1)
	a.Add(a, big.NewInt(1))

	A = new(big.Int).Exp(ch.g, a, ch.N)
	Ab = padBigIntBE(A, srpModulusLen)

	u := new(big.Int).SetBytes(sha512Concat(Ab, ch.Bb))

	dk, err := pbkdf2.Key(sha512.New, password, ch.salt, int(ch.iterations), srpPBKDF2Len)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("applehp: PBKDF2: %w", err)
	}
	inner := sha512Concat([]byte(":"), dk)
	x := new(big.Int).SetBytes(sha512Concat(ch.salt, inner))
	x.Mod(x, ch.N)

	gx := new(big.Int).Exp(ch.g, x, ch.N)
	kgx := new(big.Int).Mul(k, gx)
	kgx.Mod(kgx, ch.N)
	base := new(big.Int).Sub(ch.B, kgx)
	base.Mod(base, ch.N)

	ux := new(big.Int).Mul(u, x)
	exp := new(big.Int).Add(a, ux)
	S := new(big.Int).Exp(base, exp, ch.N)
	K = sha512Concat(padBigIntBE(S, srpModulusLen))

	hN := sha512.Sum512(ch.Nb)
	hG := sha512.Sum512(gPad)
	var hXor [64]byte
	for i := 0; i < 64; i++ {
		hXor[i] = hN[i] ^ hG[i]
	}
	hEmpty := sha512.Sum512(nil)
	M1 = sha512Concat(hXor[:], hEmpty[:], ch.salt, Ab, ch.Bb, K)
	return A, Ab, M1, K, nil
}

// AuthNonSRP performs legacy RSA1+AES (Type 33 non-SRP) authentication and
// returns the 16-byte enc1103 wrap key.
func AuthNonSRP(rw io.ReadWriter, username, password string) ([]byte, error) {
	pub, err := rsa1FetchPublicKey(rw)
	if err != nil {
		return nil, err
	}
	aesKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, err
	}
	creds := make([]byte, ardCredLen*2)
	if err := packARDField(creds[:ardCredLen], username); err != nil {
		return nil, err
	}
	if err := packARDField(creds[ardCredLen:], password); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	encCreds := make([]byte, len(creds))
	for off := 0; off < len(creds); off += 16 {
		block.Encrypt(encCreds[off:off+16], creds[off:off+16])
	}
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, aesKey)
	if err != nil {
		return nil, fmt.Errorf("applehp: RSA encrypt AES key: %w", err)
	}

	blob := make([]byte, 0, 10+len(encCreds)+len(encKey))
	blob = append(blob, 0x01, 0x00, 'R', 'S', 'A', '1', 0x00, 0x01)
	blob = append(blob, encCreds...)
	blob = append(blob, 0x00, 0x01)
	blob = append(blob, encKey...)

	pkt := make([]byte, 4+len(blob))
	binary.BigEndian.PutUint32(pkt[0:4], uint32(len(blob)))
	copy(pkt[4:], blob)
	if _, err := writeFull(rw, pkt); err != nil {
		return nil, fmt.Errorf("applehp: send non-SRP credentials: %w", err)
	}

	var resp [8]byte
	if _, err := io.ReadFull(rw, resp[:]); err != nil {
		return nil, fmt.Errorf("applehp: read non-SRP result: %w", err)
	}
	res := binary.BigEndian.Uint32(resp[4:8])
	if res != 0 {
		return nil, fmt.Errorf("%w: non-SRP result=%d", ErrAuthRejected, res)
	}
	return aesKey, nil
}

func packARDField(dst []byte, s string) error {
	b := []byte(s)
	if len(b) >= len(dst) {
		copy(dst[:len(dst)-1], b[:len(dst)-1])
		dst[len(dst)-1] = 0
		return nil
	}
	copy(dst, b)
	dst[len(b)] = 0
	if len(b)+1 < len(dst) {
		if _, err := io.ReadFull(rand.Reader, dst[len(b)+1:]); err != nil {
			return err
		}
	}
	return nil
}

func padBigIntBE(v *big.Int, width int) []byte {
	out := make([]byte, width)
	b := v.Bytes()
	if len(b) >= width {
		copy(out, b[len(b)-width:])
		return out
	}
	copy(out[width-len(b):], b)
	return out
}

func sha512Concat(parts ...[]byte) []byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func validateIPv4Addr(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return "", fmt.Errorf("applehp: IPv6 address %q unsupported for Apple HP UDP media", host)
		}
		return v4.String(), nil
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("applehp: resolve IPv4 for %q: %w", host, err)
	}
	v4 := ips[0].To4()
	if v4 == nil {
		return "", fmt.Errorf("applehp: %q has no IPv4 address", host)
	}
	return v4.String(), nil
}
