package applehp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// SRTPKeyBlobLen is the 46-byte AVConference key blob (32B AES-256 key + 14B salt).
	SRTPKeyBlobLen    = 46
	srtpMasterKeyLen  = 32
	srtpMasterSaltLen = 14
	srtpAuthTagLen    = 10
	rtpHeaderMinLen   = 12
	ntpEpochDelta     = 2208988800
)

// SSRCState captures per-SSRC RTP rollover and highest sequence numbers for RR reports.
type SSRCState struct {
	ROC         uint32
	MaxSeq      uint16
	Initialized bool
}

func splitSRTPBlob(blob []byte) ([]byte, []byte, error) {
	if len(blob) != SRTPKeyBlobLen {
		return nil, nil, fmt.Errorf("applehp: SRTP key blob must be %d bytes, got %d", SRTPKeyBlobLen, len(blob))
	}
	return blob[:srtpMasterKeyLen], blob[srtpMasterKeyLen:SRTPKeyBlobLen], nil
}

// srtpKDF implements RFC 3711 §4.3.1 AES-CM key derivation.
func srtpKDF(masterKey, masterSalt []byte, label byte, outLen int) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	var iv0 [14]byte
	copy(iv0[:], masterSalt)
	iv0[7] ^= label

	out := make([]byte, 0, ((outLen+15)/16)*16)
	var inBlock [16]byte
	var encBlock [16]byte
	for counter := uint16(0); len(out) < outLen; counter++ {
		copy(inBlock[:14], iv0[:])
		binary.BigEndian.PutUint16(inBlock[14:16], counter)
		block.Encrypt(encBlock[:], inBlock[:])
		out = append(out, encBlock[:]...)
	}
	return out[:outLen], nil
}

// SRTPDecryptor decrypts Apple AES-256-CTR + HMAC-SHA1-80 SRTP packets while
// tracking per-SSRC rollover counters.
type SRTPDecryptor struct {
	block   cipher.Block
	authKey []byte
	salt    [14]byte

	mu     sync.Mutex
	states map[uint32]*SSRCState
	counts map[uint32]int
}

// NewSRTPDecryptor builds an SRTP receiver from a 46-byte 0x1c key blob.
func NewSRTPDecryptor(blob []byte) (*SRTPDecryptor, error) {
	mk, ms, err := splitSRTPBlob(blob)
	if err != nil {
		return nil, err
	}
	cipherKey, err := srtpKDF(mk, ms, 0, 32)
	if err != nil {
		return nil, err
	}
	authKey, err := srtpKDF(mk, ms, 1, 20)
	if err != nil {
		return nil, err
	}
	salt, err := srtpKDF(mk, ms, 2, 14)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	d := &SRTPDecryptor{
		block:   block,
		authKey: authKey,
		states:  make(map[uint32]*SSRCState),
		counts:  make(map[uint32]int),
	}
	copy(d.salt[:], salt)
	return d, nil
}

// Decrypt authenticates and decrypts one SRTP packet.
func (d *SRTPDecryptor) Decrypt(pkt []byte) (hdr, payload []byte, ssrc uint32, seq uint16, ts uint32, marker bool, ok bool) {
	if len(pkt) < rtpHeaderMinLen+srtpAuthTagLen {
		return nil, nil, 0, 0, 0, false, false
	}
	bodyLen := len(pkt) - srtpAuthTagLen
	seq = binary.BigEndian.Uint16(pkt[2:4])
	ts = binary.BigEndian.Uint32(pkt[4:8])
	ssrc = binary.BigEndian.Uint32(pkt[8:12])
	marker = pkt[1]&0x80 != 0

	d.mu.Lock()
	st := d.states[ssrc]
	var curROC, rocGuess uint32
	if st != nil && st.Initialized {
		curROC = st.ROC
		diff := int32(seq) - int32(st.MaxSeq)
		switch {
		case diff > 0x7fff:
			if st.ROC > 0 {
				rocGuess = st.ROC - 1
			}
		case diff < -0x7fff:
			rocGuess = st.ROC + 1
		default:
			rocGuess = st.ROC
		}
	}
	d.mu.Unlock()

	cands := make([]uint32, 0, 4)
	addCand := func(r uint32) {
		for _, prev := range cands {
			if prev == r {
				return
			}
		}
		cands = append(cands, r)
	}
	addCand(rocGuess)
	addCand(curROC)
	addCand(rocGuess + 1)
	if rocGuess > 0 {
		addCand(rocGuess - 1)
	}

	for _, roc := range cands {
		h, p, good := d.tryDecrypt(pkt, bodyLen, seq, ssrc, roc)
		if good {
			d.mu.Lock()
			d.updateStateLocked(ssrc, roc, seq)
			d.counts[ssrc]++
			d.mu.Unlock()
			return h, p, ssrc, seq, ts, marker, true
		}
	}
	return nil, nil, ssrc, seq, ts, marker, false
}

func (d *SRTPDecryptor) tryDecrypt(pkt []byte, bodyLen int, seq uint16, ssrc, roc uint32) ([]byte, []byte, bool) {
	var rocBE [4]byte
	binary.BigEndian.PutUint32(rocBE[:], roc)
	mac := hmac.New(sha1.New, d.authKey)
	mac.Write(pkt[:bodyLen])
	mac.Write(rocBE[:])
	expected := mac.Sum(nil)[:srtpAuthTagLen]
	if !hmac.Equal(expected, pkt[bodyLen:bodyLen+srtpAuthTagLen]) {
		return nil, nil, false
	}

	b0 := pkt[0]
	cc := int(b0 & 0x0f)
	hdrLen := rtpHeaderMinLen + cc*4
	if (b0>>4)&1 == 1 {
		if hdrLen+4 > bodyLen {
			return nil, nil, false
		}
		extWords := int(binary.BigEndian.Uint16(pkt[hdrLen+2 : hdrLen+4]))
		hdrLen += 4 + extWords*4
	}
	if hdrLen > bodyLen {
		return nil, nil, false
	}

	hdr := make([]byte, hdrLen)
	copy(hdr, pkt[:hdrLen])
	if hdrLen == bodyLen {
		return hdr, nil, true
	}

	var iv [16]byte
	copy(iv[:14], d.salt[:])
	xorUint32BE(iv[4:8], ssrc)
	xorUint32BE(iv[8:12], roc)
	xorUint16BE(iv[12:14], seq)

	payload := make([]byte, bodyLen-hdrLen)
	cipher.NewCTR(d.block, iv[:]).XORKeyStream(payload, pkt[hdrLen:bodyLen])
	return hdr, payload, true
}

func (d *SRTPDecryptor) updateStateLocked(ssrc, roc uint32, seq uint16) {
	st := d.states[ssrc]
	if st == nil {
		d.states[ssrc] = &SSRCState{ROC: roc, MaxSeq: seq, Initialized: true}
		return
	}
	newFull := (uint64(roc) << 16) | uint64(seq)
	curFull := (uint64(st.ROC) << 16) | uint64(st.MaxSeq)
	if newFull > curFull {
		st.ROC = roc
		st.MaxSeq = seq
	}
}

// StateSnapshot returns per-SSRC state copies for RTCP Receiver Reports.
func (d *SRTPDecryptor) StateSnapshot() map[uint32]SSRCState {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[uint32]SSRCState, len(d.states))
	for ssrc, st := range d.states {
		if st.Initialized {
			out[ssrc] = *st
		}
	}
	return out
}

// SSRCCounts returns received packet counts per SSRC.
func (d *SRTPDecryptor) SSRCCounts() map[uint32]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[uint32]int, len(d.counts))
	for ssrc, n := range d.counts {
		out[ssrc] = n
	}
	return out
}

// SRTPEncryptor encrypts outbound RTP packets (AES-256-CTR + HMAC-SHA1-80).
type SRTPEncryptor struct {
	block   cipher.Block
	authKey []byte
	salt    [14]byte
	ssrc    uint32

	mu  sync.Mutex
	seq uint32
	roc uint32
	ts  uint32
}

// NewSRTPEncryptor constructs an SRTP sender from a 46-byte key blob and SSRC.
func NewSRTPEncryptor(blob []byte, ssrc uint32) (*SRTPEncryptor, error) {
	mk, ms, err := splitSRTPBlob(blob)
	if err != nil {
		return nil, err
	}
	cipherKey, err := srtpKDF(mk, ms, 0, 32)
	if err != nil {
		return nil, err
	}
	authKey, err := srtpKDF(mk, ms, 1, 20)
	if err != nil {
		return nil, err
	}
	salt, err := srtpKDF(mk, ms, 2, 14)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	e := &SRTPEncryptor{
		block:   block,
		authKey: authKey,
		ssrc:    ssrc,
	}
	copy(e.salt[:], salt)
	return e, nil
}

// Encrypt wraps payload into an authenticated SRTP packet.
func (e *SRTPEncryptor) Encrypt(payload []byte, pt byte, marker bool) []byte {
	e.mu.Lock()
	seq := uint16(e.seq & 0xffff)
	roc := e.roc
	ts := e.ts
	e.seq++
	if e.seq > 0xffff {
		e.seq = 0
		e.roc++
	}
	e.ts += 480
	e.mu.Unlock()

	ptByte := pt & 0x7f
	if marker {
		ptByte |= 0x80
	}
	out := make([]byte, rtpHeaderMinLen+len(payload)+srtpAuthTagLen)
	out[0] = 0x80
	out[1] = ptByte
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint32(out[4:8], ts)
	binary.BigEndian.PutUint32(out[8:12], e.ssrc)

	var iv [16]byte
	copy(iv[:14], e.salt[:])
	xorUint32BE(iv[4:8], e.ssrc)
	xorUint32BE(iv[8:12], roc)
	xorUint16BE(iv[12:14], seq)

	if len(payload) > 0 {
		cipher.NewCTR(e.block, iv[:]).XORKeyStream(out[rtpHeaderMinLen:rtpHeaderMinLen+len(payload)], payload)
	}
	bodyLen := rtpHeaderMinLen + len(payload)
	var rocBE [4]byte
	binary.BigEndian.PutUint32(rocBE[:], roc)
	mac := hmac.New(sha1.New, e.authKey)
	mac.Write(out[:bodyLen])
	mac.Write(rocBE[:])
	copy(out[bodyLen:], mac.Sum(nil)[:srtpAuthTagLen])
	return out
}

// SRTCPDecryptor authenticates and decrypts SRTCP packets.
type SRTCPDecryptor struct {
	block   cipher.Block
	authKey []byte
	salt    [14]byte
}

// NewSRTCPDecryptor builds an SRTCP receiver from a 46-byte key blob.
func NewSRTCPDecryptor(blob []byte) (*SRTCPDecryptor, error) {
	mk, ms, err := splitSRTPBlob(blob)
	if err != nil {
		return nil, err
	}
	cipherKey, err := srtpKDF(mk, ms, 3, 32)
	if err != nil {
		return nil, err
	}
	authKey, err := srtpKDF(mk, ms, 4, 20)
	if err != nil {
		return nil, err
	}
	salt, err := srtpKDF(mk, ms, 5, 14)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	d := &SRTCPDecryptor{block: block, authKey: authKey}
	copy(d.salt[:], salt)
	return d, nil
}

// Unprotect verifies and decrypts one SRTCP packet.
func (d *SRTCPDecryptor) Unprotect(pkt []byte) ([]byte, error) {
	if len(pkt) < 8+4+srtpAuthTagLen {
		return nil, errors.New("applehp: short SRTCP packet")
	}
	bodyLen := len(pkt) - srtpAuthTagLen
	mac := hmac.New(sha1.New, d.authKey)
	mac.Write(pkt[:bodyLen])
	if !hmac.Equal(mac.Sum(nil)[:srtpAuthTagLen], pkt[bodyLen:]) {
		return nil, errors.New("applehp: SRTCP auth failed")
	}
	eIndex := binary.BigEndian.Uint32(pkt[bodyLen-4 : bodyLen])
	encrypted := eIndex&0x80000000 != 0
	index := eIndex & 0x7fffffff

	hdr := pkt[:8]
	ct := pkt[8 : bodyLen-4]
	out := make([]byte, 8+len(ct))
	copy(out[:8], hdr)
	if !encrypted {
		copy(out[8:], ct)
		return out, nil
	}
	ssrc := binary.BigEndian.Uint32(hdr[4:8])
	var iv [16]byte
	copy(iv[:14], d.salt[:])
	xorUint32BE(iv[4:8], ssrc)
	xorUint32BE(iv[10:14], index)
	cipher.NewCTR(d.block, iv[:]).XORKeyStream(out[8:], ct)
	return out, nil
}

// SRTCPEncryptor encrypts and authenticates outbound RTCP packets.
type SRTCPEncryptor struct {
	block   cipher.Block
	authKey []byte
	salt    [14]byte

	mu    sync.Mutex
	index uint32
}

// NewSRTCPEncryptor builds an SRTCP sender from a 46-byte key blob.
func NewSRTCPEncryptor(blob []byte) (*SRTCPEncryptor, error) {
	mk, ms, err := splitSRTPBlob(blob)
	if err != nil {
		return nil, err
	}
	cipherKey, err := srtpKDF(mk, ms, 3, 32)
	if err != nil {
		return nil, err
	}
	authKey, err := srtpKDF(mk, ms, 4, 20)
	if err != nil {
		return nil, err
	}
	salt, err := srtpKDF(mk, ms, 5, 14)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	e := &SRTCPEncryptor{block: block, authKey: authKey}
	copy(e.salt[:], salt)
	return e, nil
}

// Protect encrypts and authenticates a compound RTCP packet.
func (e *SRTCPEncryptor) Protect(rtcpPkt []byte) ([]byte, error) {
	if len(rtcpPkt) < 8 {
		return nil, errors.New("applehp: RTCP packet shorter than 8 bytes")
	}
	e.mu.Lock()
	idx := e.index
	e.index++
	e.mu.Unlock()

	ssrc := binary.BigEndian.Uint32(rtcpPkt[4:8])
	var iv [16]byte
	copy(iv[:14], e.salt[:])
	xorUint32BE(iv[4:8], ssrc)
	xorUint32BE(iv[10:14], idx)

	out := make([]byte, len(rtcpPkt)+4+srtpAuthTagLen)
	copy(out[:8], rtcpPkt[:8])
	if len(rtcpPkt) > 8 {
		cipher.NewCTR(e.block, iv[:]).XORKeyStream(out[8:len(rtcpPkt)], rtcpPkt[8:])
	}
	binary.BigEndian.PutUint32(out[len(rtcpPkt):len(rtcpPkt)+4], 0x80000000|idx)

	mac := hmac.New(sha1.New, e.authKey)
	mac.Write(out[:len(rtcpPkt)+4])
	copy(out[len(rtcpPkt)+4:], mac.Sum(nil)[:srtpAuthTagLen])
	return out, nil
}

func xorUint32BE(dst []byte, v uint32) {
	dst[0] ^= byte(v >> 24)
	dst[1] ^= byte(v >> 16)
	dst[2] ^= byte(v >> 8)
	dst[3] ^= byte(v)
}

func xorUint16BE(dst []byte, v uint16) {
	dst[0] ^= byte(v >> 8)
	dst[1] ^= byte(v)
}

// BuildEmptySR constructs an empty Sender Report (PT=200) so AVConference
// recognizes the client SSRC as live.
func BuildEmptySR(senderSSRC uint32) []byte {
	now := time.Now()
	ntpSec := uint32(now.Unix() + ntpEpochDelta)
	ntpFrac := uint32((uint64(now.Nanosecond()) << 32) / 1e9)
	rtpTS := uint32(uint64(now.UnixNano()) * 90000 / 1e9)

	var buf [28]byte
	buf[0] = 0x80
	buf[1] = 200
	binary.BigEndian.PutUint16(buf[2:4], 6)
	binary.BigEndian.PutUint32(buf[4:8], senderSSRC)
	binary.BigEndian.PutUint32(buf[8:12], ntpSec)
	binary.BigEndian.PutUint32(buf[12:16], ntpFrac)
	binary.BigEndian.PutUint32(buf[16:20], rtpTS)
	return buf[:]
}

// BuildRR builds an RTCP Receiver Report (PT=201) covering up to 31 source SSRCs.
func BuildRR(senderSSRC uint32, sources []uint32, stats map[uint32]SSRCState) []byte {
	if len(sources) == 0 {
		var buf [8]byte
		buf[0] = 0x80
		buf[1] = 201
		binary.BigEndian.PutUint16(buf[2:4], 1)
		binary.BigEndian.PutUint32(buf[4:8], senderSSRC)
		return buf[:]
	}
	rc := len(sources)
	if rc > 31 {
		rc = 31
	}
	length := uint16(1 + rc*6)
	buf := make([]byte, 8+rc*24)
	buf[0] = byte(0x80 | rc)
	buf[1] = 201
	binary.BigEndian.PutUint16(buf[2:4], length)
	binary.BigEndian.PutUint32(buf[4:8], senderSSRC)
	for i := 0; i < rc; i++ {
		ssrc := sources[i]
		st := stats[ssrc]
		extSeq := (st.ROC << 16) | uint32(st.MaxSeq)
		off := 8 + i*24
		binary.BigEndian.PutUint32(buf[off:off+4], ssrc)
		binary.BigEndian.PutUint32(buf[off+8:off+12], extSeq)
	}
	return buf
}

// BuildLegacyFIR constructs RFC 2032 PT=192 FIR, which Apple's screensharingd
// reliably honors to emit a fresh keyframe.
func BuildLegacyFIR(targetSSRC uint32) []byte {
	var buf [8]byte
	buf[0] = 0x80
	buf[1] = 192
	binary.BigEndian.PutUint16(buf[2:4], 1)
	binary.BigEndian.PutUint32(buf[4:8], targetSSRC)
	return buf[:]
}

// BuildAVPFFIR constructs an RFC 5104 PT=206 FMT=4 Full Intra Request.
func BuildAVPFFIR(senderSSRC, targetSSRC uint32, seqNr uint8) []byte {
	var buf [20]byte
	buf[0] = 0x80 | 4
	buf[1] = 206
	binary.BigEndian.PutUint16(buf[2:4], 4)
	binary.BigEndian.PutUint32(buf[4:8], senderSSRC)
	binary.BigEndian.PutUint32(buf[12:16], targetSSRC)
	buf[16] = seqNr
	return buf[:]
}

// BuildPLI constructs an RFC 4585 PT=206 FMT=1 Picture Loss Indication.
func BuildPLI(senderSSRC, mediaSSRC uint32) []byte {
	var buf [12]byte
	buf[0] = 0x80 | 1
	buf[1] = 206
	binary.BigEndian.PutUint16(buf[2:4], 2)
	binary.BigEndian.PutUint32(buf[4:8], senderSSRC)
	binary.BigEndian.PutUint32(buf[8:12], mediaSSRC)
	return buf[:]
}
