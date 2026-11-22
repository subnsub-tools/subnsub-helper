package applehp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	enc1103MACLen    = 20 // Plain SHA-1(u32_be(seq) || framed), not HMAC.
	enc1103BlockSize = 16
	enc1103Lookahead = 6 // Forgive [ctr-1, ctr+5] window per Apple server pipelining.
)

var errInvalidRekeyBlob = errors.New("applehp: invalid 0x44f rekey blob")

// RecordCipher implements Apple's enc1103 post-authentication RFB record layer
// (AES-128-CBC with persistent chained IVs per direction and SHA-1 integrity).
type RecordCipher struct {
	CBCKey []byte

	mu     sync.Mutex
	encCBC cipher.BlockMode
	decCBC cipher.BlockMode
	encCtr uint32
	decCtr uint32
}

// NewRecordCipher unwraps the 36-byte 0x44f EncodeEncryptionInfo payload using
// the 16-byte AES-ECB wrap key derived during authentication and initializes
// independent bidirectional AES-128-CBC stream contexts.
func NewRecordCipher(rekeyBlob36, ecbKey []byte) (*RecordCipher, error) {
	if len(rekeyBlob36) != 36 {
		return nil, fmt.Errorf("%w: got %d bytes, want 36", errInvalidRekeyBlob, len(rekeyBlob36))
	}
	if len(ecbKey) < 16 {
		return nil, fmt.Errorf("%w: wrap key length %d < 16", errInvalidRekeyBlob, len(ecbKey))
	}
	wrapBlock, err := aes.NewCipher(ecbKey[:16])
	if err != nil {
		return nil, err
	}
	cbcKey := make([]byte, 16)
	cbcIV := make([]byte, 16)
	wrapBlock.Decrypt(cbcKey, rekeyBlob36[4:20])
	wrapBlock.Decrypt(cbcIV, rekeyBlob36[20:36])

	cbcBlock, err := aes.NewCipher(cbcKey)
	if err != nil {
		return nil, err
	}
	return &RecordCipher{
		CBCKey: cbcKey,
		encCBC: cipher.NewCBCEncrypter(cbcBlock, cbcIV),
		decCBC: cipher.NewCBCDecrypter(cbcBlock, cbcIV),
	}, nil
}

func (c *RecordCipher) encryptLocked(plaintext []byte) []byte {
	pad := (enc1103BlockSize - ((2 + len(plaintext) + enc1103MACLen) % enc1103BlockSize)) % enc1103BlockSize
	framedLen := 2 + len(plaintext) + pad
	block := make([]byte, framedLen+enc1103MACLen)
	binary.BigEndian.PutUint16(block[0:2], uint16(len(plaintext)))
	copy(block[2:], plaintext)

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], c.encCtr)
	h := sha1.New()
	h.Write(hdr[:])
	h.Write(block[:framedLen])
	copy(block[framedLen:], h.Sum(nil))

	out := make([]byte, 2+len(block))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(block)))
	c.encCBC.CryptBlocks(out[2:], block)
	c.encCtr++
	return out
}

// Encrypt wraps a single control-channel RFB message into a length-prefixed
// enc1103 record.
func (c *RecordCipher) Encrypt(plaintext []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.encryptLocked(plaintext)
}

// EncryptAndSend serializes encryption and socket writes under one lock so
// record counters match TCP wire order even across concurrent goroutines.
func (c *RecordCipher) EncryptAndSend(w io.Writer, plaintext []byte) error {
	c.mu.Lock()
	frame := c.encryptLocked(plaintext)
	_, err := writeFull(w, frame)
	c.mu.Unlock()
	return err
}

func writeFull(w io.Writer, b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, err := w.Write(b[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// DecryptRecord decrypts one ciphertext block (without the 2-byte length prefix)
// and verifies its SHA-1 integrity trailer. Always advances CBC state.
func (c *RecordCipher) DecryptRecord(ciphertext []byte) ([]byte, bool) {
	if len(ciphertext) < 32 || len(ciphertext)%enc1103BlockSize != 0 {
		return nil, false
	}

	c.mu.Lock()
	plain := make([]byte, len(ciphertext))
	c.decCBC.CryptBlocks(plain, ciphertext)
	ctrStart := c.decCtr
	c.decCtr++

	body := plain[:len(plain)-enc1103MACLen]
	mac := plain[len(plain)-enc1103MACLen:]
	minCtr := uint32(0)
	if ctrStart > 0 {
		minCtr = ctrStart - 1
	}

	var matched bool
	var matchedCtr uint32
	for cand := minCtr; cand < ctrStart+enc1103Lookahead; cand++ {
		var seqBE [4]byte
		binary.BigEndian.PutUint32(seqBE[:], cand)
		h := sha1.New()
		h.Write(seqBE[:])
		h.Write(body)
		sum := h.Sum(nil)
		if subtleEqual20(sum, mac) {
			matched = true
			matchedCtr = cand
			break
		}
	}
	if !matched {
		c.mu.Unlock()
		return nil, false
	}
	c.decCtr = matchedCtr + 1
	c.mu.Unlock()

	if len(body) < 2 {
		return nil, false
	}
	innerLen := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+innerLen > len(body) {
		return nil, false
	}
	msg := make([]byte, innerLen)
	copy(msg, body[2:2+innerLen])
	return msg, true
}

func subtleEqual20(a, b []byte) bool {
	if len(a) != 20 || len(b) != 20 {
		return false
	}
	var diff byte
	for i := 0; i < 20; i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// DecryptStream decrypts all complete records in data and returns the decoded
// payloads alongside the number of consumed bytes. Any partial trailing frame
// remains unconsumed for the caller to buffer until more bytes arrive.
func (c *RecordCipher) DecryptStream(data []byte) (msgs [][]byte, consumed int) {
	pos := 0
	for pos+2 <= len(data) {
		recLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		if recLen == 0 || recLen%enc1103BlockSize != 0 {
			break
		}
		if pos+2+recLen > len(data) {
			break
		}
		if msg, ok := c.DecryptRecord(data[pos+2 : pos+2+recLen]); ok {
			msgs = append(msgs, msg)
		}
		pos += 2 + recLen
	}
	return msgs, pos
}
