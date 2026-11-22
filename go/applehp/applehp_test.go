package applehp

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBplistEncodeDecodeAndExtract(t *testing.T) {
	in := map[string]any{
		"avcMediaStreamOptionRemoteEndpointInfo": []byte{0x08, 0x00, 0x10, 0x01, 0x1a, 0x03, 'm', 'a', 'c'},
		"avcMediaStreamNegotiatorMode":           7,
		"avcMediaStreamNegotiatorMediaBlob":      bytes.Repeat([]byte{0xab, 0xcd}, 20),
		"avcMediaStreamOptionCallID":             "12345678-1234-4123-8123-1234567890AB",
		"extraFlag":                              true,
		"extraUTF16":                             "\u6d4b\u8bd5Screen",
	}
	raw, err := EncodePlistDict(in)
	if err != nil {
		t.Fatalf("EncodePlistDict: %v", err)
	}
	decAny, err := DecodePlist(raw)
	if err != nil {
		t.Fatalf("DecodePlist: %v", err)
	}
	dec := decAny.(map[string]any)
	if dec["avcMediaStreamNegotiatorMode"] != int64(7) {
		t.Fatalf("mode = %v", dec["avcMediaStreamNegotiatorMode"])
	}
	if dec["avcMediaStreamOptionCallID"] != in["avcMediaStreamOptionCallID"] {
		t.Fatalf("CallID mismatch: %v", dec["avcMediaStreamOptionCallID"])
	}
	if dec["extraFlag"] != true || dec["extraUTF16"] != "\u6d4b\u8bd5Screen" {
		t.Fatalf("extra mismatch: %v / %v", dec["extraFlag"], dec["extraUTF16"])
	}
	if !bytes.Equal(dec["avcMediaStreamNegotiatorMediaBlob"].([]byte), in["avcMediaStreamNegotiatorMediaBlob"].([]byte)) {
		t.Fatal("blob mismatch")
	}

	wrapped := append([]byte{0x00, 0x1c, 0xde, 0xad, 0xbe, 0xef}, raw...)
	wrapped = append(wrapped, 0x99, 0x88, 0x77)
	gotBlob, err := ExtractPlistMediaBlob(wrapped)
	if err != nil {
		t.Fatalf("ExtractPlistMediaBlob: %v", err)
	}
	if !bytes.Equal(gotBlob, in["avcMediaStreamNegotiatorMediaBlob"].([]byte)) {
		t.Fatal("extracted blob mismatch")
	}
}

func TestOfferBuildAndAnswerParse(t *testing.T) {
	vOff, aOff, vSSRC, aSSRC, err := CreateOffers(OfferOptions{
		Codec:        "avc",
		AudioEnabled: false,
	})
	if err != nil {
		t.Fatalf("CreateOffers: %v", err)
	}
	gotV, ok := ExtractOfferSSRC(vOff, true)
	if !ok || gotV != vSSRC {
		t.Fatalf("video SSRC mismatch: got=%d ok=%v want=%d", gotV, ok, vSSRC)
	}
	gotA, ok := ExtractOfferSSRC(aOff, false)
	if !ok || gotA != aSSRC {
		t.Fatalf("audio SSRC mismatch: got=%d ok=%v want=%d", gotA, ok, aSSRC)
	}

	// Verify AVC single-tile offer uses bank 123, omits bank 100 and LTR;, and mutes audio via f4=1000.
	vp, _ := DecodePlist(vOff)
	vz, _ := zlib.NewReader(bytes.NewReader(vp.(map[string]any)["avcMediaStreamNegotiatorMediaBlob"].([]byte)))
	vBlob, _ := io.ReadAll(vz)
	if bytes.Contains(vBlob, []byte("LTR;")) {
		t.Fatal("AVC offer unexpectedly contains LTR;")
	}
	if !bytes.Contains(vBlob, []byte("FLS;MS:-1;LF:-1;CABAC;")) {
		t.Fatal("AVC offer missing bank 123 parameters")
	}

	ap, _ := DecodePlist(aOff)
	az, _ := zlib.NewReader(bytes.NewReader(ap.(map[string]any)["avcMediaStreamNegotiatorMediaBlob"].([]byte)))
	aBlob, _ := io.ReadAll(az)
	// f4 = 1000 -> tag (4<<3)|0 = 0x20, varint(1000) = 0xe8 0x07
	if !bytes.Contains(aBlob, []byte{0x20, 0xe8, 0x07}) {
		t.Fatal("muted audio offer missing f4=1000")
	}

	// Synthetic server 0x1c answer carrying 1920x1080, 1 tile.
	ansInner := appendFieldVarint(nil, 4, 1920)
	ansInner = appendFieldVarint(ansInner, 5, 1080)
	ansInner = appendFieldVarint(ansInner, 6, 1)
	ansBlob := appendFieldBytes(nil, 5, ansInner)
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	_, _ = zw.Write(ansBlob)
	_ = zw.Close()
	ansPlist, err := EncodePlistDict(map[string]any{
		"avcMediaStreamNegotiatorMode":      7,
		"avcMediaStreamNegotiatorMediaBlob": zb.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ansMsg := append([]byte{0x00, 0x1c, 0x00, 0x00, 0x01}, ansPlist...)
	w, h, tiles, ok := ExtractCanvasDims(ansMsg)
	if !ok || w != 1920 || h != 1080 || tiles != 1 {
		t.Fatalf("ExtractCanvasDims = (%d,%d,%d,%v)", w, h, tiles, ok)
	}
	// As a real host answers: the audio plist, then the video one.
	w, h, tiles, ok = ExtractCanvasDims(mockAnswer(1920, 1080))
	if !ok || w != 1920 || h != 1080 || tiles != 1 {
		t.Fatalf("ExtractCanvasDims = (%d,%d,%d,%v)", w, h, tiles, ok)
	}
}

func TestRecordCipher(t *testing.T) {
	ecbKey := []byte("0123456789abcdef")
	cbcKey := []byte("fedcba9876543210")
	cbcIV := []byte("iviviviviviviviv")

	blk, _ := aes.NewCipher(ecbKey)
	var rekey [36]byte
	binary.BigEndian.PutUint32(rekey[0:4], 1)
	blk.Encrypt(rekey[4:20], cbcKey)
	blk.Encrypt(rekey[20:36], cbcIV)

	clientCipher, err := NewRecordCipher(rekey[:], ecbKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := NewRecordCipher(rekey[:], ecbKey)
	if err != nil {
		t.Fatal(err)
	}

	msgs := [][]byte{
		BuildVirtualDisplay(1920, 1080, 1.0, false, "test"),
		BuildSetEncodings(HPEncodings),
		[]byte{0x1c, 0x00, 0x01, 0x02, 0x03},
	}
	var wire []byte
	for _, m := range msgs {
		wire = append(wire, clientCipher.Encrypt(m)...)
	}
	// Feed in two partial halves to verify DecryptStream buffering.
	split := len(wire) / 2
	out1, c1 := serverCipher.DecryptStream(wire[:split])
	tail := append([]byte(nil), wire[c1:split]...)
	tail = append(tail, wire[split:]...)
	out2, c2 := serverCipher.DecryptStream(tail)
	if c1+c2 != len(wire) {
		t.Fatalf("consumed %d+%d != %d", c1, c2, len(wire))
	}
	got := append(out1, out2...)
	if len(got) != len(msgs) {
		t.Fatalf("decoded %d msgs, want %d", len(got), len(msgs))
	}
	for i := range msgs {
		if !bytes.Equal(got[i], msgs[i]) {
			t.Fatalf("msg %d mismatch", i)
		}
	}

	// Tampered record must be rejected.
	bad := clientCipher.Encrypt([]byte("hello"))
	bad[len(bad)-1] ^= 0xff
	if _, ok := serverCipher.DecryptRecord(bad[2:]); ok {
		t.Fatal("tampered record accepted")
	}
}

func TestSRTPAndSRTCP(t *testing.T) {
	blob := make([]byte, SRTPKeyBlobLen)
	_, _ = io.ReadFull(rand.Reader, blob)

	const ssrc uint32 = 0x11223344
	enc, err := NewSRTPEncryptor(blob, ssrc)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewSRTPDecryptor(blob)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate sequence rollover across 0xFFFF -> 0x0000.
	enc.mu.Lock()
	enc.seq = 0xFFFE
	enc.mu.Unlock()
	for i := 0; i < 5; i++ {
		want := []byte{0x41, byte(i), 0xaa, 0xbb, 0xcc}
		pkt := enc.Encrypt(want, 100, i == 4)
		_, got, gSSRC, _, _, marker, ok := dec.Decrypt(pkt)
		if !ok || gSSRC != ssrc || marker != (i == 4) || !bytes.Equal(got, want) {
			t.Fatalf("SRTP rollover packet %d failed: ok=%v got=%x", i, ok, got)
		}
		if i == 0 {
			tampered := append([]byte(nil), pkt...)
			tampered[len(tampered)-1] ^= 0x01
			if _, _, _, _, _, _, ok2 := dec.Decrypt(tampered); ok2 {
				t.Fatal("tampered SRTP packet accepted")
			}
		}
	}

	// CSRC + RTP extension header test using manual SRTP construction.
	mk, ms, _ := splitSRTPBlob(blob)
	ck, _ := srtpKDF(mk, ms, 0, 32)
	ak, _ := srtpKDF(mk, ms, 1, 20)
	salt, _ := srtpKDF(mk, ms, 2, 14)
	blk, _ := aes.NewCipher(ck)
	var pkt []byte
	pkt = append(pkt, 0x91, 0xe4, 0x00, 0x01) // V=2, X=1, CC=1, M=1, PT=100, seq=1
	pkt = binary.BigEndian.AppendUint32(pkt, 90000)
	pkt = binary.BigEndian.AppendUint32(pkt, 0x55667788)
	pkt = binary.BigEndian.AppendUint32(pkt, 0xdeadbeef)              // 1 CSRC
	pkt = append(pkt, 0xbe, 0xde, 0x00, 0x01, 0x10, 0x20, 0x30, 0x40) // 1-word ext
	plain := []byte("h264-payload")
	var iv [16]byte
	copy(iv[:14], salt)
	xorUint32BE(iv[4:8], 0x55667788)
	xorUint16BE(iv[12:14], 1)
	ct := make([]byte, len(plain))
	cipher.NewCTR(blk, iv[:]).XORKeyStream(ct, plain)
	pkt = append(pkt, ct...)
	mac := hmac.New(sha1.New, ak)
	mac.Write(pkt)
	mac.Write([]byte{0, 0, 0, 0})
	pkt = append(pkt, mac.Sum(nil)[:10]...)
	hdr, gotExtPay, _, _, _, marker, ok := dec.Decrypt(pkt)
	if !ok || !marker || len(hdr) != 24 || !bytes.Equal(gotExtPay, plain) {
		t.Fatalf("SRTP CSRC+ext failed: ok=%v hdr=%d pay=%q", ok, len(hdr), gotExtPay)
	}

	// SRTCP round-trip.
	cEnc, _ := NewSRTCPEncryptor(blob)
	cDec, _ := NewSRTCPDecryptor(blob)
	rtcp := append(BuildEmptySR(ssrc), BuildLegacyFIR(ssrc)...)
	srtcp, err := cEnc.Protect(rtcp)
	if err != nil {
		t.Fatal(err)
	}
	outRTCP, err := cDec.Unprotect(srtcp)
	if err != nil || !bytes.Equal(outRTCP, rtcp) {
		t.Fatalf("SRTCP round-trip failed: err=%v match=%v", err, bytes.Equal(outRTCP, rtcp))
	}
}

func TestH264DepayloadConfigAndSPSPatch(t *testing.T) {
	// Construct a valid SPS (High profile 100, level 5.2, max_num_ref_frames=8)
	// and verify PatchAVCSPSMaxRefFrames raises 8 -> 10 bit-accurately.
	spsRBSP := encodeTestSPS(100, 52, 8)
	sps := append([]byte{0x67}, AddEmulationPrevention(spsRBSP)...)
	pps := []byte{0x68, 0xce, 0x38, 0x80}

	info, ok := ParseSPSInfo(sps)
	if !ok || info.ProfileIDC != 100 || info.LevelIDC != 52 || info.MaxNumRefFrames != 8 {
		t.Fatalf("ParseSPSInfo = %+v ok=%v", info, ok)
	}
	patched, changed := PatchAVCSPSMaxRefFrames(sps, 10)
	if !changed {
		t.Fatal("expected SPS to be patched")
	}
	info2, ok := ParseSPSInfo(patched)
	if !ok || info2.ProfileIDC != 100 || info2.LevelIDC != 52 || info2.MaxNumRefFrames != 10 {
		t.Fatalf("patched ParseSPSInfo = %+v ok=%v", info2, ok)
	}

	// Build Apple 0x92 avc1/avcC config packet.
	avcc := []byte{1, sps[1], sps[2], sps[3], 0xff, 0xe1}
	avcc = binary.BigEndian.AppendUint16(avcc, uint16(len(sps)))
	avcc = append(avcc, sps...)
	avcc = append(avcc, 1)
	avcc = binary.BigEndian.AppendUint16(avcc, uint16(len(pps)))
	avcc = append(avcc, pps...)

	cfgPkt := append([]byte{AppleAVCConfigMarker, 0x00, 0x00, 0x00}, []byte("avc1")...)
	cfgPkt = append(cfgPkt, bytes.Repeat([]byte{0}, 16)...)
	cfgPkt = append(cfgPkt, []byte("avcC")...)
	cfgPkt = append(cfgPkt, avcc...)

	gotSPS, gotPPS, ok := ParseAVCConfig(cfgPkt)
	if !ok || !bytes.Equal(gotSPS, sps) || !bytes.Equal(gotPPS, pps) {
		t.Fatalf("ParseAVCConfig failed: ok=%v", ok)
	}

	// Reassemble FU-A (Apple type-1 I-slice, slice_type=7) and single NAL (P-slice, slice_type=0).
	iSliceRBSP := encodeBitsRBSP([]uint32{0}, []uint32{0, 7}, []int{1, 1}, []uint32{0xaa}, []int{8})
	iSlice := append([]byte{0x61}, iSliceRBSP...) // NAL type 1, nal_ref_idc=3
	mid := len(iSlice) / 2
	fua1 := append([]byte{0x7c, 0x80 | 0x01}, iSlice[1:mid]...)
	fua2 := append([]byte{0x7c, 0x40 | 0x01}, iSlice[mid:]...)
	nalus := ReassembleH264([][]byte{cfgPkt, fua1, fua2})
	if len(nalus) != 1 || !bytes.Equal(nalus[0], iSlice) {
		t.Fatalf("FU-A reassembly mismatch: got %d NALs", len(nalus))
	}
	if !AUIsKeyframe(nalus) {
		t.Fatal("expected type-1 slice_type=7 to be detected as keyframe")
	}

	pSliceRBSP := encodeBitsRBSP(nil, []uint32{0, 0}, nil, []uint32{0x55}, []int{8})
	pSlice := append([]byte{0x41}, pSliceRBSP...)
	pNALs := ReassembleH264([][]byte{pSlice})
	if len(pNALs) != 1 || AUIsKeyframe(pNALs) {
		t.Fatal("P-slice misclassified")
	}
}

func encodeTestSPS(profile, level byte, maxRef uint32) []byte {
	var bits []byte
	addBits := func(v uint32, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, byte((v>>uint(i))&1))
		}
	}
	addUE := func(v uint32) {
		bits = append(bits, encodeUEBits(v)...)
	}
	addBits(uint32(profile), 8)
	addBits(0, 8)
	addBits(uint32(level), 8)
	addUE(0) // seq_parameter_set_id
	if profile == 100 {
		addUE(1) // chroma_format_idc = 4:2:0
		addUE(0) // bit_depth_luma_minus8
		addUE(0) // bit_depth_chroma_minus8
		addBits(0, 1)
		addBits(0, 1)
	}
	addUE(4)      // log2_max_frame_num_minus4
	addUE(0)      // pic_order_cnt_type
	addUE(4)      // log2_max_pic_order_cnt_lsb_minus4
	addUE(maxRef) // max_num_ref_frames
	addBits(0, 1) // gaps_in_frame_num_value_allowed_flag
	addUE(119)    // pic_width_in_mbs_minus1 (1920)
	addUE(67)     // pic_height_in_map_units_minus1 (1088)
	addBits(1, 1) // frame_mbs_only_flag
	addBits(1, 1) // direct_8x8_inference_flag
	addBits(0, 1) // frame_cropping_flag
	addBits(0, 1) // vui_parameters_present_flag
	addBits(1, 1) // rbsp_stop_one_bit
	for len(bits)%8 != 0 {
		bits = append(bits, 0)
	}
	out := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b != 0 {
			out[i>>3] |= 1 << uint(7-(i&7))
		}
	}
	return out
}

func encodeBitsRBSP(_ []uint32, ues []uint32, _ []int, tails []uint32, tailLens []int) []byte {
	var bits []byte
	for _, u := range ues {
		bits = append(bits, encodeUEBits(u)...)
	}
	for i, v := range tails {
		n := tailLens[i]
		for k := n - 1; k >= 0; k-- {
			bits = append(bits, byte((v>>uint(k))&1))
		}
	}
	bits = append(bits, 1)
	for len(bits)%8 != 0 {
		bits = append(bits, 0)
	}
	out := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b != 0 {
			out[i>>3] |= 1 << uint(7-(i&7))
		}
	}
	return out
}

func TestEndToEndMockSession(t *testing.T) {
	// Generate server RSA-2048 key and a mock 4096-bit SRP group (a 4096-bit safe prime modulus).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Use a deterministic 4096-bit odd modulus for unit test speed while keeping exact 512-byte SRP sizing.
	var modBytes [512]byte
	modBytes[0] = 0xff
	for i := 1; i < 511; i++ {
		modBytes[i] = byte(i*17 + 3)
	}
	modBytes[511] = 0xfb
	N := new(big.Int).SetBytes(modBytes[:])
	g := big.NewInt(5)
	salt := bytes.Repeat([]byte{0x42}, 32)
	const iters uint64 = 100
	password := "test-password"
	username := "alice"

	dk, err := pbkdf2.Key(sha512.New, password, salt, int(iters), srpPBKDF2Len)
	if err != nil {
		t.Fatal(err)
	}
	x := new(big.Int).SetBytes(sha512Concat(salt, sha512Concat([]byte(":"), dk)))
	x.Mod(x, N)
	v := new(big.Int).Exp(g, x, N)
	bPriv := big.NewInt(123456789)
	k := new(big.Int).SetBytes(sha512Concat(modBytes[:], padBigIntBE(g, srpModulusLen)))
	B := new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, bPriv, N))
	B.Mod(B, N)

	// Bind server TCP and client UDP ports on free ephemeral ports.
	tcpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()

	// Pick two distinct free UDP ports for ctrl & video.
	probeU1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	ctrlPort := probeU1.LocalAddr().(*net.UDPAddr).Port
	_ = probeU1.Close()
	probeU2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	videoPort := probeU2.LocalAddr().(*net.UDPAddr).Port
	_ = probeU2.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()

		// 1) RFB banner + sec types.
		_, _ = conn.Write([]byte(ProtocolVersion))
		var cliVer [12]byte
		if _, err := io.ReadFull(conn, cliVer[:]); err != nil {
			srvErr <- err
			return
		}
		_, _ = conn.Write([]byte{1, SecTypeAppleRSA})

		// 2) RSA1 pubkey request.
		var rsaInit [15]byte
		if _, err := io.ReadFull(conn, rsaInit[:]); err != nil {
			srvErr <- err
			return
		}
		pkPkt := make([]byte, 4+6+len(pubDER))
		binary.BigEndian.PutUint32(pkPkt[0:4], uint32(6+len(pubDER)))
		binary.BigEndian.PutUint32(pkPkt[6:10], uint32(len(pubDER)))
		copy(pkPkt[10:], pubDER)
		_, _ = conn.Write(pkPkt)

		// 3) Read c2s1, decrypt username, send s2c1.
		var l1 [4]byte
		if _, err := io.ReadFull(conn, l1[:]); err != nil {
			srvErr <- err
			return
		}
		c2s1 := make([]byte, binary.BigEndian.Uint32(l1[:]))
		if _, err := io.ReadFull(conn, c2s1); err != nil {
			srvErr <- err
			return
		}
		encLen := int(binary.BigEndian.Uint16(c2s1[8:10]))
		decIdent, err := rsa.DecryptPKCS1v15(rand.Reader, rsaKey, c2s1[10:10+encLen])
		if err != nil {
			srvErr <- err
			return
		}
		uLen := int(binary.BigEndian.Uint32(decIdent[4:8]))
		if string(decIdent[8:8+uLen]) != username {
			srvErr <- io.ErrUnexpectedEOF
			return
		}

		capStr := []byte("mda=SHA-512")
		// As macOS 15 sends it: the control byte, N, g, salt, B, the iterations and the options,
		// behind a 10-byte header (u16 0, u16 2, u16 len+4, u32 len).
		s2c1 := []byte{0x00}
		s2c1 = binary.BigEndian.AppendUint16(s2c1, srpModulusLen)
		s2c1 = append(s2c1, modBytes[:]...)
		s2c1 = binary.BigEndian.AppendUint16(s2c1, 1)
		s2c1 = append(s2c1, 5)
		s2c1 = append(s2c1, byte(len(salt)))
		s2c1 = append(s2c1, salt...)
		Bb := padBigIntBE(B, srpModulusLen)
		s2c1 = binary.BigEndian.AppendUint16(s2c1, uint16(len(Bb)))
		s2c1 = append(s2c1, Bb...)
		s2c1 = binary.BigEndian.AppendUint64(s2c1, iters)
		s2c1 = binary.BigEndian.AppendUint16(s2c1, uint16(len(capStr)))
		s2c1 = append(s2c1, capStr...)
		head := []byte{0x00, 0x00, 0x00, 0x02}
		head = binary.BigEndian.AppendUint16(head, uint16(len(s2c1)+4))
		head = binary.BigEndian.AppendUint32(head, uint32(len(s2c1)))
		s2c1 = append(head, s2c1...)
		_, _ = conn.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s2c1))))
		_, _ = conn.Write(s2c1)

		// 4) Read c2s2, verify M1, send M2 + SecurityResult=0.
		var l2 [4]byte
		if _, err := io.ReadFull(conn, l2[:]); err != nil {
			srvErr <- err
			return
		}
		c2s2 := make([]byte, binary.BigEndian.Uint32(l2[:]))
		if _, err := io.ReadFull(conn, c2s2); err != nil {
			srvErr <- err
			return
		}
		sdLen := int(binary.BigEndian.Uint32(c2s2[10:14]))
		sd := c2s2[14 : 14+sdLen]
		aLen := int(binary.BigEndian.Uint16(sd[0:2]))
		Ab := sd[2 : 2+aLen]
		m1Len := int(sd[2+aLen])
		clientM1 := sd[3+aLen : 3+aLen+m1Len]

		A := new(big.Int).SetBytes(Ab)
		u := new(big.Int).SetBytes(sha512Concat(Ab, Bb))
		vu := new(big.Int).Exp(v, u, N)
		Avu := new(big.Int).Mod(new(big.Int).Mul(A, vu), N)
		S := new(big.Int).Exp(Avu, bPriv, N)
		K := sha512Concat(padBigIntBE(S, srpModulusLen))
		hN := sha512.Sum512(modBytes[:])
		hG := sha512.Sum512(padBigIntBE(g, srpModulusLen))
		var hXor [64]byte
		for i := 0; i < 64; i++ {
			hXor[i] = hN[i] ^ hG[i]
		}
		hEmpty := sha512.Sum512(nil)
		wantM1 := sha512Concat(hXor[:], hEmpty[:], salt, Ab, Bb, K)
		if !bytes.Equal(clientM1, wantM1) {
			_, _ = conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1})
			srvErr <- io.ErrUnexpectedEOF
			return
		}
		ecbKey := sha256.Sum256(K)
		_, _ = conn.Write([]byte{0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0})

		// 5) ClientInit -> ServerInit.
		var ci [1]byte
		if _, err := io.ReadFull(conn, ci[:]); err != nil {
			srvErr <- err
			return
		}
		var si [24]byte
		binary.BigEndian.PutUint16(si[0:2], 1920)
		binary.BigEndian.PutUint16(si[2:4], 1080)
		_, _ = conn.Write(si[:])

		// 6) Read ViewerInfo (66B) + 0x12 followup (12B) + SetEncodings (4 + 13*4 = 56B).
		prelude := make([]byte, 66+12+4+len(HPEncodings)*4)
		if _, err := io.ReadFull(conn, prelude); err != nil {
			srvErr <- err
			return
		}

		// 7) Send 0x44f rekey.
		cbcKey := bytes.Repeat([]byte{0x11}, 16)
		cbcIV := bytes.Repeat([]byte{0x22}, 16)
		wrapBlk, _ := aes.NewCipher(ecbKey[:16])
		var rekey [36]byte
		binary.BigEndian.PutUint32(rekey[0:4], 1)
		wrapBlk.Encrypt(rekey[4:20], cbcKey)
		wrapBlk.Encrypt(rekey[20:36], cbcIV)
		fbu := make([]byte, 4+12+36)
		binary.BigEndian.PutUint16(fbu[2:4], 1)
		binary.BigEndian.PutUint32(fbu[12:16], uint32(EncAppleRekey))
		copy(fbu[16:], rekey[:])
		_, _ = conn.Write(fbu)

		// 8) Read PostEncryptionToggle (8B).
		var tog [8]byte
		if _, err := io.ReadFull(conn, tog[:]); err != nil {
			srvErr <- err
			return
		}

		srvCipher, _ := NewRecordCipher(rekey[:], ecbKey[:16])
		// Read encrypted SetEncodings + 0x1c + FBURequest.
		var enc0x1c []byte
		for i := 0; i < 3; i++ {
			var rl [2]byte
			if _, err := io.ReadFull(conn, rl[:]); err != nil {
				srvErr <- err
				return
			}
			ct := make([]byte, binary.BigEndian.Uint16(rl[:]))
			if _, err := io.ReadFull(conn, ct); err != nil {
				srvErr <- err
				return
			}
			dec, ok := srvCipher.DecryptRecord(ct)
			if !ok {
				srvErr <- io.ErrUnexpectedEOF
				return
			}
			if dec[0] == MsgClientMediaNegotiation {
				enc0x1c = dec
			}
		}

		// Pull video_key_s from 0x1c to encrypt SRTP frames!
		as := int(binary.BigEndian.Uint16(enc0x1c[10:12]))
		vo := 0x80 + as
		videoKeyS := enc0x1c[vo+0x2e : vo+0x5c]

		// Send 0x1c answer with 1920x1080 / 1 tile.
		ansInner := appendFieldVarint(nil, 4, 1920)
		ansInner = appendFieldVarint(ansInner, 5, 1080)
		ansInner = appendFieldVarint(ansInner, 6, 1)
		ansBlob := appendFieldBytes(nil, 5, ansInner)
		var zb bytes.Buffer
		zw := zlib.NewWriter(&zb)
		_, _ = zw.Write(ansBlob)
		_ = zw.Close()
		ansPlist, _ := EncodePlistDict(map[string]any{
			"avcMediaStreamNegotiatorMode":      7,
			"avcMediaStreamNegotiatorMediaBlob": zb.Bytes(),
		})
		_ = ansPlist
		_, _ = conn.Write(srvCipher.Encrypt(mockAnswer(1920, 1080)))

		// 9) Stream SRTP UDP H.264 frames (0x92 config + FU-A I-slice + P-slice) to client videoPort!
		time.Sleep(100 * time.Millisecond)
		udpSender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: videoPort})
		if err != nil {
			srvErr <- err
			return
		}
		defer udpSender.Close()

		vEnc, err := NewSRTPEncryptor(videoKeyS, 0x01020304)
		if err != nil {
			srvErr <- err
			return
		}
		sps := append([]byte{0x67}, AddEmulationPrevention(encodeTestSPS(100, 52, 8))...)
		pps := []byte{0x68, 0xce, 0x38, 0x80}
		avcc := []byte{1, sps[1], sps[2], sps[3], 0xff, 0xe1}
		avcc = binary.BigEndian.AppendUint16(avcc, uint16(len(sps)))
		avcc = append(avcc, sps...)
		avcc = append(avcc, 1)
		avcc = binary.BigEndian.AppendUint16(avcc, uint16(len(pps)))
		avcc = append(avcc, pps...)
		cfgPkt := append([]byte{AppleAVCConfigMarker, 0, 0, 0}, []byte("avc1avcC")...)
		cfgPkt = append(cfgPkt, avcc...)

		iSlice := append([]byte{0x61}, encodeBitsRBSP(nil, []uint32{0, 7}, nil, []uint32{0xaa}, []int{8})...)
		pSlice := append([]byte{0x41}, encodeBitsRBSP(nil, []uint32{0, 0}, nil, []uint32{0x55}, []int{8})...)

		_, _ = udpSender.Write(vEnc.Encrypt(cfgPkt, 100, false))
		_, _ = udpSender.Write(vEnc.Encrypt(iSlice, 100, true))
		vEnc.mu.Lock()
		vEnc.ts += 3000
		vEnc.mu.Unlock()
		_, _ = udpSender.Write(vEnc.Encrypt(pSlice, 100, true))
		srvErr <- nil
	}()

	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port
	cfg := DefaultConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = tcpPort
	cfg.Username = username
	cfg.Password = password
	cfg.UDPBindAddr = "127.0.0.1"
	cfg.UDPCtrlPort = ctrlPort
	cfg.UDPVideoPort = videoPort
	cfg.WarmupTCP = false
	cfg.Curtain = false

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer sess.Close()

	dumpPath := filepath.Join(t.TempDir(), "out.h264")
	rep, err := sess.CollectProbeStats(ctx, 500*time.Millisecond, dumpPath)
	if err != nil {
		t.Fatalf("CollectProbeStats failed: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("mock server error: %v", err)
	}
	if rep.SRTPOK < 3 || rep.Keyframes != 1 || rep.FramesTotal != 2 || rep.PatchedMaxRef != 10 {
		t.Fatalf("unexpected probe report: %+v", rep)
	}
	rawOut, err := os.ReadFile(dumpPath)
	if err != nil || !bytes.Contains(rawOut, []byte{0, 0, 0, 1, 0x67}) {
		t.Fatalf("Annex-B dump invalid: err=%v len=%d", err, len(rawOut))
	}
}

// A mode of a display of the session's own is its size in points, then that
// size over the pixel scale, which is how macOS reads it (BuildVirtualDisplay).
func TestBuildVirtualDisplayModes(t *testing.T) {
	for _, c := range []struct {
		w, h  int
		scale float64
		want  [4]uint32
	}{
		{1000, 600, 2, [4]uint32{1000, 600, 500, 300}},
		{1280, 800, 1, [4]uint32{1280, 800, 1280, 800}},
		{1500, 900, 1.5, [4]uint32{1500, 900, 1000, 600}},
	} {
		msg := BuildVirtualDisplay(c.w, c.h, c.scale, false, "")
		const d = 0x0c
		cur := int(binary.BigEndian.Uint16(msg[d+0x92 : d+0x94]))
		e := d + 0x9c + 28*cur
		var got [4]uint32
		for i := range got {
			got[i] = binary.BigEndian.Uint32(msg[e+4*i : e+4*i+4])
		}
		if got != c.want {
			t.Fatalf("%dx%d at %v: mode %v, want %v", c.w, c.h, c.scale, got, c.want)
		}
	}
}
