package applehp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf16"
)

var (
	errInvalidPlist = errors.New("applehp: invalid binary plist")
	errBlobNotFound = errors.New("applehp: media blob not found")
)

const bplistTrailerSize = 32

// EncodePlistDict encodes a top-level string-keyed dictionary into an Apple
// binary plist (bplist00). Supported value types: string, []byte, int, int64,
// uint64, bool, and nested map[string]any / []any.
func EncodePlistDict(dict map[string]any) ([]byte, error) {
	type slot struct {
		raw []byte
	}
	var slots []slot
	var addObj func(v any) (int, error)

	// Store placeholder first so parent comes before children (index 0 = root).
	addObj = func(v any) (int, error) {
		idx := len(slots)
		slots = append(slots, slot{})

		switch val := v.(type) {
		case nil:
			slots[idx].raw = []byte{0x00}
		case bool:
			if val {
				slots[idx].raw = []byte{0x09}
			} else {
				slots[idx].raw = []byte{0x08}
			}
		case int:
			slots[idx].raw = encodePlistInt(int64(val))
		case int64:
			slots[idx].raw = encodePlistInt(val)
		case uint64:
			slots[idx].raw = encodePlistUint(val)
		case []byte:
			slots[idx].raw = append(encodePlistHeader(0x40, len(val)), val...)
		case string:
			if isASCIIString(val) {
				slots[idx].raw = append(encodePlistHeader(0x50, len(val)), []byte(val)...)
			} else {
				u16 := utf16.Encode([]rune(val))
				buf := make([]byte, 0, 8+len(u16)*2)
				buf = append(buf, encodePlistHeader(0x60, len(u16))...)
				for _, ch := range u16 {
					buf = binary.BigEndian.AppendUint16(buf, ch)
				}
				slots[idx].raw = buf
			}
		case map[string]any:
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			keyRefs := make([]int, len(keys))
			valRefs := make([]int, len(keys))
			for i, k := range keys {
				kr, err := addObj(k)
				if err != nil {
					return 0, err
				}
				vr, err := addObj(val[k])
				if err != nil {
					return 0, err
				}
				keyRefs[i] = kr
				valRefs[i] = vr
			}
			// Temporarily hold refs inside a sentinel encoding; rewritten after objRefSize is known.
			buf := encodePlistHeader(0xD0, len(keys))
			for _, r := range keyRefs {
				buf = binary.BigEndian.AppendUint32(buf, uint32(r))
			}
			for _, r := range valRefs {
				buf = binary.BigEndian.AppendUint32(buf, uint32(r))
			}
			slots[idx].raw = buf
		default:
			return 0, fmt.Errorf("applehp: unsupported plist value type %T", v)
		}
		return idx, nil
	}

	if _, err := addObj(dict); err != nil {
		return nil, err
	}

	numObjects := len(slots)
	refSize := 1
	if numObjects > 0xFF {
		refSize = 2
	}
	if numObjects > 0xFFFF {
		refSize = 4
	}

	// Shrink temporary 4-byte dict refs down to refSize before computing offsets.
	// Note: we mark dicts cleanly by re-encoding dict headers + refs in-place.
	var rewriteDicts func(v any, idxRef *int)
	rewriteDicts = func(v any, idxRef *int) {
		cur := *idxRef
		*idxRef++
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		hdr := encodePlistHeader(0xD0, len(keys))
		// slots[cur].raw has hdr followed by 2*len(keys) uint32 refs.
		rawRefs := slots[cur].raw[len(hdr):]
		out := make([]byte, 0, len(hdr)+2*len(keys)*refSize)
		out = append(out, hdr...)
		for i := 0; i < 2*len(keys); i++ {
			ref := binary.BigEndian.Uint32(rawRefs[i*4 : (i+1)*4])
			out = appendSizedUint(out, uint64(ref), refSize)
		}
		slots[cur].raw = out
		for _, k := range keys {
			*idxRef++ // key string slot
			rewriteDicts(m[k], idxRef)
		}
	}
	walkIdx := 0
	rewriteDicts(dict, &walkIdx)

	out := make([]byte, 0, 256)
	out = append(out, []byte("bplist00")...)
	offsets := make([]uint64, numObjects)
	for i, s := range slots {
		offsets[i] = uint64(len(out))
		out = append(out, s.raw...)
	}
	offsetTableOffset := uint64(len(out))

	offsetSize := 1
	if offsetTableOffset > 0xFF {
		offsetSize = 2
	}
	if offsetTableOffset > 0xFFFF {
		offsetSize = 4
	}
	if offsetTableOffset > 0xFFFFFFFF {
		offsetSize = 8
	}
	for _, off := range offsets {
		out = appendSizedUint(out, off, offsetSize)
	}

	var trailer [bplistTrailerSize]byte
	trailer[6] = byte(offsetSize)
	trailer[7] = byte(refSize)
	binary.BigEndian.PutUint64(trailer[8:16], uint64(numObjects))
	binary.BigEndian.PutUint64(trailer[16:24], 0)
	binary.BigEndian.PutUint64(trailer[24:32], offsetTableOffset)
	out = append(out, trailer[:]...)
	return out, nil
}

func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func encodePlistHeader(tag byte, length int) []byte {
	if length < 15 {
		return []byte{tag | byte(length)}
	}
	return append([]byte{tag | 0x0F}, encodePlistUint(uint64(length))...)
}

func encodePlistInt(v int64) []byte {
	if v >= 0 {
		return encodePlistUint(uint64(v))
	}
	var buf [9]byte
	buf[0] = 0x13
	binary.BigEndian.PutUint64(buf[1:], uint64(v))
	return buf[:]
}

func encodePlistUint(v uint64) []byte {
	switch {
	case v <= 0xFF:
		return []byte{0x10, byte(v)}
	case v <= 0xFFFF:
		return []byte{0x11, byte(v >> 8), byte(v)}
	case v <= 0xFFFFFFFF:
		var buf [5]byte
		buf[0] = 0x12
		binary.BigEndian.PutUint32(buf[1:], uint32(v))
		return buf[:]
	default:
		var buf [9]byte
		buf[0] = 0x13
		binary.BigEndian.PutUint64(buf[1:], v)
		return buf[:]
	}
}

func appendSizedUint(dst []byte, v uint64, size int) []byte {
	switch size {
	case 1:
		return append(dst, byte(v))
	case 2:
		return binary.BigEndian.AppendUint16(dst, uint16(v))
	case 4:
		return binary.BigEndian.AppendUint32(dst, uint32(v))
	case 8:
		return binary.BigEndian.AppendUint64(dst, v)
	default:
		return dst
	}
}

func readSizedUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}
	return v
}

type plistTrailer struct {
	offsetIntSize     int
	objectRefSize     int
	numObjects        uint64
	topObject         uint64
	offsetTableOffset uint64
}

func parsePlistTrailer(data []byte) (plistTrailer, bool) {
	if len(data) < 8+bplistTrailerSize || !bytes.HasPrefix(data, []byte("bplist00")) {
		return plistTrailer{}, false
	}
	tr := data[len(data)-bplistTrailerSize:]
	for i := 0; i < 6; i++ {
		if tr[i] != 0 {
			return plistTrailer{}, false
		}
	}
	offSz := int(tr[6])
	refSz := int(tr[7])
	if !validIntSize(offSz) || !validIntSize(refSz) {
		return plistTrailer{}, false
	}
	numObj := binary.BigEndian.Uint64(tr[8:16])
	topObj := binary.BigEndian.Uint64(tr[16:24])
	offTable := binary.BigEndian.Uint64(tr[24:32])
	if numObj == 0 || numObj > 65536 || topObj >= numObj || offTable < 8 {
		return plistTrailer{}, false
	}
	bodyLen := uint64(len(data) - bplistTrailerSize)
	if offTable > bodyLen {
		return plistTrailer{}, false
	}
	tableBytes := numObj * uint64(offSz)
	if tableBytes/uint64(offSz) != numObj || offTable+tableBytes != bodyLen {
		return plistTrailer{}, false
	}
	switch offSz {
	case 1:
		if offTable > 0xFF {
			return plistTrailer{}, false
		}
	case 2:
		if offTable > 0xFFFF {
			return plistTrailer{}, false
		}
	case 4:
		if offTable > 0xFFFFFFFF {
			return plistTrailer{}, false
		}
	}
	return plistTrailer{
		offsetIntSize:     offSz,
		objectRefSize:     refSz,
		numObjects:        numObj,
		topObject:         topObj,
		offsetTableOffset: offTable,
	}, true
}

func validIntSize(n int) bool {
	return n == 1 || n == 2 || n == 4 || n == 8
}

// DecodePlist decodes an Apple binary plist (bplist00) into Go primitives.
func DecodePlist(data []byte) (any, error) {
	tr, ok := parsePlistTrailer(data)
	if !ok {
		return nil, errInvalidPlist
	}
	offsets := make([]uint64, tr.numObjects)
	ot := int(tr.offsetTableOffset)
	for i := uint64(0); i < tr.numObjects; i++ {
		pos := ot + int(i)*tr.offsetIntSize
		off := readSizedUint(data[pos : pos+tr.offsetIntSize])
		if off < 8 || off >= tr.offsetTableOffset {
			return nil, errInvalidPlist
		}
		offsets[i] = off
	}

	var decodeAt func(objIdx uint64, depth int) (any, error)
	readLength := func(marker byte, pos int) (int, int, error) {
		n := int(marker & 0x0F)
		if n < 0x0F {
			return n, pos, nil
		}
		if pos >= int(tr.offsetTableOffset) {
			return 0, 0, errInvalidPlist
		}
		intMarker := data[pos]
		if intMarker&0xF0 != 0x10 {
			return 0, 0, errInvalidPlist
		}
		byteCount := 1 << (intMarker & 0x0F)
		pos++
		if byteCount > 8 || pos+byteCount > int(tr.offsetTableOffset) {
			return 0, 0, errInvalidPlist
		}
		v := readSizedUint(data[pos : pos+byteCount])
		if v > math.MaxInt32 {
			return 0, 0, errInvalidPlist
		}
		return int(v), pos + byteCount, nil
	}

	decodeAt = func(objIdx uint64, depth int) (any, error) {
		if depth > 32 || objIdx >= tr.numObjects {
			return nil, errInvalidPlist
		}
		off := int(offsets[objIdx])
		if off >= int(tr.offsetTableOffset) {
			return nil, errInvalidPlist
		}
		marker := data[off]
		pos := off + 1
		objType := marker & 0xF0

		switch objType {
		case 0x00:
			switch marker {
			case 0x00:
				return nil, nil
			case 0x08:
				return false, nil
			case 0x09:
				return true, nil
			default:
				return nil, errInvalidPlist
			}
		case 0x10:
			byteCount := 1 << (marker & 0x0F)
			if byteCount > 16 || pos+byteCount > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			if byteCount == 8 {
				return int64(binary.BigEndian.Uint64(data[pos : pos+8])), nil
			}
			if byteCount == 16 {
				// Rarely used; preserve signed 64-bit lower half if representable.
				return int64(binary.BigEndian.Uint64(data[pos+8 : pos+16])), nil
			}
			return int64(readSizedUint(data[pos : pos+byteCount])), nil
		case 0x20:
			byteCount := 1 << (marker & 0x0F)
			if pos+byteCount > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			switch byteCount {
			case 4:
				return float64(math.Float32frombits(binary.BigEndian.Uint32(data[pos : pos+4]))), nil
			case 8:
				return math.Float64frombits(binary.BigEndian.Uint64(data[pos : pos+8])), nil
			default:
				return nil, errInvalidPlist
			}
		case 0x30:
			if pos+8 > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			return math.Float64frombits(binary.BigEndian.Uint64(data[pos : pos+8])), nil
		case 0x40:
			n, p, err := readLength(marker, pos)
			if err != nil || p+n > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			cp := make([]byte, n)
			copy(cp, data[p:p+n])
			return cp, nil
		case 0x50:
			n, p, err := readLength(marker, pos)
			if err != nil || p+n > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			return string(data[p : p+n]), nil
		case 0x60:
			n, p, err := readLength(marker, pos)
			if err != nil || p+n*2 > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			u16 := make([]uint16, n)
			for i := 0; i < n; i++ {
				u16[i] = binary.BigEndian.Uint16(data[p+i*2 : p+i*2+2])
			}
			return string(utf16.Decode(u16)), nil
		case 0xA0:
			n, p, err := readLength(marker, pos)
			if err != nil || p+n*tr.objectRefSize > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			arr := make([]any, n)
			for i := 0; i < n; i++ {
				ref := readSizedUint(data[p+i*tr.objectRefSize : p+(i+1)*tr.objectRefSize])
				v, err := decodeAt(ref, depth+1)
				if err != nil {
					return nil, err
				}
				arr[i] = v
			}
			return arr, nil
		case 0xD0:
			n, p, err := readLength(marker, pos)
			if err != nil || p+2*n*tr.objectRefSize > int(tr.offsetTableOffset) {
				return nil, errInvalidPlist
			}
			m := make(map[string]any, n)
			for i := 0; i < n; i++ {
				koff := p + i*tr.objectRefSize
				voff := p + (n+i)*tr.objectRefSize
				kref := readSizedUint(data[koff : koff+tr.objectRefSize])
				vref := readSizedUint(data[voff : voff+tr.objectRefSize])
				kv, err := decodeAt(kref, depth+1)
				if err != nil {
					return nil, err
				}
				ks, ok := kv.(string)
				if !ok {
					return nil, errInvalidPlist
				}
				vv, err := decodeAt(vref, depth+1)
				if err != nil {
					return nil, err
				}
				m[ks] = vv
			}
			return m, nil
		default:
			return nil, errInvalidPlist
		}
	}

	return decodeAt(tr.topObject, 0)
}

// ExtractPlistMediaBlob locates an embedded bplist00 inside a server 0x1c answer
// message and returns the compressed avcMediaStreamNegotiatorMediaBlob bytes.
func ExtractPlistMediaBlob(msg []byte) ([]byte, error) {
	magic := []byte("bplist00")
	for start := 0; start+8+bplistTrailerSize <= len(msg); {
		rel := bytes.Index(msg[start:], magic)
		if rel < 0 {
			break
		}
		idx := start + rel
		for end := idx + 8 + bplistTrailerSize; end <= len(msg); end++ {
			cand := msg[idx:end]
			if _, ok := parsePlistTrailer(cand); !ok {
				continue
			}
			val, err := DecodePlist(cand)
			if err != nil {
				continue
			}
			if m, ok := val.(map[string]any); ok {
				if blob, ok := m["avcMediaStreamNegotiatorMediaBlob"].([]byte); ok && len(blob) > 0 {
					return blob, nil
				}
			}
		}
		start = idx + 8
	}
	return nil, errBlobNotFound
}

// ExtractPlistMediaBlobs returns the avcMediaStreamNegotiatorMediaBlob of every plist in msg,
// in order, looking for the plists in it: at most plistScanMax of them are tried.
func ExtractPlistMediaBlobs(msg []byte) [][]byte {
	magic := []byte("bplist00")
	var out [][]byte
	tried := 0
	for start := 0; start+8+bplistTrailerSize <= len(msg) && tried < plistScanMax; {
		rel := bytes.Index(msg[start:], magic)
		if rel < 0 {
			break
		}
		idx := start + rel
		tried++
		next := idx + 8
		for end := idx + 8 + bplistTrailerSize; end <= len(msg); end++ {
			cand := msg[idx:end]
			if _, ok := parsePlistTrailer(cand); !ok {
				continue
			}
			if _, err := DecodePlist(cand); err != nil {
				continue
			}
			if blob := plistMediaBlob(cand); blob != nil {
				out = append(out, blob)
			}
			next = end
			break
		}
		start = next
	}
	return out
}

// plistScanMax bounds the plists looked for in one message; an answer has one per stream.
const plistScanMax = 8

func plistMediaBlob(pl []byte) []byte {
	val, err := DecodePlist(pl)
	if err != nil {
		return nil
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil
	}
	blob, _ := m["avcMediaStreamNegotiatorMediaBlob"].([]byte)
	if len(blob) == 0 {
		return nil
	}
	return blob
}

// answerMediaBlobs returns the media blobs in the body of an answer's 0x3f2 rectangle (from its
// u16 length on): by the lengths it declares where it is laid out as macOS 15 lays it out, else
// by looking for the plists in it.
func answerMediaBlobs(body []byte) [][]byte {
	pls := answerPlists(body)
	if pls == nil {
		return ExtractPlistMediaBlobs(body)
	}
	var out [][]byte
	for _, pl := range pls {
		if blob := plistMediaBlob(pl); blob != nil {
			out = append(out, blob)
		}
	}
	return out
}

// answerPlists splits an answer's 0x3f2 body: u16 length (of the rest), u16 version, u16 plist
// count, u32, a u16 length for each plist from offset 10 (room for five), the plists from offset
// 20, ending with the body. Captured from macOS 15 with version 2 and two plists, audio then
// video. nil when the body is not laid out so.
func answerPlists(body []byte) [][]byte {
	const head, slots = 20, 5
	if len(body) < head || int(binary.BigEndian.Uint16(body[0:2]))+2 != len(body) {
		return nil
	}
	count := int(binary.BigEndian.Uint16(body[4:6]))
	if count == 0 || count > slots {
		return nil
	}
	out := make([][]byte, 0, count)
	at := head
	for i := 0; i < count; i++ {
		n := int(binary.BigEndian.Uint16(body[10+2*i : 12+2*i]))
		if n == 0 || at+n > len(body) {
			return nil
		}
		out = append(out, body[at:at+n])
		at += n
	}
	if at != len(body) {
		return nil
	}
	return out
}
