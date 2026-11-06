package main

/* ── the tailnet road to A, for a fetch ──

   A fetch (filesfetch.go) asks A over the tailnet first when both machines
   are on one (user 2026-11-05: first tailnet, then tailcat): the operating
   system's Tailscale carries the bytes, and tailcat is the road taken when
   that does not answer. The page names A's tailnet listener as A's hello
   told it (ip, port, and the machine's X25519 key); this machine opens a
   session there with the job's own node key, which A lets in for as long as
   it holds the grant (tailnet.go tailnetLetIn), and asks its questions inside
   the session as the page does on that road (monitor-direct.js): each one
   sealed, each answer read as sealed records.

   What is trusted of the network is what tailnet.go trusts of it: nothing.
   An address on someone else's tailnet, or one that changed hands, is a
   machine that cannot prove it holds A's key: the session's proof is checked
   against the key the page named, and the agent it answers with must be the
   one the page named, before any question is asked. */

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/types/key"
)

const (
	// How long the session's opening may take before the job goes by tailcat.
	fetchTnOpenWait = 5 * time.Second
	// After a tailnet road that would not open, how long before the next
	// dial tries it again.
	fetchTnRest = 2 * time.Minute
	// A sealed record is a 32 KiB piece at most (tailnet.go tailnetRecord),
	// its kind and its tag.
	fetchTnRecordMax = 64 << 10
)

var fetchTnKeyRe = regexp.MustCompile(`^nodekey:[0-9a-f]{64}$`)

// fetchTn is A's listener on its tailnet, as A's hello told the page.
type fetchTn struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Key  string `json:"key"`
}

// fetchTnArg is the page's word on A's tailnet listener, or nil when it says
// none or what it says is not one: an address outside Tailscale's range, a
// port that is not one, a key that is not a key. Such a word costs the job
// nothing but the tailnet: it goes by tailcat.
func fetchTnArg(t *fetchTn) *fetchTn {
	if t == nil {
		return nil
	}
	a, err := netip.ParseAddr(t.IP)
	if err != nil || !a.Is4() || !tailnetCGNAT.Contains(a) || t.Port < 1 || t.Port > 65535 || !fetchTnKeyRe.MatchString(t.Key) {
		return nil
	}
	if _, ok := econParsePublic(t.Key); !ok {
		return nil
	}
	return &fetchTn{IP: a.String(), Port: t.Port, Key: t.Key}
}

// fetchDialTn is the tailnet road to A, or nil when there is none: this
// machine is on no tailnet (or its tailnet road is off), or A's listener did
// not open a session in time. A test puts its own in its place.
var fetchDialTn = func(ctx context.Context, tn *fetchTn, agent string, priv key.NodePrivate) fetchRoad {
	if tn == nil || tailnetRoadNow() == nil {
		return nil
	}
	rd, err := openTnRoad(ctx, "http://"+net.JoinHostPort(tn.IP, strconv.Itoa(tn.Port)), tn.Key, agent, priv)
	if err != nil {
		return nil
	}
	return rd
}

// tnRoad is a session on A's tailnet listener, as an HTTP client's transport.
type tnRoad struct {
	base   string
	agent  string
	mkey   *ecdh.PublicKey // A's key, as the page named it
	mtext  string
	static *ecdh.PrivateKey // the job's node key
	pub    string
	outer  *http.Client
	hc     *http.Client

	mu  sync.Mutex
	ses *tnSes
}

type tnSes struct {
	sid string
	in  cipher.AEAD
	out []byte
	seq uint64
}

// openTnRoad opens a session on A's listener at base, with the job's key.
func openTnRoad(ctx context.Context, base, machineKey, agent string, priv key.NodePrivate) (*tnRoad, error) {
	mk, ok := econParsePublic(machineKey)
	if !ok {
		return nil, errors.New("tailnet: not a key")
	}
	pt, err := priv.MarshalText()
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(string(pt), "privkey:"))
	if err != nil {
		return nil, err
	}
	static, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	pub := econKeyPrefix + hex.EncodeToString(static.PublicKey().Bytes())
	t := &tnRoad{base: base, agent: agent, mkey: mk, mtext: machineKey, static: static, pub: pub,
		// No redirect is followed: whatever answers at the address could send
		// this machine anywhere before it has proven anything. A 3xx is an
		// answer like any other that is not the session's, and the job goes
		// by tailcat.
		outer: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: fetchTnOpenWait}).DialContext,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       time.Minute,
			ResponseHeaderTimeout: fetchPieceIdle,
		}}}
	t.hc = &http.Client{Transport: t}
	octx, cancel := context.WithTimeout(ctx, fetchTnOpenWait)
	defer cancel()
	s, err := t.open(octx)
	if err != nil {
		t.outer.CloseIdleConnections()
		return nil, err
	}
	t.ses = s
	return t, nil
}

func (t *tnRoad) HTTP() *http.Client { return t.hc }

// Route is the tailnet's: how Tailscale carries it, direct or by its relays,
// is the operating system's to know.
func (t *tnRoad) Route(ctx context.Context) string { return "tailnet" }

func (t *tnRoad) Close() { t.outer.CloseIdleConnections() }

func (t *tnRoad) post(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	return t.outer.Do(req)
}

// open is a new session: both keys and both ephemerals into the session's
// two keys, and A's proof that it holds the key the page named.
func (t *tnRoad) open(ctx context.Context) (*tnSes, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nc := make([]byte, 16)
	if _, err := rand.Read(nc); err != nil {
		return nil, err
	}
	ePub, ncHex := hex.EncodeToString(eph.PublicKey().Bytes()), hex.EncodeToString(nc)
	q, _ := json.Marshal(map[string]any{"v": 1, "c": t.pub, "e": ePub, "n": ncHex})
	resp, err := t.post(ctx, "/tn/open", q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tailnet: open answered %d", resp.StatusCode)
	}
	var a struct {
		V int    `json:"v"`
		S string `json:"s"`
		E string `json:"e"`
		N string `json:"n"`
		A string `json:"a"`
		M string `json:"m"`
	}
	if json.Unmarshal(b, &a) != nil || a.V != 1 || a.S == "" || len(a.S) > tailnetMaxSID {
		return nil, errors.New("tailnet: open answered nothing it should")
	}
	if a.A != t.agent {
		return nil, errors.New("tailnet: another machine answers there")
	}
	eRaw, err := hex.DecodeString(a.E)
	if err != nil || len(eRaw) != 32 {
		return nil, errors.New("tailnet: no ephemeral")
	}
	peerE, err := ecdh.X25519().NewPublicKey(eRaw)
	if err != nil {
		return nil, err
	}
	ss, err1 := t.static.ECDH(t.mkey)
	ee, err2 := eph.ECDH(peerE)
	if err1 != nil || err2 != nil {
		return nil, errors.New("tailnet: no shared secret")
	}
	info := strings.Join([]string{a.A, t.mtext, t.pub, ePub, strings.ToLower(a.E), ncHex, strings.ToLower(a.N)}, "\n")
	in, out, err := tailnetKeys(ss, ee, info)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, out)
	m.Write([]byte(tailnetConfirm + a.S))
	got, err := hex.DecodeString(a.M)
	if err != nil || !hmac.Equal(m.Sum(nil), got) {
		return nil, errors.New("tailnet: the machine there does not hold the key")
	}
	aead, err := tailnetAEAD(in)
	if err != nil {
		return nil, err
	}
	return &tnSes{sid: a.S, in: aead, out: out}, nil
}

// session is the session to ask on, opened again if it went, and the number
// this question takes in it.
func (t *tnRoad) session(ctx context.Context) (*tnSes, uint64, error) {
	t.mu.Lock()
	s := t.ses
	t.mu.Unlock()
	if s == nil {
		octx, cancel := context.WithTimeout(ctx, fetchTnOpenWait)
		ns, err := t.open(octx)
		cancel()
		if err != nil {
			return nil, 0, err
		}
		t.mu.Lock()
		if t.ses == nil {
			t.ses = ns
		}
		s = t.ses
		t.mu.Unlock()
	}
	t.mu.Lock()
	s.seq++
	q := s.seq
	t.mu.Unlock()
	return s, q, nil
}

// gone lets a session go that A no longer knows (410: A restarted, or the
// session sat idle past A's keeping it).
func (t *tnRoad) gone(s *tnSes) {
	t.mu.Lock()
	if t.ses == s {
		t.ses = nil
	}
	t.mu.Unlock()
}

var errTnGone = errors.New("tailnet: session gone")

// RoundTrip is a question to A inside the session: the request sealed, the
// answer's records read as they come.
func (t *tnRoad) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, tailnetMaxFirst+1))
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(b) > tailnetMaxFirst {
			return nil, errors.New("tailnet: request too large")
		}
		body = b
	}
	for try := 0; ; try++ {
		s, q, err := t.session(req.Context())
		if err != nil {
			return nil, err
		}
		resp, err := t.call(req, s, q, body)
		if errors.Is(err, errTnGone) && try == 0 {
			t.gone(s)
			continue
		}
		return resp, err
	}
}

func (t *tnRoad) call(req *http.Request, s *tnSes, q uint64, body []byte) (*http.Response, error) {
	plain, err := json.Marshal(map[string]any{"q": q, "m": req.Method, "p": req.URL.RequestURI(), "b": base64.StdEncoding.EncodeToString(body)})
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := append(nonce, s.in.Seal(nil, nonce, plain, []byte("c\n"+s.sid))...)
	resp, err := t.post(req.Context(), "/tn/rpc?s="+url.QueryEscape(s.sid), sealed)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusGone {
		resp.Body.Close()
		return nil, errTnGone
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("tailnet: answered %d", resp.StatusCode)
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], q)
	m := hmac.New(sha256.New, s.out)
	m.Write([]byte("r"))
	m.Write(seq[:])
	aead, err := tailnetAEAD(m.Sum(nil))
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	rr := &tnRecords{r: resp.Body, aead: aead, aad: []byte("s\n" + s.sid)}
	kind, head, err := rr.next()
	if err != nil || kind != tnKindHead {
		resp.Body.Close()
		if err == nil {
			err = errors.New("tailnet: an answer with no head")
		}
		return nil, err
	}
	var h struct {
		S int    `json:"s"`
		T string `json:"t"`
		L *int64 `json:"l"`
	}
	if json.Unmarshal(head, &h) != nil || h.S < 100 || h.S > 999 {
		resp.Body.Close()
		return nil, errors.New("tailnet: a head that says nothing")
	}
	out := &http.Response{
		Status:        strconv.Itoa(h.S) + " " + http.StatusText(h.S),
		StatusCode:    h.S,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          &tnBody{rr: rr, c: resp.Body},
		ContentLength: -1,
		Request:       req,
	}
	if h.T != "" {
		out.Header.Set("Content-Type", h.T)
	}
	if h.L != nil && *h.L >= 0 {
		out.ContentLength = *h.L
	}
	return out, nil
}

// tnRecords reads an answer's sealed records: a length, then the record.
type tnRecords struct {
	r    io.Reader
	aead cipher.AEAD
	aad  []byte
	n    uint64
}

func (t *tnRecords) next() (byte, []byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(t.r, l[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n == 0 || n > fetchTnRecordMax {
		return 0, nil, errors.New("tailnet: a record of no size it could be")
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(t.r, ct); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], t.n)
	t.n++
	rec, err := t.aead.Open(nil, nonce[:], ct, t.aad)
	if err != nil || len(rec) == 0 {
		return 0, nil, errors.New("tailnet: a record that does not open")
	}
	return rec[0], rec[1:], nil
}

// tnBody is an answer's bytes: its data records, to its end record. An answer
// that stops before that is cut off, never whole.
type tnBody struct {
	rr   *tnRecords
	c    io.Closer
	buf  []byte
	done bool
	err  error
}

func (b *tnBody) Read(p []byte) (int, error) {
	for len(b.buf) == 0 {
		if b.done {
			return 0, io.EOF
		}
		if b.err != nil {
			return 0, b.err
		}
		kind, rec, err := b.rr.next()
		switch {
		case err != nil:
			b.err = err
		case kind == tnKindData:
			b.buf = rec
		case kind == tnKindEnd:
			b.done = true
		default:
			b.err = errors.New("tailnet: a record out of place")
		}
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

func (b *tnBody) Close() error { return b.c.Close() }
