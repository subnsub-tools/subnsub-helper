package main

// musicdav.go — a WebDAV folder (Nextcloud, ownCloud, a NAS, Jianguoyun,
// rclone serve, Alist …) as one of this machine's music roots. The helper does
// the talking: the folder is listed with PROPFIND and read in ranges with GET,
// so the server needs no CORS for a browser and its password never reaches
// one. The bytes still leave this machine only through the direct roads
// (music.go).
//
// A server whose certificate the system does not trust (a NAS's own) is
// refused until its certificate is pinned: the first answer is the
// certificate's SHA-256, the page shows it, and only a second request that
// names that same fingerprint adds the folder. From then on that certificate
// and no other is accepted for it.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	davBlock     = 256 << 10 // what one ranged read for tags fetches
	davBlocks    = 48        // at most this many blocks held per file
	davListMax   = 16 << 20  // a PROPFIND answer larger than this is refused
	davDirsMax   = 20000
	davDepthMax  = 24
	davTimeout   = 30 * time.Second
	davPinPrefix = "sha256:"
)

type davRoot struct {
	base   *url.URL // always ends in "/"
	user   string
	pass   string
	pin    string
	client *http.Client
	// Set once a server answers a ranged GET with the whole file: reads for
	// tags then stay at the front, where one GET is enough.
	mu      sync.Mutex
	noRange bool
}

// davError is a refusal the page can say in words: its code is one of the
// dav-* errors below, and Detail the certificate's fingerprint for
// cert-untrusted.
type davError struct {
	Code   string
	Detail string
}

func (e *davError) Error() string { return e.Code }

func davFail(code string) error { return &davError{Code: code} }

// cleanDavURL parses what somebody typed: http or https, a host, no
// credentials in it (they go in their own fields), and a path that ends in
// "/" so that children resolve under it.
func cleanDavURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return nil, davFail("bad-url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, davFail("bad-url")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, davFail("bad-url")
	}
	if u.User != nil {
		return nil, davFail("bad-url")
	}
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawPath = ""
	return u, nil
}

func newDav(raw, user, pass, pin string) (*davRoot, error) {
	u, err := cleanDavURL(raw)
	if err != nil {
		return nil, err
	}
	d := &davRoot{base: u, user: user, pass: pass, pin: strings.ToLower(strings.TrimSpace(pin))}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if d.pin != "" {
		if !strings.HasPrefix(d.pin, davPinPrefix) || len(d.pin) != len(davPinPrefix)+64 {
			return nil, davFail("bad-pin")
		}
		want := d.pin
		// The pinned certificate, and that one only, stands in for the
		// system's judgement: the chain is not checked, the leaf's bytes are.
		tlsConf.InsecureSkipVerify = true
		tlsConf.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || certPin(cs.PeerCertificates[0]) != want {
				return davFail("cert-changed")
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: davTimeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
	}
	d.client = &http.Client{
		Transport: tr,
		// A redirect may leave the folder, or the scheme: followed only
		// within the same origin, and never from https to http.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 || req.URL.Scheme != u.Scheme || req.URL.Host != u.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return d, nil
}

func certPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return davPinPrefix + hex.EncodeToString(sum[:])
}

// where is how the page names this root: the host and path, never the
// account.
func (d *davRoot) where() string {
	return strings.TrimSuffix(d.base.Host+d.base.Path, "/")
}

func (d *davRoot) urlFor(rel string) *url.URL {
	u := *d.base
	if rel != "" {
		u.Path = d.base.Path + rel
	}
	u.RawPath = ""
	return &u
}

func (d *davRoot) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if d.user != "" || d.pass != "" {
		req.SetBasicAuth(d.user, d.pass)
	}
	req.Header.Set("User-Agent", "subnsub-monitor/"+helperVersion)
	resp, err := d.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, d.classify(ctx, err)
	}
	return resp, nil
}

// classify turns a transport failure into one of the page's words. A
// certificate the system does not trust is answered with its fingerprint,
// read with a second, unverified handshake that sends nothing else.
func (d *davRoot) classify(ctx context.Context, err error) error {
	var de *davError
	if errors.As(err, &de) {
		return de
	}
	var unk x509.UnknownAuthorityError
	var host x509.HostnameError
	var inv x509.CertificateInvalidError
	var ver *tls.CertificateVerificationError
	if errors.As(err, &unk) || errors.As(err, &host) || errors.As(err, &inv) || errors.As(err, &ver) {
		if fp := d.fingerprint(ctx); fp != "" {
			return &davError{Code: "cert-untrusted", Detail: fp}
		}
		return davFail("cert-untrusted")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return davFail("dav-unreachable")
}

func (d *davRoot) fingerprint(ctx context.Context) string {
	if d.base.Scheme != "https" {
		return ""
	}
	host := d.base.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dl := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: d.base.Hostname(), MinVersion: tls.VersionTLS12}}
	c, err := dl.DialContext(dctx, "tcp", host)
	if err != nil {
		return ""
	}
	defer c.Close()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return ""
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	return certPin(certs[0])
}

type davEntry struct {
	Rel  string // decoded, slash-separated, under the root
	Dir  bool
	Size int64
	Mod  int64 // unix seconds
	ETag string
}

type davMultistatus struct {
	Responses []struct {
		Href      string `xml:"href"`
		Propstats []struct {
			Status string `xml:"status"`
			Prop   struct {
				ResourceType struct {
					Collection *struct{} `xml:"collection"`
				} `xml:"resourcetype"`
				Length   string `xml:"getcontentlength"`
				Modified string `xml:"getlastmodified"`
				ETag     string `xml:"getetag"`
			} `xml:"prop"`
		} `xml:"propstat"`
	} `xml:"response"`
}

const davPropfind = `<?xml version="1.0" encoding="utf-8"?>` +
	`<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/>` +
	`<d:getlastmodified/><d:getetag/></d:prop></d:propfind>`

// list is one folder's children (Depth 1), the folder itself left out.
func (d *davRoot) list(ctx context.Context, rel string) ([]davEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*davTimeout)
	defer cancel()
	req, err := http.NewRequest("PROPFIND", d.urlFor(rel).String(), strings.NewReader(davPropfind))
	if err != nil {
		return nil, davFail("bad-url")
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	resp, err := d.do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, davFail("dav-auth")
	case resp.StatusCode == http.StatusNotFound:
		return nil, davFail("dav-not-found")
	case resp.StatusCode != http.StatusMultiStatus:
		return nil, davFail("dav-not-webdav")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, davListMax+1))
	if err != nil {
		return nil, davFail("dav-unreachable")
	}
	if len(body) > davListMax {
		return nil, davFail("dav-too-large")
	}
	var ms davMultistatus
	if xml.Unmarshal(body, &ms) != nil {
		return nil, davFail("dav-not-webdav")
	}
	self := strings.TrimSuffix(rel, "/")
	var out []davEntry
	for _, r := range ms.Responses {
		child, ok := d.relOf(r.Href)
		if !ok || strings.TrimSuffix(child, "/") == self {
			continue
		}
		var e davEntry
		e.Rel = strings.TrimSuffix(child, "/")
		found := false
		for _, ps := range r.Propstats {
			if ps.Status != "" && !strings.Contains(ps.Status, " 200") {
				continue
			}
			found = true
			e.Dir = ps.Prop.ResourceType.Collection != nil
			e.Size, _ = strconv.ParseInt(strings.TrimSpace(ps.Prop.Length), 10, 64)
			if t, err := http.ParseTime(strings.TrimSpace(ps.Prop.Modified)); err == nil {
				e.Mod = t.Unix()
			}
			e.ETag = strings.Trim(strings.TrimSpace(ps.Prop.ETag), `"`)
			if len(e.ETag) > 128 {
				e.ETag = e.ETag[:128]
			}
		}
		if !found || e.Rel == "" || !musicRelOK(e.Rel) {
			continue
		}
		// A server answers Depth 1 with children only; one that answered with
		// grandchildren as well is taken at its word for the ones directly
		// under this folder and asked again for the rest.
		if self == "" && strings.Contains(e.Rel, "/") || self != "" && path.Dir(e.Rel) != self {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// relOf turns an href (an absolute path or a whole URL, percent-encoded) into
// a path under the root, or false when it is not under it.
func (d *davRoot) relOf(href string) (string, bool) {
	ref, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", false
	}
	u := d.base.ResolveReference(ref)
	if u.Host != d.base.Host || u.Scheme != d.base.Scheme {
		return "", false
	}
	p := u.Path
	if !strings.HasPrefix(p, d.base.Path) {
		return "", false
	}
	return strings.TrimPrefix(p, d.base.Path), true
}

// probe answers whether the root is a WebDAV folder these credentials may
// list: the check made before one is added.
func (d *davRoot) probe(ctx context.Context) error {
	_, err := d.list(ctx, "")
	return err
}

// walk visits every file under the root, breadth first, within the limits
// above. fn's error stops the walk.
func (d *davRoot) walk(ctx context.Context, fn func(davEntry) error) error {
	queue := []string{""}
	// seen: a server can list a folder under itself, or one folder under two
	// names that resolve alike; each is listed once. The queue is held to the
	// folder limit too, so a server listing a million folders in one answer
	// is not a million strings in memory.
	seen := map[string]bool{"": true}
	dirs := 0
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dir := queue[0]
		queue = queue[1:]
		dirs++
		if dirs > davDirsMax {
			return nil
		}
		entries, err := d.list(ctx, dir)
		if err != nil {
			if dir == "" {
				return err
			}
			continue // one unreadable folder is not the library's loss
		}
		for _, e := range entries {
			name := path.Base(e.Rel)
			if e.Dir {
				sub := e.Rel + "/"
				if musicSkipDir(name) || strings.Count(e.Rel, "/") >= davDepthMax || seen[sub] || dirs+len(queue) >= davDirsMax {
					continue
				}
				seen[sub] = true
				queue = append(queue, sub)
				continue
			}
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// get reads [off, off+n) of one file, or from off to the end when n is 0. A
// server that ignores Range answers with the whole file; what comes before off
// is skipped here, so the caller always gets the bytes it asked for.
func (d *davRoot) get(ctx context.Context, rel string, off, n int64) (io.ReadCloser, string, error) {
	req, err := http.NewRequest(http.MethodGet, d.urlFor(rel).String(), nil)
	if err != nil {
		return nil, "", davFail("bad-url")
	}
	if off > 0 || n > 0 {
		if n > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+n-1))
		} else {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
		}
	}
	resp, err := d.do(ctx, req)
	if err != nil {
		return nil, "", err
	}
	ct := resp.Header.Get("Content-Type")
	switch resp.StatusCode {
	case http.StatusPartialContent:
		if n > 0 {
			return limitedBody{io.LimitReader(resp.Body, n), resp.Body}, ct, nil
		}
		return resp.Body, ct, nil
	case http.StatusOK:
		d.mu.Lock()
		d.noRange = d.noRange || off > 0 || n > 0
		d.mu.Unlock()
		if off > 0 {
			if _, err := io.CopyN(io.Discard, resp.Body, off); err != nil {
				resp.Body.Close()
				return nil, "", davFail("dav-unreachable")
			}
		}
		if n > 0 {
			return limitedBody{io.LimitReader(resp.Body, n), resp.Body}, ct, nil
		}
		return resp.Body, ct, nil
	case http.StatusRequestedRangeNotSatisfiable:
		resp.Body.Close()
		return io.NopCloser(strings.NewReader("")), ct, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		resp.Body.Close()
		return nil, "", davFail("dav-auth")
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, "", davFail("dav-not-found")
	}
	resp.Body.Close()
	return nil, "", davFail("dav-unreachable")
}

type limitedBody struct {
	io.Reader
	c io.Closer
}

func (l limitedBody) Close() error { return l.c.Close() }

// davSource reads one remote file for its tags, a block at a time, keeping the
// blocks it has fetched: the tag readers ask for small pieces in many places.
type davSource struct {
	ctx    context.Context
	d      *davRoot
	rel    string
	size   int64
	blocks map[int64][]byte
	order  []int64
}

func (d *davRoot) source(ctx context.Context, rel string, size int64) *davSource {
	return &davSource{ctx: ctx, d: d, rel: rel, size: size, blocks: map[int64][]byte{}}
}

func (s *davSource) Size() int64 { return s.size }

func (s *davSource) block(i int64) ([]byte, error) {
	if b, ok := s.blocks[i]; ok {
		return b, nil
	}
	s.d.mu.Lock()
	whole := s.d.noRange
	s.d.mu.Unlock()
	// Without ranges, only the front can be had for the price of one read.
	if whole && i != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	// Each block on its own clock: the walk's context runs for the whole
	// folder, and a server that stalls mid-body would hold the walk with it.
	ctx, cancel := context.WithTimeout(s.ctx, 2*davTimeout)
	defer cancel()
	rc, _, err := s.d.get(ctx, s.rel, i*davBlock, davBlock)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(rc, davBlock))
	rc.Close()
	if err != nil {
		return nil, err
	}
	if len(s.order) >= davBlocks {
		delete(s.blocks, s.order[0])
		s.order = s.order[1:]
	}
	s.blocks[i] = b
	s.order = append(s.order, i)
	return b, nil
}

func (s *davSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= s.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off+int64(n) < s.size {
		at := off + int64(n)
		b, err := s.block(at / davBlock)
		if err != nil {
			return n, err
		}
		in := int(at % davBlock)
		if in >= len(b) {
			return n, io.ErrUnexpectedEOF
		}
		n += copy(p[n:], b[in:])
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
