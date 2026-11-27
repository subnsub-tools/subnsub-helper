package main

// serve.go — the Demos tab (index.html #panel-demos, demos-app.js): the web
// pages this machine serves on its tailnet, one port each, as its Tailscale
// keeps them (the LocalAPI's serve-config, what `tailscale serve` reads and
// writes), and a folder served on a port of its own.
//
// WHAT IS LISTED. Every web handler of the serve config, background and
// foreground, by port: a folder Tailscale serves itself (a path handler), a
// folder this helper serves (below), a proxy, a text, a TCP forward. A folder
// is looked at, within limits, for what the page shows of it: its page's
// title, how many files and bytes, the newest change, a picture the page
// names for itself (og:image) or one called preview, cover, screenshot.
//
// WHAT IS ADDED. A folder on a port: this helper serves the folder on
// 127.0.0.1, on a local port below the range systems hand out at random
// (serveListenLocal), and Tailscale's serve config proxies the tailnet port
// there. The folder is the one a link to it leads to, checked as such; its
// server shows nothing whose name starts with a dot and follows no link. Tailscale serves a folder itself only for
// root or an operator who may run sudo tailscale, and not at all from the
// macOS app, whose daemon is sandboxed away from the disks; a proxy to a
// local port needs only the write access the serve config always asks
// (Linux: the operator). The folders served so are kept in serve.json beside
// the helper's other files and served again when it starts; one whose port
// someone took off the serve config is forgotten.
//
// WHAT IS STOPPED. The handler the page saw, taken off the serve config
// once it is checked to serve still what the page saw (the port with it
// when no other handler is left there), or a whole port; the folder stays
// where it is.
//
// WHO MAY. The console's grant, as the Files tab's: a pinned dashboard, the
// console switch, a browser on the allowlist, the tunnel or the tailnet road,
// never the relay (runFilesCommand). A console already runs any command as
// this user, tailscale serve among them.
//
// Writing the serve config sends it whole, under the ETag it was read with,
// so a change made meanwhile by someone else is read again rather than
// overwritten; what this file does not know of it (services, app
// capabilities, newer fields) is sent back as it came.

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	serveTimeout = 8 * time.Second
	// A folder is counted up to this many files, for this long; past either
	// the count says "more".
	serveScanFiles = 20000
	serveScanTime  = 1500 * time.Millisecond
	// Every folder of one list, together.
	serveScanAll  = 6 * time.Second
	serveStatTTL  = time.Minute
	serveItemsMax = 300
	serveTitleMax = 160
	// What is read of a folder's index.html for its title and picture.
	serveHeadMax = 64 << 10
	// Ports below are the system's; the page offers none of them.
	servePortMin = 1024
	serveOwnFile = "serve.json"
	// The local ports this helper serves folders on: below 32768, where
	// Linux starts handing out ports to whoever asks for any (macOS and
	// Windows start at 49152).
	serveLocalMin  = 20000
	serveLocalSpan = 10000
	// A local server's request head, and how long an idle connection stays.
	serveReadHeader = 10 * time.Second
	serveIdle       = 60 * time.Second
	// How long after start the helper keeps asking a Tailscale that is not
	// up yet about the folders it serves.
	serveSettleFor  = 15 * time.Minute
	serveSettleStep = 30 * time.Second
)

// serveItem is one handler of the serve config, as the page lists it.
type serveItem struct {
	Port  int    `json:"port"`
	Route string `json:"route"`
	// path: a folder (or a file) Tailscale serves itself. folder: one this
	// helper serves. proxy, text, tcp: the rest.
	Kind   string `json:"kind"`
	Dir    string `json:"dir,omitempty"`
	Target string `json:"target,omitempty"`
	HTTPS  bool   `json:"https,omitempty"`
	Funnel bool   `json:"funnel,omitempty"`
	// Fg: a foreground session's (tailscale serve without --bg), which ends
	// with that session and is not stopped from here.
	Fg bool `json:"fg,omitempty"`
	// What the folder holds (serveStat).
	Title string `json:"title,omitempty"`
	Files int    `json:"files,omitempty"`
	Bytes int64  `json:"bytes,omitempty"`
	More  bool   `json:"more,omitempty"`
	M     int64  `json:"m,omitempty"`
	Index bool   `json:"index,omitempty"`
	File  bool   `json:"file,omitempty"`
	Thumb string `json:"thumb,omitempty"`
	// Missing: the folder is not there (any more).
	Missing bool `json:"missing,omitempty"`
	// Down: a folder this helper serves whose local server is not running.
	Down bool `json:"down,omitempty"`
}

type serveListBody struct {
	V int `json:"v"`
	// ok, denied (the serve config may not be read), stopped, absent, error:
	// as the tailnet map's (tsview.go).
	State string `json:"state"`
	OS    string `json:"os"`
	// The machine's MagicDNS name, its first label, its first IPv4 address.
	Host  string      `json:"host,omitempty"`
	Name  string      `json:"name,omitempty"`
	IP    string      `json:"ip,omitempty"`
	Items []serveItem `json:"items"`
	Cut   bool        `json:"cut,omitempty"`
	// Where the page puts a folder it brings here: home's demos folder.
	Home string `json:"home,omitempty"`
	Root string `json:"root,omitempty"`
	At   int64  `json:"at"`
}

// serveConfDoc is as much of the serve config as is read for the list.
type serveConfDoc struct {
	TCP map[string]struct {
		HTTPS      bool
		HTTP       bool
		TCPForward string
	}
	Web map[string]struct {
		Handlers map[string]struct {
			Path  string
			Proxy string
			Text  string
		}
	}
	AllowFunnel map[string]bool
	Foreground  map[string]json.RawMessage
}

func runServeCommand(op string, arg filesArgs) (any, string) {
	ctx, cancel := context.WithTimeout(context.Background(), serveTimeout+serveScanAll)
	defer cancel()
	switch op {
	case "serve-list":
		return serveList(ctx), ""
	case "serve-add":
		it, code := serveAdd(ctx, arg.Dir, arg.Port)
		if code != "" {
			return nil, code
		}
		return it, ""
	case "serve-port":
		it, code := serveProxyAdd(ctx, arg.Port, arg.Local, arg.Addr)
		if code != "" {
			return nil, code
		}
		return it, ""
	case "serve-stop":
		if code := serveStop(ctx, arg.Port, arg.Route, arg.Dir, arg.Target); code != "" {
			return nil, code
		}
		return map[string]any{"port": arg.Port, "route": arg.Route}, ""
	}
	return nil, "unknown-op"
}

// ── reading ──────────────────────────────────────────────────────────────

// serveSelf is this machine as its Tailscale names it: the state as the
// tailnet map words it, and on "ok" the MagicDNS name and address.
func serveSelf(ctx context.Context) (state, host, ip string) {
	code, raw, err := tsLocal(ctx, http.MethodGet, "status")
	switch {
	case errors.Is(err, errTSAbsent):
		return "absent", "", ""
	case err != nil:
		return "error", "", ""
	case code == http.StatusForbidden:
		return "denied", "", ""
	case code != http.StatusOK:
		return "error", "", ""
	}
	var st tsLocalStatus
	if json.Unmarshal(raw, &st) != nil || st.Self == nil {
		return "error", "", ""
	}
	if st.BackendState != "Running" {
		return "stopped", "", ""
	}
	host = strings.TrimSuffix(st.Self.DNSName, ".")
	for _, a := range st.Self.TailscaleIPs {
		if p, err := netip.ParseAddr(a); err == nil && p.Is4() {
			ip = p.String()
			break
		}
	}
	return "ok", host, ip
}

func serveList(ctx context.Context) serveListBody {
	out := serveListBody{V: 1, OS: runtime.GOOS, Items: []serveItem{}, At: time.Now().Unix()}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out.Home = filepath.Clean(home)
		out.Root = filepath.Join(out.Home, "demos")
	}
	state, host, ip := serveSelf(ctx)
	out.State, out.Host, out.IP = state, host, ip
	if host != "" {
		out.Name, _, _ = strings.Cut(host, ".")
	}
	if state != "ok" {
		return out
	}
	code, raw, _, err := tsLocalDo(ctx, http.MethodGet, "serve-config", nil, nil)
	switch {
	case errors.Is(err, errTSAbsent):
		out.State = "absent"
		return out
	case err != nil || (code != http.StatusOK && code != http.StatusForbidden):
		out.State = "error"
		return out
	case code == http.StatusForbidden:
		out.State = "denied"
		return out
	}
	items, ok := serveItemsOf(raw, false)
	if !ok {
		out.State = "error"
		return out
	}
	own := serveOwned()
	for i := range items {
		if it := &items[i]; it.Kind == "proxy" {
			if o, ok := own[it.Port]; ok && it.Target == serveLocalURL(o.Local) {
				it.Kind, it.Dir, it.Target = "folder", o.Dir, ""
				it.Down = !serveRunning(it.Port)
			}
		}
	}
	sort.SliceStable(items, func(a, b int) bool {
		if items[a].Port != items[b].Port {
			return items[a].Port < items[b].Port
		}
		return items[a].Route < items[b].Route
	})
	if len(items) > serveItemsMax {
		items, out.Cut = items[:serveItemsMax], true
	}
	until := time.Now().Add(serveScanAll)
	for i := range items {
		if it := &items[i]; it.Dir != "" {
			serveStatInto(it, until)
		}
	}
	out.Items = items
	return out
}

// serveItemsOf is every handler of a serve config, and its foreground
// sessions' (fg). False: it is not a serve config.
func serveItemsOf(raw []byte, fg bool) ([]serveItem, bool) {
	var doc serveConfDoc
	if t := strings.TrimSpace(string(raw)); t != "" && t != "null" {
		if json.Unmarshal(raw, &doc) != nil {
			return nil, false
		}
	}
	out := []serveItem{}
	for hp, web := range doc.Web {
		port := servePortOf(hp)
		if port == 0 {
			continue
		}
		tcp := doc.TCP[strconv.Itoa(port)]
		for route, h := range web.Handlers {
			it := serveItem{Port: port, Route: route, HTTPS: tcp.HTTPS, Funnel: doc.AllowFunnel[hp], Fg: fg}
			switch {
			case h.Path != "":
				it.Kind, it.Dir = "path", filepath.Clean(h.Path)
			case h.Proxy != "":
				it.Kind, it.Target = "proxy", h.Proxy
			default:
				it.Kind = "text"
			}
			out = append(out, it)
		}
	}
	for p, tcp := range doc.TCP {
		port, err := strconv.Atoi(p)
		if err != nil || tcp.TCPForward == "" {
			continue
		}
		out = append(out, serveItem{Port: port, Kind: "tcp", Target: tcp.TCPForward, Fg: fg})
	}
	for _, sub := range doc.Foreground {
		if more, ok := serveItemsOf(sub, true); ok {
			out = append(out, more...)
		}
	}
	return out, true
}

// servePortOf is the port of a serve config's "host:port" key, 0 for one
// that is not (a service's name).
func servePortOf(hp string) int {
	i := strings.LastIndexByte(hp, ':')
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(hp[i+1:])
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// ── what a folder holds ─────────────────────────────────────────────────

type serveStatEntry struct {
	at   time.Time
	mod  time.Time
	item serveItem
}

var serveStats struct {
	sync.Mutex
	m map[string]serveStatEntry
}

var (
	serveTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	serveH1Re    = regexp.MustCompile(`(?is)<h1[^>]*>(.*?)</h1>`)
	serveTagRe   = regexp.MustCompile(`(?s)<[^>]*>`)
	serveMetaRe  = regexp.MustCompile(`(?is)<meta\s[^>]*>`)
	serveAttrRe  = regexp.MustCompile(`(?is)([a-z:-]+)\s*=\s*("[^"]*"|'[^']*')`)
	servePicRe   = regexp.MustCompile(`(?i)^(preview|cover|screenshot|thumb|thumbnail|og|og-image|social)[._-]?[^/]*\.(png|jpe?g|webp|gif|avif)$`)
	servePicExt  = regexp.MustCompile(`(?i)\.(png|jpe?g|webp|gif|avif|svg)$`)
)

// serveStatInto fills what the page shows of a folder (or a file), from a
// minute-old look while the folder itself has not changed.
func serveStatInto(it *serveItem, until time.Time) {
	fi, err := os.Stat(it.Dir)
	if err != nil {
		it.Missing = true
		return
	}
	if !fi.IsDir() {
		it.File, it.Files, it.Bytes, it.M = true, 1, fi.Size(), fi.ModTime().Unix()
		return
	}
	serveStats.Lock()
	e, ok := serveStats.m[it.Dir]
	serveStats.Unlock()
	if ok && time.Since(e.at) < serveStatTTL && e.mod.Equal(fi.ModTime()) {
		serveStatCopy(it, e.item)
		return
	}
	if time.Now().After(until) {
		it.More = true
		return
	}
	var s serveItem
	serveCount(it.Dir, &s, until)
	serveLook(it.Dir, &s)
	if s.M < fi.ModTime().Unix() {
		s.M = fi.ModTime().Unix()
	}
	serveStats.Lock()
	if serveStats.m == nil {
		serveStats.m = map[string]serveStatEntry{}
	}
	if len(serveStats.m) > 4*serveItemsMax {
		clear(serveStats.m)
	}
	serveStats.m[it.Dir] = serveStatEntry{at: time.Now(), mod: fi.ModTime(), item: s}
	serveStats.Unlock()
	serveStatCopy(it, s)
}

func serveStatCopy(it *serveItem, s serveItem) {
	it.Title, it.Files, it.Bytes, it.More, it.M, it.Index, it.Thumb = s.Title, s.Files, s.Bytes, s.More, s.M, s.Index, s.Thumb
}

// serveCount is how many files the folder holds and their bytes, its newest
// change: links not followed, .git and node_modules left out.
func serveCount(dir string, s *serveItem, until time.Time) {
	stop := time.Now().Add(serveScanTime)
	if stop.After(until) {
		stop = until
	}
	errStop := errors.New("stop")
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if s.Files >= serveScanFiles || (s.Files%256 == 0 && time.Now().After(stop)) {
			s.More = true
			return errStop
		}
		s.Files++
		if fi, err := d.Info(); err == nil {
			s.Bytes += fi.Size()
			if m := fi.ModTime().Unix(); m > s.M {
				s.M = m
			}
		}
		return nil
	})
}

// serveLook reads the folder's index.html for its title and its picture.
func serveLook(dir string, s *serveItem) {
	head := ""
	if b, ok := serveReadHead(filepath.Join(dir, "index.html")); ok {
		head = string(b)
		s.Index = true
	}
	if head != "" {
		s.Title = serveText(serveTitleRe, head)
		if s.Title == "" {
			s.Title = serveText(serveH1Re, head)
		}
		for _, m := range serveMetaRe.FindAllString(head, 20) {
			attrs := map[string]string{}
			for _, a := range serveAttrRe.FindAllStringSubmatch(m, 8) {
				attrs[strings.ToLower(a[1])] = html.UnescapeString(strings.Trim(a[2], `"'`))
			}
			if k := strings.ToLower(attrs["property"] + attrs["name"]); k == "og:image" || k == "twitter:image" {
				if p := serveInside(dir, attrs["content"]); p != "" {
					s.Thumb = p
					break
				}
			}
		}
	}
	if s.Thumb != "" {
		return
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.Type().IsRegular() && servePicRe.MatchString(e.Name()) {
			s.Thumb = filepath.Join(dir, e.Name())
			return
		}
	}
}

// serveReadHead is the start of a file that is one: not a link, a device
// or a pipe (whose open would wait for a writer).
func serveReadHead(p string) ([]byte, bool) {
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	b, _ := io.ReadAll(io.LimitReader(f, serveHeadMax))
	return b, true
}

// serveText is the first match's words: tags out, entities read, spaces
// closed, cut to serveTitleMax.
func serveText(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(serveTagRe.ReplaceAllString(m[1], " "))), " ")
	if utf8.RuneCountInString(t) > serveTitleMax {
		r := []rune(t)
		t = string(r[:serveTitleMax-1]) + "…"
	}
	return t
}

// serveInside is a picture a page names, as a path in its folder: relative,
// staying inside, there, a picture. "" for anything else (an address on the
// web is not the folder's to show).
func serveInside(dir, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.Contains(ref, "://") || strings.HasPrefix(ref, "//") || strings.HasPrefix(ref, "data:") {
		return ""
	}
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		ref = ref[:i]
	}
	p := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(ref, "/")))
	if !strings.HasPrefix(p, dir+string(filepath.Separator)) || !servePicExt.MatchString(p) {
		return ""
	}
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return p
}

// ── writing ──────────────────────────────────────────────────────────────

// serveEdit reads the serve config, lets fn change its TCP, Web and
// AllowFunnel maps (each entry as it came), and writes it back under the
// ETag it was read with: read again and tried again when someone else
// wrote in between. fn's code ends it unwritten; so does a change of
// nothing.
func serveEdit(ctx context.Context, fn func(tcp, web, funnel map[string]json.RawMessage) (bool, string)) string {
	for try := 0; try < 3; try++ {
		code, raw, hdr, err := tsLocalDo(ctx, http.MethodGet, "serve-config", nil, nil)
		if c := serveTSCode(code, err); c != "" {
			return c
		}
		top := map[string]json.RawMessage{}
		if t := strings.TrimSpace(string(raw)); t != "" && t != "null" {
			if json.Unmarshal(raw, &top) != nil {
				return "ts-error"
			}
		}
		sub := func(k string) map[string]json.RawMessage {
			m := map[string]json.RawMessage{}
			if r, ok := top[k]; ok && strings.TrimSpace(string(r)) != "null" {
				json.Unmarshal(r, &m)
			}
			return m
		}
		tcp, web, funnel := sub("TCP"), sub("Web"), sub("AllowFunnel")
		changed, c := fn(tcp, web, funnel)
		if c != "" || !changed {
			return c
		}
		for k, m := range map[string]map[string]json.RawMessage{"TCP": tcp, "Web": web, "AllowFunnel": funnel} {
			if len(m) == 0 {
				delete(top, k)
				continue
			}
			b, err := json.Marshal(m)
			if err != nil {
				return "ts-error"
			}
			top[k] = b
		}
		body, err := json.Marshal(top)
		if err != nil {
			return "ts-error"
		}
		h := map[string]string{"Content-Type": "application/json"}
		if hdr != nil && hdr.Get("Etag") != "" {
			h["If-Match"] = hdr.Get("Etag")
		}
		code, _, _, err = tsLocalDo(ctx, http.MethodPost, "serve-config", body, h)
		if code == http.StatusPreconditionFailed {
			continue
		}
		return serveTSCode(code, err)
	}
	return "ts-busy"
}

// serveTSCode is a LocalAPI answer as the page reads it. ts-denied: this
// user may not change Tailscale's settings (Linux: not its operator).
// ts-admin: the serve config holds a folder Tailscale serves itself, and
// only root or an operator who may run sudo tailscale may write such a one.
func serveTSCode(code int, err error) string {
	switch {
	case errors.Is(err, errTSAbsent):
		return "ts-absent"
	case err != nil:
		return "ts-error"
	case code == http.StatusOK:
		return ""
	case code == http.StatusForbidden:
		return "ts-denied"
	case code == http.StatusUnauthorized:
		return "ts-admin"
	}
	return "ts-error"
}

func serveLocalURL(port int) string { return "http://127.0.0.1:" + strconv.Itoa(port) }

// serveAdd serves a folder on a port of the tailnet.
func serveAdd(ctx context.Context, dirRaw string, port int) (serveItem, string) {
	dir, code := musicPathArg(dirRaw)
	if code != "" {
		return serveItem{}, code
	}
	// The folder a link leads to is the one checked and served.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return serveItem{}, musicFolderErr(dir, err)
	}
	dir = real
	fi, err := os.Stat(dir)
	if err != nil {
		return serveItem{}, musicFolderErr(dir, err)
	}
	if !fi.IsDir() {
		return serveItem{}, "not-a-folder"
	}
	if filesTooBroad(dir) {
		return serveItem{}, "too-broad"
	}
	if port < servePortMin || port > 65535 || port == tailnetPort {
		return serveItem{}, "bad-port"
	}
	state, host, _ := serveSelf(ctx)
	if state != "ok" {
		return serveItem{}, "ts-" + state
	}
	if host == "" {
		return serveItem{}, "ts-no-name"
	}
	serveOwn.Lock()
	defer serveOwn.Unlock()
	if _, ok := serveOwn.run[port]; ok {
		return serveItem{}, "port-taken"
	}
	ln, local, err := serveListenLocal(0, port)
	if err != nil {
		return serveItem{}, "no-listen"
	}
	run, code := serveRunOn(dir, ln)
	if code != "" {
		ln.Close()
		return serveItem{}, code
	}
	hp := host + ":" + strconv.Itoa(port)
	code = serveEdit(ctx, func(tcp, web, _ map[string]json.RawMessage) (bool, string) {
		if _, ok := tcp[strconv.Itoa(port)]; ok {
			return false, "port-taken"
		}
		for k := range web {
			if servePortOf(k) == port {
				return false, "port-taken"
			}
		}
		tcp[strconv.Itoa(port)] = json.RawMessage(`{"HTTP":true}`)
		h, _ := json.Marshal(map[string]any{"Handlers": map[string]any{"/": map[string]string{"Proxy": serveLocalURL(local)}}})
		web[hp] = h
		return true, ""
	})
	if code != "" {
		run.stop()
		return serveItem{}, code
	}
	serveOwn.run[port] = run
	serveOwn.items[port] = serveOwnItem{Port: port, Dir: dir, Local: local}
	serveOwnSave()
	it := serveItem{Port: port, Route: "/", Kind: "folder", Dir: dir}
	serveStatInto(&it, time.Now().Add(serveScanAll))
	return it, ""
}

// serveProxyAdd serves on a port of the tailnet what a program here serves
// on the local port (the Ports view's Serve on the tailnet): the serve
// config proxies the tailnet port to it, on 127.0.0.1 or ::1, whichever it
// answers on.
func serveProxyAdd(ctx context.Context, port, local int, addr string) (serveItem, string) {
	if port < servePortMin || port > 65535 || port == tailnetPort || local < 1 || local > 65535 {
		return serveItem{}, "bad-port"
	}
	hosts, code := serveProxyHosts(addr)
	if code != "" {
		return serveItem{}, code
	}
	target, answered := "", false
	for _, h := range hosts {
		hp := net.JoinHostPort(h, strconv.Itoa(local))
		ok, open := serveAnswersHTTP(ctx, hp)
		answered = answered || open
		if ok {
			target = "http://" + hp
			break
		}
	}
	if target == "" {
		if answered {
			return serveItem{}, "not-http"
		}
		return serveItem{}, "not-listening"
	}
	state, host, _ := serveSelf(ctx)
	if state != "ok" {
		return serveItem{}, "ts-" + state
	}
	if host == "" {
		return serveItem{}, "ts-no-name"
	}
	serveOwn.Lock()
	defer serveOwn.Unlock()
	if _, ok := serveOwn.run[port]; ok {
		return serveItem{}, "port-taken"
	}
	hp := host + ":" + strconv.Itoa(port)
	code = serveEdit(ctx, func(tcp, web, _ map[string]json.RawMessage) (bool, string) {
		if _, ok := tcp[strconv.Itoa(port)]; ok {
			return false, "port-taken"
		}
		for k := range web {
			if servePortOf(k) == port {
				return false, "port-taken"
			}
		}
		tcp[strconv.Itoa(port)] = json.RawMessage(`{"HTTP":true}`)
		h, _ := json.Marshal(map[string]any{"Handlers": map[string]any{"/": map[string]string{"Proxy": target}}})
		web[hp] = h
		return true, ""
	})
	if code != "" {
		return serveItem{}, code
	}
	return serveItem{Port: port, Route: "/", Kind: "proxy", Target: target}, ""
}

// serveProxyHosts: where the program listening on addr is reached from
// here. Its own address when it listens on one of this computer's, the
// loopback of its family when on every address; none given (a page from
// before addr), IPv4's loopback then IPv6's. Any other address is refused:
// the proxy reaches this computer's programs, not another computer.
func serveProxyHosts(addr string) ([]string, string) {
	switch addr {
	case "":
		return []string{"127.0.0.1", "::1"}, ""
	case "*", "0.0.0.0":
		return []string{"127.0.0.1"}, ""
	case "::":
		return []string{"::1", "127.0.0.1"}, ""
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, "bad-args"
	}
	if ip.IsLoopback() {
		return []string{ip.String()}, ""
	}
	if as, err := net.InterfaceAddrs(); err == nil {
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return []string{ip.String()}, ""
			}
		}
	}
	return nil, "bad-args"
}

// serveAnswersHTTP: whether hp takes a connection (open), and answers a
// HEAD request as an HTTP server does (ok). An SSH or database port, or
// one that speaks only TLS, is open but not ok.
func serveAnswersHTTP(ctx context.Context, hp string) (ok, open bool) {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "tcp", hp)
	if err != nil {
		return false, false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + hp + "\r\nUser-Agent: subnsub-helper\r\n\r\n")); err != nil {
		return false, true
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		return false, true
	}
	return string(buf) == "HTTP/", true
}

// serveStop takes off the serve config the handler on route of the port,
// the port with it when no other handler is left there; with no route,
// every handler on the port. dir or target, when given, is what that
// handler must still serve (a folder, a proxy's address): "changed" when it
// serves something else now, nothing taken off. This helper's own server
// there stops when its handler goes.
func serveStop(ctx context.Context, port int, route, dir, target string) string {
	if port < 1 || port > 65535 {
		return "bad-port"
	}
	p := strconv.Itoa(port)
	serveOwn.Lock()
	defer serveOwn.Unlock()
	own, mine := serveOwn.items[port]
	ownURL := ""
	if mine {
		ownURL = serveLocalURL(own.Local)
	}
	// This helper keeps the folder a link led to.
	dirReal := dir
	if r, err := filepath.EvalSymlinks(dir); dir != "" && err == nil {
		dirReal = r
	}
	dropOwn := false
	code := serveEdit(ctx, func(tcp, web, funnel map[string]json.RawMessage) (bool, string) {
		dropOwn = false
		found, left := false, false
		if route == "" {
			if _, ok := tcp[p]; ok {
				delete(tcp, p)
				found = true
			}
		}
		for k, raw := range web {
			if servePortOf(k) != port {
				continue
			}
			if route == "" {
				delete(web, k)
				found, dropOwn = true, mine
				continue
			}
			entry, hs, ok := serveHandlers(raw)
			if !ok {
				return false, "ts-error"
			}
			h, ok := hs[route]
			if !ok {
				left = left || len(hs) > 0
				continue
			}
			var was struct{ Path, Proxy string }
			json.Unmarshal(h, &was)
			isOwn := mine && was.Proxy == ownURL
			if dir != "" && !(was.Path != "" && filepath.Clean(was.Path) == filepath.Clean(dir)) && !(isOwn && (own.Dir == dir || own.Dir == dirReal)) {
				return false, "changed"
			}
			if target != "" && was.Proxy != target {
				return false, "changed"
			}
			found, dropOwn = true, dropOwn || isOwn
			delete(hs, route)
			if len(hs) == 0 {
				delete(web, k)
				continue
			}
			left = true
			web[k] = serveHandlersPut(entry, hs)
		}
		if !found {
			return false, "not-served"
		}
		if !left {
			delete(tcp, p)
			for k := range funnel {
				if servePortOf(k) == port {
					delete(funnel, k)
				}
			}
		}
		return true, ""
	})
	if code == "not-served" && serveForeground(ctx, port) {
		return "foreground"
	}
	if code == "not-served" && mine && (route == "" || route == "/") {
		// Taken off by someone else already: this helper's server there
		// stops all the same.
		dropOwn = true
	}
	if code != "" && code != "not-served" {
		return code
	}
	if dropOwn {
		serveOwn.run[port].stop()
		delete(serveOwn.run, port)
		delete(serveOwn.items, port)
		serveOwnSave()
		return ""
	}
	return code
}

// serveHandlers is a web entry of the serve config, and its handlers by
// route, each as it came.
func serveHandlers(raw json.RawMessage) (map[string]json.RawMessage, map[string]json.RawMessage, bool) {
	var entry, hs map[string]json.RawMessage
	if json.Unmarshal(raw, &entry) != nil {
		return nil, nil, false
	}
	if entry == nil {
		entry = map[string]json.RawMessage{}
	}
	if b := entry["Handlers"]; len(b) > 0 {
		if json.Unmarshal(b, &hs) != nil {
			return nil, nil, false
		}
	}
	if hs == nil {
		hs = map[string]json.RawMessage{}
	}
	return entry, hs, true
}

// serveHandlersPut is the entry again with these handlers.
func serveHandlersPut(entry, hs map[string]json.RawMessage) json.RawMessage {
	entry["Handlers"], _ = json.Marshal(hs)
	b, _ := json.Marshal(entry)
	return b
}

// serveRepoint points the port's "/" from one local server of this helper
// to another, while it still points at the first; the rest of the entry
// (other routes, its other fields) stays as it was.
func serveRepoint(ctx context.Context, port int, from, to string) string {
	return serveEdit(ctx, func(_, web, _ map[string]json.RawMessage) (bool, string) {
		for k, raw := range web {
			if servePortOf(k) != port {
				continue
			}
			entry, hs, ok := serveHandlers(raw)
			if !ok {
				return false, "ts-error"
			}
			var h map[string]json.RawMessage
			if json.Unmarshal(hs["/"], &h) != nil || h == nil {
				continue
			}
			var was string
			if json.Unmarshal(h["Proxy"], &was) != nil || was != from {
				continue
			}
			h["Proxy"], _ = json.Marshal(to)
			hs["/"], _ = json.Marshal(h)
			web[k] = serveHandlersPut(entry, hs)
			return true, ""
		}
		return false, "changed"
	})
}

// serveListenLocal is a listener on 127.0.0.1 for the folder served on a
// tailnet port: on want when that is free, else on a port of serveLocalMin's
// span, tried from one the tailnet port picks. Below the range systems hand
// out to a program that asks for any port, so that while this helper is
// away the port Tailscale proxies to is not one some other program was
// given by chance.
func serveListenLocal(want, port int) (net.Listener, int, error) {
	try := func(p int) (net.Listener, int, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			return nil, 0, err
		}
		return ln, ln.Addr().(*net.TCPAddr).Port, nil
	}
	if want > 0 {
		if ln, p, err := try(want); err == nil {
			return ln, p, nil
		}
	}
	var last error
	for i := 0; i < serveLocalSpan; i++ {
		ln, p, err := try(serveLocalMin + (port+i)%serveLocalSpan)
		if err == nil {
			return ln, p, nil
		}
		last = err
	}
	return nil, 0, last
}

// serveForeground: a foreground session serves the port.
func serveForeground(ctx context.Context, port int) bool {
	code, raw, _, err := tsLocalDo(ctx, http.MethodGet, "serve-config", nil, nil)
	if err != nil || code != http.StatusOK {
		return false
	}
	items, _ := serveItemsOf(raw, false)
	for _, it := range items {
		if it.Fg && it.Port == port {
			return true
		}
	}
	return false
}

// ── the folders this helper serves ──────────────────────────────────────

type serveOwnItem struct {
	Port  int    `json:"port"`
	Dir   string `json:"dir"`
	Local int    `json:"local"`
}

type serveRun struct {
	srv *http.Server
}

func (r *serveRun) stop() {
	if r != nil && r.srv != nil {
		r.srv.Close()
	}
}

var serveOwn = struct {
	sync.Mutex
	items map[int]serveOwnItem
	run   map[int]*serveRun
}{items: map[int]serveOwnItem{}, run: map[int]*serveRun{}}

// serveOwned is a copy of the folders this helper serves, by port.
func serveOwned() map[int]serveOwnItem {
	serveOwn.Lock()
	defer serveOwn.Unlock()
	out := make(map[int]serveOwnItem, len(serveOwn.items))
	for k, v := range serveOwn.items {
		out[k] = v
	}
	return out
}

func serveRunning(port int) bool {
	serveOwn.Lock()
	defer serveOwn.Unlock()
	return serveOwn.run[port] != nil
}

func serveOwnPath() string {
	if d := configDir(); d != "" {
		return filepath.Join(d, serveOwnFile)
	}
	return ""
}

// serveOwnSave writes the list; the caller holds the lock.
func serveOwnSave() {
	path := serveOwnPath()
	if path == "" {
		return
	}
	list := make([]serveOwnItem, 0, len(serveOwn.items))
	for _, v := range serveOwn.items {
		list = append(list, v)
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Port < list[b].Port })
	b, err := json.Marshal(map[string]any{"v": 1, "items": list})
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := writeFileAtomic(path, append(b, '\n')); err != nil {
		warnf("serve: could not keep the list of served folders: %v", err)
	}
}

// serveRunOn serves a folder on a listener, read through serveFS.
func serveRunOn(dir string, ln net.Listener) (*serveRun, string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, musicFolderErr(dir, err)
	}
	files := http.FileServerFS(serveFS{root})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		for _, seg := range strings.Split(r.URL.Path, "/") {
			if strings.HasPrefix(seg, ".") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		files.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: serveReadHeader, IdleTimeout: serveIdle}
	go func() {
		srv.Serve(ln)
		root.Close()
	}()
	return &serveRun{srv: srv}, ""
}

// serveFS is a served folder as its server reads it: through an os.Root, so
// nothing outside it; nothing whose name starts with a dot; no link
// followed, even to a file inside; only folders and plain files (a pipe's
// open would wait); a folder's list without what it would not serve.
type serveFS struct{ root *os.Root }

func (s serveFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name != "." {
		parts := strings.Split(name, "/")
		for i, part := range parts {
			gone := &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
			if strings.HasPrefix(part, ".") {
				return nil, gone
			}
			fi, err := s.root.Lstat(strings.Join(parts[:i+1], "/"))
			if err != nil {
				return nil, err
			}
			if !fi.IsDir() && (i < len(parts)-1 || !fi.Mode().IsRegular()) {
				return nil, gone
			}
		}
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	return serveFile{f}, nil
}

type serveFile struct{ *os.File }

func (f serveFile) ReadDir(n int) ([]fs.DirEntry, error) {
	for {
		ents, err := f.File.ReadDir(n)
		out := ents[:0]
		for _, e := range ents {
			if !strings.HasPrefix(e.Name(), ".") && (e.IsDir() || e.Type().IsRegular()) {
				out = append(out, e)
			}
		}
		if len(out) > 0 || err != nil || n <= 0 {
			return out, err
		}
	}
}

// serveStart serves again the folders kept in serve.json, each on its local
// port where that is free (else on a new one, the serve config told), and
// forgets those whose port is no longer in the serve config once Tailscale
// is up to say so.
func serveStart(ctx context.Context) {
	path := serveOwnPath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc struct {
		Items []serveOwnItem `json:"items"`
	}
	if json.Unmarshal(b, &doc) != nil {
		warnf("serve: %s is not readable; the folders in it are not served", path)
		return
	}
	// A folder served again on another local port than before, by its
	// tailnet port: the local port it had.
	moved := map[int]int{}
	serveOwn.Lock()
	for _, it := range doc.Items {
		if it.Port < servePortMin || it.Port > 65535 || it.Dir == "" || !filepath.IsAbs(it.Dir) {
			continue
		}
		// Checked again as it is now: a folder that has become a link to
		// one too broad is not served.
		if real, err := filepath.EvalSymlinks(it.Dir); err == nil && filesTooBroad(real) {
			warnf("serve: %s is not served on port %d: too-broad", it.Dir, it.Port)
			serveOwn.items[it.Port] = it
			continue
		}
		ln, local, err := serveListenLocal(it.Local, it.Port)
		if err != nil {
			serveOwn.items[it.Port] = it
			continue
		}
		if local != it.Local {
			moved[it.Port] = it.Local
			it.Local = local
		}
		run, code := serveRunOn(it.Dir, ln)
		if code != "" {
			ln.Close()
			warnf("serve: %s is not served on port %d: %s", it.Dir, it.Port, code)
			serveOwn.items[it.Port] = it
			continue
		}
		serveOwn.items[it.Port] = it
		serveOwn.run[it.Port] = run
	}
	serveOwn.Unlock()
	go serveSettle(ctx, moved)
}

// serveSettle squares the kept list with the serve config once Tailscale
// answers: a folder whose port someone took away is forgotten, one served on
// a new local port is pointed at it.
func serveSettle(ctx context.Context, moved map[int]int) {
	deadline := time.Now().Add(serveSettleFor)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		c, cancel := context.WithTimeout(ctx, serveTimeout)
		done := serveSettleOnce(c, moved)
		cancel()
		if done {
			return
		}
		if !sleepCtx(ctx, serveSettleStep) {
			return
		}
	}
}

func serveSettleOnce(ctx context.Context, moved map[int]int) bool {
	state, host, _ := serveSelf(ctx)
	if state != "ok" || host == "" {
		return state == "denied"
	}
	// Held from the read on, so that a folder added meanwhile is not taken
	// for one someone took away.
	serveOwn.Lock()
	defer serveOwn.Unlock()
	code, raw, _, err := tsLocalDo(ctx, http.MethodGet, "serve-config", nil, nil)
	if err != nil || code != http.StatusOK {
		return code == http.StatusForbidden
	}
	items, ok := serveItemsOf(raw, false)
	if !ok {
		return true
	}
	at := map[int]string{}
	for _, it := range items {
		if it.Kind == "proxy" && it.Route == "/" && !it.Fg {
			at[it.Port] = it.Target
		}
	}
	changed, done := false, true
	for port, it := range serveOwn.items {
		target, ok := at[port]
		switch {
		case ok && target == serveLocalURL(it.Local):
		case ok && moved[port] != 0 && target == serveLocalURL(moved[port]):
			// Served again on another local port than the one Tailscale
			// proxies to: pointed at the new one, and kept so once it is.
			if serveRepoint(ctx, port, target, serveLocalURL(it.Local)) == "" {
				delete(moved, port)
				changed = true
			} else {
				done = false
			}
		default:
			// Taken off the serve config while this helper was away, or
			// pointed elsewhere by someone: not this helper's any more.
			serveOwn.run[port].stop()
			delete(serveOwn.run, port)
			delete(serveOwn.items, port)
			changed = true
		}
	}
	if changed {
		serveOwnSave()
	}
	return done
}
