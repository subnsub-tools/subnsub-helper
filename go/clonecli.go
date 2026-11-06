package main

/* ── the command line's half of a portable copy ─────────────────────────

   The dashboard's "Create and copy" puts one line on the clipboard, smc1.…:
   the copy's two private keys, the certificate the dashboard signed for them
   (clone.go), and the tailcat address of every machine it covers. That line
   is the whole copy, and it is a password until it expires.

     subnsub-helper clone use [line | -]   keep it here (clone-access, 0600);
                                            no line, or "-", reads it from stdin
     subnsub-helper clone                  what it is, until when, which machines
     subnsub-helper clone forget           delete it
     subnsub-helper run <machine> [--] <command…>
     subnsub-helper shell <machine>

   SUBNSUB_CLONE=<line> stands in for the kept file, for one-off use.

   run and shell reach the machine exactly as the dashboard's console does:
   over tailcat to the helper's port inside the tunnel, a command signed with
   the copy's key (`sh` for run, `pty` for shell, then the terminal's own
   streams). Nothing passes through our relay, and nothing here needs a
   Monitor account or this computer to run a helper of its own. */

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"

	"github.com/tailscale/tailcat"
	"golang.org/x/term"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	cloneBlobPrefix = "smc1."
	cloneAccessFile = "clone-access"
	cloneEnvVar     = "SUBNSUB_CLONE"
	cloneBlobMax    = 64 << 10
	// How long to wait for the machine's hello: the tunnel's own handshake
	// through a DERP relay, the first time, takes a few seconds.
	cloneHelloWait = 30 * time.Second
	// A console line runs for at most thirty seconds at the machine.
	cloneRunWait = 50 * time.Second
	// The terminal's heartbeat: the machine ends a session nobody has shown a
	// sign of life on for three minutes (pty.go ptyQuietMax).
	cloneBeat = 60 * time.Second
)

type cloneMachine struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Addr string `json:"addr"`
}

type cloneBlob struct {
	V        int            `json:"v"`
	Cert     string         `json:"cert"`
	SK       string         `json:"sk"` // the Ed25519 seed, base64, 32 bytes
	NK       string         `json:"nk"` // privkey:<hex>
	Machines []cloneMachine `json:"machines"`
}

type cloneAccess struct {
	blob cloneBlob
	cert cloneCert
	sign ed25519.PrivateKey
	node key.NodePrivate
}

func parseCloneBlob(s string) (cloneAccess, error) {
	var a cloneAccess
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, cloneBlobPrefix) || len(s) > cloneBlobMax {
		return a, errors.New("not a portable copy (it starts with " + cloneBlobPrefix + ")")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[len(cloneBlobPrefix):])
	if err != nil {
		return a, errors.New("the copy is damaged (not base64url) — copy it again")
	}
	if err := json.Unmarshal(raw, &a.blob); err != nil || a.blob.V != 1 {
		return a, errors.New("the copy is damaged or from a newer dashboard")
	}
	cert, ok := parseCloneCert(a.blob.Cert)
	if !ok {
		return a, errors.New("the copy's certificate is malformed")
	}
	a.cert = cert
	seed, err := base64.StdEncoding.DecodeString(a.blob.SK)
	if err != nil || len(seed) != ed25519.SeedSize {
		return a, errors.New("the copy's signing key is malformed")
	}
	a.sign = ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(a.sign.Public().(ed25519.PublicKey)) != cert.SK {
		return a, errors.New("the copy's signing key does not match its certificate")
	}
	if err := a.node.UnmarshalText([]byte(a.blob.NK)); err != nil {
		return a, errors.New("the copy's tunnel key is malformed")
	}
	if pub, _ := a.node.Public().MarshalText(); string(pub) != cert.NK {
		return a, errors.New("the copy's tunnel key does not match its certificate")
	}
	if len(a.blob.Machines) == 0 {
		return a, errors.New("the copy names no machine")
	}
	for _, m := range a.blob.Machines {
		if !cloneAgentRe.MatchString(m.ID) || !strings.HasPrefix(m.Addr, "tc") || len(m.Addr) > 4096 || len(m.Name) > 200 {
			return a, errors.New("the copy's machine list is malformed")
		}
	}
	return a, nil
}

func cloneAccessPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, cloneAccessFile)
}

func loadCloneAccess() (cloneAccess, error) {
	if s := os.Getenv(cloneEnvVar); strings.TrimSpace(s) != "" {
		return parseCloneBlob(s)
	}
	path := cloneAccessPath()
	if path == "" {
		return cloneAccess{}, errors.New("no config directory")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cloneAccess{}, errors.New("no portable copy here — on the Monitor page press Create and copy (Manage → Copies), then: subnsub-helper clone use")
		}
		return cloneAccess{}, err
	}
	return parseCloneBlob(string(b))
}

func (a cloneAccess) expires() time.Time { return time.Unix(a.cert.EXP, 0) }

func (a cloneAccess) name(m cloneMachine) string {
	if m.Name != "" {
		return m.Name
	}
	return m.ID
}

// machine finds one by its id, then by its name (any case), then by a
// prefix of either — and refuses to choose between two: a command run on the
// wrong machine is the one mistake this must never make quietly (review
// 2026-10-17).
func (a cloneAccess) machine(q string) (cloneMachine, error) {
	ms := a.blob.Machines
	for _, m := range ms {
		if m.ID == q {
			return m, nil
		}
	}
	var hit []cloneMachine
	for _, m := range ms {
		if q != "" && strings.EqualFold(m.Name, q) {
			hit = append(hit, m)
		}
	}
	if len(hit) == 0 {
		lq := strings.ToLower(q)
		for _, m := range ms {
			if q != "" && (strings.HasPrefix(strings.ToLower(m.Name), lq) || strings.HasPrefix(m.ID, q)) {
				hit = append(hit, m)
			}
		}
	}
	if len(hit) == 1 {
		return hit[0], nil
	}
	var names []string
	for _, m := range ms {
		names = append(names, a.name(m))
	}
	if len(hit) > 1 {
		return cloneMachine{}, fmt.Errorf("%q matches more than one machine: %s", q, strings.Join(names, ", "))
	}
	return cloneMachine{}, fmt.Errorf("no machine %q in this copy; it covers: %s", q, strings.Join(names, ", "))
}

func humanLeft(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	switch {
	case h >= 48:
		return fmt.Sprintf("%dd %dh left", h/24, h%24)
	case h > 0:
		return fmt.Sprintf("%dh %dm left", h, m)
	default:
		return fmt.Sprintf("%dm left", m)
	}
}

func printCloneSummary(a cloneAccess) {
	label := a.cert.Label
	if label == "" {
		label = "(no label)"
	}
	fmt.Printf("portable copy %s  %s\n", a.cert.ID, label)
	fmt.Printf("good until %s (%s); may run: %s\n", a.expires().Local().Format("2006-01-02 15:04 MST"), humanLeft(time.Until(a.expires())), a.cert.Caps)
	for _, m := range a.blob.Machines {
		fmt.Printf("  %-16s %s\n", a.name(m), m.ID)
	}
}

func runCloneCLI(args []string) int {
	verb := ""
	if len(args) > 0 {
		verb = args[0]
	}
	switch verb {
	case "", "show":
		a, err := loadCloneAccess()
		if err != nil {
			warnf("%v", err)
			return 1
		}
		printCloneSummary(a)
		return 0
	case "use":
		var line string
		if len(args) >= 2 && args[1] != "-" {
			line = args[1]
		} else {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, cloneBlobMax+1))
			if err != nil {
				warnf("could not read the copy from stdin: %v", err)
				return 1
			}
			line = string(b)
		}
		a, err := parseCloneBlob(line)
		if err != nil {
			warnf("%v", err)
			return 1
		}
		if !time.Now().Before(a.expires()) {
			warnf("that copy has already expired; make a new one on the Monitor page")
			return 1
		}
		path := cloneAccessPath()
		if path == "" {
			warnf("no config directory to keep it in")
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			warnf("%v", err)
			return 1
		}
		tmp := path + ".new"
		if err := os.WriteFile(tmp, []byte(strings.TrimSpace(line)+"\n"), 0o600); err != nil {
			warnf("%v", err)
			return 1
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			warnf("%v", err)
			return 1
		}
		printCloneSummary(a)
		fmt.Println("kept in " + path + " — try: subnsub-helper run <machine> -- uname -a")
		return 0
	case "forget":
		path := cloneAccessPath()
		if path != "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				warnf("%v", err)
				return 1
			}
		}
		fmt.Println("forgotten")
		return 0
	}
	warnf("usage: subnsub-helper clone [use <line>|-] | clone forget")
	return 2
}

/* ── reaching one machine ─────────────────────────────────────────────── */

type cloneConn struct {
	a  cloneAccess
	m  cloneMachine
	cl *tailcat.Client
	hc *http.Client
}

func dialCloneMachine(ctx context.Context, a cloneAccess, m cloneMachine) (*cloneConn, error) {
	if !time.Now().Before(a.expires()) {
		return nil, errors.New("this portable copy has expired; make a new one on the Monitor page")
	}
	cl := &tailcat.Client{Server: tailcat.ConnBlob(m.Addr), Key: a.node, Logf: logger.Discard}
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return cl.DialTCPPort(ctx, directPort)
		},
		MaxIdleConnsPerHost: 4,
	}}
	c := &cloneConn{a: a, m: m, cl: cl, hc: hc}
	hctx, cancel := context.WithTimeout(ctx, cloneHelloWait)
	defer cancel()
	f, err := c.get(hctx, "/v1/hello")
	if err != nil {
		cl.Close()
		if hctx.Err() != nil {
			return nil, fmt.Errorf("%s did not answer over tailcat within %s — it is offline, its address changed since the copy was made, or it has not admitted this copy yet (keep the Monitor page open so it can tell the machine)", a.name(m), cloneHelloWait)
		}
		return nil, fmt.Errorf("%s: %v", a.name(m), err)
	}
	if f.Type == transport.TypeError {
		cl.Close()
		var e transport.Error
		json.Unmarshal(f.Body, &e)
		return nil, fmt.Errorf("%s refused this copy (%s)", a.name(m), e.Code)
	}
	if f.AgentID != m.ID {
		cl.Close()
		return nil, fmt.Errorf("the machine at that address is not %s any more — make a new copy", a.name(m))
	}
	return c, nil
}

func (c *cloneConn) Close() { c.cl.Close() }

func (c *cloneConn) url(path string) string { return "http://tailcat" + path }

func (c *cloneConn) get(ctx context.Context, path string) (transport.Frame, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return transport.Frame{}, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return transport.Frame{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return transport.Frame{}, err
	}
	return transport.Decode(b)
}

func newCloneCmdID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// command sends one signed command and returns the machine's result.
func (c *cloneConn) command(ctx context.Context, kind, cmd, target string) (consoleResult, error) {
	id := newCloneCmdID()
	at := time.Now().Unix()
	sig := ed25519.Sign(c.a.sign, commandSigningInput(c.m.ID, id, kind, target, at, cmd))
	f, err := transport.New(transport.TypeCommand, c.m.ID, id, transport.Command{
		Kind: kind, Cmd: cmd, Target: target, Sig: base64.StdEncoding.EncodeToString(sig), At: at,
	})
	if err != nil {
		return consoleResult{}, err
	}
	body, err := transport.Encode(f)
	if err != nil {
		return consoleResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/v1/command"), strings.NewReader(string(body)))
	if err != nil {
		return consoleResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return consoleResult{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return consoleResult{}, err
	}
	out, err := transport.Decode(b)
	if err != nil {
		return consoleResult{}, fmt.Errorf("unreadable answer (%d)", resp.StatusCode)
	}
	if out.Type == transport.TypeError {
		var e transport.Error
		json.Unmarshal(out.Body, &e)
		return consoleResult{}, errors.New(e.Code)
	}
	var res consoleResult
	if err := json.Unmarshal(out.Body, &res); err != nil {
		return consoleResult{}, err
	}
	return res, nil
}

func cloneRefusal(code string) string {
	switch code {
	case "console-off":
		return "the console is off on that machine (subnsub-helper console on, there)"
	case "clone-not-allowed":
		return "this copy may not do that"
	case "clone-expired":
		return "this copy has expired or was revoked on that machine"
	case "bad-signature", "unsigned", "unpinned":
		return "that machine does not accept this copy (" + code + ") — it may have been revoked, or the dashboard key that made it is no longer trusted there"
	case "stale-command":
		return "that machine's clock and this one disagree by more than five minutes"
	case "busy":
		return "that machine is busy with another command; try again"
	case "pty-unsupported":
		return "that machine has no terminals (Windows helper)"
	}
	return code
}

func cloneTarget(args []string) (cloneAccess, cloneMachine, []string, bool) {
	a, err := loadCloneAccess()
	if err != nil {
		warnf("%v", err)
		return a, cloneMachine{}, nil, false
	}
	if len(args) == 0 {
		warnf("say which machine — this copy covers:")
		for _, m := range a.blob.Machines {
			warnf("  %s", a.name(m))
		}
		return a, cloneMachine{}, nil, false
	}
	m, err := a.machine(args[0])
	if err != nil {
		warnf("%v", err)
		return a, m, nil, false
	}
	return a, m, args[1:], true
}

// run: one console line, its output, its exit status. The machine runs it
// as /bin/sh -c for at most thirty seconds and returns at most sixteen
// kilobytes, as the dashboard's console does.
func runRunCLI(args []string) int {
	a, m, rest, ok := cloneTarget(args)
	if !ok {
		return 2
	}
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	line := strings.Join(rest, " ")
	if strings.TrimSpace(line) == "" {
		warnf("usage: subnsub-helper run <machine> [--] <command…>")
		return 2
	}
	if len(line) > 2000 {
		warnf("that command is longer than the 2000 characters a console line may be")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), cloneRunWait+cloneHelloWait)
	defer cancel()
	c, err := dialCloneMachine(ctx, a, m)
	if err != nil {
		warnf("%v", err)
		return 255
	}
	defer c.Close()
	res, err := c.command(ctx, "sh", line, "")
	if err != nil {
		warnf("%s: %s", a.name(m), cloneRefusal(err.Error()))
		return 255
	}
	if res.Error != "" {
		os.Stdout.WriteString(res.Out)
		warnf("%s: %s", a.name(m), cloneRefusal(res.Error))
		return 255
	}
	os.Stdout.WriteString(res.Out)
	if res.Truncated {
		warnf("(output cut at the console's limit)")
	}
	if res.Code < 0 || res.Code > 254 {
		return 1
	}
	return res.Code
}

// shell: a terminal, as the dashboard opens one, attached to this one.
func runShellCLI(args []string) int {
	a, m, rest, ok := cloneTarget(args)
	if !ok {
		return 2
	}
	if len(rest) > 0 {
		warnf("shell takes no command — use: subnsub-helper run %s -- …", args[0])
		return 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dctx, dcancel := context.WithTimeout(ctx, cloneHelloWait)
	c, err := dialCloneMachine(dctx, a, m)
	dcancel()
	if err != nil {
		warnf("%v", err)
		return 255
	}
	defer c.Close()

	in := int(os.Stdin.Fd())
	tty := term.IsTerminal(in)
	cols, rows := 80, 24
	if tty {
		if w, h, err := term.GetSize(in); err == nil && w > 1 && h > 1 {
			cols, rows = min(w, ptyMaxCols), min(h, ptyMaxRows)
		}
	}
	octx, ocancel := context.WithTimeout(ctx, cloneRunWait)
	res, err := c.command(octx, "pty", "", fmt.Sprintf("%dx%d", cols, rows))
	ocancel()
	if err == nil && res.Error != "" {
		err = errors.New(res.Error)
	}
	if err != nil {
		warnf("%s: %s", a.name(m), cloneRefusal(err.Error()))
		return 255
	}
	tok := res.Out
	q := "?s=" + tok
	post := func(path string, body io.Reader) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), body)
		if err != nil {
			return
		}
		if resp, err := c.hc.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	if tty {
		if old, err := term.MakeRaw(in); err == nil {
			defer term.Restore(in, old)
		}
	}
	// Out: until the machine ends the session. Attached BEFORE a keystroke
	// is sent: a shell fed from a pipe can run its input and exit before a
	// late reader asks, and the session — output and all — is gone by then
	// (2026-10-17: `printf '…; exit' | shell` printed nothing).
	done := make(chan struct{})
	ready := make(chan struct{})
	var readyOnce sync.Once
	markReady := func() { readyOnce.Do(func() { close(ready) }) }
	go func() {
		defer close(done)
		defer markReady()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/pty/out"+q), nil)
		if err != nil {
			return
		}
		resp, err := c.hc.Do(req)
		markReady()
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			io.Copy(os.Stdout, resp.Body)
		}
	}()
	select {
	case <-ready:
	case <-done:
	}
	// In: one long body, fed by the keyboard.
	pr, pw := io.Pipe()
	go post("/v1/pty/in"+q, pr)
	go func() {
		io.Copy(pw, os.Stdin)
		pw.Close()
	}()
	// The window's size, and the heartbeat that keeps the session.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		beat := time.Now()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			w, h := cols, rows
			if tty {
				if nw, nh, err := term.GetSize(in); err == nil && nw > 1 && nh > 1 {
					w, h = min(nw, ptyMaxCols), min(nh, ptyMaxRows)
				}
			}
			if w != cols || h != rows || time.Since(beat) > cloneBeat {
				cols, rows, beat = w, h, time.Now()
				post(fmt.Sprintf("/v1/pty/resize%s&c=%d&r=%d", q, cols, rows), nil)
			}
		}
	}()
	<-done
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	if req, err := http.NewRequestWithContext(cctx, http.MethodPost, c.url("/v1/pty/close"+q), nil); err == nil {
		if resp, err := c.hc.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	ccancel()
	return 0
}
