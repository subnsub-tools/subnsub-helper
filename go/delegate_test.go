package main

// delegate_test.go — the delegated trust boundary: which kinds a primary's
// signature may run (delegatedKinds), that delegated keys never seal a
// machine, and the delegate/undelegate commands' file behaviour.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// delegatedFixture is a member Mac: a pinned full key, an allowlisted
// browser, and — once delegatedFile is called — one delegated (primary)
// signing key plus the coordinator's tunnel key.
type delegatedFixture struct {
	h     *directHandler
	brows key.NodePublic
	priv  ed25519.PrivateKey // the full (browser/dashboard) key
	dpub  ed25519.PublicKey  // the primary's signing key
	dpriv ed25519.PrivateKey
	node  key.NodePublic // the coordinator's tunnel key
	n     int
}

func newDelegatedFixture(t *testing.T) *delegatedFixture {
	t.Helper()
	scratchHome(t)
	f := &delegatedFixture{h: newDirectHandler(), brows: key.NewNode().Public()}
	if err := allowClient(f.brows.String()); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.priv = priv
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	f.dpub, f.dpriv, _ = ed25519.GenerateKey(nil)
	f.node = key.NewNode().Public()
	return f
}

// delegatedFile writes delegated-keys the way delegate would have.
func (f *delegatedFixture) delegatedFile(t *testing.T) {
	t.Helper()
	if err := writeDelegatedKeys(delegatedKey{
		Pub: f.dpub, PubText: base64.StdEncoding.EncodeToString(f.dpub), Node: f.node,
	}); err != nil {
		t.Fatal(err)
	}
}

// command signs with whichever key the caller names and drives the tunnel's
// command door as the allowlisted browser, like putFixture.command.
func (f *delegatedFixture) command(t *testing.T, priv ed25519.PrivateKey, kind, target, cmd string) consoleResult {
	t.Helper()
	f.n++
	c := signedCmd(t, priv, agentID(), consoleCmd{ID: fmt.Sprintf("d%x-%d", time.Now().UnixNano(), f.n), Kind: kind, Target: target, Cmd: cmd})
	fr, _ := transport.New(transport.TypeCommand, "", c.ID, transport.Command{Kind: c.Kind, Cmd: c.Cmd, Target: c.Target, Sig: c.Sig, At: c.IssuedAt})
	body, _ := transport.Encode(fr)
	req := httptest.NewRequest(http.MethodPost, "/v1/command", strings.NewReader(string(body)))
	req = req.WithContext(transport.WithPeer(req.Context(), f.brows))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", kind, rec.Code, rec.Body.String())
	}
	out, err := transport.Decode(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var res consoleResult
	if err := json.Unmarshal(out.Body, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// The kinds a delegated signature may run, and every kind it may not —
// checked at verifyCommand, where the boundary lives. Ids are unique per
// case because a verified command is single-use.
func TestDelegatedKinds(t *testing.T) {
	fullPub, _, _ := ed25519.GenerateKey(nil)
	dpub, dpriv, _ := ed25519.GenerateKey(nil)
	trust := trust{keys: []ed25519.PublicKey{fullPub}, sealed: true, delegated: []ed25519.PublicKey{dpub}}
	now := time.Now()
	const agent = "ho2JBnXCez_Q"

	delegated := []string{"put-key", "put-peer", "put-peers", "rename", "update", "refresh", "inspect", "myip"}
	for i, kind := range delegated {
		c := signedCmd(t, dpriv, agent, consoleCmd{ID: fmt.Sprintf("dk%d", i), Kind: kind, Cmd: "{}"})
		if why := verifyCommand(c, agent, trust, now); why != "" {
			t.Errorf("delegated kind %q refused: %s", kind, why)
		}
	}
	// Everything else — the console kinds, the shell forms, the six primary
	// kinds, delegate itself, and a kind nobody knows — is not delegated.
	refused := []string{"sh", "", "esh", "pty", "pty-attach", "screen", "files", "clone", "unclone",
		"music", "act", "allow", "primary-on", "primary-off", "primary-roster", "primary-ticket",
		"primary-join", "primary-status", "delegate", "undelegate", "bogus-kind"}
	for i, kind := range refused {
		c := signedCmd(t, dpriv, agent, consoleCmd{ID: fmt.Sprintf("dr%d", i), Kind: kind, Cmd: "{}"})
		if why := verifyCommand(c, agent, trust, now); why != "not-delegated" {
			t.Errorf("kind %q: got %q, want not-delegated", kind, why)
		}
	}
	// A full key still runs what a delegated key cannot.
	fullPub2, fullPriv2, _ := ed25519.GenerateKey(nil)
	trust.keys = []ed25519.PublicKey{fullPub2}
	c := signedCmd(t, fullPriv2, agent, consoleCmd{ID: "dfull", Kind: "sh", Cmd: "uptime"})
	if why := verifyCommand(c, agent, trust, now); why != "" {
		t.Errorf("full-key sh refused: %s", why)
	}
}

// Delegated keys do not seal: a machine with only delegated-keys pinned
// still counts as unpinned, and a delegated signature is waved through the
// same unsigned path as everything else there.
func TestDelegatedDoesNotSeal(t *testing.T) {
	scratchHome(t)
	f := &delegatedFixture{h: newDirectHandler(), brows: key.NewNode().Public()}
	f.dpub, f.dpriv, _ = ed25519.GenerateKey(nil)
	f.node = key.NewNode().Public()
	f.delegatedFile(t)
	tr := loadTrust()
	if tr.sealed {
		t.Fatal("delegated-keys alone sealed the machine")
	}
	if len(tr.keys) != 0 || len(tr.delegated) != 1 {
		t.Fatalf("trust = %+v", tr)
	}
	// And with a full key pinned too, sealed stays true on the full key's
	// account alone.
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	if !loadTrust().sealed {
		t.Fatal("trusted-keys did not seal")
	}
}

// The delegate command writes delegated-keys and appends the coordinator's
// node key to the allowlist; a second delegate strikes the old node.
func TestDelegateCommand(t *testing.T) {
	f := newDelegatedFixture(t)
	args, _ := json.Marshal(map[string]string{
		"key":  base64.StdEncoding.EncodeToString(f.dpub),
		"node": f.node.String(),
	})
	res := f.command(t, f.priv, "delegate", "", string(args))
	if res.Code != 0 {
		t.Fatalf("delegate: %+v", res)
	}
	lines := readDelegatedKeys()
	if len(lines) != 1 || !lines[0].Pub.Equal(f.dpub) || lines[0].Node != f.node {
		t.Fatalf("delegated-keys: %+v", lines)
	}
	// The coordinator's node key lives only in delegated-keys — never on
	// the allowlist, whose peers reach the whole mux.
	for _, k := range loadAllowedClients() {
		if k == f.node {
			t.Fatal("the coordinator's node key is on the allowlist")
		}
	}
	if !delegatedPeer(f.node) {
		t.Fatal("the coordinator's node key is not a delegate peer")
	}
	// A delegated signature cannot run delegate — it is not a delegated kind.
	res = f.command(t, f.dpriv, "delegate", "", string(args))
	if res.Error != "not-delegated" {
		t.Fatalf("delegated delegate: %+v", res)
	}
	// Re-delegate to a new coordinator node: the file follows and only the
	// new node is a delegate peer.
	node2 := key.NewNode().Public()
	args2, _ := json.Marshal(map[string]string{
		"key":  base64.StdEncoding.EncodeToString(f.dpub),
		"node": node2.String(),
	})
	res = f.command(t, f.priv, "delegate", "", string(args2))
	if res.Code != 0 {
		t.Fatalf("re-delegate: %+v", res)
	}
	if delegatedPeer(f.node) {
		t.Fatal("the old coordinator node is still a delegate peer")
	}
	if !delegatedPeer(node2) {
		t.Fatal("the new coordinator node is not a delegate peer")
	}
	// undelegate with the matching key clears the file and the node.
	res = f.command(t, f.priv, "undelegate", "", `{"key":"`+base64.StdEncoding.EncodeToString(f.dpub)+`"}`)
	if res.Code != 0 {
		t.Fatalf("undelegate: %+v", res)
	}
	if got := readDelegatedKeys(); len(got) != 0 {
		t.Fatalf("delegated-keys after undelegate: %+v", got)
	}
	if delegatedPeer(node2) {
		t.Fatal("the coordinator node is still a delegate peer after undelegate")
	}
	// undelegate naming a different key refuses and keeps the file.
	f.delegatedFile(t)
	other, _, _ := ed25519.GenerateKey(nil)
	res = f.command(t, f.priv, "undelegate", "", `{"key":"`+base64.StdEncoding.EncodeToString(other)+`"}`)
	if res.Error != "bad-key" {
		t.Fatalf("undelegate wrong key: %+v", res)
	}
	if got := readDelegatedKeys(); len(got) != 1 {
		t.Fatal("undelegate with a wrong key removed the delegation anyway")
	}
	// undelegate with an empty command removes whatever is there.
	res = f.command(t, f.priv, "undelegate", "", "")
	if res.Code != 0 {
		t.Fatalf("undelegate empty: %+v", res)
	}
	if got := readDelegatedKeys(); len(got) != 0 {
		t.Fatal("undelegate with empty cmd kept the delegation")
	}
}

// A delegated signature runs a delegated kind end to end: put-key verifies
// under delegated-keys and answers.
func TestDelegatedCommandRuns(t *testing.T) {
	f := newDelegatedFixture(t)
	f.delegatedFile(t)
	was := putSupported
	putSupported = true
	putReset()
	putSeen.Store(true) // put is on this Mac, so put-key gives its keys
	t.Cleanup(func() { putSupported = was; putReset() })
	res := f.command(t, f.dpriv, "put-key", "", `["agentB01"]`)
	if res.Code != 0 {
		t.Fatalf("delegated put-key: %+v", res)
	}
	var out struct {
		Keys map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(res.Out), &out); err != nil || len(out.Keys) != 1 {
		t.Fatalf("put-key out: %q %v", res.Out, err)
	}
	if !strings.HasPrefix(out.Keys["agentB01"], "nodekey:") {
		t.Fatalf("put-key key: %q", out.Keys["agentB01"])
	}
	// And a non-delegated kind signed the same way is refused at the door.
	res = f.command(t, f.dpriv, "sh", "", "uptime")
	if res.Error != "not-delegated" {
		t.Fatalf("delegated sh: %+v", res)
	}
}

// The coordinator's tunnel key reaches the hello and the command door —
// where its delegated signature is judged — and nothing else the mux
// answers a browser. delegated-keys is read per request, so a replaced
// node is refused at once.
func TestDelegatedNodeDoor(t *testing.T) {
	f := newDelegatedFixture(t)
	f.delegatedFile(t)
	call := func(method, path string, peer key.NodePublic) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(transport.WithPeer(req.Context(), peer))
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/v1/snapshot"}, {http.MethodGet, "/v1/events"},
		{http.MethodGet, "/v1/history"}, {http.MethodGet, "/v1/music/index"},
		{http.MethodGet, putStreamPath}, {http.MethodPost, "/v1/pty/in"},
		{http.MethodPost, "/v1/files/put"},
	} {
		if rec := call(c.method, c.path, f.node); rec.Code != http.StatusForbidden || errCodeOf(rec) != "not-allowed" {
			t.Errorf("%s %s as the coordinator: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/v1/hello"}, {http.MethodPost, "/v1/command"},
	} {
		if rec := call(c.method, c.path, f.node); rec.Code == http.StatusForbidden {
			t.Errorf("%s %s refused the coordinator: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	// A replaced node loses the door on its next request.
	node2 := key.NewNode().Public()
	if err := writeDelegatedKeys(delegatedKey{
		Pub: f.dpub, PubText: base64.StdEncoding.EncodeToString(f.dpub), Node: node2,
	}); err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodGet, "/v1/hello", f.node); rec.Code != http.StatusForbidden {
		t.Fatalf("replaced node still admitted: %d", rec.Code)
	}
	if rec := call(http.MethodGet, "/v1/hello", node2); rec.Code == http.StatusForbidden {
		t.Fatalf("new node refused: %d", rec.Code)
	}
}

// delegated-keys is owner-only like every secret file here.
func TestDelegatedKeysFilePerms(t *testing.T) {
	f := newDelegatedFixture(t)
	f.delegatedFile(t)
	fi, err := os.Stat(delegatedKeysPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("delegated-keys mode %v", fi.Mode().Perm())
	}
}
