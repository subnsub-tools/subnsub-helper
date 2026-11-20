package main

// primary_test.go — the primary helper's commands, state files, join door
// and coordinator round, plus the real-DERP end to end.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

// primaryFixture is a sealed, allowlisted Mac with put — everything the
// primary commands and the coordinator need.
type primaryFixture struct {
	h     *directHandler
	brows key.NodePublic
	priv  ed25519.PrivateKey
	n     int
}

func newPrimaryFixture(t *testing.T) *primaryFixture {
	t.Helper()
	home := scratchHome(t)
	was, wasPaths := putSupported, putAppPaths
	putSupported = true
	putAppPaths = func() []string { return []string{filepath.Join(home, "Applications", "put.app")} }
	putReset()
	primaryReset()
	// The primary is a Mac put is on, as in the fleet; a test says otherwise.
	putSeen.Store(true)
	t.Cleanup(func() { putSupported, putAppPaths = was, wasPaths; putReset(); primaryReset() })
	f := &primaryFixture{h: newDirectHandler(), brows: key.NewNode().Public()}
	if err := allowClient(f.brows.String()); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.priv = priv
	if err := trustKey(base64.StdEncoding.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	return f
}

// primaryReset forgets what an earlier test left in the process: the known
// set, the connection cache and any pending wake.
func primaryReset() {
	primaryKnown.Lock()
	primaryKnown.m = nil
	primaryKnown.Unlock()
	primaryAbsent.Lock()
	primaryAbsent.m = nil
	primaryAbsent.Unlock()
	primaryLinkCache.Lock()
	primaryLinkCache.m = nil
	primaryLinkCache.Unlock()
	select {
	case <-primaryWakeCh:
	default:
	}
}

// command drives the tunnel's command door as the allowlisted browser,
// signed with the fixture's full key.
func (f *primaryFixture) command(t *testing.T, kind, target, cmd string) consoleResult {
	t.Helper()
	f.n++
	c := signedCmd(t, f.priv, agentID(), consoleCmd{ID: fmt.Sprintf("r%x-%d", time.Now().UnixNano(), f.n), Kind: kind, Target: target, Cmd: cmd})
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

func (f *primaryFixture) primaryOn(t *testing.T) string {
	t.Helper()
	res := f.command(t, "primary-on", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-on: %+v", res)
	}
	var out struct {
		Pub  string `json:"pub"`
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal([]byte(res.Out), &out); err != nil || out.Pub == "" {
		t.Fatalf("primary-on out: %q %v", res.Out, err)
	}
	return out.Pub
}

func rosterMember(agent, name, addr string) primaryMember {
	return primaryMember{Agent: agent, Name: name, Addr: addr}
}

// primary-on makes the signing key once and keeps it; primary-off removes
// the role's files and keeps the dial seed.
func TestPrimaryOnOff(t *testing.T) {
	f := newPrimaryFixture(t)
	if primaryIsPrimary() {
		t.Fatal("primary before primary-on")
	}
	pub := f.primaryOn(t)
	if !primaryIsPrimary() {
		t.Fatal("primary-sign missing after primary-on")
	}
	for _, name := range []string{primarySignFile, primarySeedFile} {
		fi, err := os.Stat(primaryPath(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", name, fi.Mode().Perm())
		}
	}
	// Idempotent: a second primary-on answers the same key.
	if again := f.primaryOn(t); again != pub {
		t.Fatalf("primary-on rotated the key: %q then %q", pub, again)
	}
	// The hello says this machine is the primary.
	fr, err := f.h.helloFrame(httptest.NewRequest(http.MethodGet, "/v1/hello", nil))
	if err != nil {
		t.Fatal(err)
	}
	var hf transport.Frame
	if err := json.Unmarshal(fr, &hf); err != nil {
		t.Fatal(err)
	}
	var hello transport.Hello
	if err := json.Unmarshal(hf.Body, &hello); err != nil {
		t.Fatal(err)
	}
	if !hello.Primary {
		t.Fatal("hello does not say primary")
	}
	// primary-off clears the role and keeps primary-seed.
	res := f.command(t, "primary-off", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-off: %+v", res)
	}
	if primaryIsPrimary() {
		t.Fatal("primary-sign survived primary-off")
	}
	if _, err := os.Stat(primaryPath(primarySeedFile)); err != nil {
		t.Fatalf("primary-seed was removed: %v", err)
	}
	res = f.command(t, "primary-off", "", "")
	if res.Error != "not-primary" {
		t.Fatalf("second primary-off: %+v", res)
	}
}

// primary-roster edits the member list: kids are a:<agent>, dial keys are
// derived per kid, updates keep the kid, removals queue a drop.
func TestPrimaryRoster(t *testing.T) {
	f := newPrimaryFixture(t)
	if res := f.command(t, "primary-roster", "", `{}`); res.Error != "not-primary" {
		t.Fatalf("roster before primary-on: %+v", res)
	}
	f.primaryOn(t)
	add, _ := json.Marshal(map[string]any{
		"add": []primaryMember{
			rosterMember("memberAA", "Member A", testPutAddr(t)),
			rosterMember("memberBB", "Member B", testPutAddr(t)),
		},
	})
	res := f.command(t, "primary-roster", "", string(add))
	if res.Code != 0 {
		t.Fatalf("roster add: %+v", res)
	}
	var out struct {
		Roster []struct {
			Agent string `json:"agent"`
			Name  string `json:"name"`
			Kid   string `json:"kid"`
		} `json:"roster"`
		Keys map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(res.Out), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Roster) != 2 {
		t.Fatalf("roster: %+v", out.Roster)
	}
	for _, m := range out.Roster {
		if m.Kid != "a:"+m.Agent {
			t.Fatalf("kid %q for %q", m.Kid, m.Agent)
		}
		want, err := primaryDialPubText(m.Kid)
		if err != nil || out.Keys[m.Agent] != want {
			t.Fatalf("keys[%s]=%q want %q (%v)", m.Agent, out.Keys[m.Agent], want, err)
		}
		if !strings.HasPrefix(out.Keys[m.Agent], "nodekey:") {
			t.Fatalf("keys[%s] is not a nodekey: %q", m.Agent, out.Keys[m.Agent])
		}
	}
	// An update keeps the kid.
	upd, _ := json.Marshal(map[string]any{
		"add": []primaryMember{rosterMember("memberAA", "Renamed", testPutAddr(t))},
	})
	res = f.command(t, "primary-roster", "", string(upd))
	if res.Code != 0 {
		t.Fatalf("roster update: %+v", res)
	}
	for _, m := range readPrimaryRoster() {
		if m.Agent == "memberAA" && (m.Kid != "a:memberAA" || m.Name != "Renamed") {
			t.Fatalf("updated member: %+v", m)
		}
	}
	// Bad input is refused.
	bad, _ := json.Marshal(map[string]any{
		"add": []primaryMember{rosterMember("bad agent!", "X", testPutAddr(t))},
	})
	if res := f.command(t, "primary-roster", "", string(bad)); res.Error != "bad-args" {
		t.Fatalf("bad roster add: %+v", res)
	}
	// A removal drops the member and leaves its primary-drops tombstone.
	rm, _ := json.Marshal(map[string]any{"remove": []string{"memberBB"}})
	res = f.command(t, "primary-roster", "", string(rm))
	if res.Code != 0 {
		t.Fatalf("roster remove: %+v", res)
	}
	for _, m := range readPrimaryRoster() {
		if m.Agent == "memberBB" {
			t.Fatal("memberBB survived removal")
		}
	}
	drops := primaryDropsLoad()
	found := false
	for _, d := range drops {
		if d.Agent == "memberBB" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no tombstone for memberBB: %+v", drops)
	}
}

// primary-ticket mints a one-use join token; the fields are the signing
// pub, the derived dial pub for t:<id>, the join private key and the
// tunnel address.
func TestPrimaryTicket(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	res := f.command(t, "primary-ticket", "", "")
	if res.Error != "no-tunnel" {
		t.Fatalf("ticket without a tunnel address: %+v", res)
	}
	addr := testPutAddr(t)
	setDirectAddress(addr)
	t.Cleanup(func() { setDirectAddress("") })
	res = f.command(t, "primary-ticket", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-ticket: %+v", res)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(res.Out), &out); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(out.Token, ".")
	if len(parts) != 4 {
		t.Fatalf("token fields: %d", len(parts))
	}
	if parts[3] != addr {
		t.Fatalf("token addr %q, want %q", parts[3], addr)
	}
	if len(parts[1]) != 64 || len(parts[2]) != 64 {
		t.Fatalf("token keys: %q %q", parts[1], parts[2])
	}
	// The ticket on disk names the same join key, and its pub is admitted.
	tickets := primaryTicketsLoad()
	if len(tickets) != 1 {
		t.Fatalf("tickets: %+v", tickets)
	}
	tk := tickets[0]
	var tokenJoinPriv key.NodePrivate
	if err := tokenJoinPriv.UnmarshalText([]byte("privkey:" + parts[2])); err != nil {
		t.Fatal(err)
	}
	if tk.JoinPub != tokenJoinPriv.Public().String() || tk.ID == "" {
		t.Fatalf("ticket: %+v vs token %v", tk, parts)
	}
	kid := "t:" + tk.ID
	wantPub, err := primaryDialPubText(kid)
	if err != nil {
		t.Fatal(err)
	}
	if "nodekey:"+parts[1] != wantPub {
		t.Fatalf("token dial key %q, want %q", parts[1], wantPub)
	}
	// The join pub is one of the admitted join nodes.
	joinPub, ok := ticketJoinPub(tk)
	if !ok {
		t.Fatal("ticket join key does not parse")
	}
	admitted := false
	for _, k := range activeJoinNodes() {
		if k == joinPub {
			admitted = true
		}
	}
	if !admitted {
		t.Fatal("the ticket's join key is not admitted")
	}
	// The first token field is the primary's signing pub.
	k, err := primarySignKey()
	if err != nil {
		t.Fatal(err)
	}
	if parts[0] != base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)) {
		t.Fatal("token's first field is not the signing pub")
	}
}

// The join door: a ticket's join key reaches POST /v1/primary/join and
// nothing else; a good join consumes the ticket and grows the roster.
func TestPrimaryJoinDoor(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	setDirectAddress(testPutAddr(t))
	t.Cleanup(func() { setDirectAddress("") })
	res := f.command(t, "primary-ticket", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-ticket: %+v", res)
	}
	tk := primaryTicketsLoad()[0]
	joinPub, ok := ticketJoinPub(tk)
	if !ok {
		t.Fatal("ticket join key does not parse")
	}
	member := primaryMember{Agent: "joinMem01", Name: "Joiner", Addr: testPutAddr(t)}
	body, _ := json.Marshal(member)

	call := func(method, path string, peer key.NodePublic, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(payload))
		if peer.String() != "" {
			req = req.WithContext(transport.WithPeer(req.Context(), peer))
		}
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec
	}
	// The join key reaches nothing but its one door.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/hello"},
		{http.MethodPost, "/v1/command"},
		{http.MethodGet, "/v1/primary/join"},
		{http.MethodGet, "/v1/put/stream"},
	} {
		rec := call(tc.method, tc.path, joinPub, "")
		if rec.Code == http.StatusOK {
			t.Fatalf("%s %s answered a join key", tc.method, tc.path)
		}
	}
	// A bad body is refused before the ticket is spent.
	if rec := call(http.MethodPost, "/v1/primary/join", joinPub, "not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad join body: %d", rec.Code)
	}
	if len(primaryTicketsLoad()) != 1 {
		t.Fatal("a bad join body consumed the ticket")
	}
	// The real join: 200, ticket consumed, roster gains the member.
	rec := call(http.MethodPost, "/v1/primary/join", joinPub, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("join: %d %s", rec.Code, rec.Body.String())
	}
	if got := primaryTicketsLoad(); len(got) != 0 {
		t.Fatalf("ticket survived its join: %+v", got)
	}
	var joined *primaryMember
	for i, m := range readPrimaryRoster() {
		if m.Agent == "joinMem01" {
			joined = &readPrimaryRoster()[i]
		}
	}
	if joined == nil || joined.Kid != "t:"+tk.ID || joined.Addr != member.Addr {
		t.Fatalf("roster after join: %+v", readPrimaryRoster())
	}
	// The same ticket cannot join twice.
	if rec := call(http.MethodPost, "/v1/primary/join", joinPub, string(body)); rec.Code != http.StatusForbidden {
		t.Fatalf("second join: %d", rec.Code)
	}
	// An expired ticket is refused the same way.
	expiredPriv := key.NewNode()
	expired := primaryTicket{
		ID:      "expired01",
		JoinPub: expiredPriv.Public().String(),
		Until:   time.Now().Add(-time.Hour).Unix(),
	}
	if err := primaryTicketsSave([]primaryTicket{expired}); err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodPost, "/v1/primary/join", expiredPriv.Public(), string(body)); rec.Code != http.StatusForbidden {
		t.Fatalf("expired join: %d", rec.Code)
	}
}

// A join cannot take over an identity: the primary's own agent id, or an
// agent already on the roster under another kid, is refused 409 and the
// ticket stays live. The same agent under the same kid updates.
func TestPrimaryJoinTaken(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	setDirectAddress(testPutAddr(t))
	t.Cleanup(func() { setDirectAddress("") })

	call := func(peer key.NodePublic, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/primary/join", strings.NewReader(payload))
		req = req.WithContext(transport.WithPeer(req.Context(), peer))
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec
	}
	mint := func() (primaryTicket, key.NodePublic) {
		t.Helper()
		res := f.command(t, "primary-ticket", "", "")
		if res.Code != 0 {
			t.Fatalf("primary-ticket: %+v", res)
		}
		tickets := primaryTicketsLoad()
		tk := tickets[len(tickets)-1]
		pub, ok := ticketJoinPub(tk)
		if !ok {
			t.Fatal("ticket join key does not parse")
		}
		return tk, pub
	}
	ticketsBefore := len(primaryTicketsLoad())

	// The primary's own agent id is never a member.
	_, pub := mint()
	body, _ := json.Marshal(primaryMember{Agent: agentID(), Name: "Self", Addr: testPutAddr(t)})
	if rec := call(pub, string(body)); rec.Code != http.StatusConflict || errCode(t, rec) != "agent-taken" {
		t.Fatalf("self join: %d %s", rec.Code, rec.Body.String())
	}
	if len(primaryTicketsLoad()) != ticketsBefore+1 {
		t.Fatal("a refused join consumed the ticket")
	}

	// An agent the page already rostered under its own kid keeps it.
	if err := primaryRosterSave([]primaryMember{
		{Agent: "takenMem", Name: "Taken", Addr: testPutAddr(t), Kid: "a:takenMem"},
	}); err != nil {
		t.Fatal(err)
	}
	_, pub2 := mint()
	body, _ = json.Marshal(primaryMember{Agent: "takenMem", Name: "Usurper", Addr: testPutAddr(t)})
	if rec := call(pub2, string(body)); rec.Code != http.StatusConflict || errCode(t, rec) != "agent-taken" {
		t.Fatalf("taken-agent join: %d %s", rec.Code, rec.Body.String())
	}
	for _, m := range readPrimaryRoster() {
		if m.Agent == "takenMem" && m.Kid != "a:takenMem" {
			t.Fatalf("roster after refused join: %+v", readPrimaryRoster())
		}
	}

	// The same agent under the same kid — a retry — updates instead.
	tk3, pub3 := mint()
	if err := primaryRosterSave([]primaryMember{
		{Agent: "retryMem", Name: "Old", Addr: "tc-old", Kid: "t:" + tk3.ID},
	}); err != nil {
		t.Fatal(err)
	}
	newAddr := testPutAddr(t)
	body, _ = json.Marshal(primaryMember{Agent: "retryMem", Name: "New", Addr: newAddr})
	rec := call(pub3, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("same-kid retry: %d %s", rec.Code, rec.Body.String())
	}
	if len(primaryTicketsLoad()) != ticketsBefore+2 {
		t.Fatalf("retry did not consume its ticket: %+v", primaryTicketsLoad())
	}
	var updated *primaryMember
	for i, m := range readPrimaryRoster() {
		if m.Agent == "retryMem" {
			updated = &readPrimaryRoster()[i]
		}
	}
	if updated == nil || updated.Name != "New" || updated.Addr != newAddr || updated.Kid != "t:"+tk3.ID {
		t.Fatalf("roster after retry: %+v", readPrimaryRoster())
	}
}

// fakeMemberConn is a memberConn that records what the coordinator sends.
type fakeMemberConn struct {
	agent    string
	caps     []string
	helloErr error
	putKey   string // Out for put-key; "" → the default two-key answer
	mu       sync.Mutex
	helloN   int
	cmds     []fakeCmd
	failOn   map[string]bool // kinds that answer an error
}

type fakeCmd struct {
	kind, target, cmd string
}

func (f *fakeMemberConn) hello(ctx context.Context) (string, []string, error) {
	f.mu.Lock()
	f.helloN++
	f.mu.Unlock()
	if f.helloErr != nil {
		return "", nil, f.helloErr
	}
	return f.agent, f.caps, nil
}

func (f *fakeMemberConn) command(ctx context.Context, kind, target, cmd string) (consoleResult, error) {
	f.mu.Lock()
	f.cmds = append(f.cmds, fakeCmd{kind, target, cmd})
	f.mu.Unlock()
	if f.failOn[kind] {
		return consoleResult{Code: -1, Error: "boom"}, nil
	}
	if kind == "put-key" {
		out := f.putKey
		if out == "" {
			out = `{"keys":{},"held":{}}`
		}
		return consoleResult{Code: 0, Out: out}, nil
	}
	return consoleResult{Code: 0, Out: "{}"}, nil
}

func (f *fakeMemberConn) kinds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.cmds {
		out = append(out, c.kind+":"+c.target)
	}
	return out
}

func (f *fakeMemberConn) hellos() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.helloN
}

func (f *fakeMemberConn) recorded() []fakeCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCmd(nil), f.cmds...)
}

// withFakeMembers points primaryDialFor at the given conns for the round.
func withFakeMembers(t *testing.T, conns map[string]*fakeMemberConn) {
	t.Helper()
	old := primaryDialFor
	primaryDialFor = func(ctx context.Context, m primaryMember, sign ed25519.PrivateKey) (memberConn, error) {
		if c, ok := conns[m.Agent]; ok {
			return c, nil
		}
		return nil, fmt.Errorf("no fake for %s", m.Agent)
	}
	t.Cleanup(func() { primaryDialFor = old })
}

func rosterJSON(t *testing.T, members ...primaryMember) string {
	t.Helper()
	add := map[string]any{"add": members}
	b, _ := json.Marshal(add)
	return string(b)
}

// One coordinator round: put-key goes to every put member with the roster's
// other agents as dests; put-peer pushes each known source's entry; a
// matching held digest skips the push; queued drops go to every put member.
func TestPrimaryRound(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	self := agentID()
	selfAddr, addrA, addrB := testPutAddr(t), testPutAddr(t), testPutAddr(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember(self, "This Mac", selfAddr),
		rosterMember("memberAA", "Member A", addrA),
		rosterMember("memberBB", "Member B", addrB),
	))
	fa := &fakeMemberConn{agent: "memberAA", caps: []string{transport.CapPut}}
	// memberAA holds a dial key for the primary itself, so the primary is
	// a put-peer target this round too — answered in-process.
	selfKey := key.NewNode().Public().String()
	fa.putKey = `{"keys":{"` + self + `":"` + selfKey + `"},"held":{}}`
	fb := &fakeMemberConn{agent: "memberBB", caps: []string{transport.CapPut}}
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa, "memberBB": fb})

	primaryRound(context.Background())

	// Each member was asked put-key with the other roster agents as dests.
	for _, fc := range []*fakeMemberConn{fa, fb} {
		if len(fc.cmds) == 0 || fc.cmds[0].kind != "put-key" {
			t.Fatalf("%s: first command %+v", fc.agent, fc.cmds)
		}
		var dests []string
		if err := json.Unmarshal([]byte(fc.cmds[0].cmd), &dests); err != nil {
			t.Fatalf("%s put-key cmd: %q", fc.agent, fc.cmds[0].cmd)
		}
		want := map[string]bool{self: true, "memberAA": true, "memberBB": true}
		delete(want, fc.agent)
		if len(dests) != len(want) {
			t.Fatalf("%s dests %v", fc.agent, dests)
		}
		for _, d := range dests {
			if !want[d] {
				t.Fatalf("%s dest %q not in roster", fc.agent, d)
			}
		}
	}
	// Every member answered an empty keys map, so the only entries pushed
	// are the primary's own (in-process): each member gets one put-peer
	// naming it, with the key the primary uses to dial it.
	for _, fc := range []*fakeMemberConn{fa, fb} {
		var pushes []fakeCmd
		for _, c := range fc.cmds {
			if c.kind == "put-peer" {
				pushes = append(pushes, c)
			}
		}
		if len(pushes) != 1 || pushes[0].target != self {
			t.Fatalf("%s put-peer pushes: %+v", fc.agent, pushes)
		}
		var entry map[string]string
		if err := json.Unmarshal([]byte(pushes[0].cmd), &entry); err != nil {
			t.Fatal(err)
		}
		wantKey, err := putKeyFor(fc.agent)
		if err != nil {
			t.Fatal(err)
		}
		if entry["k"] != wantKey.Public().String() {
			t.Fatalf("%s entry key %q want %q", fc.agent, entry["k"], wantKey.Public().String())
		}
		if entry["a"] != selfAddr {
			t.Fatalf("%s entry addr %q want %q", fc.agent, entry["a"], selfAddr)
		}
	}
	// And the primary's own put list gained memberAA's entry, in-process.
	foundAA := false
	for _, p := range putPeers() {
		if p.Agent == "memberAA" {
			foundAA = true
		}
	}
	if !foundAA {
		t.Fatalf("memberAA's entry did not reach the primary's own put list: %+v", putPeers())
	}
}

// A member whose put-key says put is not on it is no source — its entry goes
// to no one, the primary's own list included — and every member holding its
// entry gets an empty put-peer for it. A member that does not say (an older
// helper) counts as having put.
func TestPrimaryRoundAbsent(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	self := agentID()
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember(self, "This Mac", testPutAddr(t)),
		rosterMember("memberAA", "Member A", testPutAddr(t)),
		rosterMember("memberBB", "Member B", testPutAddr(t)),
	))
	fa := &fakeMemberConn{agent: "memberAA", caps: []string{transport.CapPut}}
	fa.putKey = `{"keys":{},"held":{"memberBB":"0123456789abcdef"}}`
	fb := &fakeMemberConn{agent: "memberBB", caps: []string{transport.CapPut}}
	fb.putKey = `{"keys":{"` + self + `":"` + key.NewNode().Public().String() + `","memberAA":"` + key.NewNode().Public().String() + `"},"held":{},"present":false}`
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa, "memberBB": fb})

	primaryRound(context.Background())

	var drops, pushesOfB int
	for _, c := range fa.recorded() {
		if c.kind == "put-peer" && c.target == "memberBB" {
			if c.cmd == "" {
				drops++
			} else {
				pushesOfB++
			}
		}
	}
	if drops != 1 || pushesOfB != 0 {
		t.Fatalf("memberAA: %d drops and %d pushes of memberBB: %+v", drops, pushesOfB, fa.recorded())
	}
	for _, p := range putPeers() {
		if p.Agent == "memberBB" {
			t.Fatalf("memberBB reached the primary's own list: %+v", putPeers())
		}
	}
	// It is still a target: it gets the primary's entry like any member.
	gotSelf := false
	for _, c := range fb.recorded() {
		gotSelf = gotSelf || (c.kind == "put-peer" && c.target == self && c.cmd != "")
	}
	if !gotSelf {
		t.Fatalf("memberBB no longer gets the others' entries: %+v", fb.recorded())
	}

	// Once its helper says put is there, it is a source again.
	fb.mu.Lock()
	fb.putKey = strings.Replace(fb.putKey, `"present":false`, `"present":true`, 1)
	fb.cmds = nil
	fb.mu.Unlock()
	primaryRound(context.Background())
	back := false
	for _, p := range putPeers() {
		back = back || p.Agent == "memberBB"
	}
	if !back {
		t.Fatalf("memberBB did not come back to the primary's own list: %+v", putPeers())
	}

	// The primary itself without put: its own entry is taken off the members that hold it.
	putSeen.Store(false)
	fa.mu.Lock()
	fa.putKey = `{"keys":{},"held":{"` + self + `":"0123456789abcdef"}}`
	fa.cmds = nil
	fa.mu.Unlock()
	primaryRound(context.Background())
	selfDropped := false
	for _, c := range fa.recorded() {
		selfDropped = selfDropped || (c.kind == "put-peer" && c.target == self && c.cmd == "")
	}
	if !selfDropped {
		t.Fatalf("the primary without put was not taken off memberAA: %+v", fa.recorded())
	}
}

// A member offline when another said put is not on it is told to drop that
// one once it is back, even if that one is offline by then; a present answer
// ends it.
func TestPrimaryRoundAbsentRemembered(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember(agentID(), "This Mac", testPutAddr(t)),
		rosterMember("memberBB", "Member B", testPutAddr(t)),
		rosterMember("memberCC", "Member C", testPutAddr(t)),
	))
	fb := &fakeMemberConn{agent: "memberBB", caps: []string{transport.CapPut}, putKey: `{"keys":{},"held":{},"present":false}`}
	fc := &fakeMemberConn{agent: "memberCC", caps: []string{transport.CapPut}, helloErr: errors.New("offline"),
		putKey: `{"keys":{},"held":{"memberBB":"0123456789abcdef"}}`}
	withFakeMembers(t, map[string]*fakeMemberConn{"memberBB": fb, "memberCC": fc})
	primaryRound(context.Background())

	fb.mu.Lock()
	fb.helloErr = errors.New("offline")
	fb.mu.Unlock()
	fc.mu.Lock()
	fc.helloErr = nil
	fc.mu.Unlock()
	primaryRound(context.Background())
	drops := 0
	for _, c := range fc.recorded() {
		if c.kind == "put-peer" && c.target == "memberBB" && c.cmd == "" {
			drops++
		}
	}
	if drops != 1 {
		t.Fatalf("memberCC, back, was not told to drop memberBB: %+v", fc.recorded())
	}

	fb.mu.Lock()
	fb.helloErr = nil
	fb.putKey = `{"keys":{},"held":{},"present":true}`
	fb.mu.Unlock()
	fc.mu.Lock()
	fc.cmds = nil
	fc.mu.Unlock()
	primaryRound(context.Background())
	for _, c := range fc.recorded() {
		if c.kind == "put-peer" && c.target == "memberBB" && c.cmd == "" {
			t.Fatalf("memberBB is dropped after its helper said put is there: %+v", fc.recorded())
		}
	}
}

// A member whose hello names a different agent is skipped entirely.
func TestPrimaryRoundHelloMismatch(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember("memberAA", "Member A", testPutAddr(t))))
	fa := &fakeMemberConn{agent: "memberBB", caps: []string{transport.CapPut}} // hello says memberBB
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa})
	primaryRound(context.Background())
	if len(fa.cmds) != 0 {
		t.Fatalf("a mismatched hello still got commands: %+v", fa.cmds)
	}
}

// A roster removal leaves a primary-drops tombstone; each round carries its
// empty put-peer to every answered put member that has not acked — the
// primary's own put list included — and the tombstone is gone once all have.
func TestPrimaryRoundDrops(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember(agentID(), "This Mac", testPutAddr(t)),
		rosterMember("memberAA", "Member A", testPutAddr(t)),
		rosterMember("memberBB", "No put", testPutAddr(t)),
		rosterMember("goneAgent", "Gone", testPutAddr(t))))
	f.command(t, "primary-roster", "", `{"remove":["goneAgent"]}`)
	if drops := primaryDropsLoad(); len(drops) != 1 || drops[0].Agent != "goneAgent" {
		t.Fatalf("tombstone after remove: %+v", drops)
	}
	fa := &fakeMemberConn{agent: "memberAA", caps: []string{transport.CapPut}}
	fb := &fakeMemberConn{agent: "memberBB", caps: []string{}} // no put cap
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa, "memberBB": fb})
	// The primary itself holds the dropped peer, so the round's empty
	// put-peer to self must take it off the list.
	seed, _ := json.Marshal(map[string]string{
		"n": "Gone", "a": testPutAddr(t), "k": key.NewNode().Public().String(),
	})
	if r := f.command(t, "put-peer", "goneAgent", string(seed)); r.Code != 0 {
		t.Fatalf("seed put-peer: %+v", r)
	}
	primaryRound(context.Background())
	for _, fc := range []*fakeMemberConn{fa, fb} {
		var drops []fakeCmd
		for _, c := range fc.cmds {
			if c.kind == "put-peer" && c.target == "goneAgent" && c.cmd == "" {
				drops = append(drops, c)
			}
		}
		if fc.agent == "memberAA" && len(drops) != 1 {
			t.Fatalf("memberAA drops: %+v", fc.cmds)
		}
		if fc.agent == "memberBB" && len(drops) != 0 {
			t.Fatalf("memberBB (no put) got a drop: %+v", fc.cmds)
		}
	}
	// The primary itself is a member: the drop hit its put list too.
	for _, p := range putPeers() {
		if p.Agent == "goneAgent" {
			t.Fatal("drop did not reach the primary's own put list")
		}
	}
	// Every put-capable member acked, so the tombstone is gone.
	if drops := primaryDropsLoad(); len(drops) != 0 {
		t.Fatalf("tombstone survived full ack: %+v", drops)
	}
}

// A member that fails the drop is not marked done and is asked again next
// round; the ones that acked are not asked twice.
func TestPrimaryRoundDropsRetry(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember(agentID(), "This Mac", testPutAddr(t)),
		rosterMember("memberAA", "Member A", testPutAddr(t)),
		rosterMember("memberBB", "Member B", testPutAddr(t)),
		rosterMember("goneAgent", "Gone", testPutAddr(t))))
	f.command(t, "primary-roster", "", `{"remove":["goneAgent"]}`)
	fa := &fakeMemberConn{agent: "memberAA", caps: []string{transport.CapPut}, failOn: map[string]bool{"put-peer": true}}
	fb := &fakeMemberConn{agent: "memberBB", caps: []string{transport.CapPut}}
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa, "memberBB": fb})
	drops := func(fc *fakeMemberConn) int {
		n := 0
		for _, c := range fc.recorded() {
			if c.kind == "put-peer" && c.target == "goneAgent" && c.cmd == "" {
				n++
			}
		}
		return n
	}
	primaryRound(context.Background())
	if drops(fa) != 1 || drops(fb) != 1 {
		t.Fatalf("round one drops: A=%d B=%d", drops(fa), drops(fb))
	}
	if d := primaryDropsLoad(); len(d) != 1 || len(d[0].Done) != 2 {
		t.Fatalf("tombstone after round one: %+v", d)
	}
	// The retry lands once the member answers again; the acked member is
	// still not asked twice and the finished tombstone is gone.
	delete(fa.failOn, "put-peer")
	primaryRound(context.Background())
	if drops(fa) != 2 {
		t.Fatalf("the failed member was not retried: %d drops", drops(fa))
	}
	if drops(fb) != 1 {
		t.Fatalf("an acked member was asked again: %d drops", drops(fb))
	}
	if d := primaryDropsLoad(); len(d) != 0 {
		t.Fatalf("tombstone survived the retry: %+v", d)
	}
}

// Re-adding a removed agent clears its tombstone; the file is the state, so
// a fresh read is the reload.
func TestPrimaryDropsReadd(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember("memberAA", "Member A", testPutAddr(t)),
		rosterMember("goneAgent", "Gone", testPutAddr(t))))
	f.command(t, "primary-roster", "", `{"remove":["goneAgent"]}`)
	if drops := primaryDropsLoad(); len(drops) != 1 {
		t.Fatalf("tombstone after remove: %+v", drops)
	}
	f.command(t, "primary-roster", "", rosterJSON(t, rosterMember("goneAgent", "Back", testPutAddr(t))))
	if drops := primaryDropsLoad(); len(drops) != 0 {
		t.Fatalf("tombstone survived the re-add: %+v", drops)
	}
}

// A member that fails put-key is neither a source nor a target this round.
func TestPrimaryRoundPutKeyFailure(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember("memberAA", "Member A", testPutAddr(t)),
		rosterMember("memberBB", "Member B", testPutAddr(t))))
	fa := &fakeMemberConn{agent: "memberAA", caps: []string{transport.CapPut}}
	fb := &fakeMemberConn{agent: "memberBB", caps: []string{transport.CapPut}, failOn: map[string]bool{"put-key": true}}
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa, "memberBB": fb})
	primaryRound(context.Background())
	// memberBB answered put-key with an error → no put-peer to it.
	for _, c := range fb.cmds {
		if c.kind == "put-peer" {
			t.Fatalf("put-key failure still got put-peer: %+v", fb.cmds)
		}
	}
	// memberAA got nothing from memberBB either (memberBB's keys unknown).
	for _, c := range fa.cmds {
		if c.kind == "put-peer" && c.target == "memberBB" {
			t.Fatalf("memberAA got memberBB's entry: %+v", fa.cmds)
		}
	}
}

// TestE2EPrimaryOverTailcat runs the real thing over a DERP: two carriers in
// one process — the member's tunnel (admitting only the coordinator's dial
// key) and the primary's (admitting the ticket's join key) — a
// primary-signed put-key answered under delegated-keys, and a join that
// consumes its ticket into the roster.
func TestE2EPrimaryOverTailcat(t *testing.T) {
	if os.Getenv("MON_E2E") == "" {
		t.Skip("set MON_E2E=1 to run against a real DERP")
	}
	f := newPrimaryFixture(t)
	pub := f.primaryOn(t)
	sign, err := primarySignKey()
	if err != nil {
		t.Fatal(err)
	}
	// The member's side of the delegation, in this shared config dir: the
	// primary's signing pub and the coordinator's dial node for the member's
	// kid. memberKid stands in for "a:<agent>" — the member's roster entry.
	memberAgent := "e2eMember01"
	memberKid := "a:" + memberAgent
	dialPubText, err := primaryDialPubText(memberKid)
	if err != nil {
		t.Fatal(err)
	}
	dialNode, ok := transport.ParseNodeKey(dialPubText)
	if !ok {
		t.Fatalf("bad dial pub %q", dialPubText)
	}
	if err := writeDelegatedKeys(delegatedKey{
		Pub: mustParsePub(t, pub), PubText: pub, Node: dialNode,
	}); err != nil {
		t.Fatal(err)
	}
	// The member's carrier admits the coordinator's key the way the real
	// tunnel does: delegated-keys alone, for the coordination door only.
	memberState := filepath.Join(t.TempDir(), "member-state")
	memberTC, err := transport.StartTailcat(transport.TailcatConfig{
		StateDir: memberState,
		Port:     directPort,
		Allowed:  func() []key.NodePublic { return activeDelegateNodes() },
		Handler:  f.h,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer memberTC.Close()
	// The primary's carrier admits the file's browsers plus live join keys.
	primaryState := filepath.Join(t.TempDir(), "primary-state")
	primaryTC, err := transport.StartTailcat(transport.TailcatConfig{
		StateDir: primaryState,
		Port:     directPort,
		Allowed: func() []key.NodePublic {
			return append(loadAllowedClients(), activeJoinNodes()...)
		},
		Handler: f.h,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer primaryTC.Close()

	// The coordinator's client dials the member over real DERP and sends a
	// primary-signed put-key; the member verifies it under delegated-keys.
	conn, err := primaryDialFor(context.Background(), primaryMember{
		Agent: agentID(), Name: "Member", Addr: memberTC.ConnBlob(), Kid: memberKid,
	}, sign)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := conn.(interface{ Close() }); ok {
		defer closer.Close()
	}
	agent, caps, err := conn.hello(context.Background())
	if err != nil {
		t.Fatalf("member hello: %v", err)
	}
	if agent != agentID() {
		t.Fatalf("member agent %q", agent)
	}
	if !capsHas(caps, transport.CapDelegate) {
		t.Fatalf("member caps lack delegate: %v", caps)
	}
	res, err := conn.command(context.Background(), "put-key", "", `["agentB01"]`)
	if err != nil {
		t.Fatalf("put-key: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("delegated put-key over DERP: %+v", res)
	}
	var pk struct {
		Keys map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(res.Out), &pk); err != nil || len(pk.Keys) != 1 {
		t.Fatalf("put-key out: %q %v", res.Out, err)
	}
	// A kind outside delegatedKinds is refused the same way.
	res, err = conn.command(context.Background(), "sh", "", "uptime")
	if err != nil {
		t.Fatalf("sh: %v", err)
	}
	if res.Error != "not-delegated" {
		t.Fatalf("delegated sh over DERP: %+v", res)
	}

	// The join: a ticket on the primary, the join key dialing the primary's
	// carrier over real DERP, the roster gaining the member.
	setDirectAddress(primaryTC.ConnBlob())
	res = f.command(t, "primary-ticket", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-ticket: %+v", res)
	}
	tk := primaryTicketsLoad()[0]
	// The tunnel's own admit list is seeded at Start; the join key minted
	// after it needs the same AddAllowed the serveDirect ticker would do.
	if joinPub, ok := ticketJoinPub(tk); ok {
		primaryTC.AddAllowed(joinPub)
	}
	// The token carries the join private key; the ticket keeps only its pub.
	var tout struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(res.Out), &tout); err != nil {
		t.Fatal(err)
	}
	tparts := strings.Split(tout.Token, ".")
	var joinPriv key.NodePrivate
	if len(tparts) != 4 || joinPriv.UnmarshalText([]byte("privkey:"+tparts[2])) != nil {
		t.Fatalf("token join key: %q", tout.Token)
	}
	body, _ := json.Marshal(map[string]string{
		"agent": memberAgent, "name": "E2E Member", "addr": memberTC.ConnBlob(),
	})
	status, _, err := primaryJoinPost(context.Background(), primaryTC.ConnBlob(), joinPriv, body)
	if err != nil {
		t.Fatalf("join post: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("join status %d", status)
	}
	var joined bool
	for _, m := range readPrimaryRoster() {
		if m.Agent == memberAgent && m.Kid == "t:"+tk.ID {
			joined = true
		}
	}
	if !joined {
		t.Fatalf("roster after join: %+v", readPrimaryRoster())
	}
	// And the ticket is spent: a second join is refused.
	status, _, err = primaryJoinPost(context.Background(), primaryTC.ConnBlob(), joinPriv, body)
	if err != nil {
		t.Fatalf("second join post: %v", err)
	}
	if status != http.StatusForbidden {
		t.Fatalf("second join status %d", status)
	}
}

// The coordinator outlives the primary role: started before primary-on, it
// idles until the wake a primary-on sends, then a round happens — and
// primary-off stops the rounds without stopping the loop.
func TestPrimaryCoordinatorFollowsPrimaryOn(t *testing.T) {
	f := newPrimaryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { runPrimaryCoordinator(ctx); close(done) }()
	// Let it reach its wait with no primary-sign present.
	time.Sleep(50 * time.Millisecond)
	if primaryIsPrimary() {
		t.Fatal("primary before primary-on")
	}
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember("memberAA", "Member A", testPutAddr(t))))
	fa := &fakeMemberConn{agent: "memberAA", caps: []string{transport.CapPut}}
	withFakeMembers(t, map[string]*fakeMemberConn{"memberAA": fa})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && fa.hellos() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if fa.hellos() == 0 {
		t.Fatal("no round after primary-on")
	}
	// primary-off ends the rounds; the coordinator itself keeps waiting.
	res := f.command(t, "primary-off", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-off: %+v", res)
	}
	before := fa.hellos()
	time.Sleep(150 * time.Millisecond)
	if fa.hellos() != before {
		t.Fatal("a round ran after primary-off")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("coordinator did not stop with its context")
	}
}

func mustParsePub(t *testing.T, b64 string) ed25519.PublicKey {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("bad pub %q", b64)
	}
	return ed25519.PublicKey(b)
}

// A full roster refuses a NEW agent's join with 409 roster-full and keeps
// the ticket; once a slot frees, the same ticket joins.
func TestPrimaryJoinRosterFull(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	setDirectAddress(testPutAddr(t))
	t.Cleanup(func() { setDirectAddress("") })
	members := make([]primaryMember, 0, putMaxPeers)
	for i := 0; i < putMaxPeers; i++ {
		members = append(members, rosterMember(fmt.Sprintf("fillMem%02d", i), "F", testPutAddr(t)))
	}
	// The command door bounds Cmd at 2000 chars, so the adds go in batches.
	for i := 0; i < len(members); i += 4 {
		f.command(t, "primary-roster", "", rosterJSON(t, members[i:min(i+4, len(members))]...))
	}
	res := f.command(t, "primary-ticket", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-ticket: %+v", res)
	}
	tk := primaryTicketsLoad()[len(primaryTicketsLoad())-1]
	joinPub, ok := ticketJoinPub(tk)
	if !ok {
		t.Fatal("ticket join key does not parse")
	}
	body, _ := json.Marshal(primaryMember{Agent: "newJoin01", Name: "New", Addr: testPutAddr(t)})
	req := httptest.NewRequest(http.MethodPost, "/v1/primary/join", strings.NewReader(string(body)))
	req = req.WithContext(transport.WithPeer(req.Context(), joinPub))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "roster-full" {
		t.Fatalf("full-roster join: %d %s", rec.Code, rec.Body.String())
	}
	if len(primaryTicketsLoad()) != 1 {
		t.Fatal("a roster-full refusal consumed the ticket")
	}
	// Free a slot; the same ticket now joins.
	f.command(t, "primary-roster", "", `{"remove":["fillMem00"]}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/primary/join", strings.NewReader(string(body)))
	req = req.WithContext(transport.WithPeer(req.Context(), joinPub))
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("join after a slot freed: %d %s", rec.Code, rec.Body.String())
	}
}

// After primary-off the join door is shut and nothing comes back: the
// role's files stay gone and a join attempt is refused.
func TestPrimaryOffClosesJoin(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	setDirectAddress(testPutAddr(t))
	t.Cleanup(func() { setDirectAddress("") })
	res := f.command(t, "primary-ticket", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-ticket: %+v", res)
	}
	tk := primaryTicketsLoad()[0]
	joinPub, ok := ticketJoinPub(tk)
	if !ok {
		t.Fatal("ticket join key does not parse")
	}
	body, _ := json.Marshal(primaryMember{Agent: "lateJoin1", Name: "Late", Addr: testPutAddr(t)})
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/primary/join", strings.NewReader(string(body)))
		req = req.WithContext(transport.WithPeer(req.Context(), joinPub))
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec
	}
	res = f.command(t, "primary-off", "", "")
	if res.Code != 0 {
		t.Fatalf("primary-off: %+v", res)
	}
	for _, name := range []string{primarySignFile, primaryRosterFile, primaryTicketsFile, primaryDropsFile} {
		if _, err := os.Stat(primaryPath(name)); !os.IsNotExist(err) {
			t.Fatalf("%s came back after primary-off", name)
		}
	}
	if rec := call(); rec.Code != http.StatusForbidden {
		t.Fatalf("join after primary-off: %d %s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{primarySignFile, primaryRosterFile, primaryTicketsFile, primaryDropsFile} {
		if _, err := os.Stat(primaryPath(name)); !os.IsNotExist(err) {
			t.Fatalf("%s came back after the refused join", name)
		}
	}
}

// The connection cache is keyed by the signing pub too: a different key
// redials, and primary-off/on clears the cache so the next round dials
// again even under the same key.
func TestPrimaryConnCacheFollowsKey(t *testing.T) {
	f := newPrimaryFixture(t)
	f.primaryOn(t)
	f.command(t, "primary-roster", "", rosterJSON(t,
		rosterMember("memberAA", "Member A", testPutAddr(t))))
	m := readPrimaryRoster()[0]
	sign, err := primarySignKey()
	if err != nil {
		t.Fatal(err)
	}
	dials := 0
	var lastPub string
	old := primaryDialFor
	primaryDialFor = func(ctx context.Context, mm primaryMember, s ed25519.PrivateKey) (memberConn, error) {
		dials++
		lastPub = base64.StdEncoding.EncodeToString(s.Public().(ed25519.PublicKey))
		return &fakeMemberConn{agent: mm.Agent}, nil
	}
	t.Cleanup(func() { primaryDialFor = old })
	ctx := context.Background()
	if _, err := primaryConnFor(ctx, m, sign); err != nil {
		t.Fatal(err)
	}
	if _, err := primaryConnFor(ctx, m, sign); err != nil {
		t.Fatal(err)
	}
	if dials != 1 {
		t.Fatalf("cached conn redialed: %d", dials)
	}
	// A different signing key never reuses the conn.
	_, other, _ := ed25519.GenerateKey(nil)
	otherPub := base64.StdEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
	if _, err := primaryConnFor(ctx, m, other); err != nil {
		t.Fatal(err)
	}
	if dials != 2 || lastPub != otherPub {
		t.Fatalf("key change did not redial: dials=%d pub=%q", dials, lastPub)
	}
	// primary-off/on clears the cache: the same key dials again.
	if res := f.command(t, "primary-off", "", ""); res.Code != 0 {
		t.Fatalf("primary-off: %+v", res)
	}
	if res := f.command(t, "primary-on", "", ""); res.Code != 0 {
		t.Fatalf("primary-on: %+v", res)
	}
	sign2, err := primarySignKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := primaryConnFor(ctx, m, sign2); err != nil {
		t.Fatal(err)
	}
	if dials != 3 {
		t.Fatalf("off/on did not clear the conn cache: %d", dials)
	}
}
