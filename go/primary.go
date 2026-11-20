package main

// primary.go — the primary helper: one machine that holds its own ed25519
// signing key (primary-sign, generated here and never leaving), a roster of
// the owner's other helpers, and a coordinator that does over the tunnel
// what the page's putSweep does while the page is closed.
//
// Trust boundary: members accept the primary's signature only for the kinds
// in delegatedKinds (signing.go), pinned on each member as delegated-keys
// (delegate.go). The primary's private key signs commands exactly as a
// browser's does — commandSigningInput — but commandSigner stays
// full-keys-only, so a primary can never own a terminal, a screen or a
// files grant. Members join two ways: the page adds them to the roster and
// sends `delegate`; or they install with --primary <token> and dial the
// join door below with a one-time ticket key.
//
// Files (all 0600 in the 0700 config dir):
//   primary-sign    64 hex — the ed25519 seed; its presence means THIS
//                   machine is the primary.
//   primary-seed    64 hex — random 32-byte seed for coordinator dial keys.
//   primary-roster  JSON [{"agent","name","addr","kid"}]
//   primary-tickets JSON [{"id","join_pub","until"}] — join_pub is a
//                   nodekey: text, until unix seconds; the private join
//                   key lives only in the minted token.
//   primary-drops   JSON [{"agent","at","done":[…]}] — roster removals
//                   still being carried to the members as empty put-peer.
//   primary-join    installer-written on a MEMBER: line 1 the primary's
//                   tunnel address, line 2 the ticket's join private key.

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	primarySignFile    = "primary-sign"
	primarySeedFile    = "primary-seed"
	primaryRosterFile  = "primary-roster"
	primaryTicketsFile = "primary-tickets"
	primaryDropsFile   = "primary-drops"
	primaryJoinFile    = "primary-join"

	primaryTicketTTL   = 7 * 24 * time.Hour
	primaryTicketMax   = 64
	primaryJoinEvery   = 30 * time.Second
	primaryJoinBodyMax = 4 << 10
	primaryRoundEvery  = 10 * time.Minute
	primaryConnIdle    = 10 * time.Minute
	primaryCallWait    = 30 * time.Second
	primaryDropMaxAge  = 30 * 24 * time.Hour
)

// primaryFileMu serialises roster/tickets read-modify-write: the join door
// and the commands can meet on the same files.
var primaryFileMu sync.Mutex

func primaryPath(name string) string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, name)
}

// primaryIsPrimary reports whether primary-sign exists — its presence is
// the whole claim, per the file contract.
func primaryIsPrimary() bool {
	path := primaryPath(primarySignFile)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func primarySignKey() (ed25519.PrivateKey, error) {
	path := primaryPath(primarySignFile)
	if path == "" {
		return nil, errors.New("no config directory")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("primary-sign is not a 32-byte hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func primarySeedBytes() ([]byte, error) {
	path := primaryPath(primarySeedFile)
	if path == "" {
		return nil, errors.New("no config directory")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != 32 {
		return nil, errors.New("primary-seed is not a 32-byte hex seed")
	}
	return seed, nil
}

// ensurePrimarySeeds creates primary-sign and primary-seed when absent and
// answers the signing public key in base64. Idempotent: an existing seed is
// kept, so the answer never rotates.
func ensurePrimarySeeds() (string, error) {
	if k, err := primarySignKey(); err == nil {
		return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), nil
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	dial := make([]byte, 32)
	if _, err := rand.Read(dial); err != nil {
		return "", err
	}
	dir := configDir()
	if dir == "" {
		return "", errors.New("no config directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for name, b := range map[string][]byte{primarySignFile: seed, primarySeedFile: dial} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		tmp := path + ".new"
		if err := os.WriteFile(tmp, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return "", err
		}
	}
	k, err := primarySignKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), nil
}

// primaryDialKey is the key the coordinator dials the member named by kid
// from: HMAC-SHA256(primary-seed, "primary dial key\x00"+kid), clamped
// exactly as putKeyFor does (put.go).
func primaryDialKey(kid string) (key.NodePrivate, error) {
	seed, err := primarySeedBytes()
	if err != nil {
		return key.NodePrivate{}, err
	}
	mac := hmac.New(sha256.New, seed)
	io.WriteString(mac, "primary dial key\x00"+kid)
	raw := mac.Sum(nil)
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte("privkey:" + hex.EncodeToString(raw))); err != nil {
		return key.NodePrivate{}, err
	}
	return priv, nil
}

// primaryDialPubText is "nodekey:<hex>" for the coordinator dial key of kid.
func primaryDialPubText(kid string) (string, error) {
	priv, err := primaryDialKey(kid)
	if err != nil {
		return "", err
	}
	return priv.Public().String(), nil
}

// ── roster and tickets ─────────────────────────────────────────────────

type primaryMember struct {
	Agent string `json:"agent"`
	Name  string `json:"name"`
	Addr  string `json:"addr"`
	Kid   string `json:"kid"`
}

type primaryTicket struct {
	ID string `json:"id"`
	// JoinPub is the join key's PUBLIC half as "nodekey:<hex>" — the private
	// key is minted into the token and never kept at rest.
	JoinPub string `json:"join_pub"`
	Until   int64  `json:"until"`
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSONFile(path string, v any) error {
	if path == "" {
		return errors.New("no config directory")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// primaryRosterLoad/Save are the unlocked halves; callers hold primaryFileMu
// when a read-modify-write must be atomic (the join door).
func primaryRosterLoad() []primaryMember {
	path := primaryPath(primaryRosterFile)
	if path == "" {
		return nil
	}
	var list []primaryMember
	if err := readJSONFile(path, &list); err != nil {
		if !os.IsNotExist(err) {
			warnf("primary: %s is unreadable; the roster reads empty", path)
		}
		return nil
	}
	return list
}

func primaryRosterSave(list []primaryMember) error {
	return writeJSONFile(primaryPath(primaryRosterFile), list)
}

func readPrimaryRoster() []primaryMember {
	primaryFileMu.Lock()
	defer primaryFileMu.Unlock()
	return primaryRosterLoad()
}

func primaryTicketsLoad() []primaryTicket {
	path := primaryPath(primaryTicketsFile)
	if path == "" {
		return nil
	}
	var list []primaryTicket
	if err := readJSONFile(path, &list); err != nil {
		if !os.IsNotExist(err) {
			warnf("primary: %s is unreadable; the tickets read empty", path)
		}
		return nil
	}
	return list
}

func primaryTicketsSave(list []primaryTicket) error {
	return writeJSONFile(primaryPath(primaryTicketsFile), list)
}

// ticketJoinPub is the join public key a ticket admits, stored as text.
func ticketJoinPub(t primaryTicket) (key.NodePublic, bool) {
	return transport.ParseNodeKey(t.JoinPub)
}

func ticketLive(t primaryTicket, now time.Time) bool {
	return t.Until > now.Unix()
}

// activeJoinNodes are the join public keys the tunnel admits: unexpired,
// unused tickets (a used one is deleted at the door) — and only while this
// machine is the primary, so a stale file after primary-off admits nothing.
func activeJoinNodes() []key.NodePublic {
	if !primaryIsPrimary() {
		return nil
	}
	var out []key.NodePublic
	now := time.Now()
	for _, t := range primaryTicketsLoad() {
		if !ticketLive(t, now) {
			continue
		}
		if pub, ok := ticketJoinPub(t); ok {
			out = append(out, pub)
		}
	}
	return out
}

// primaryJoinForNode finds the live ticket whose join key this peer holds.
func primaryJoinForNode(k key.NodePublic) (primaryTicket, bool) {
	if !primaryIsPrimary() {
		return primaryTicket{}, false
	}
	now := time.Now()
	for _, t := range primaryTicketsLoad() {
		if !ticketLive(t, now) {
			continue
		}
		if pub, ok := ticketJoinPub(t); ok && pub == k {
			return t, true
		}
	}
	return primaryTicket{}, false
}

// ── the coordinator's wake ─────────────────────────────────────────────

var primaryWakeCh = make(chan struct{}, 1)

func primaryWake() {
	select {
	case primaryWakeCh <- struct{}{}:
	default:
	}
}

// ── the six command kinds ──────────────────────────────────────────────

// primarySealed is the gate every primary command shares: a pinned full
// key, like the put commands (put.go).
func primarySealed(c consoleCmd) (consoleResult, bool) {
	res := consoleResult{ID: c.ID, Kind: c.Kind, Code: -1}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res, false
	}
	return res, true
}

// runPrimaryOn makes this machine the primary: primary-sign and
// primary-seed are created once and kept, so the answer is stable.
func runPrimaryOn(c consoleCmd) consoleResult {
	res, ok := primarySealed(c)
	if !ok {
		return res
	}
	if strings.TrimSpace(c.Target) != "" || strings.TrimSpace(c.Cmd) != "" {
		res.Error = "bad-args"
		return res
	}
	pub, err := ensurePrimarySeeds()
	if err != nil {
		warnf("primary: could not make the signing key: %v", err)
		res.Error = "unavailable"
		return res
	}
	primaryConnsReset()
	primaryWake()
	b, _ := json.Marshal(map[string]string{"pub": pub, "addr": directAddress()})
	res.Code, res.Out = 0, string(b)
	return res
}

// runPrimaryOff ends the primary role: the signing key, the roster and the
// tickets go; primary-seed stays, so a later primary-on derives the same
// dial keys for the same kids.
func runPrimaryOff(c consoleCmd) consoleResult {
	res, ok := primarySealed(c)
	if !ok {
		return res
	}
	if strings.TrimSpace(c.Target) != "" || strings.TrimSpace(c.Cmd) != "" {
		res.Error = "bad-args"
		return res
	}
	if !primaryIsPrimary() {
		res.Error = "not-primary"
		return res
	}
	// Under the lock, and failing closed: while primary-sign survives this
	// machine still IS the primary, so its removal failing is the command's
	// failure — the other files warn and the role still ends.
	primaryFileMu.Lock()
	for _, name := range []string{primarySignFile, primaryRosterFile, primaryTicketsFile, primaryDropsFile} {
		if path := primaryPath(name); path != "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				if name == primarySignFile {
					primaryFileMu.Unlock()
					res.Error = "save-failed"
					return res
				}
				warnf("primary: could not remove %s: %v", name, err)
			}
		}
	}
	primaryFileMu.Unlock()
	primaryConnsReset()
	primaryWake()
	res.Code, res.Out = 0, "{}"
	return res
}

// rosterArgs is the primary-roster command's payload.
type rosterArgs struct {
	Add    []primaryMember `json:"add"`
	Remove []string        `json:"remove"`
}

func primaryMemberOK(m primaryMember) bool {
	if !putAgentRE.MatchString(m.Agent) || !putNameOK(m.Name) || len(m.Addr) > putAddrMax {
		return false
	}
	_, err := tailcat.ParseAddr(tailcat.Addr(m.Addr))
	return err == nil
}

// runPrimaryRoster edits the member list. kid is "a:<agent>" for page-added
// members and is kept across name/addr updates; removals leave a tombstone
// in primary-drops that the coordinator carries to every put member as an
// empty put-peer until they have all acked or it ages out.
func runPrimaryRoster(c consoleCmd) consoleResult {
	res, ok := primarySealed(c)
	if !ok {
		return res
	}
	if !primaryIsPrimary() {
		res.Error = "not-primary"
		return res
	}
	var args rosterArgs
	cmd := strings.TrimSpace(c.Cmd)
	if cmd != "" {
		if json.Unmarshal([]byte(cmd), &args) != nil {
			res.Error = "bad-args"
			return res
		}
	}
	primaryFileMu.Lock()
	list := primaryRosterLoad()
	for _, m := range args.Add {
		if !primaryMemberOK(m) {
			primaryFileMu.Unlock()
			res.Error = "bad-args"
			return res
		}
	}
	seen := map[string]bool{}
	var added []string
	for _, m := range args.Add {
		if seen[m.Agent] {
			continue
		}
		seen[m.Agent] = true
		added = append(added, m.Agent)
		found := false
		for i := range list {
			if list[i].Agent == m.Agent {
				list[i].Name, list[i].Addr = m.Name, m.Addr // kid kept
				found = true
				break
			}
		}
		if !found {
			if len(list) >= putMaxPeers {
				primaryFileMu.Unlock()
				res.Error = "too-many"
				return res
			}
			list = append(list, primaryMember{Agent: m.Agent, Name: m.Name, Addr: m.Addr, Kid: "a:" + m.Agent})
		}
	}
	var removed []string
	for _, agent := range args.Remove {
		keep := list[:0]
		for _, m := range list {
			if m.Agent == agent {
				removed = append(removed, agent)
				continue
			}
			keep = append(keep, m)
		}
		list = keep
	}
	if err := primaryRosterSave(list); err != nil {
		primaryFileMu.Unlock()
		res.Error = "save-failed"
		return res
	}
	// The roster is already saved, so a drops failure warns rather than
	// fails the command — a retry would find the agent gone from the
	// roster and never write the tombstone.
	if err := primaryDropsUpdate(added, removed); err != nil {
		warnf("primary: roster saved but primary-drops would not write: %v", err)
	}
	primaryFileMu.Unlock()
	rosterJSON := []map[string]string{}
	keys := map[string]string{}
	for _, m := range list {
		rosterJSON = append(rosterJSON, map[string]string{"agent": m.Agent, "name": m.Name, "kid": m.Kid})
		if text, err := primaryDialPubText(m.Kid); err == nil {
			keys[m.Agent] = text
		}
	}
	b, _ := json.Marshal(map[string]any{"roster": rosterJSON, "keys": keys})
	res.Code, res.Out = 0, string(b)
	primaryWake()
	return res
}

// primaryDrop is one roster removal still being carried to the members:
// put-peer drops are fire-and-forget over the tunnel, so the tombstone is
// a file — it survives restarts and keeps each member's ack until every
// put-capable member has answered or it ages out.
type primaryDrop struct {
	Agent string   `json:"agent"`
	At    int64    `json:"at"`
	Done  []string `json:"done"`
}

func primaryDropsLoad() []primaryDrop {
	path := primaryPath(primaryDropsFile)
	if path == "" {
		return nil
	}
	var out []primaryDrop
	if err := readJSONFile(path, &out); err != nil {
		if !os.IsNotExist(err) {
			warnf("primary: %s is unreadable; the drops read empty", path)
		}
		return nil
	}
	return out
}

func primaryDropsSave(drops []primaryDrop) error {
	return writeJSONFile(primaryPath(primaryDropsFile), drops)
}

// primaryDropsUpdate applies one roster edit to the tombstones: a removed
// agent gains one, a re-added agent loses it. Callers hold primaryFileMu.
func primaryDropsUpdate(added, removed []string) error {
	drops := primaryDropsLoad()
	dirty := false
	if len(added) > 0 {
		keep := drops[:0]
		for _, d := range drops {
			back := false
			for _, a := range added {
				if d.Agent == a {
					back = true
					break
				}
			}
			if back {
				dirty = true
			} else {
				keep = append(keep, d)
			}
		}
		drops = keep
	}
	for _, agent := range removed {
		found := false
		for _, d := range drops {
			if d.Agent == agent {
				found = true
				break
			}
		}
		if !found {
			drops = append(drops, primaryDrop{Agent: agent, At: time.Now().Unix()})
			dirty = true
		}
	}
	if !dirty {
		return nil
	}
	return primaryDropsSave(drops)
}

// primaryDropsRound carries each tombstone's empty put-peer to every
// answered put member that has not acked it — the primary itself
// in-process included — then drops what is finished or too old.
func primaryDropsRound(ctx context.Context, links []*sweepLink) {
	drops := primaryDropsLoad()
	if len(drops) == 0 {
		return
	}
	var putMembers []*sweepLink
	for _, l := range links {
		if l.put {
			putMembers = append(putMembers, l)
		}
	}
	dirty := false
	kept := drops[:0]
	for _, d := range drops {
		if time.Since(time.Unix(d.At, 0)) > primaryDropMaxAge {
			dirty = true
			continue
		}
		done := map[string]bool{}
		for _, a := range d.Done {
			done[a] = true
		}
		complete := func() bool {
			for _, l := range putMembers {
				if !done[l.agent] {
					return false
				}
			}
			return true
		}
		if complete() {
			dirty = true
			continue
		}
		for _, l := range putMembers {
			if !l.answered || done[l.agent] {
				continue
			}
			if primaryPutPeer(ctx, l, d.Agent, "") {
				d.Done = append(d.Done, l.agent)
				done[l.agent] = true
				dirty = true
			}
		}
		if complete() {
			dirty = true
			continue
		}
		kept = append(kept, d)
	}
	if dirty {
		if err := primaryDropsSave(kept); err != nil {
			warnf("primary: could not save primary-drops: %v", err)
		}
	}
}

// runPrimaryTicket mints a one-time join ticket: the page puts the token
// into an install line as --primary <token>.
func runPrimaryTicket(c consoleCmd) consoleResult {
	res, ok := primarySealed(c)
	if !ok {
		return res
	}
	if !primaryIsPrimary() {
		res.Error = "not-primary"
		return res
	}
	if strings.TrimSpace(c.Target) != "" || strings.TrimSpace(c.Cmd) != "" {
		res.Error = "bad-args"
		return res
	}
	addr := directAddress()
	if addr == "" {
		res.Error = "no-tunnel"
		return res
	}
	pub, err := primarySignKey()
	if err != nil {
		res.Error = "unavailable"
		return res
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		res.Error = "unavailable"
		return res
	}
	id := hex.EncodeToString(idb[:])
	join := key.NewNode()
	joinText, _ := join.MarshalText()
	joinHex := strings.TrimPrefix(string(joinText), "privkey:")
	kid := "t:" + id
	dialPub, err := primaryDialPubText(kid)
	if err != nil {
		res.Error = "unavailable"
		return res
	}
	dialHex := strings.TrimPrefix(dialPub, "nodekey:")
	ticket := primaryTicket{ID: id, JoinPub: join.Public().String(), Until: time.Now().Add(primaryTicketTTL).Unix()}
	primaryFileMu.Lock()
	tickets := primaryTicketsLoad()
	// Unexpired tickets only count toward the cap; expired ones are pruned.
	live := tickets[:0]
	now := time.Now()
	for _, t := range tickets {
		if ticketLive(t, now) {
			live = append(live, t)
		}
	}
	for len(live) >= primaryTicketMax {
		live = live[1:]
	}
	live = append(live, ticket)
	if err := primaryTicketsSave(live); err != nil {
		primaryFileMu.Unlock()
		res.Error = "save-failed"
		return res
	}
	primaryFileMu.Unlock()
	admitNow(join.Public())
	primaryWake()
	token := base64.StdEncoding.EncodeToString(pub.Public().(ed25519.PublicKey)) + "." +
		dialHex + "." + joinHex + "." + addr
	b, _ := json.Marshal(map[string]string{"token": token})
	res.Code, res.Out = 0, string(b)
	return res
}

// ── the join door (the primary's side) ─────────────────────────────────

// primaryJoinServe is the only door a ticket's join key reaches: POST
// /v1/primary/join, classified in ServeHTTP like a put peer's stream.
func (h *directHandler) primaryJoinServe(w http.ResponseWriter, r *http.Request, ticket primaryTicket) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/primary/join" {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, primaryJoinBodyMax+1))
	if err != nil || len(body) > primaryJoinBodyMax {
		h.refuse(w, http.StatusBadRequest, "bad-frame")
		return
	}
	var m primaryMember
	if len(body) == 0 || json.Unmarshal(body, &m) != nil || !primaryMemberOK(m) {
		h.refuse(w, http.StatusBadRequest, "bad-args")
		return
	}
	m.Kid = "t:" + ticket.ID
	primaryFileMu.Lock()
	// Everything is judged under the lock: the role may have ended between
	// the classification and this request, the ticket may have been spent
	// or expired, and a refusal must never consume it.
	if !primaryIsPrimary() {
		primaryFileMu.Unlock()
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	tickets := primaryTicketsLoad()
	live := false
	kept := tickets[:0]
	now := time.Now()
	for _, t := range tickets {
		if t.ID == ticket.ID {
			if ticketLive(t, now) {
				live = true
			}
			continue
		}
		kept = append(kept, t)
	}
	if !live {
		primaryFileMu.Unlock()
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	// A join must not take over an identity: the primary's own agent id is
	// never a member, and an agent already on the roster under another kid
	// keeps it — only a retry under the same kid updates.
	if m.Agent == agentID() {
		primaryFileMu.Unlock()
		h.refuse(w, http.StatusConflict, "agent-taken")
		return
	}
	list := primaryRosterLoad()
	found := false
	for _, e := range list {
		if e.Agent == m.Agent && e.Kid != m.Kid {
			primaryFileMu.Unlock()
			h.refuse(w, http.StatusConflict, "agent-taken")
			return
		}
		if e.Agent == m.Agent {
			found = true
		}
	}
	// A new agent needs a roster slot; a full roster refuses without
	// spending the ticket.
	if !found && len(list) >= putMaxPeers {
		primaryFileMu.Unlock()
		h.refuse(w, http.StatusConflict, "roster-full")
		return
	}
	for i := range list {
		if list[i].Agent == m.Agent {
			list[i].Name, list[i].Addr, list[i].Kid = m.Name, m.Addr, m.Kid
			found = true
			break
		}
	}
	if !found {
		list = append(list, m)
	}
	if err := primaryRosterSave(list); err != nil {
		primaryFileMu.Unlock()
		h.refuse(w, http.StatusInternalServerError, "unavailable")
		return
	}
	// The ticket is spent last — after the roster landed. A save failure
	// here still answers the join that already happened.
	if err := primaryTicketsSave(kept); err != nil {
		warnf("primary: %s joined but its ticket would not clear: %v", m.Agent, err)
	}
	primaryFileMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(`{"ok":true}`))
	primaryWake()
}

// ── the join client (a member's side) ─────────────────────────────────

// primaryJoinFileState is what runPrimaryJoin needs from primary-join.
type primaryJoinFileState struct {
	addr string
	priv key.NodePrivate
	mod  time.Time
}

func readPrimaryJoinFile(path string) (*primaryJoinFileState, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 2 {
		return nil, errors.New("primary-join names no join key")
	}
	addr := strings.TrimSpace(lines[0])
	if _, err := tailcat.ParseAddr(tailcat.Addr(addr)); err != nil {
		return nil, fmt.Errorf("primary-join's address: %w", err)
	}
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte("privkey:" + strings.TrimSpace(lines[1]))); err != nil {
		return nil, fmt.Errorf("primary-join's key: %w", err)
	}
	return &primaryJoinFileState{addr: addr, priv: priv, mod: fi.ModTime()}, nil
}

// primaryJoinPost dials the primary and posts the join body; it answers the
// HTTP status and the refusal's error code when the body carries one.
func primaryJoinPost(ctx context.Context, addr string, priv key.NodePrivate, body []byte) (int, string, error) {
	cl := &tailcat.Client{Server: tailcat.ConnBlob(addr), Key: priv, Logf: logger.Discard, DERPMapURL: derpMapURL()}
	defer cl.Close()
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return cl.DialTCPPort(ctx, directPort)
		},
		MaxIdleConnsPerHost: 2,
	}}
	ctx, cancel := context.WithTimeout(ctx, primaryCallWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://tailcat/v1/primary/join", strings.NewReader(string(body)))
	if err != nil {
		return 0, "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	var code string
	if f, derr := transport.Decode(b); derr == nil && f.Type == transport.TypeError {
		var e transport.Error
		if json.Unmarshal(f.Body, &e) == nil {
			code = e.Code
		}
	}
	return resp.StatusCode, code, nil
}

// runPrimaryJoin is the member's side of --primary: while the installer-
// written primary-join file exists and this machine's tunnel is up, it
// dials the primary with the ticket's join key and asks to join. 200, 403
// and every 409 end it — joined, or refused for good; anything else
// retries.
func runPrimaryJoin(ctx context.Context, conf string) {
	if conf == "" {
		return
	}
	path := filepath.Join(conf, primaryJoinFile)
	for {
		st, err := readPrimaryJoinFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			warnf("primary: could not read primary-join: %v", err)
			os.Remove(path)
		case time.Since(st.mod) > primaryTicketTTL:
			os.Remove(path)
		default:
			if addr := directAddress(); addr != "" {
				body, _ := json.Marshal(map[string]string{
					"agent": agentID(), "name": agentLabel(), "addr": addr,
				})
				status, code, jerr := primaryJoinPost(ctx, st.addr, st.priv, body)
				switch {
				case jerr == nil && status == http.StatusOK:
					os.Remove(path)
					warnf("primary: joined %s — this machine is on its roster", st.addr)
				case jerr == nil && status == http.StatusForbidden:
					os.Remove(path)
					warnf("primary: the join was refused (403) — primary-join removed; mint a new line if this was a mistake")
				case jerr == nil && status == http.StatusConflict:
					os.Remove(path)
					if code != "" {
						warnf("primary: the join was refused (%s) — primary-join removed", code)
					} else {
						warnf("primary: the join was refused — primary-join removed")
					}
				case jerr != nil && ctx.Err() == nil:
					// Unreachable or timed out: try again next tick.
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(primaryJoinEvery):
		}
	}
}

// ── the coordinator ────────────────────────────────────────────────────

// memberConn is one member's tunnel connection for a coordinator round —
// the seam the round is unit-tested through.
type memberConn interface {
	// hello answers the member's agent id and capability list.
	hello(ctx context.Context) (agent string, caps []string, err error)
	// command sends one signed command and returns the console result.
	command(ctx context.Context, kind, target, cmd string) (consoleResult, error)
}

// primaryConn is the real memberConn: a tailcat client under the
// coordinator's dial key for the member's kid, commands signed with
// primary-sign — the clonecli.go command() pattern.
type primaryConn struct {
	agent string
	cl    *tailcat.Client
	hc    *http.Client
	sign  ed25519.PrivateKey
}

// primaryDialFor makes a member's connection; a test puts fakes in its
// place, as putDial does for put clients.
var primaryDialFor = func(ctx context.Context, m primaryMember, sign ed25519.PrivateKey) (memberConn, error) {
	priv, err := primaryDialKey(m.Kid)
	if err != nil {
		return nil, err
	}
	cl := &tailcat.Client{Server: tailcat.ConnBlob(m.Addr), Key: priv, Logf: logger.Discard, DERPMapURL: derpMapURL()}
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return cl.DialTCPPort(ctx, directPort)
		},
		MaxIdleConnsPerHost: 2,
	}}
	return &primaryConn{agent: m.Agent, cl: cl, hc: hc, sign: sign}, nil
}

func (c *primaryConn) Close() { c.cl.Close() }

func (c *primaryConn) get(ctx context.Context, path string) (transport.Frame, error) {
	ctx, cancel := context.WithTimeout(ctx, primaryCallWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://tailcat"+path, nil)
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

func (c *primaryConn) hello(ctx context.Context) (string, []string, error) {
	f, err := c.get(ctx, "/v1/hello")
	if err != nil {
		return "", nil, err
	}
	if f.Type == transport.TypeError {
		var e transport.Error
		json.Unmarshal(f.Body, &e)
		return "", nil, errors.New(e.Code)
	}
	if f.Type != transport.TypeHello {
		return "", nil, errors.New("bad-frame")
	}
	var h transport.Hello
	if err := json.Unmarshal(f.Body, &h); err != nil {
		return "", nil, err
	}
	return f.AgentID, h.Caps, nil
}

func primaryCmdID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (c *primaryConn) command(ctx context.Context, kind, target, cmd string) (consoleResult, error) {
	id := primaryCmdID()
	at := time.Now().Unix()
	sig := ed25519.Sign(c.sign, commandSigningInput(c.agent, id, kind, target, at, cmd))
	f, err := transport.New(transport.TypeCommand, c.agent, id, transport.Command{
		Kind: kind, Cmd: cmd, Target: target, Sig: base64.StdEncoding.EncodeToString(sig), At: at,
	})
	if err != nil {
		return consoleResult{}, err
	}
	body, err := transport.Encode(f)
	if err != nil {
		return consoleResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, primaryCallWait*4)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://tailcat/v1/command", strings.NewReader(string(body)))
	if err != nil {
		return consoleResult{}, err
	}
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

// ── the round ──────────────────────────────────────────────────────────

// primaryLinkEntry is a cached member connection, the putClients pattern:
// kept between rounds so the next one finds the tunnel up, recreated when
// the member's addr or kid changes, reaped when idle.
var primaryLinkCache = struct {
	sync.Mutex
	m map[string]*primaryLinkEntry
}{}

type primaryLinkEntry struct {
	conn      memberConn
	closer    interface{ Close() }
	pub       string // the signing key's base64 — a conn never crosses keys
	addr, kid string
	last      time.Time
}

// primaryConnsReset drops every cached member connection: a signing-key
// change must never reuse a conn opened under the old key.
func primaryConnsReset() {
	primaryLinkCache.Lock()
	defer primaryLinkCache.Unlock()
	for _, e := range primaryLinkCache.m {
		if c, ok := e.conn.(interface{ Close() }); ok {
			c.Close()
		}
	}
	primaryLinkCache.m = nil
}

func primaryConnFor(ctx context.Context, m primaryMember, sign ed25519.PrivateKey) (memberConn, error) {
	primaryLinkCache.Lock()
	defer primaryLinkCache.Unlock()
	if primaryLinkCache.m == nil {
		primaryLinkCache.m = map[string]*primaryLinkEntry{}
	}
	pubText := base64.StdEncoding.EncodeToString(sign.Public().(ed25519.PublicKey))
	if e := primaryLinkCache.m[m.Agent]; e != nil && e.addr == m.Addr && e.kid == m.Kid && e.pub == pubText {
		e.last = time.Now()
		return e.conn, nil
	}
	if e := primaryLinkCache.m[m.Agent]; e != nil {
		delete(primaryLinkCache.m, m.Agent)
		if c, ok := e.conn.(interface{ Close() }); ok {
			c.Close()
		}
	}
	conn, err := primaryDialFor(ctx, m, sign)
	if err != nil {
		return nil, err
	}
	primaryLinkCache.m[m.Agent] = &primaryLinkEntry{conn: conn, pub: pubText, addr: m.Addr, kid: m.Kid, last: time.Now()}
	return conn, nil
}

func primaryReapConns() {
	primaryLinkCache.Lock()
	defer primaryLinkCache.Unlock()
	for agent, e := range primaryLinkCache.m {
		if time.Since(e.last) > primaryConnIdle {
			delete(primaryLinkCache.m, agent)
			if c, ok := e.conn.(interface{ Close() }); ok {
				c.Close()
			}
		}
	}
}

// primaryKnown mirrors the page's putKnown: per-member put-key answers
// kept between rounds, pruned to the roster (agent present, same addr and
// kid) exactly as the page prunes to its listed machines.
var primaryKnown = struct {
	sync.Mutex
	m map[string]*primaryKnownEntry
}{}

type primaryKnownEntry struct {
	agent, name, addr, kid string
	keys                   map[string]string
}

// sweepLink is one member's state within a round.
type sweepLink struct {
	agent, name, addr, kid string
	conn                   memberConn // nil → the primary itself, in-process
	self                   bool
	put                    bool // hello said put (self: putSupported)
	answered               bool // put-key succeeded this round
	keys, held             map[string]string
}

func capsHas(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// primarySelfName prefers the machine's own reported name over the roster's.
func primarySelfName(m primaryMember) string {
	if n := agentLabel(); n != "" {
		return n
	}
	return m.Name
}

// primaryPutKey asks one link for its dial keys and held digests — over the
// tunnel for a member, in-process for the primary itself.
func primaryPutKey(ctx context.Context, l *sweepLink, dests []string) bool {
	dj, _ := json.Marshal(dests)
	var out string
	if l.self {
		r := runPutKey(consoleCmd{ID: primaryCmdID(), Kind: "put-key", Cmd: string(dj)})
		if r.Code != 0 {
			return false
		}
		out = r.Out
	} else {
		r, err := l.conn.command(ctx, "put-key", "", string(dj))
		if err != nil || r.Code != 0 {
			return false
		}
		out = r.Out
	}
	var po struct {
		Keys map[string]string `json:"keys"`
		Held map[string]string `json:"held"`
	}
	if json.Unmarshal([]byte(out), &po) != nil {
		return false
	}
	l.keys, l.held = po.Keys, po.Held
	return true
}

// primaryPutPeer sends one put-peer entry (or a drop, with cmd == "") —
// over the tunnel for a member, in-process for the primary itself.
func primaryPutPeer(ctx context.Context, l *sweepLink, target, cmd string) bool {
	if l.self {
		r := runPutPeer(consoleCmd{ID: primaryCmdID(), Kind: "put-peer", Target: target, Cmd: cmd})
		return r.Code == 0
	}
	r, err := l.conn.command(ctx, "put-peer", target, cmd)
	return err == nil && r.Code == 0
}

// primaryRound is one coordination pass: hello every member, collect
// put-key answers, push the put-peer diffs, then the queued drops — the
// page's putSweep with the roster in place of the page's list.
func primaryRound(ctx context.Context) {
	sign, err := primarySignKey()
	if err != nil || sign == nil {
		return
	}
	roster := readPrimaryRoster()
	if len(roster) == 0 {
		return
	}
	var links []*sweepLink
	var agents []string
	for _, m := range roster {
		agents = append(agents, m.Agent)
	}
	for _, m := range roster {
		if m.Agent == agentID() {
			// The primary can be a put member itself; in-process, never
			// over its own tunnel (and only where put runs — put.go).
			if putSupported {
				links = append(links, &sweepLink{
					agent: m.Agent, name: primarySelfName(m), addr: m.Addr, kid: m.Kid,
					self: true, put: true,
				})
			}
			continue
		}
		l := &sweepLink{agent: m.Agent, name: m.Name, addr: m.Addr, kid: m.Kid}
		if conn, err := primaryConnFor(ctx, m, sign); err == nil {
			if agent, caps, herr := conn.hello(ctx); herr == nil && agent == m.Agent {
				l.conn = conn
				l.put = capsHas(caps, transport.CapPut)
			}
		}
		links = append(links, l)
	}
	// put-key for every put-capable link; dests are all roster agents but
	// the asker's own, as the page sends them.
	for _, l := range links {
		if !l.put {
			continue
		}
		var dests []string
		for _, a := range agents {
			if a != l.agent {
				dests = append(dests, a)
			}
		}
		if primaryPutKey(ctx, l, dests) {
			l.answered = true
		}
		// A failed put-key only keeps the member out of this round's
		// pushes; it is still put-capable, so the queued drops still go.
	}
	// Merge this round's answers into the known set, pruned to the roster.
	primaryKnown.Lock()
	if primaryKnown.m == nil {
		primaryKnown.m = map[string]*primaryKnownEntry{}
	}
	inRoster := map[string]primaryMember{}
	for _, m := range roster {
		inRoster[m.Agent] = m
	}
	for agent, e := range primaryKnown.m {
		m, ok := inRoster[agent]
		if !ok || m.Addr != e.addr || m.Kid != e.kid {
			delete(primaryKnown.m, agent)
		}
	}
	for _, l := range links {
		if !l.answered {
			continue
		}
		e := primaryKnown.m[l.agent]
		if e == nil {
			e = &primaryKnownEntry{agent: l.agent, addr: l.addr, kid: l.kid, keys: map[string]string{}}
			primaryKnown.m[l.agent] = e
		}
		e.name = l.name
		for d, k := range l.keys {
			e.keys[d] = k
		}
	}
	sources := make([]*primaryKnownEntry, 0, len(primaryKnown.m))
	for _, e := range primaryKnown.m {
		sources = append(sources, e)
	}
	primaryKnown.Unlock()
	// put-peer pushes: for each answered target, every known source's entry.
	for _, t := range links {
		if !t.answered {
			continue
		}
		for _, s := range sources {
			if s.agent == t.agent {
				continue
			}
			key, ok := s.keys[t.agent]
			if !ok {
				continue
			}
			entry := putPeer{Agent: s.agent, Key: key, Addr: s.addr, Name: s.name}
			if t.held[s.agent] == putEntryDigest(entry) {
				continue
			}
			b, _ := json.Marshal(map[string]string{"n": s.name, "a": s.addr, "k": key})
			if !primaryPutPeer(ctx, t, s.agent, string(b)) {
				break
			}
		}
	}
	// The persisted removals: each tombstone's empty put-peer goes to every
	// answered put member that has not acked it yet.
	primaryDropsRound(ctx, links)
}

// runPrimaryCoordinator keeps the rounds coming for as long as the carrier
// lives: a 10-minute timer and the wake signal (roster change, join,
// primary-on/off). It stays up even while this machine is not the primary —
// primary-on takes effect without a restart — and simply idles then.
func runPrimaryCoordinator(ctx context.Context) {
	tick := time.NewTicker(primaryRoundEvery)
	defer tick.Stop()
	for {
		if primaryIsPrimary() {
			primaryRound(ctx)
			primaryReapConns()
		}
		select {
		case <-ctx.Done():
			return
		case <-primaryWakeCh:
		case <-tick.C:
		}
	}
}
