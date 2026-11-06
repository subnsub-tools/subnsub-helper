package main

// Codex, live.
//
// The account's rate limits as the Codex CLI itself sees them, asked over the
// app-server's stdio JSON-RPC:
//
//	codex app-server
//	  → {"id":1,"method":"initialize","params":{"clientInfo":{…}}}
//	  → {"method":"initialized"}
//	  → {"id":2,"method":"account/rateLimits/read","params":null}
//	  ← {"id":2,"result":{"rateLimits":{…},"rateLimitsByLimitId":{…}}}
//
// Why this exists when codex.go already reads the number off the disk: the log
// holds only what a PERSISTED session recorded, and a machine whose Codex usage
// is all `codex exec --ephemeral` records nothing at all. One of ours reported
// 88% left for two weeks while the account was down to 19% — the reading was
// faithful to the file, and the file had stopped moving. A collector that can
// only be as fresh as your last interactive session is not a quota gauge.
//
// It also answers something the log cannot. `rateLimitsByLimitId` carries one
// bucket per metered limit — the account's own, and on this plan a separate
// weekly window for GPT-5.3-Codex-Spark. The logged envelope is a single flat
// snapshot with primary/secondary, so a second bucket has nowhere to go and
// simply never appears no matter how fresh the file is.
//
// Costs, measured rather than assumed: ~1.5s wall and ~90 MB peak RSS for the
// child, once per cache floor rather than once per push. It writes no session
// file and does not touch auth.json. Its rows in Codex's own log database are
// real but bounded — that database prunes on its own retention and was 99% free
// pages when this was written, so these land on space it already carries.
//
// What it gives up, which is the honest part: the log collector could say "no
// credential, no network". This one still holds no credential — it never opens
// auth.json — but it does ask the vendor's own tool to make a call on our
// behalf, exactly as amp.go does, and that tool may refresh the credential it
// owns while doing so. That is the `cli` rung, and the panel prints "via CLI"
// instead of "local log", so the difference is on screen rather than only in
// this comment.
//
// Upstream marks the app-server experimental, so this is a PREFERENCE and never
// a requirement. No binary, a protocol that moved, a machine that is signed out
// — every one of them falls through to the log scan, which is unchanged. The
// fallback is not decoration: on a box with no Codex binary in a place this is
// willing to run from, it is the only leg there is.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Generous next to the 1.5s a warm run takes, because the first spawn on a cold
// page cache is a different animal and a timeout here costs a whole cycle's
// reading. Still well inside collectAll's own budget.
//
// A var rather than a const only so the hang test can shorten it. Nothing else
// writes it.
var codexRPCTimeout = 20 * time.Second

const (
	codexBinEnv = "MON_CODEX_BIN"

	// The app-server is chatty — notifications about threads, plugins and
	// startup arrive interleaved with our answers — so the read loop needs a
	// budget rather than a promise. Both bite before memory does; whichever
	// comes first refuses the reading rather than parsing what arrived.
	codexRPCMaxBytes = 1 << 20
	codexRPCMaxLines = 4000
	codexRPCMaxLine  = 512 << 10

	// Limit keys are capped at 24 characters by the relay. A bucket key is
	// built rather than passed through, so it is cut HERE, where the cut can be
	// seen, instead of silently downstream.
	codexKeyMax = 24
)

var codexLiveCache = provCache{pace: paceMark{id: "codex"}}

// Everything that can vary is decoded as `any` for the same reason codex.go
// does it: this is another program's output, and one unrelated field arriving
// in an unexpected shape must not throw away a perfectly good usedPercent
// sitting next to it.
type codexLiveWindow struct {
	UsedPercent any `json:"usedPercent"`
	WindowMins  any `json:"windowDurationMins"`
	ResetsAt    any `json:"resetsAt"`
}

type codexLiveCredits struct {
	HasCredits any `json:"hasCredits"`
	Unlimited  any `json:"unlimited"`
	Balance    any `json:"balance"`
}

// The tolerance has to reach the OBJECTS too, which is why every nested value
// below is held raw and decoded on its own. Typed nesting looks like it says the
// same thing and does not: with `credits` declared as a struct pointer, a vendor
// that ships it as a string one day takes the whole payload down with it —
// usedPercent, plan, every bucket in the map — and this leg goes dark on a
// machine whose only other leg is a log that may be a fortnight stale. Field by
// field, entry by entry, view by view: a shape nobody here recognises costs
// exactly the value it arrived in.
type codexLiveBucket struct {
	LimitID   any             `json:"limitId"`
	LimitName any             `json:"limitName"`
	Primary   json.RawMessage `json:"primary"`
	Secondary json.RawMessage `json:"secondary"`
	PlanType  any             `json:"planType"`
	Credits   json.RawMessage `json:"credits"`
	// A workspace's monthly credit pool for this seat (Team, Enterprise,
	// Edu): {limit, used, remainingPercent, resetsAt}, the same figures the
	// usage endpoint's individual_limit carries (adapters.json). Read as
	// CodexBar's UsageFetcher reads it (RPCSpendControlLimitSnapshot): the
	// limit must be positive; used is taken as sent, else from the
	// remaining percent, else nothing is used.
	IndividualLimit json.RawMessage `json:"individualLimit"`
}

// The pool's fields, every one loose — numbers have arrived as strings.
type codexLiveIndividualLimit struct {
	Limit            any `json:"limit"`
	Used             any `json:"used"`
	RemainingPercent any `json:"remainingPercent"`
	ResetsAt         any `json:"resetsAt"`
}

// The monthly pool as a window, or nil when the bucket carries none worth
// drawing. Key "monthly_credits" on the account's own bucket — the table's
// key for the same pool — so the card and the history meet.
func codexIndividualLimit(ref codexBucketRef) *Limit {
	if ref.b == nil || len(ref.b.IndividualLimit) == 0 {
		return nil
	}
	var il codexLiveIndividualLimit
	if json.Unmarshal(ref.b.IndividualLimit, &il) != nil {
		return nil
	}
	// adapterNum rather than asNum: these arrive as strings as often as
	// numbers ("1000", "36.797…"), as the usage endpoint sends them.
	limit, ok := adapterNum(il.Limit)
	if !ok || limit <= 0 {
		return nil
	}
	used, ok := adapterNum(il.Used)
	if !ok {
		if rp, ok := adapterNum(il.RemainingPercent); ok {
			used = limit * math.Max(0, math.Min(100, 100-rp)) / 100
		} else {
			used = 0
		}
	}
	if used < 0 {
		used = 0
	}
	key := "monthly_credits"
	if !ref.primary {
		key = codexLimitKey(ref.id, "monthly")
	}
	l := Limit{
		Key: key, UsedPercent: round2(math.Min(100, used/limit*100)),
		WindowLabel: sp("month"), Unit: "credits",
		UsedAmount: fp(round2(used)), TotalAmount: fp(round2(limit)),
		RemainingAmount: fp(round2(math.Max(0, limit-used))),
	}
	if !ref.primary {
		if scope := asStr(ref.b.LimitName, 40); scope != "" {
			l.Scope = sp(scope)
		}
	}
	if e, ok := adapterNum(il.ResetsAt); ok && e > 0 {
		l.ResetsAt = fp(e)
	}
	return &l
}

// Both views held raw, and that includes the map itself rather than only its
// entries: declared as a map, a `rateLimitsByLimitId` that arrived as anything
// but an object takes the flat view down with it, and the flat view is the one
// carrying the account's own quota.
type codexLiveResult struct {
	// The backward-compatible single-bucket view, same shape the session log
	// carries. Kept as the fallback for a build that predates the map.
	RateLimits json.RawMessage `json:"rateLimits"`
	// One entry per metered limit, keyed by limitId.
	ByLimitID json.RawMessage `json:"rateLimitsByLimitId"`
}

func codexBucketMap(raw json.RawMessage) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// One nested object, or nothing. JSON `null` decodes into a zeroed value rather
// than an error, which is the right answer for all three: every field inside is
// optional and reads as absent.
func codexWindow(raw json.RawMessage) *codexLiveWindow {
	if len(raw) == 0 {
		return nil
	}
	var w codexLiveWindow
	if json.Unmarshal(raw, &w) != nil {
		return nil
	}
	return &w
}

func codexCredits(raw json.RawMessage) *codexLiveCredits {
	if len(raw) == 0 {
		return nil
	}
	var c codexLiveCredits
	if json.Unmarshal(raw, &c) != nil {
		return nil
	}
	return &c
}

func codexBucket(raw json.RawMessage) *codexLiveBucket {
	if len(raw) == 0 {
		return nil
	}
	var b codexLiveBucket
	if json.Unmarshal(raw, &b) != nil {
		return nil
	}
	return &b
}

// Whether a bucket carries a window anyone could read a number off. "Present"
// and "readable" are different questions, and the account bucket is chosen on
// the second one.
func codexBucketReadable(b *codexLiveBucket) bool {
	if b == nil {
		return false
	}
	for _, raw := range []json.RawMessage{b.Primary, b.Secondary} {
		if w := codexWindow(raw); w != nil && asNum(w.UsedPercent) != nil {
			return true
		}
	}
	return false
}

type codexRPCMessage struct {
	ID     *int64          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

var (
	errCodexNoBinary = errors.New("no codex binary")
	errCodexSpawn    = errors.New("app-server would not start")
	errCodexTimeout  = errors.New("app-server timed out")
	errCodexProtocol = errors.New("app-server answered in an unknown shape")
	errCodexRefused  = errors.New("app-server refused the request")
)

// Where the Codex CLI is allowed to be.
//
// PATH is not consulted to FIND it, for the reason spelled out at length in
// amp.go: PATH is inherited from whatever launched the helper, and a service
// that runs "the first thing called codex on PATH" is one prepended directory
// away from executing somebody else's file.
//
// Worth being exact about what that does and does not buy, because the
// equivalent comment on the other CLI collectors reads as a stronger promise
// than it is. `codex` from npm is a script beginning `#!/usr/bin/env node`, so
// choosing the script from a fixed list still leaves the kernel resolving
// `node` through PATH at exec time. Pinning an interpreter instead is not an
// option worth the trade: naming one would mean hard-coding one layout, and a
// helper that cannot find node stops reporting rather than reports safely.
// codexEnv does the part that is worth doing — it puts the chosen install's own
// directory at the front of the child's PATH, so the interpreter comes from the
// same place the tool did — but that is about getting the RIGHT node, not about
// keeping out a wrong one. What the fixed list actually guarantees is that the
// TOOL is the one the user installed; the interpreter is trusted exactly as far
// as this account's PATH is, which is the same footing every other CLI-rung
// collector here has always stood on.
//
// The node version managers are the difference from vendorCandidates' fixed
// list. Codex ships as an npm package, so on a great many machines it lives
// under a per-version directory whose name cannot be written down in advance.
// A glob over ONE fixed shape is still a fixed set of directories — it is not
// PATH, and nothing outside ~/.nvm/versions/node/*/bin can answer to it.
func codexBinary() string {
	if v := strings.TrimSpace(os.Getenv(codexBinEnv)); v != "" {
		// An override that does not hold up is a refusal, not a reason to go
		// looking elsewhere: someone pointed us at a specific file on purpose.
		if filepath.IsAbs(v) && usableBinary(v) {
			return v
		}
		return ""
	}
	cands := vendorCandidates("codex")
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cands = append(cands,
			filepath.Join(home, ".bun", "bin", "codex"),
			filepath.Join(home, ".volta", "bin", "codex"),
			filepath.Join(home, ".npm-global", "bin", "codex"))
		cands = append(cands, codexNodeVersionCandidates(home)...)
	}
	for _, c := range cands {
		if usableBinary(c) {
			return c
		}
	}
	return ""
}

// nvm's installs, newest version first.
//
// Compared as NUMBERS, component by component, and not as strings — the whole
// point of this function. "v9" sorts after "v22" lexically, and one level down
// the same trap sits again: "v22.9.0" sorts after "v22.19.0". Getting only the
// major right would still hand a machine an older CLI than the one it has, and
// an older CLI is one that may not speak the protocol this asks for.
func codexNodeVersionCandidates(home string) []string {
	matches, err := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "codex"))
	if err != nil || len(matches) == 0 {
		return nil
	}
	// …/node/<version>/bin/codex → [major, minor, patch]. An unparseable
	// component reads as -1, which sorts it below every real version rather
	// than letting it win by accident.
	parts := func(p string) [3]int {
		v := strings.TrimPrefix(filepath.Base(filepath.Dir(filepath.Dir(p))), "v")
		out := [3]int{-1, -1, -1}
		for i, f := range strings.SplitN(v, ".", 3) {
			if i > 2 {
				break
			}
			if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
				out[i] = n
			}
		}
		return out
	}
	sort.SliceStable(matches, func(i, j int) bool {
		a, b := parts(matches[i]), parts(matches[j])
		for k := 0; k < 3; k++ {
			if a[k] != b[k] {
				return a[k] > b[k]
			}
		}
		return matches[i] > matches[j]
	})
	return matches
}

// The child's environment, with the chosen install's own directory in front of
// PATH.
//
// Finding the CLI is only half of it. `codex` from npm begins
// `#!/usr/bin/env node`, so choosing the script leaves the kernel to resolve
// `node` through PATH — and PATH here is whatever the service manager handed
// this helper, which routinely has no version manager on it at all. Searching
// ~/.nvm for the newest Codex and then launching it under a PATH that cannot
// see that install's node is a search that finds the right file and runs the
// wrong one, or nothing.
//
// The node an install was built against is the one sitting beside it, so that
// directory goes first. This is not a pin and not a sandbox — everything the
// account could already reach is still on PATH behind it — it is only where to
// look first, and it makes the tool and its interpreter come from one place.
func codexEnv(bin string) []string {
	env := vendorEnv([]string{"CODEX_"})
	dir := filepath.Dir(bin)
	if dir == "" || dir == "." {
		return env
	}
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + dir + string(os.PathListSeparator) + kv[len("PATH="):]
			return env
		}
	}
	return append(env, "PATH="+dir)
}

// One app-server conversation: start it, initialize, ask, leave.
//
// THE DEADLINE IS ON THE READ, not only on the context, and that distinction is
// the whole reason this function is shaped the way it is.
//
// `codex` from npm is a Node script that spawns the real Codex binary with
// inherited stdio. Cancelling the context kills the Node process this started
// and nothing else, so the grandchild still holds the write end of our stdout
// pipe: no EOF ever arrives, a Scan() blocked on it stays blocked, and
// cmd.WaitDelay cannot help because it only bounds Wait(), which we would not
// reach until after the read we are stuck in. The collector holds its cache
// mutex throughout, and collectAll waits on every collector, so one hung
// app-server would take the entire helper off the air rather than cost one
// provider one cycle.
//
// os.Pipe with a read deadline ends that: the read fails on time no matter who
// else is holding the pipe open. Closing stdin then gives the grandchild the
// EOF a stdio server shuts down on, which is what actually collects it —
// killing Node alone would leave it running.
func codexAskRateLimits(bin string) (*codexLiveResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), codexRPCTimeout)
	defer cancel()

	cmd := toolCommand(ctx, bin, "app-server")
	cmd.Env = codexEnv(bin)
	// nil is the null device, which is what we want for stderr: the app-server
	// writes progress there and nobody reads it, and an unread pipe that fills
	// is a deadlock rather than a missing log line.
	cmd.Stderr = nil
	// Its own process group, so the cleanup below can take down what it starts
	// rather than only what we started. Has to be said before Start.
	setProcessGroup(cmd)

	// Deliberately NOT cmd.StdoutPipe(): that hands back a pipe whose lifetime
	// belongs to Wait(), and an *os.File we made ourselves is the only one we
	// can put a deadline on. os/exec never closes a file handed to it as
	// cmd.Stdout, so every path out of here that does not reach Start has to
	// close both ends itself.
	//
	// Made BEFORE StdinPipe, which is the only ordering with no leak in it: a
	// failure here would otherwise strand a stdin pipe that only Start or Wait
	// knows how to close, and neither ever runs. Running out of descriptors is
	// exactly when os.Pipe fails, so that is the worst moment to leak two.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, errCodexSpawn
	}
	cmd.Stdout = pw
	stdin, err := cmd.StdinPipe()
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, errCodexSpawn
	}
	cmd.WaitDelay = 2 * time.Second

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, errCodexSpawn
	}
	// The child holds its own copy now. Ours has to go, or the read end never
	// sees EOF even when every process in the tree has exited.
	pw.Close()
	defer func() {
		// Order matters. stdin first: EOF is how a stdio server is asked to
		// leave, and it is what collects a healthy one — a kill reaches the
		// process we started and not the binary it spawned. Then the read end,
		// so nothing is left blocked on it. Then the whole process group for
		// the server that did not take the hint, then exactly one Wait to reap
		// the one child that is ours to reap.
		stdin.Close()
		pr.Close()
		killProcessTree(cmd)
		cmd.Wait()
	}()

	// The SAME instant the context is already counting to, not a fresh twenty
	// seconds from here: two deadlines that drift apart would let a slow spawn
	// push the total past the only number this function promises. The error is
	// checked because ignoring it is how the permanent hang comes back — a pipe
	// the runtime could not register for polling takes no deadline at all, and
	// a Scan on it blocks until something else in the tree decides otherwise.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(codexRPCTimeout)
	}
	if err := pr.SetReadDeadline(deadline); err != nil {
		return nil, errCodexSpawn
	}
	stdout := pr

	send := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return errCodexProtocol
		}
		if _, err := stdin.Write(append(b, '\n')); err != nil {
			return errCodexSpawn
		}
		return nil
	}

	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 0, 64<<10), codexRPCMaxLine)
	read := 0
	seen := 0
	// The answer to one id, skipping everything else the server says on the
	// way. Notifications are not errors here — they are the normal traffic of a
	// server that has just started up.
	await := func(id int64) (json.RawMessage, error) {
		for lines.Scan() {
			b := lines.Bytes()
			read += len(b)
			seen++
			if read > codexRPCMaxBytes || seen > codexRPCMaxLines {
				return nil, errCodexProtocol
			}
			var m codexRPCMessage
			if json.Unmarshal(b, &m) != nil || m.ID == nil || *m.ID != id {
				continue
			}
			if len(m.Error) > 0 && string(m.Error) != "null" {
				// Deliberately not quoting it. This travels to the relay and is
				// published, and an error from somebody's account endpoint is
				// the last thing that should be repeated verbatim on a page.
				return nil, errCodexRefused
			}
			if len(m.Result) == 0 {
				return nil, errCodexProtocol
			}
			return m.Result, nil
		}
		// The read deadline is the one that fires when a grandchild is holding
		// the pipe open, so it is checked before the context: ctx may not be
		// done yet when the pipe already gave up.
		if err := lines.Err(); errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, errCodexTimeout
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, errCodexTimeout
		}
		// Clean EOF without our answer: a server that started and left, which
		// is what a signed-out or half-installed CLI looks like from here. A
		// line past the budget lands here too, and means the same thing to a
		// caller — this is not the protocol we know.
		return nil, errCodexProtocol
	}

	if err := send(map[string]any{
		"id": 1, "method": "initialize",
		"params": map[string]any{
			"clientInfo": map[string]any{"name": "subnsub-helper", "version": helperVersion},
		},
	}); err != nil {
		return nil, err
	}
	if _, err := await(1); err != nil {
		return nil, err
	}
	// The handshake's second half is a notification, so there is nothing to
	// wait for; the request after it is what we actually came for.
	if err := send(map[string]any{"method": "initialized"}); err != nil {
		return nil, err
	}
	if err := send(map[string]any{"id": 2, "method": "account/rateLimits/read", "params": nil}); err != nil {
		return nil, err
	}
	raw, err := await(2)
	if err != nil {
		return nil, err
	}
	var res codexLiveResult
	if json.Unmarshal(raw, &res) != nil {
		return nil, errCodexProtocol
	}
	if len(res.RateLimits) == 0 && len(res.ByLimitID) == 0 {
		return nil, errCodexProtocol
	}
	return &res, nil
}

// The account's own bucket, by name. Everything else on the payload — the plan,
// the credit balance — belongs to this one; the extra buckets are windows on
// other meters and carry their own nulls for the rest.
const codexPrimaryLimitID = "codex"

// A bucket, the name it was filed under, and whether it is the account's own.
//
// The map key is carried rather than re-derived from the bucket's own limitId:
// the two are the same today, the protocol promises only the key, and a bucket
// whose embedded id is null would otherwise lose the one identifier it had.
//
// `primary` is carried for the same reason, and it is not the same as "first".
// It was read off position once — the account bucket sorts first, so index zero
// meant account — which held right up until a payload arrived with extra meters
// and no account bucket at all. Then the first EXTRA meter inherited everything
// that belongs to the account: the bare "primary" key, no scope to tell it
// apart, and the right to name the plan and the credit balance. Identity is
// something this either knows or does not; it is not something to infer from
// where a thing ended up in a slice.
type codexBucketRef struct {
	id      string
	b       *codexLiveBucket
	primary bool
}

// Buckets in a stable order: the account's own first, then the rest by id.
// Stable because the card rebuilds itself whenever the shape of its rows
// changes, and a map iterated in Go's order would change that shape every
// thirty seconds.
//
// The flat `rateLimits` is not a lesser copy to be dropped as soon as the map
// exists — the protocol defines it as the backward-compatible view of the
// account's own bucket, so it is the fallback for the account WHENEVER the map
// does not carry one. An earlier version took "map is non-empty" as licence to
// ignore it entirely, which on a payload holding extra meters and no `codex`
// entry would have thrown away the main quota and then read the plan and credit
// balance off whichever extra meter happened to sort first.
//
// "Does not carry one" is decided on READABILITY, not on whether the key is
// present. A `codex` entry that arrived with no window in it, or with a window
// whose usedPercent is a shape nobody can parse, is not an account reading —
// and preferring it over a flat view that is perfectly intact would lose the
// main quota to a technicality, silently if any extra meter was there to keep
// the reading alive.
func codexOrderedBuckets(res *codexLiveResult) []codexBucketRef {
	var out []codexBucketRef
	byID := codexBucketMap(res.ByLimitID)
	primaryID := codexPrimaryLimitID
	primary := codexBucket(byID[codexPrimaryLimitID])
	if !codexBucketReadable(primary) {
		if flat := codexBucket(res.RateLimits); codexBucketReadable(flat) {
			primary = flat
			if id := asStr(flat.LimitID, 64); id != "" {
				primaryID = id
			}
		}
	}
	if primary != nil {
		out = append(out, codexBucketRef{id: primaryID, b: primary, primary: true})
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if id == primaryID || id == codexPrimaryLimitID {
			continue
		}
		// Decoded one at a time on purpose: a single entry in an unexpected
		// shape costs that meter its row, not every other meter theirs.
		if b := codexBucket(byID[id]); b != nil {
			out = append(out, codexBucketRef{id: id, b: b})
		}
	}
	return out
}

// A limit key for a bucket that is not the account's own, inside the 24
// characters the relay allows.
//
// Truncating a long id would invite two meters to arrive under one key, and a
// card cannot tell two rows with the same key apart. The head stays readable
// and the tail carries the difference. Cut by RUNE — a byte cut can leave half
// a character on the wire.
func codexLimitKey(id, window string) string {
	suffix := "/" + window[:1]
	budget := codexKeyMax - len(suffix)
	if id == "" {
		id = "limit"
	}
	if len(id) <= budget {
		return id + suffix
	}
	sum := sha256.Sum256([]byte(id))
	tag := "~" + hex.EncodeToString(sum[:2])
	var head strings.Builder
	for _, r := range id {
		if head.Len()+len(string(r)) > budget-len(tag) {
			break
		}
		head.WriteRune(r)
	}
	return head.String() + tag + suffix
}

// One bucket's windows as Limits.
//
// The account's own bucket keeps the keys the log collector has always used —
// "primary" and "secondary" — so a machine switching legs does not look to the
// page like a provider that grew new windows. Other buckets are namespaced and
// carry a scope, which is the row's second label on the card.
//
// The scope falls back to the bucket's id when the vendor supplies no name for
// the meter, which the protocol allows. Without that fallback two nameless
// weekly buckets both render as "7d" and nothing on the card says which is
// which — the row label is the window, and the window is what they share.
func codexBucketLimits(ref codexBucketRef) []Limit {
	b := ref.b
	if b == nil {
		return nil
	}
	scope := asStr(b.LimitName, 40)
	if scope == "" {
		scope = ref.id
	}
	var out []Limit
	for _, w := range []struct {
		key string
		raw json.RawMessage
	}{{"primary", b.Primary}, {"secondary", b.Secondary}} {
		win := codexWindow(w.raw)
		if win == nil {
			continue
		}
		used := asNum(win.UsedPercent)
		if used == nil {
			continue
		}
		key := w.key
		if !ref.primary {
			key = codexLimitKey(ref.id, w.key)
		}
		l := Limit{
			Key:         key,
			UsedPercent: round2(*used),
			// Codex reports no severity; the page colours these by percentage.
			Severity: nil, Active: nil,
		}
		if !ref.primary && scope != "" {
			l.Scope = sp(scope)
		}
		if m := asNum(win.WindowMins); m != nil {
			l.WindowMinutes = m
			l.WindowLabel = windowLabel(*m)
		}
		l.ResetsAt = asNum(win.ResetsAt)
		out = append(out, l)
	}
	if il := codexIndividualLimit(ref); il != nil {
		out = append(out, *il)
	}
	return out
}

// The live reading, or a failure to be told about. Nothing here falls back —
// collectCodex does that, because "the log is fresher than nothing" is a
// decision about the provider, not about this request.
func codexLiveFetch() Provider {
	p := Provider{ID: "codex", Name: "Codex", Source: "cli", CapturedAt: now()}
	bin := codexBinary()
	if bin == "" {
		p.failWith("not-installed", "cli-missing", "codex")
		return p
	}
	res, err := codexAskRateLimits(bin)
	if err != nil {
		// Never err.Error() from exec: those quote the full path being run,
		// which carries the local username onto every watcher's screen.
		switch err {
		case errCodexTimeout:
			p.failWith("unreachable", "cli-timeout", "codex app-server")
		case errCodexRefused:
			p.failWith("cli-failed", "cli-exit", "codex app-server")
		case errCodexProtocol:
			p.failWith("cli-failed", "cli-shape", "codex app-server")
		default:
			p.failWith("cli-failed", "cli-failed", "codex app-server")
		}
		return p
	}

	// The account's own bucket is the only one the plan and the credit balance
	// may come from: every other bucket is a window on some other meter and
	// carries nulls for both. Asked of the ref rather than of its position — a
	// payload with no account bucket has nobody to answer, and the first extra
	// meter is not a stand-in.
	for _, ref := range codexOrderedBuckets(res) {
		p.Limits = append(p.Limits, codexBucketLimits(ref)...)
		if !ref.primary {
			continue
		}
		if plan := asStr(ref.b.PlanType, 40); plan != "" {
			p.PlanType = sp(plan)
		}
		if c := codexCredits(ref.b.Credits); c != nil {
			p.Credits = &Credits{
				HasCredits: asBool(c.HasCredits),
				Unlimited:  asBool(c.Unlimited),
				Balance:    anyToString(c.Balance),
			}
		}
	}
	if len(p.Limits) == 0 {
		// An answer with no usable window is not a reading. Saying ok here
		// would leave the page showing its previous gauge, freshly stamped
		// live — worse than showing nothing, and worse than the log.
		p.failWith("no-readings", "no-window")
		return p
	}
	p.OK = true
	// Asked and answered in the same breath, so the reading is as of now. The
	// cache floor keeps CapturedAt moving while this stands still, which is
	// what makes a served-from-cache number visibly age on the card.
	p.RecordedAt = fp(p.CapturedAt)
	return p
}

// The Codex tile: its quota from whichever leg answers, and what it spent on
// this machine riding on either — that count is the session logs' whatever
// leg the quota came from (codexactivity.go).
func collectCodex() Provider {
	p := collectCodexQuota()
	if p.OK {
		p.Activity = codexActivity(now())
	}
	return p
}

// Prefer the live reading; fall back to the session log.
//
// The fallback is deliberately silent about WHY it fell back, and that is not
// the same as hiding it. What the reader needs is which leg produced the number
// in front of them, and that is on the card already: `source` prints as "via
// CLI" or "local log", and a log reading that has stopped moving wears its own
// age next to it. A machine with no Codex installed would otherwise gain a
// permanent red error for a feature it never had.
//
// "Live wins" is a claim about FRESHNESS, so it has to be checked rather than
// assumed. The cache keeps serving its last success for a while after refreshes
// start failing (provhttp.go), which is right — a stale real number beats an
// error — but it means an `ok` reading here can be minutes old while a session
// written since then sits unread on disk. So a live answer that is no longer
// fresh is compared against the log rather than trusted on its rung alone, and
// whichever was recorded later is the one that goes out.
//
// Freshness is an AGE, and an age below zero is not a very small one. These are
// wall-clock seconds, so a machine that steps its clock backwards — ntp settling
// after a boot, a laptop returning from suspend, a VM resuming — produces a
// reading that appears to have been taken in the future. Reading that as "newer
// than new" would pin the live leg in place for as long as the jump lasted,
// which is exactly the interval when the log is the thing worth consulting. Only
// a plainly recent reading skips the comparison; everything else goes on to it.
//
// An unstamped live reading takes the same road for the same reason: unknown is
// not fresh. codexLiveFetch always stamps one, so that branch stands as the
// invariant holding rather than a case anyone expects to see.
func collectCodexQuota() Provider {
	live := codexLiveCache.collect(codexLiveFetch)
	if !live.OK {
		return collectCodexLog()
	}
	if live.RecordedAt != nil {
		if age := live.CapturedAt - *live.RecordedAt; age >= 0 && age < provMinInterval {
			return live
		}
	}
	logged := collectCodexLog()
	if !logged.OK || logged.RecordedAt == nil {
		return live
	}
	if live.RecordedAt == nil || *logged.RecordedAt > *live.RecordedAt {
		return logged
	}
	return live
}
