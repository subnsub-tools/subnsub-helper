package main

/* ── who is allowed to give this machine orders ────────────────────────────

   The console, the update button and the diagnostics drawer all arrive the
   same way: this helper polls a relay, and the relay hands it a command. The
   local switches decide WHETHER this machine takes instruction at all. They do
   not decide FROM WHOM — and until this file existed, the honest answer to
   "who can run a command here" was "whoever controls the relay", because a
   command carries no evidence of who wrote it and the helper had none to
   check. That is a protocol boundary, not a bug in anybody's server, and no
   amount of care on the relay side can close it.

   So a command can now carry a signature, and this is where it is checked.
   The private key lives in the dashboard's browser and is never sent
   anywhere; the PUBLIC key is pinned on this machine at install time and can
   be extended at the keyboard afterwards. A relay is then a courier: it can
   drop a command, delay it, or hand back an old one — availability was always
   its to withhold — but it cannot compose one, because it never holds the key
   that would make a command acceptable here.

   Two rules that shape everything below:

     - Pinning is the switch. With no trusted key on the machine, the
       closed-form mailbox commands (update, refresh, inspect, myip) are taken
       unsigned, as every helper took them before signing existed — an
       existing install would otherwise stop taking them the moment it
       updated. That is the whole of what an unpinned machine runs: a shell
       line never comes by the relay road (console.go, mailboxRefusal), and a
       sealed line (econ.go) or any tunnel command (direct.go) is refused
       until something is pinned. With one or more pinned, an unsigned or
       badly signed command is REFUSED, and refused out loud so the dashboard
       can say why.
     - Verifying the signature is not enough by itself. A signature is valid
       forever, so a relay could keep a command somebody legitimately sent and
       replay it later — at a worse moment, or a hundred times. Freshness and
       single-use are enforced here too, and they are what make this a control
       rather than a decoration. */

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// One key per line, base64 (standard alphabet), written by the installer
	// and by `subnsub-helper trust`.
	trustedKeysFile = "trusted-keys"
	// How far a command's own timestamp may be from this machine's clock. Wide
	// enough for ordinary skew between a laptop and a server nobody runs NTP
	// on, narrow enough that a captured command stops being useful quickly.
	//
	// This is the replay window, and it is a genuine trade: shrinking it makes
	// a stolen frame useless sooner and makes a badly-set clock refuse
	// everything. Five minutes is the same order as the clock error a machine
	// can have while still looking healthy on the dashboard.
	commandSkew = 5 * time.Minute
	// Ids remembered for single-use enforcement, as a backstop on memory only:
	// what actually bounds this set is the freshness window, since an id is
	// dropped once a command bearing it would be refused as stale anyway.
	// Reaching this many INSIDE that window means thousands of validly signed
	// commands per minute at one machine, which no dashboard can produce — so
	// the cap refuses rather than evicting, and never fires in ordinary use.
	seenIDsMax = 4096
)

// Envelope version. It is signed along with everything else, so a future
// format cannot be presented to an old helper as this one.
const cmdSigVersion = "mon-cmd-v2"

// What the browser signed. Every field the machine will act on is in here, in
// a fixed order, each one preceded by its length in bytes.
//
// The length prefixes are the whole point, and v1 not having them is why this
// is v2. Joining fields with a separator that can appear INSIDE a field makes
// two different commands sign the same bytes: with plain newlines, a signature
// over (target: "", cmd: "cd /safe\nrm -rf *") is byte-for-byte the signature
// over (target: "\ncd /safe", cmd: "rm -rf *") — and `sh` ignores target, so a
// relay could hand this machine the second line of a signed command without
// the first and it would verify. Prefixing each field with its length leaves
// no way to move a byte from one field to another.
//
// Leaving any field out would leave it free to change in transit: a signature
// over the command text alone would let a relay redirect a command at a
// different machine, or replay a `sh` as an `update`.
func commandSigningInput(agent, id, kind, target string, issuedAt int64, cmd string) []byte {
	var b strings.Builder
	b.WriteString(cmdSigVersion)
	b.WriteByte('\n')
	for _, f := range []string{agent, id, kind, strconv.FormatInt(issuedAt, 10), target, cmd} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func trustedKeysPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, trustedKeysFile)
}

// What this machine has been told about who may command it.
//
// sealed answers a different question from len(keys), and the difference is
// the one that matters when something is wrong: sealed means "somebody set
// this up", keys are the ones currently usable. A list that exists but cannot
// be read is sealed with nothing in it, and every command is refused.
type trust struct {
	keys   []ed25519.PublicKey
	sealed bool
}

// Read on every command rather than cached, for the same reason the console
// switch is: removing a key has to be the fast direction.
//
// The three outcomes are deliberately not two. NO FILE is a machine that never
// pinned anything — every install before today — and it keeps working as it
// always did. A FILE WITH KEYS requires a signature. A file that EXISTS and
// yields nothing usable — unreadable, truncated, corrupted, someone's editor
// backup — is the case worth being careful about: treating it like "no file"
// would turn a damaged permission bit into a silent downgrade back to "the
// relay may command this machine", which is precisely the property the file
// was there to buy. So it refuses instead, out loud, and is fixed at the
// keyboard where it was set up.
//
// A file that is empty or nothing but comments is NOT that case: writing an
// empty file is how `untrust` removes the last key, and it says so when it
// does.
func loadTrust() trust {
	path := trustedKeysPath()
	if path == "" {
		return trust{}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return trust{}
		}
		return trust{sealed: true}
	}
	var out []ed25519.PublicKey
	content := false
	for _, line := range strings.Split(string(body), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			content = true
		}
		if k := parsePublicKey(line); k != nil {
			out = append(out, k)
		}
	}
	return trust{keys: out, sealed: len(out) > 0 || content}
}

// One key from one line, or nil. Comments and blanks are skipped so the file
// can be annotated by whoever is administering the machine.
func parsePublicKey(line string) ed25519.PublicKey {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	// A trailing label is allowed — "<key> laptop" — because a file listing
	// three keys and no hint of whose they are is a file nobody dares prune.
	if i := strings.IndexAny(line, " \t"); i > 0 {
		line = line[:i]
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}

/*
── single use ──────────────────────────────────────────────────────────

	Held in memory rather than on disk. A restart forgets, which sounds like a
	hole and is bounded by the freshness window: a replayed command has to be
	under five minutes old to be considered at all, so the exposure is a restart
	inside that window rather than "forever". Writing every command id to disk
	would put a write on the path of every keystroke in the console, for a
	window this narrow.

	Forgetting is by AGE, never by count. An id has to be remembered exactly as
	long as a command carrying it could still be accepted — issuedAt plus the
	skew — and no longer. Dropping the oldest to make room, which is what this
	did first, quietly breaks that: hand a busy machine enough commands and the
	one you want to replay falls out of the set while its signature is still
	fresh, which is the entire attack this set exists to stop.
*/
var seen = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// "" to run it, otherwise why not — in the vocabulary the dashboard renders.
func rememberCommand(id string, now time.Time) string {
	seen.Lock()
	defer seen.Unlock()
	for k, t := range seen.at {
		// Anything this old is refused as stale before it ever gets here, so
		// remembering it no longer protects anything.
		if now.Sub(t) > commandSkew || t.Sub(now) > commandSkew {
			delete(seen.at, k)
		}
	}
	if _, dup := seen.at[id]; dup {
		return "replayed-command"
	}
	if len(seen.at) >= seenIDsMax {
		// Refuse rather than evict: evicting is the bug above, and getting here
		// means something is generating validly signed commands far faster than
		// a person at a keyboard can.
		return "too-many-commands"
	}
	seen.at[id] = now
	return ""
}

// Why a command was refused, in the vocabulary the dashboard already renders.
// Empty means "run it".
func verifyCommand(c consoleCmd, agent string, t trust, now time.Time) string {
	if !t.sealed {
		// Nothing pinned: this machine has not been told who may command it,
		// and behaves as every helper did before signing existed.
		return ""
	}
	if len(t.keys) == 0 {
		// Sealed with nothing usable in it. Refused with its own reason: "the
		// list on that machine is broken" and "that machine does not trust this
		// browser" are fixed in completely different places.
		return "trust-unreadable"
	}
	if c.Sig == "" {
		return "unsigned"
	}
	sig, err := base64.StdEncoding.DecodeString(c.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "bad-signature"
	}
	// The timestamp is checked BEFORE the signature only in the sense that both
	// must pass; it is signed, so a relay cannot move it without breaking the
	// signature — which is exactly why it is worth checking.
	if c.IssuedAt == 0 {
		return "bad-signature"
	}
	issued := time.Unix(c.IssuedAt, 0)
	if issued.After(now.Add(commandSkew)) || issued.Before(now.Add(-commandSkew)) {
		return "stale-command"
	}
	msg := commandSigningInput(agent, c.ID, c.Kind, c.Target, c.IssuedAt, c.Cmd)
	ok := false
	for _, k := range t.keys {
		if ed25519.Verify(k, msg, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return "bad-signature"
	}
	// Last, because a replay of something that never verified is not worth
	// remembering — and because burning an id on a bad signature would let a
	// relay lock out the real command that follows it.
	return rememberCommand(c.ID, now)
}

// commandSigner is the pinned key a command verifies under, or nil. For a
// command verifyCommand has already passed, where what is wanted is WHO: a
// terminal session is that key's, and ends when the key is unpinned.
func commandSigner(c consoleCmd, agent string, t trust) ed25519.PublicKey {
	sig, err := base64.StdEncoding.DecodeString(c.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil
	}
	msg := commandSigningInput(agent, c.ID, c.Kind, c.Target, c.IssuedAt, c.Cmd)
	for _, k := range t.keys {
		if ed25519.Verify(k, msg, sig) {
			return k
		}
	}
	return nil
}

// trustsKey reports whether k is pinned on this machine right now.
func trustsKey(k ed25519.PublicKey) bool {
	if len(k) == 0 {
		return false
	}
	t := loadTrust()
	if !t.sealed {
		return false
	}
	for _, have := range t.keys {
		if have.Equal(k) {
			return true
		}
	}
	return false
}

/* ── administering the list, from the machine itself ───────────────────── */

// Add a key. Deliberately a command somebody runs ON the machine: the whole
// property being bought is that authority is granted at the keyboard, and an
// endpoint that could add a key over the network would hand it straight back.
func trustKey(line string) error {
	k := parsePublicKey(line)
	if k == nil {
		return errString("not an Ed25519 public key in base64")
	}
	path := trustedKeysPath()
	if path == "" {
		return errString("no config directory to write to")
	}
	for _, have := range loadTrust().keys {
		if have.Equal(k) {
			return nil // already trusted; saying so twice is not an error
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(strings.TrimSpace(line) + "\n")
	return err
}

// Remove a key, or all of them. Removing the last one returns this machine to
// unsigned operation, which is a real choice and is reported as such.
func untrustKey(line string) error {
	path := trustedKeysPath()
	if path == "" {
		return errString("no config directory")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	want := parsePublicKey(line)
	if want == nil {
		return errString("not an Ed25519 public key in base64")
	}
	var keep []string
	for _, l := range strings.Split(string(body), "\n") {
		k := parsePublicKey(l)
		if k != nil && k.Equal(want) {
			continue
		}
		if strings.TrimSpace(l) != "" {
			keep = append(keep, l)
		}
	}
	out := ""
	if len(keep) > 0 {
		out = strings.Join(keep, "\n") + "\n"
	}
	// Written beside the real file and renamed over it, rather than truncated
	// in place. A crash halfway through an in-place rewrite would leave a file
	// that exists and holds no key — which now means "refuse everything" — and
	// the console is the thing you would be trying to use to fix it.
	//
	// 0600 on rewrite as well as on create: this file decides who may run
	// commands here, and a mode that widened on an edit would be the kind of
	// detail nobody looks at again.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
