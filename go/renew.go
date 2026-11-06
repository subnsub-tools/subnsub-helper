package main

// Keeping the relay token alive without ever holding a permanent secret.
//
// The token this helper pushes with expires. That is deliberate — it is a
// self-contained statement that an account was entitled to the relay when it
// was issued, and a statement nobody can revoke had better stop being true on
// its own. But the installer writes one token and walks away, so without
// something here every machine an account owns goes dark on the same day, and
// the dashboard reports it as "these machines stopped reporting" when the
// machines are fine.
//
// So: shortly before it expires, trade the current token for a fresh one. The
// site re-checks the subscription while doing it, which is the part that makes
// this more than a workaround — today a cancelled subscription keeps working
// until the token runs out because nobody ever looks again.
//
// WHAT THIS DELIBERATELY IS NOT. It is not a channel. The response is one
// string, and it is accepted only if it is the SAME ACCOUNT, expires later than
// what we hold, and does not claim an absurd lifetime. Nothing here can be told
// to change an interval, run a command, or fetch anything — the helper's habit
// of not parsing what the network says is worth keeping, and the way to keep it
// while still renewing is to make the one parsed value a token and nothing else.
//
// And it does not talk to the relay. The relay has no database and no idea who
// anyone is; entitlement lives on the site that issued the token in the first
// place. Renewing there keeps the relay a stateless verifier that never learns
// an identity, and never lets a relay response steer renewal — see
// transport.go, and hint.go for the one thing a push response now says.
//
// ⚠ THE TOKEN IS A BEARER SECRET AND IT BELONGS TO ONE RELAY. This file will
// not send it anywhere the operator did not point it. Renewal is OFF unless the
// relay is the one this build ships with, or the operator named a renewal site
// themselves — see renewalSite(). A helper aimed at somebody's own relay must
// never hand that relay's credential to ours because our relay happened to
// answer 403.

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// The relay this build ships with, and the site that issues tokens for it.
	// Renewal is enabled only for that pair, or for a site the operator names.
	officialRelay = "https://monitor.subnsub.com"
	defaultSite   = "https://tools.subnsub.com"
	siteEnv       = "SUBNSUB_MONITOR_SITE"
	tokenEnv      = "SUBNSUB_MONITOR_TOKEN"
	renewPath     = "/api/monitor-token/renew"

	// Start trying with a week left. The server refuses renewals until a token
	// is inside its own, wider window, so this can be generous without
	// hammering: it is the point at which we begin, not a deadline.
	renewLead = 7 * 24 * time.Hour

	// After a failure, and why the floor is an hour rather than a few seconds:
	// every reason a renewal fails is slow to change. An expired subscription,
	// a machine that has been off too long, a site outage — none of them are
	// fixed by asking again in a minute, and a helper that retried at push
	// cadence would turn one lapsed account into 2,880 requests a day.
	renewRetryMin = time.Hour
	renewRetryMax = 12 * time.Hour
	// A refusal that says "this credential is finished" is not retried on that
	// schedule at all. Nothing this side can do fixes it, and a machine left
	// running for a year should not spend the year asking.
	//
	// ⚠ RESERVED FOR 401 AND NOTHING ELSE. A lapsed subscription looks similar
	// and is not the same: entitlement changes outside this process, so somebody
	// who resubscribes the next morning must not find their machines frozen out
	// for a month. Only "this token will never verify again" belongs here.
	renewRetryDead = 30 * 24 * time.Hour

	// However long a backoff says, stop short of the expiry of the token we are
	// holding. A freeze that outlives the credential it was protecting is not a
	// backoff, it is an outage with extra steps — the machine wakes up, finds an
	// expired token, and the forced path is still parked.
	renewLastCall = time.Hour

	// A renewal answer is two short fields. Anything larger is not one.
	maxRenewBody = 4 << 10

	// The longest life this helper will believe a renewed token claims. The
	// issuer hands out 30 days; the cap exists so a wrong or manipulated answer
	// cannot mint something that outranks the installed token effectively
	// forever — the file is chosen over the environment BY EXPIRY, so a forged
	// year-long expiry would win every restart from here on.
	maxTokenLife = 60 * 24 * time.Hour

	// Where a renewed token is kept, beside the id and the name so that
	// --uninstall takes it with everything else.
	tokenFile = "token.current"
)

// The 44-byte token layout:
// 16 bytes of identity, 4 bytes of big-endian expiry, 8 of nonce, 16 of tag.
// Only the identity and the expiry are read here — the helper has no business
// interpreting the rest, and cannot verify the tag anyway.
const (
	tokenBytes   = 44
	tokenIDLen   = 16
	tokenExpOff  = 16
	legacyTokLen = 43 // the self-minted tokens that predate signing: 32 raw bytes
)

func tokenRaw(tok string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != tokenBytes {
		return nil, false
	}
	return raw, true
}

// When this token stops being accepted, if it says.
//
// Tokens minted by the old `token` subcommand carry no expiry at all, and there
// are installs in the field holding one. They report ok=false and are simply
// never renewed — there is nothing to renew them from, and the relay's
// allow-list path they depend on does not expire either.
func tokenExpiry(tok string) (time.Time, bool) {
	raw, ok := tokenRaw(tok)
	if !ok {
		return time.Time{}, false
	}
	secs := binary.BigEndian.Uint32(raw[tokenExpOff : tokenExpOff+4])
	if secs == 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0), true
}

// Which ACCOUNT a token speaks for, as the opaque 16 bytes the relay names a
// room after. Not verifiable here — the tag needs a secret this side does not
// have — but comparing two tokens' identities does not need verification, and
// that comparison is what stops a renewal answer from quietly moving this
// machine's readings into somebody else's dashboard.
func tokenIdentity(tok string) (string, bool) {
	raw, ok := tokenRaw(tok)
	if !ok {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(raw[:tokenIDLen]), true
}

// The alphabet the relay accepts, applied to anything the site hands back.
// Not a formality: this value is about to be written to disk and sent as an
// Authorization header, and a response that arrived with a newline in it would
// be the interesting kind of bug.
func cleanToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 24 || len(s) > 128 {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return ""
		}
	}
	return s
}

func sameHost(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}

// Where THIS invocation may renew, and whether it may at all.
//
// Two ways to get a site, and no third:
//  1. the operator named one, which is how somebody running their own relay
//     opts in to their own issuer;
//  2. the relay is the one this build ships with, so the site that issues its
//     tokens is known.
//
// Anything else — `connect https://relay.example.com`, MON_RELAY pointed
// elsewhere — gets no renewal. That token was not issued by us, is not ours to
// present anywhere, and sending it to our site because their relay answered 403
// would be handing a third party's bearer secret to a server they never chose.
func renewalSite(relay string) (string, bool) {
	if v := siteOverride(); v != "" {
		if strings.HasPrefix(v, "https://") {
			return strings.TrimRight(v, "/"), true
		}
		// An http:// override would put the token on the wire in clear. Refuse
		// rather than honour it, and do not silently fall back to ours either:
		// somebody who set this meant to use their own.
		warnf("ignoring %s: renewal requires an https:// URL", siteEnv)
		return "", false
	}
	if sameHost(relay, officialRelay) {
		return defaultSite, true
	}
	return "", false
}

// The site the operator named, wherever they were able to name it.
//
// Kept separate from renewalSite so the two decisions stay legible: this one is
// "did anyone say", that one is "may we renew at all". A custom relay that only
// worked on the platforms whose service manager carries an environment would be
// an install that looked fine and stopped reporting a month later, when the
// token it could not renew expired.
func siteOverride() string {
	if v := strings.TrimSpace(os.Getenv(siteEnv)); v != "" {
		return v
	}
	return strings.TrimSpace(installedEnv()[siteEnv])
}

// ── the token the installer wrote ──────────────────────────────────────────
//
// A last resort, consulted only when neither the environment nor the command
// line named one — which is exactly the state a Windows install is in, and the
// reason this exists.
//
// The other two platforms get the token from their service manager: systemd
// reads this same file as an EnvironmentFile, launchd carries it inside the
// plist. Task Scheduler has no equivalent. It runs a program with arguments and
// nothing else, so the only two places a token could go there are the command
// line — visible to every other process on the machine, which is the thing the
// installer's comment about `ps` is about — or the user's persistent
// environment, which would hand it to every program that user ever starts.
// Neither is acceptable for a bearer secret, so the helper reads the file
// itself and the task carries no secret at all.
//
// Parsed as KEY=VALUE lines because that is the format systemd requires of it.
// Nothing is executed and nothing is exported: two names are recognised and
// every other line is skipped.
const (
	tokenEnvFile = "token"
	// The installer writes about a hundred bytes. Anything remotely near this
	// is not the file it wrote.
	maxTokenFile = 8 << 10
)

func installedEnv() map[string]string {
	dir := configDir()
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, tokenEnvFile)
	// Lstat BEFORE opening, and refuse anything that is not a plain file.
	//
	// Not tidiness. Opening a FIFO blocks in open(2) until somebody writes to
	// it, which would hang `connect` at startup — before the push loop, before
	// the console, with no output — and the only way back is a kill. A symlink
	// is refused for its own reason: this path is where a credential is read
	// from, and the installers only ever write a regular file here.
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	// And again on the OPEN HANDLE, which is the check that cannot be raced:
	// the Lstat above describes the path as it was a moment ago.
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil
	}
	// One byte more than the cap, so a file AT the limit is distinguishable
	// from one cut off at it — and an oversized file is refused WHOLE rather
	// than parsed from its prefix. A valid-looking first line in front of a
	// megabyte of something else is not a config file this program wrote.
	buf := make([]byte, maxTokenFile+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil
	}
	if n <= 0 || n > maxTokenFile {
		return nil
	}
	out := map[string]string{}
	// A byte-order mark, if a text editor put one there. Notepad adds one to
	// every UTF-8 file it saves, and the installer that writes this file is a
	// PowerShell script — whose own default encoding added one until PowerShell
	// 6. Left in place it prefixes the first key, the name no longer matches,
	// and the machine installs perfectly and never appears on the board.
	body := strings.TrimPrefix(string(buf[:n]), "\ufeff")
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case tokenEnv, siteEnv, cpaURLEnv, ipv4EnvVar, myipEnvVar:
			out[k] = strings.TrimSpace(v)
		case cpaKeyEnv:
			// Credentials are opaque data. Leading and trailing spaces can be
			// part of a password or API key, so only the fields whose grammar
			// permits surrounding whitespace are trimmed.
			out[k] = v
		}
	}
	return out
}

// ── where a renewed token lives ────────────────────────────────────────────
//
// NOT the file above. That one is written once by the installer; Linux also
// gets a token-only EnvironmentFile derived from it. Writing a renewal into
// either would take effect on one platform, after a restart, and never on the
// others. A file the HELPER owns works the same everywhere and leaves the
// installer's formats alone.
//
// It records the RELAY the token belongs to. There is one such file per
// install, and `connect` takes an arbitrary URL, so without that field a
// renewal obtained for our relay could be picked up and presented to whatever
// relay the next invocation happens to name.

type storedCred struct {
	Relay string `json:"relay"`
	Token string `json:"token"`
}

func tokenPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, tokenFile)
}

// The token saved for this relay, or "" if there is none that belongs to it.
func storedToken(relay string) string {
	path := tokenPath()
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var c storedCred
	if err := json.Unmarshal(b, &c); err != nil {
		return ""
	}
	if !sameHost(c.Relay, relay) {
		return ""
	}
	return cleanToken(c.Token)
}

func saveToken(relay, tok string) error {
	dir := configDir()
	if dir == "" {
		return os.ErrNotExist
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, tokenFile)
	body, err := json.Marshal(storedCred{Relay: strings.TrimRight(relay, "/"), Token: tok})
	if err != nil {
		return err
	}
	// Write-then-rename at 0600, the same shape the installer and the agent id
	// use: a plain create follows a symlink to wherever it points and can leave
	// half a secret behind if the process dies mid-write.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// Do not leave a bearer secret lying around under a name nothing will
		// ever read or clean up.
		os.Remove(tmp)
		return err
	}
	return nil
}

// Which of the two tokens this machine holds is the live one.
//
// The installer's token is the bootstrap; a renewed one supersedes it. They are
// compared by expiry rather than by preferring the file, because the file is
// also what a REINSTALL has to be able to override: paste a fresh token from
// the panel and the install writes it to the environment, where it is newer
// than whatever renewal left on disk and therefore wins. A rule of "the file
// always wins" would make reinstalling silently do nothing.
//
// A stored token that names a DIFFERENT ACCOUNT never wins, whatever its
// expiry says. Reinstalling with somebody else's token — a shared machine, a
// second account — must not keep pushing this machine's readings into the old
// account's dashboard.
func pickToken(envTok, fileTok string) string {
	envTok, fileTok = cleanToken(envTok), cleanToken(fileTok)
	if fileTok == "" {
		return envTok
	}
	if envTok == "" {
		return fileTok
	}
	fileExp, fileOK := tokenExpiry(fileTok)
	envExp, envOK := tokenExpiry(envTok)
	if !fileOK {
		return envTok
	}
	// An unsigned environment token (the pre-signing kind, no expiry) is not
	// something a dated file should displace: it works through the relay's
	// allow-list, which a renewed token would not be on.
	if !envOK {
		return envTok
	}
	// Same account, or the file does not apply here at all.
	envID, ok1 := tokenIdentity(envTok)
	fileID, ok2 := tokenIdentity(fileTok)
	if !ok1 || !ok2 || envID != fileID {
		return envTok
	}
	if fileExp.After(envExp) {
		return fileTok
	}
	return envTok
}

// The token to start pushing with, given the relay we are pointed at.
//
// The stored token is only consulted when renewal is enabled for this relay —
// which is the same condition that could have produced it. Without that,
// `connect https://other-relay TOKEN` would pick up a credential minted for
// ours and present it there.
func resolveStartToken(relay, bootstrap string) string {
	if _, ok := renewalSite(relay); !ok {
		return bootstrap
	}
	return pickToken(bootstrap, storedToken(relay))
}

// ── the renewal loop's state ───────────────────────────────────────────────

type renewer struct {
	site    string
	relay   string
	enabled bool
	next    time.Time // earliest next attempt; zero means "decide from the token"
	fails   int

	// A renewed token is used immediately but NOT written to disk until a push
	// with it has been accepted. The issuer and the relay verify with the same
	// secret, and the one operation that can put them out of step is rotating
	// it — during which the site happily issues tokens the relay refuses.
	// Committing on proof rather than on receipt means that window costs a
	// failed push, not an install that has overwritten its only working
	// credential and cannot get back.
	pending string
	prev    string
}

func newRenewer(relay string) *renewer {
	site, ok := renewalSite(relay)
	if !ok {
		return &renewer{relay: relay}
	}
	return &renewer{site: site, relay: relay, enabled: true}
}

// Should we try now? `forced` is the push loop reporting that the relay just
// refused us, which is the other moment a token is worth questioning.
//
// A forced attempt still respects the backoff. Without that, a relay answering
// 403 for a reason renewal cannot fix — a room that was never enabled, a
// subscription that really did lapse — would mean one renewal request per push,
// forever.
func (r *renewer) due(tok string, now time.Time, forced bool) bool {
	if !r.enabled || now.Before(r.next) {
		return false
	}
	if forced {
		// Still nothing to renew from: an unsigned token cannot be presented to
		// the issuer, and asking would just leak it to a server that will
		// refuse it.
		if _, ok := tokenExpiry(tok); !ok {
			r.next = now.Add(renewRetryMax)
			return false
		}
		return true
	}
	exp, ok := tokenExpiry(tok)
	if !ok {
		// Nothing to renew from. Park it rather than asking again every push.
		r.next = now.Add(renewRetryMax)
		return false
	}
	return !now.Before(exp.Add(-renewLead))
}

// Try once. Returns the token to keep using — the new one on success, the one
// we came in with on any failure.
func (r *renewer) attempt(tok string, now time.Time) string {
	fresh, err := requestRenewal(r.site, tok)
	if err != nil {
		r.fails++
		r.park(now, tok, r.backoff(err))
		warnf("could not renew the relay token: %v", err)
		return tok
	}
	r.fails = 0
	// Held, not committed. confirm() writes it once the relay has accepted a
	// push made with it.
	r.prev, r.pending = tok, fresh
	if exp, ok := tokenExpiry(fresh); ok {
		r.next = exp.Add(-renewLead)
	} else {
		r.next = now.Add(renewRetryMax)
	}
	return fresh
}

// How long to wait after a failure.
//
// Typed rather than one curve for everything: "your token is finished" and
// "the site is having a bad minute" are not the same event, and the second is
// the only one worth asking about again soon. Jitter on every branch for the
// same reason the push loop has it — machines installed in one sitting share a
// token, hit the renewal window within seconds of each other, and would
// otherwise retry in lockstep forever.
func (r *renewer) backoff(err error) time.Duration {
	var d, ceiling time.Duration
	floor := time.Duration(0)
	switch e := err.(type) {
	case renewRefusal:
		switch {
		case e.retryAfter > 0:
			// The server said when. A floor as well as a ceiling: `renew_after`
			// is a number off the network, and it is not a channel for making
			// this helper sleep for a year OR spin.
			d, ceiling, floor = e.retryAfter, renewRetryMax, renewRetryMin/4
		case e.terminal:
			d, ceiling = renewRetryDead, renewRetryDead
		default:
			d, ceiling = r.growing(), renewRetryMax
		}
	default:
		d, ceiling = r.growing(), renewRetryMax
	}
	// ±5%, so a fleet that failed together does not return together. Both bounds
	// are re-applied AFTER the jitter, not before: clamping first leaves a
	// ceiling that is really the ceiling plus 5% (the shape a hostile
	// renew_after would aim for) and a floor that is really the floor minus 5%
	// — and undershooting the floor lands the request back inside the server's
	// own pacing gap, earning a second 429 and a longer wait than if it had
	// simply waited.
	d = time.Duration(float64(d) * (0.95 + 0.1*jitter()))
	if d > ceiling {
		d = ceiling
	}
	if d < floor {
		d = floor
	}
	return d
}

// Park until `now + d`, but never past the last moment the token we hold could
// still have been renewed.
//
// Every backoff here is longer than some token's remaining life: the server
// only renews inside a 14-day window and the helper starts at 7 days, so a
// 30-day freeze — or even a 12-hour one on a token with six hours left —
// guarantees the machine is still parked when its credential dies, at which
// point the forced path cannot rescue it either because the freeze outlives
// that too. Clamping here is what keeps a backoff from becoming a one-way door.
func (r *renewer) park(now time.Time, tok string, d time.Duration) {
	next := now.Add(d)
	if exp, ok := tokenExpiry(tok); ok && exp.After(now) {
		latest := exp.Add(-renewLastCall)
		if !latest.After(now) {
			// Already inside the final hour. Keep trying, but not in a spin.
			latest = now.Add(renewRetryMin / 4)
		}
		if next.After(latest) {
			next = latest
		}
	}
	r.next = next
}

func (r *renewer) growing() time.Duration {
	d := renewRetryMin * time.Duration(1<<min(r.fails-1, 8))
	if d > renewRetryMax || d <= 0 {
		d = renewRetryMax
	}
	return d
}

// The relay accepted a push made with the token we are holding. If that token
// was a renewal, it has now proven itself and can be written down.
//
// Retried on every accepted push rather than once: a save that failed because
// the config directory was momentarily unwritable would otherwise leave the new
// token alive only in memory, and a restart after the bootstrap token expired
// would strand the machine with nothing that works.
func (r *renewer) confirm() {
	if r.pending == "" {
		return
	}
	if err := saveToken(r.relay, r.pending); err != nil {
		warnf("renewed the relay token but could not save it yet: will retry")
		return
	}
	r.pending, r.prev = "", ""
}

// The relay refused a token we had just renewed into. Go back to the one that
// was working — the new one is not trustworthy here, whatever the site said —
// and do not try again for a long time.
//
// Returns the token to use and whether anything changed.
func (r *renewer) rollback(now time.Time) (string, bool) {
	if r.pending == "" {
		return "", false
	}
	back := r.prev
	r.pending, r.prev = "", ""
	// Long enough to sit out a secret rotation, but CLAMPED TO THE OLD TOKEN'S
	// OWN LIFE. The token we are falling back to has at most a fortnight left —
	// the server only renews inside that window — so an unbounded freeze here
	// would still be in force when it expired, and the forced path that exists
	// to rescue exactly that case would find itself parked too. A month of
	// silence, from a helper that had a working credential the whole time.
	r.park(now, back, renewRetryMax)
	warnf("the relay refused the renewed token; falling back to the previous one")
	return back, true
}

// Fold a push result into the renewal state, and hand back the token to use for
// the next one.
//
// This lives here rather than inline in the push loop so that the thing the
// tests drive is the thing transport.go runs. Testing confirm() and rollback()
// directly proved they worked and proved nothing about whether anyone called
// them — a push loop that committed on a 429, or never rolled back at all,
// would have left every one of those tests green.
func (r *renewer) afterPush(code int, tok string, now time.Time) string {
	switch {
	case code == 200:
		// This token just worked. If it came from a renewal it has now earned
		// its place on disk — see the note on renewer.pending for why receipt
		// was not enough.
		r.confirm()
	case code == 401 || code == 403:
		// If we are pushing with a token the site just handed us and the relay
		// will not take it, the renewal was the problem. Going back beats
		// renewing again into the same wall — the two sides verify with one
		// secret, and the state where they disagree is a rotation in progress,
		// not something to retry.
		if back, rolled := r.rollback(now); rolled {
			return back
		}
		if r.due(tok, now, true) {
			return r.attempt(tok, now)
		}
	}
	return tok
}

// One renewal request.
func requestRenewal(site, tok string) (string, error) {
	req, err := http.NewRequest("POST", site+renewPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "subnsub-helper")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
		// Same refusal as the push path, for the same reason: Go's default
		// client keeps Authorization across a redirect to the same host or a
		// subdomain, judging by host alone without checking the scheme, so an
		// https→http hop would put the token on the wire in clear.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", renewError(resp)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRenewBody))
	if err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", errString("renewal answer was not JSON")
	}
	fresh := cleanToken(out.Token)
	if fresh == "" {
		return "", errString("renewal answer carried no usable token")
	}

	// ── everything below decides whether this answer is worth believing ──
	//
	// The tag cannot be checked here, so these are the properties that can be:
	// same account, longer life, and a life that is not absurd. They are what
	// keeps a wrong answer from being a permanent one, since the stored token
	// is chosen over the installed one BY EXPIRY.
	newID, ok := tokenIdentity(fresh)
	if !ok {
		return "", errString("renewed token is not the shape a token has")
	}
	if oldID, ok := tokenIdentity(tok); ok && newID != oldID {
		return "", errString("renewed token names a different account")
	}
	newExp, ok := tokenExpiry(fresh)
	if !ok {
		return "", errString("renewed token carries no expiry")
	}
	// It has to actually be worth swapping to. A reply that hands back something
	// expiring no later than what we hold is either a bug or someone playing,
	// and taking it would reset nothing while overwriting a working token.
	if oldExp, ok := tokenExpiry(tok); ok && !newExp.After(oldExp) {
		return "", errString("renewed token expires no later than the current one")
	}
	if newExp.After(time.Now().Add(maxTokenLife)) {
		return "", errString("renewed token claims an implausible lifetime")
	}
	return fresh, nil
}

// A refusal, carried as a type so the backoff can tell the kinds apart. The
// status is the whole decision; the message is for a human reading stderr.
type renewRefusal struct {
	msg        string
	terminal   bool // nothing this side does will change the answer
	retryAfter time.Duration
}

func (e renewRefusal) Error() string { return e.msg }

// Turn a refusal into something the log can explain, without parsing anything
// we would then act on.
func renewError(resp *http.Response) error {
	var out struct {
		Error      string  `json:"error"`
		RenewAfter float64 `json:"renew_after"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRenewBody))
	_ = json.Unmarshal(body, &out)
	switch {
	case resp.StatusCode == 401:
		return renewRefusal{
			msg:      "this machine's token is no longer valid — reinstall to reconnect it",
			terminal: true,
		}
	case resp.StatusCode == 403 && out.Error == "plus-required":
		// NOT terminal, despite reading like it. Entitlement is state that
		// changes outside this process: somebody who resubscribes tomorrow
		// morning must not find their machines frozen out until next month.
		// The ordinary curve caps at twelve hours, and the token expires within
		// a fortnight anyway — at which point 401 takes over and that one really
		// is final.
		return renewRefusal{msg: "this account is no longer entitled to the relay"}
	case resp.StatusCode == 403 && out.Error == "subject-unknown":
		return renewRefusal{msg: "this token predates renewal — open the Monitor panel once to link it"}
	case resp.StatusCode == 429:
		var after time.Duration
		if out.RenewAfter > 0 {
			// Absolute unix seconds, as the endpoint sends it. Treated as a
			// hint and clamped by the caller.
			if d := time.Until(time.Unix(int64(out.RenewAfter), 0)); d > 0 {
				after = d
			}
		}
		if after == 0 {
			after = renewRetryMin
		}
		return renewRefusal{msg: "too early to renew", retryAfter: after}
	default:
		return renewRefusal{msg: "renewal refused: " + itoa(resp.StatusCode)}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
