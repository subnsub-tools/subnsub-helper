package main

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A token of the real shape, for a named account, expiring when asked. Only the
// identity and expiry fields are ever read by this package, so the tag is
// filler — but the LENGTH is not filler: the decoders refuse anything that is
// not exactly 44 bytes, which is what keeps a 43-byte self-minted token from
// being read as a signed one whose expiry happens to land somewhere plausible.
func fakeTokenFor(account byte, exp time.Time) string {
	raw := make([]byte, tokenBytes)
	for i := range raw {
		raw[i] = byte(i)
	}
	for i := 0; i < tokenIDLen; i++ {
		raw[i] = account
	}
	binary.BigEndian.PutUint32(raw[tokenExpOff:tokenExpOff+4], uint32(exp.Unix()))
	return base64.RawURLEncoding.EncodeToString(raw)
}

func fakeToken(exp time.Time) string { return fakeTokenFor(0xA1, exp) }

func legacyToken() string { return base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }

func TestTokenExpiryReadsTheSignedLayout(t *testing.T) {
	want := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	got, ok := tokenExpiry(fakeToken(want))
	if !ok || !got.Equal(want) {
		t.Fatalf("tokenExpiry = %v, %v; want %v, true", got, ok, want)
	}
}

func TestTokenExpiryRefusesUnsignedAndJunk(t *testing.T) {
	if len(legacyToken()) != legacyTokLen {
		t.Fatalf("legacy token is %d chars, expected %d", len(legacyToken()), legacyTokLen)
	}
	for _, tok := range []string{legacyToken(), "", "not base64!!", base64.RawURLEncoding.EncodeToString(make([]byte, 45))} {
		if _, ok := tokenExpiry(tok); ok {
			t.Errorf("tokenExpiry(%q) reported an expiry it should not have", tok)
		}
	}
	// All-zero expiry is a token that never carried one, not one that expired
	// in 1970 — the difference decides between "park it" and "renew forever".
	if _, ok := tokenExpiry(fakeToken(time.Unix(0, 0))); ok {
		t.Error("a zero expiry should not read as an expiry")
	}
}

func TestCleanTokenHoldsTheRelayAlphabet(t *testing.T) {
	good := fakeToken(time.Now())
	if cleanToken("  "+good+"\n") != good {
		t.Error("surrounding whitespace should be trimmed, not fatal")
	}
	for _, bad := range []string{"short", "has space in it aaaaaaaaaaaaaaaaaaaaa", "line\nbreak_aaaaaaaaaaaaaaaaaaaa", "plus+slash/aaaaaaaaaaaaaaaaaaaa"} {
		if cleanToken(bad) != "" {
			t.Errorf("cleanToken(%q) accepted a value the relay would refuse", bad)
		}
	}
}

// ── who may renew, and where ───────────────────────────────────────────────

func TestRenewalIsOffForRelaysWeDoNotIssueFor(t *testing.T) {
	t.Setenv(siteEnv, "")

	if site, ok := renewalSite(officialRelay); !ok || site != defaultSite {
		t.Errorf("the shipped relay should renew against the shipped site, got %q %v", site, ok)
	}
	if _, ok := renewalSite("https://monitor.subnsub.com/"); !ok {
		t.Error("a trailing slash is the same relay")
	}
	// ★ The finding this test exists for: `connect URL` and MON_RELAY are
	// documented ways to point at your own relay. That relay's token is not
	// ours, and answering its 403 by POSTing the token to our site would hand a
	// third party's bearer secret to a server they never chose.
	for _, hostile := range []string{
		"https://relay.example.com",
		"https://monitor.subnsub.com.evil.test",
		"https://evil.test/monitor.subnsub.com",
	} {
		if site, ok := renewalSite(hostile); ok {
			t.Errorf("★ renewalSite(%q) enabled renewal against %q — a custom relay's token must never be sent to our site", hostile, site)
		}
	}
}

func TestOperatorCanNameTheirOwnSite(t *testing.T) {
	t.Setenv(siteEnv, "https://issuer.example.com/")
	site, ok := renewalSite("https://relay.example.com")
	if !ok || site != "https://issuer.example.com" {
		t.Errorf("an explicitly named site should be used, got %q %v", site, ok)
	}
	// An http:// site would put the token on the wire in clear — and must NOT
	// silently fall back to ours, because somebody who set this meant theirs.
	t.Setenv(siteEnv, "http://issuer.example.com")
	if _, ok := renewalSite(officialRelay); ok {
		t.Error("★ an http:// site must disable renewal, not fall back to the default site")
	}
}

// ── choosing between the installed token and a renewed one ─────────────────

func TestPickTokenPrefersTheLongerLife(t *testing.T) {
	now := time.Now()
	old := fakeToken(now.Add(2 * 24 * time.Hour))
	fresh := fakeToken(now.Add(29 * 24 * time.Hour))

	if got := pickToken(old, fresh); got != fresh {
		t.Error("a renewed token on disk should supersede the installed one")
	}
	// The reinstall case, and the reason this is not simply "the file wins":
	// pasting a new token from the panel writes it to the environment, and if
	// the stale file outranked it, reinstalling would silently do nothing.
	if got := pickToken(fresh, old); got != fresh {
		t.Error("a freshly installed token should override an older renewed one")
	}
	if got := pickToken(old, ""); got != old {
		t.Error("no file means the installed token")
	}
	if got := pickToken("", fresh); got != fresh {
		t.Error("no environment token means the file")
	}
	if got := pickToken(old, "garbage\x00"); got != old {
		t.Error("an unusable file must not displace a working token")
	}
	if got := pickToken(legacyToken(), fresh); got != legacyToken() {
		t.Error("a signed file token must not displace an unsigned allow-listed one")
	}
}

func TestPickTokenRefusesAnotherAccountsToken(t *testing.T) {
	now := time.Now()
	mine := fakeTokenFor(0xA1, now.Add(2*24*time.Hour))
	theirs := fakeTokenFor(0xB2, now.Add(29*24*time.Hour))
	// ★ Reinstalling with a second account's token must not leave this machine
	// pushing into the first account's dashboard just because the old renewal
	// happens to last longer.
	if got := pickToken(mine, theirs); got != mine {
		t.Error("★ a stored token for a different account must never win on expiry alone")
	}
}

func TestStoredTokenIsScopedToItsRelay(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	conf := filepath.Join(dir, ".config", "subnsub-helper")
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	tok := fakeToken(time.Now().Add(20 * 24 * time.Hour))
	if err := saveToken(officialRelay, tok); err != nil {
		t.Fatal(err)
	}

	if got := storedToken(officialRelay); got != tok {
		t.Error("the token saved for a relay should be readable for that relay")
	}
	// ★ One file, and `connect` takes any URL. Without the relay field a
	// credential minted for ours would be presented to somebody else's relay.
	if got := storedToken("https://relay.example.com"); got != "" {
		t.Error("★ a token stored for one relay must not be handed to another")
	}

	t.Setenv(siteEnv, "")
	if got := resolveStartToken("https://relay.example.com", legacyToken()); got != legacyToken() {
		t.Error("★ a relay we cannot renew for must not consult the stored token at all")
	}
	if got := resolveStartToken(officialRelay, fakeToken(time.Now().Add(time.Hour))); got != tok {
		t.Error("for the shipped relay the longer-lived stored token should win")
	}
}

func TestSaveTokenLeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := saveToken(officialRelay, fakeToken(time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, ".config", "subnsub-helper", tokenFile+".new")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("the staging file must not survive a successful save — it holds a bearer secret")
	}
}

// ── when to try, and how hard ──────────────────────────────────────────────

func TestRenewerWaitsUntilTheLeadWindow(t *testing.T) {
	now := time.Now()
	r := newRenewer(officialRelay)

	if r.due(fakeToken(now.Add(20*24*time.Hour)), now, false) {
		t.Error("a token with 20 days left should not be renewed yet")
	}
	if !r.due(fakeToken(now.Add(renewLead-time.Hour)), now, false) {
		t.Error("a token inside the lead window should be renewed")
	}
}

func TestRenewerIsInertWhenDisabled(t *testing.T) {
	t.Setenv(siteEnv, "")
	now := time.Now()
	r := newRenewer("https://relay.example.com")
	if r.enabled {
		t.Fatal("a custom relay with no named site must not enable renewal")
	}
	// ★ Including on the forced path — that is the one a hostile relay controls,
	// by answering 403 to a push.
	if r.due(fakeToken(now.Add(time.Hour)), now, true) {
		t.Error("★ a disabled renewer must not attempt even when the relay refuses a push")
	}
}

func TestRenewerBackoffAlsoBindsForcedAttempts(t *testing.T) {
	now := time.Now()
	r := newRenewer(officialRelay)
	tok := fakeToken(now.Add(20 * 24 * time.Hour))

	if !r.due(tok, now, true) {
		t.Fatal("the first forced attempt should go through")
	}
	// …but once an attempt has failed and set a backoff, forcing must NOT get
	// past it. Without this a relay answering 403 for a reason renewal cannot
	// fix means one renewal request per push, forever.
	r.next = now.Add(renewRetryMin)
	if r.due(tok, now, true) {
		t.Error("a forced attempt must still respect the backoff")
	}
	if !r.due(tok, now.Add(renewRetryMin+time.Second), true) {
		t.Error("after the backoff elapses, forcing should work again")
	}
}

func TestForcedAttemptStillNeedsSomethingToRenewFrom(t *testing.T) {
	now := time.Now()
	r := newRenewer(officialRelay)
	// An unsigned token cannot be presented to the issuer; asking would only
	// leak it to a server that will refuse it.
	if r.due(legacyToken(), now, true) {
		t.Error("★ a token with no expiry must not be sent to the issuer even on a forced attempt")
	}
	if !r.next.After(now) {
		t.Error("and it should be parked rather than re-evaluated every push")
	}
}

func TestBackoffTellsTheKindsApart(t *testing.T) {
	r := newRenewer(officialRelay)
	r.fails = 1

	dead := r.backoff(renewRefusal{msg: "gone", terminal: true})
	if dead < renewRetryMax {
		t.Errorf("★ a terminal refusal should not be retried on the ordinary curve (got %v)", dead)
	}
	paced := r.backoff(renewRefusal{msg: "too early", retryAfter: 30 * time.Minute})
	if paced < 20*time.Minute || paced > time.Hour {
		t.Errorf("a server-supplied wait should be honoured within reason (got %v)", paced)
	}
	// …but not without bound: retryAfter is a number from the network.
	silly := r.backoff(renewRefusal{msg: "too early", retryAfter: 400 * 24 * time.Hour})
	if silly > renewRetryMax {
		t.Errorf("★ a server must not be able to make this helper sleep for a year (got %v)", silly)
	}
	ordinary := r.backoff(errString("network"))
	if ordinary <= 0 || ordinary > renewRetryMax {
		t.Errorf("an ordinary failure should back off within the cap (got %v)", ordinary)
	}
	// Jitter: two draws for the same input should differ, or a fleet sharing one
	// token returns in lockstep.
	same := 0
	for i := 0; i < 8; i++ {
		if r.backoff(errString("network")) == ordinary {
			same++
		}
	}
	if same == 8 {
		t.Error("★ backoff must be jittered — machines share a token and hit the window together")
	}
}

// ── what a renewal answer has to prove ─────────────────────────────────────

func renewServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("renewal must present the current token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestRenewalAnswerMustBeTheSameAccount(t *testing.T) {
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	other := fakeTokenFor(0xB2, now.Add(30*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+other+`"}`)
	defer srv.Close()
	if _, err := requestRenewal(srv.URL, held); err == nil {
		t.Error("★ a token naming a different account must be refused — it would move this machine's readings into someone else's dashboard")
	}
}

func TestRenewalAnswerMustNotClaimAnAbsurdLifetime(t *testing.T) {
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	forever := fakeTokenFor(0xA1, now.Add(5*365*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+forever+`"}`)
	defer srv.Close()
	// The stored token beats the installed one BY EXPIRY, so a forged far-future
	// expiry would win every restart from here on — permanently.
	if _, err := requestRenewal(srv.URL, held); err == nil {
		t.Error("★ an implausible lifetime must be refused")
	}
}

func TestRenewalAnswerMustActuallyExtend(t *testing.T) {
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	sooner := fakeTokenFor(0xA1, now.Add(time.Hour))

	srv := renewServer(t, 200, `{"token":"`+sooner+`"}`)
	defer srv.Close()
	if _, err := requestRenewal(srv.URL, held); err == nil {
		t.Error("a token expiring sooner than the one held must be refused")
	}
}

func TestRenewalAcceptsAGoodAnswer(t *testing.T) {
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	good := fakeTokenFor(0xA1, now.Add(30*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+good+`"}`)
	defer srv.Close()
	got, err := requestRenewal(srv.URL, held)
	if err != nil || got != good {
		t.Errorf("a same-account, longer-lived, plausible token should be accepted: %q %v", got, err)
	}
}

func TestRenewalRefusalsAreTyped(t *testing.T) {
	held := fakeTokenFor(0xA1, time.Now().Add(3*24*time.Hour))

	dead := renewServer(t, 401, `{"error":"bad-token"}`)
	defer dead.Close()
	_, err := requestRenewal(dead.URL, held)
	if r, ok := err.(renewRefusal); !ok || !r.terminal {
		t.Errorf("401 should be terminal, got %#v", err)
	}

	lapsed := renewServer(t, 403, `{"error":"plus-required"}`)
	defer lapsed.Close()
	_, err = requestRenewal(lapsed.URL, held)
	// ★ NOT terminal. Entitlement changes outside this process — somebody who
	// resubscribes tomorrow must not find their machines frozen out for a
	// month. Only 401 ("this token will never verify again") earns that.
	if r, ok := err.(renewRefusal); !ok || r.terminal {
		t.Errorf("★ a lapsed subscription is recoverable and must not be treated as final: %#v", err)
	}

	unlinked := renewServer(t, 403, `{"error":"subject-unknown"}`)
	defer unlinked.Close()
	_, err = requestRenewal(unlinked.URL, held)
	if r, ok := err.(renewRefusal); !ok || r.terminal {
		t.Errorf("an unlinked token is fixable by opening the panel, not terminal: %#v", err)
	}
}

// ── committing only what the relay accepted ────────────────────────────────

func TestRenewedTokenIsCommittedOnlyAfterAPushSucceeds(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	good := fakeTokenFor(0xA1, now.Add(30*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+good+`"}`)
	defer srv.Close()

	r := newRenewer(officialRelay)
	r.site = srv.URL
	got := r.attempt(held, now)
	if got != good {
		t.Fatalf("the renewed token should be used immediately, got %q", got)
	}
	// ★ Not on disk yet. The issuer and the relay verify with one secret, and a
	// rotation in progress is exactly the state where the site issues tokens the
	// relay refuses — committing on receipt would overwrite the only working
	// credential with a broken one.
	if storedToken(officialRelay) != "" {
		t.Error("★ a renewed token must not be persisted before the relay has accepted it")
	}

	r.confirm()
	if storedToken(officialRelay) != good {
		t.Error("once a push with it succeeded, it belongs on disk")
	}
}

func TestRejectedRenewalRollsBackToTheWorkingToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	good := fakeTokenFor(0xA1, now.Add(30*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+good+`"}`)
	defer srv.Close()

	r := newRenewer(officialRelay)
	r.site = srv.URL
	_ = r.attempt(held, now)

	back, rolled := r.rollback(now)
	if !rolled || back != held {
		t.Errorf("★ a relay that refuses the renewed token should send us back to the one that worked, got %q %v", back, rolled)
	}
	if storedToken(officialRelay) != "" {
		t.Error("and nothing should have been written")
	}
	if !r.next.After(now.Add(time.Minute)) {
		t.Error("and it should not immediately try again")
	}
	// ★ The freeze must expire while the token we fell back to is STILL ALIVE.
	// It has at most a fortnight left (the server only renews inside that
	// window), so an unbounded park would still be in force when it died — and
	// the forced path that exists to rescue exactly that would be parked too.
	// A month of silence from a helper that had a working credential all along.
	heldExp, _ := tokenExpiry(held)
	if !r.next.Before(heldExp) {
		t.Errorf("★ the rollback freeze outlives the token it protects: next=%v, token dies %v", r.next, heldExp)
	}
	if _, again := r.rollback(now); again {
		t.Error("there is nothing left to roll back to")
	}
}

func TestConfirmRetriesASaveThatFailed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	good := fakeTokenFor(0xA1, now.Add(30*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+good+`"}`)
	defer srv.Close()

	r := newRenewer(officialRelay)
	r.site = srv.URL
	_ = r.attempt(held, now)

	// A config directory that cannot be written — the sandboxed-service case.
	blocked := filepath.Join(dir, ".config")
	if err := os.MkdirAll(blocked, 0o500); err != nil {
		t.Fatal(err)
	}
	r.confirm()
	if r.pending == "" {
		t.Error("★ a failed save must keep the token pending, or a restart after the bootstrap expires strands the machine")
	}

	if err := os.Chmod(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	r.confirm()
	if storedToken(officialRelay) != good {
		t.Error("the next accepted push should retry the save")
	}
}

// ── the state machine as the push loop actually drives it ──────────────────
//
// These go through afterPush, which is what transport.go calls. Driving
// confirm() and rollback() directly proved they worked and proved nothing
// about whether anything called them: a push loop that committed on a 429, or
// never rolled back at all, left every one of those tests green.

func newRenewerAt(t *testing.T, srvURL string) *renewer {
	t.Helper()
	r := newRenewer(officialRelay)
	r.site = srvURL
	return r
}

func TestAfterPushCommitsOnlyOnAcceptance(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	good := fakeTokenFor(0xA1, now.Add(30*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+good+`"}`)
	defer srv.Close()
	r := newRenewerAt(t, srv.URL)
	tok := r.attempt(held, now)

	// Anything that is not a 200 must leave it pending. 429 is the one that
	// matters: the relay paces a busy room routinely, and treating that as
	// proof would commit a token the relay has not actually accepted.
	// 409 is "room full": the relay refusing the MACHINE, with the token as
	// good as ever — renewing or rolling back would be answering a question
	// nobody asked.
	for _, code := range []int{409, 429, 500, 503} {
		if got := r.afterPush(code, tok, now); got != tok {
			t.Errorf("a %d should not change the token in hand", code)
		}
		if storedToken(officialRelay) != "" {
			t.Errorf("★ a %d is not acceptance and must not commit the renewal", code)
		}
	}

	if got := r.afterPush(200, tok, now); got != tok {
		t.Error("an accepted push keeps the token")
	}
	if storedToken(officialRelay) != good {
		t.Error("★ and commits it — this is the only path that may")
	}
}

func TestAfterPushRollsBackWhenTheRelayRefusesARenewal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(3*24*time.Hour))
	good := fakeTokenFor(0xA1, now.Add(30*24*time.Hour))

	srv := renewServer(t, 200, `{"token":"`+good+`"}`)
	defer srv.Close()
	r := newRenewerAt(t, srv.URL)
	tok := r.attempt(held, now)

	got := r.afterPush(403, tok, now)
	if got != held {
		t.Errorf("★ the push loop must fall back to the token that was working, got %q", got)
	}
	if storedToken(officialRelay) != "" {
		t.Error("and must not have written the refused one")
	}
	// The freeze has to end while the fallback token is still alive.
	heldExp, _ := tokenExpiry(held)
	if !r.next.Before(heldExp) {
		t.Errorf("★ freeze outlives the token it fell back to: next=%v, dies %v", r.next, heldExp)
	}
}

func TestParkNeverOutlivesTheTokenItProtects(t *testing.T) {
	now := time.Now()
	r := newRenewer(officialRelay)

	// A token with six hours left and a twelve-hour backoff: the clamp is the
	// only thing that keeps the next attempt on the living side of expiry.
	short := fakeTokenFor(0xA1, now.Add(6*time.Hour))
	r.park(now, short, renewRetryMax)
	exp, _ := tokenExpiry(short)
	if !r.next.Before(exp) {
		t.Errorf("★ parked past expiry: next=%v, token dies %v", r.next, exp)
	}

	// Inside the final hour it should still come back, and not spin.
	last := fakeTokenFor(0xA1, now.Add(20*time.Minute))
	r.park(now, last, renewRetryMax)
	if !r.next.After(now) || r.next.After(now.Add(time.Hour)) {
		t.Errorf("in the final stretch it should retry soon but not spin, got %v", r.next.Sub(now))
	}

	// A token with no expiry has nothing to clamp against; the plain backoff
	// stands.
	r.park(now, legacyToken(), renewRetryMax)
	if r.next.Before(now.Add(renewRetryMax / 2)) {
		t.Error("an unsigned token should still get the full backoff")
	}
}

func TestLapsedEntitlementIsRetriedBeforeTheTokenDies(t *testing.T) {
	now := time.Now()
	held := fakeTokenFor(0xA1, now.Add(10*24*time.Hour))

	srv := renewServer(t, 403, `{"error":"plus-required"}`)
	defer srv.Close()
	r := newRenewerAt(t, srv.URL)
	_ = r.attempt(held, now)

	// ★ Somebody who resubscribes tomorrow morning must find their machines
	// renewing again, not frozen out until next month.
	if r.next.After(now.Add(renewRetryMax + time.Minute)) {
		t.Errorf("★ a lapsed subscription must be re-checked within hours, not weeks (parked %v)", r.next.Sub(now))
	}
}

func TestRetryAfterKeepsItsFloorThroughTheJitter(t *testing.T) {
	r := newRenewer(officialRelay)
	r.fails = 1
	floor := renewRetryMin / 4
	for i := 0; i < 64; i++ {
		d := r.backoff(renewRefusal{msg: "too early", retryAfter: floor})
		if d < floor {
			// Undershooting lands the request back inside the server's own
			// pacing gap, earning a second 429 and a longer wait than simply
			// waiting would have cost.
			t.Fatalf("★ jitter took the wait below its floor: %v < %v", d, floor)
		}
		if d > renewRetryMax {
			t.Fatalf("and it must still respect the ceiling: %v", d)
		}
	}
}

// ── the token the installer wrote ──────────────────────────────────────────
//
// This file is the ONLY source of credentials on a Windows install: Task
// Scheduler carries no environment, and the two alternatives — the command line
// and the user's persistent environment — are both readable by every other
// program that user runs. So a parsing bug here is not an inconvenience, it is
// a machine that silently never reports.

func writeTokenFile(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "subnsub-helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestInstalledEnvReadsWhatTheInstallerWrites(t *testing.T) {
	// Byte for byte what install.sh and install.ps1 produce.
	writeTokenFile(t, "SUBNSUB_MONITOR_TOKEN=abcdefghijklmnopqrstuvwxyz012345\nSUBNSUB_MONITOR_SITE=https://tools.example.com\nMON_CPA_URL=https://cpa.example.com\nMON_CPA_KEY=key\n")
	env := installedEnv()
	if got := env[tokenEnv]; got != "abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatalf("token: %q", got)
	}
	if got := env[siteEnv]; got != "https://tools.example.com" {
		t.Fatalf("site: %q", got)
	}
	if got := env[cpaURLEnv]; got != "https://cpa.example.com" || env[cpaKeyEnv] != "key" || len(env) != 4 {
		t.Fatalf("CPA whitelist: %v", env)
	}
}

func TestInstalledEnvIsNotAnEnvironment(t *testing.T) {
	// A fixed whitelist, not a loader. Anything else in the file is
	// somebody else's business and must not become a setting this program acts
	// on — the file lives in a directory a local user may be able to write.
	writeTokenFile(t, "PATH=/tmp/evil\nSUBNSUB_MONITOR_RELAY=https://elsewhere.example\nSUBNSUB_MONITOR_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n")
	env := installedEnv()
	if len(env) != 1 {
		t.Fatalf("read a name outside the fixed whitelist: %v", env)
	}
	if _, ok := env["PATH"]; ok {
		t.Fatal("★ read PATH out of the token file")
	}
}

func TestInstalledEnvSurvivesTheAbsentAndTheOdd(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no file at all
	if env := installedEnv(); len(env) != 0 {
		t.Fatalf("a missing file produced settings: %v", env)
	}
	// Trailing whitespace and CRLF: the Windows installer writes this file with
	// PowerShell, whose default line ending is \r\n. A token with a stray \r on
	// the end is refused by the relay, and the symptom is a machine that
	// installs cleanly and never appears.
	writeTokenFile(t, "SUBNSUB_MONITOR_TOKEN=abcdefghijklmnopqrstuvwxyz012345\r\n")
	if got := installedEnv()[tokenEnv]; got != "abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatalf("★ CRLF left something on the token: %q", got)
	}
	// And a byte-order mark, which Notepad puts on every UTF-8 file it saves
	// and PowerShell put on this one until version 6. It prefixes the KEY, not
	// the value, so the symptom is not a broken token but no token at all.
	writeTokenFile(t, "\ufeffSUBNSUB_MONITOR_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n")
	if got := installedEnv()[tokenEnv]; got != "abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatalf("★ a BOM hid the token from the parser: %q", got)
	}
}

// A file this program did not write is refused WHOLE, not parsed as far as it
// looks plausible. This one holds a credential and lives in a directory a local
// user may be able to reach, so every uncertainty here is a no.
func TestInstalledEnvRefusesWhatItCannotVouchFor(t *testing.T) {
	// Oversized: a valid-looking first line in front of a megabyte of anything
	// else. Reading the prefix and stopping would accept it.
	writeTokenFile(t, "SUBNSUB_MONITOR_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n"+
		strings.Repeat("x", 9<<10))
	if env := installedEnv(); len(env) != 0 {
		t.Fatalf("★ read a token out of an oversized file: %v", env)
	}

	// Exactly at the cap still works — the limit is a limit, not an off-by-one.
	line := "SUBNSUB_MONITOR_TOKEN=abcdefghijklmnopqrstuvwxyz012345\n"
	writeTokenFile(t, line+strings.Repeat("#", maxTokenFile-len(line)))
	if got := installedEnv()[tokenEnv]; got != "abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatalf("a file exactly at the cap should be read: %q", got)
	}

	// A directory where the file should be.
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".config", "subnsub-helper", "token"), 0o700); err != nil {
		t.Fatal(err)
	}
	if env := installedEnv(); len(env) != 0 {
		t.Fatalf("★ a directory was read as a config file: %v", env)
	}
}

func TestSiteOverridePrefersTheEnvironment(t *testing.T) {
	writeTokenFile(t, "SUBNSUB_MONITOR_SITE=https://from-file.example\n")
	if got := siteOverride(); got != "https://from-file.example" {
		t.Fatalf("file: %q", got)
	}
	// Whoever started the process wins over what an older install wrote, which
	// is the same precedence every other switch in this helper follows.
	t.Setenv(siteEnv, "https://from-env.example")
	if got := siteOverride(); got != "https://from-env.example" {
		t.Fatalf("env: %q", got)
	}
}
