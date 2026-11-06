package main

// A newer adapter table, applied without a rebuild.
//
// The table in adapters.json is the part of the CPA rung that rots: a vendor
// renames a field, a console bumps the User-Agent it sends, a window grows a
// new key. Every one of those used to cost a helper release — a build, seven
// uploads, and a button pressed on every machine. Now the table travels on
// its own: this program looks at the release bucket a few times a day, and a
// newer table that carries a valid signature replaces the one in force, in
// memory, between two pushes. Nothing restarts. The next push reads by the
// new table.
//
// update.go refuses to poll for binaries on its own, and says why at length:
// an unattended fetch-and-run channel on every machine is more authority
// than anyone granted. This is a timer, so the difference has to be argued,
// not assumed. Three things make a table a different object from a binary:
//
//   - it cannot run. adapter.go reads field names and formats out of it and
//     nothing else; there is no instruction in the vocabulary.
//   - it cannot move a credential. Every URL it names must sit under a host
//     in cpa.go's compiled-in allow-list, and CPA — not this program — holds
//     the token that goes with the request.
//   - it is signed by a key that is not the bucket's. The public half is the
//     constant below, compiled into this binary; the private half never
//     leaves the release machine. The bucket is a courier: it can withhold a
//     table or replay an old one (and an old one is refused by version), but
//     it cannot compose one.
//
// What a bad table CAN do is publish a wrong number for a while. That is the
// same power the embedded table always had, and it is what the verify-before-
// publish step in release-adapters.sh is for.
//
// The last good table is kept beside the token, 0600, and is loaded — and
// verified again — at start, so a restart does not fall back to the build's
// table and a machine that cannot reach the bucket keeps what it had.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// The release key's public half. Rotating it is a helper release, by
	// design: a table that could name its own key would be a table that
	// could sign itself.
	adapterFeedPubKey = "CMREWENxYZaVTWrJD/Y2RovFpGAj9SwnJLBW2Pb6TKA="
	// What is signed is the table prefixed with this line, so a signature
	// over some other document by the same key means nothing here.
	adapterFeedDomain = "subnsub-monitor adapters\n"

	adapterFeedFile    = "adapters.json"
	adapterFeedSigFile = "adapters.sig"
	adapterFeedEvery   = 6 * time.Hour
	adapterFeedMax     = 256 * 1024
	// "off" keeps whatever table this build embeds and never looks. The
	// environment belongs to whoever started the process.
	adapterFeedEnv = "MON_ADAPTERS"
)

var adapterFeedKeys = func() []ed25519.PublicKey {
	if k := parsePublicKey(adapterFeedPubKey); k != nil {
		return []ed25519.PublicKey{k}
	}
	return nil
}()

// True when `sig` (base64) is the release key's signature over `raw`.
func adapterSigned(raw, sig []byte, keys []ed25519.PublicKey) bool {
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(s) != ed25519.SignatureSize || len(keys) == 0 {
		return false
	}
	msg := append([]byte(adapterFeedDomain), raw...)
	for _, k := range keys {
		if ed25519.Verify(k, msg, s) {
			return true
		}
	}
	return false
}

func adaptersVersion() int { return currentAdapters().Version }

// The table kept beside the token from an earlier fetch, if it verifies.
// Read once, at the first use of the table in a process.
var adapterPersistOnce sync.Once

func loadPersistedAdapters() {
	adapterPersistOnce.Do(func() {
		dir := configDir()
		if dir == "" || len(adapterFeedKeys) == 0 {
			return
		}
		raw, err := readRegular(filepath.Join(dir, adapterFeedFile), adapterFeedMax)
		if err != nil {
			return
		}
		sig, err := readRegular(filepath.Join(dir, adapterFeedSigFile), 4096)
		if err != nil || !adapterSigned(raw, sig, adapterFeedKeys) {
			return
		}
		// Straight to the installer, never through currentAdapters: this
		// runs inside the Once that currentAdapters waits on.
		if v, ok, _ := installAdaptersIfNewer(raw); ok {
			warnf("adapters: table v%d in force (kept from an earlier fetch)", v)
		}
	})
}

// A regular file, whole, or nothing: the same refusals installedEnv makes,
// for the same reasons — this path is under the config directory, and a
// FIFO or a symlink there is not something this program wrote.
func readRegular(path string, max int64) ([]byte, error) {
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return readBounded(f, max)
}

func persistAdapters(raw, sig []byte) error {
	dir := configDir()
	if dir == "" {
		return errors.New("no config directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range [][2]string{{adapterFeedFile, string(raw)}, {adapterFeedSigFile, string(sig)}} {
		path := filepath.Join(dir, f[0])
		tmp := path + ".new"
		if err := os.WriteFile(tmp, []byte(f[1]), 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

// Where the table is published: beside the binaries, and movable only from
// this machine's own environment (the update.go rule).
func adapterFeedBase() string {
	if v := strings.TrimSpace(os.Getenv(updateBaseEnv)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return updateBase
}

// One look at the bucket. Returns whether a newer table was put in force.
func adapterRefreshOnce(ctx context.Context, base string, keys []ed25519.PublicKey) (bool, error) {
	if len(keys) == 0 {
		return false, errors.New("this build carries no adapter key")
	}
	c := updateClient()
	raw, err := fetchBytes(ctx, c, base+"/"+adapterFeedFile, adapterFeedMax)
	if err != nil {
		return false, err
	}
	sig, err := fetchBytes(ctx, c, base+"/"+adapterFeedSigFile, 4096)
	if err != nil {
		return false, err
	}
	if !adapterSigned(raw, sig, keys) {
		return false, errors.New("the published table is not signed by the release key")
	}
	v, installed, err := installAdaptersIfNewer(raw)
	if err != nil {
		return false, err
	}
	if !installed {
		return false, nil
	}
	if err := persistAdapters(raw, sig); err != nil {
		warnf("adapters: table v%d in force, but could not be kept for the next start", v)
	}
	return true, nil
}

// One file from the bucket, whole and bounded. Not fetchText: that one is
// sized for a VERSION line, and this one has to refuse a table one byte
// over its cap rather than parse a prefix of it.
func fetchBytes(ctx context.Context, c *http.Client, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "subnsub-helper")
	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.New("the bucket could not be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, errStatus(resp.StatusCode)
	}
	return readBounded(resp.Body, max)
}

// The loop the daemon runs: a first look shortly after start, then a few a
// day. Errors are said once per distinct cause, not once per attempt.
func startAdapterFeed(ctx context.Context) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(adapterFeedEnv)), "off") {
		return
	}
	if len(adapterFeedKeys) == 0 {
		return
	}
	loadPersistedAdapters()
	go func() {
		wait := time.Duration(30+rand.Intn(60)) * time.Second
		lastErr := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			installed, err := adapterRefreshOnce(ctx, adapterFeedBase(), adapterFeedKeys)
			switch {
			case err != nil:
				if msg := err.Error(); msg != lastErr {
					warnf("adapters: %s", msg)
					lastErr = msg
				}
			case installed:
				warnf("adapters: table v%d in force", adaptersVersion())
				lastErr = ""
			default:
				lastErr = ""
			}
			// Spread across machines, so a fleet does not ask in unison.
			wait = adapterFeedEvery + time.Duration(rand.Intn(1800))*time.Second
		}
	}()
}
