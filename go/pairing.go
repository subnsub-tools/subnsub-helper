package main

// Pairing — how a machine installed with the self-hosted page's line tells
// the browser that made the line where it waits, with no relay to say so.
// transport/pair.go is the node itself; the page mints its identity
// (monitor-direct.js pairMint).
//
// THE FILE IS `pairing`, written by the installer from --pair and nothing
// else: the token on its first line, the browser key it is for on its
// second, 0600 like every secret here. While it is there and unexpired, and
// this machine's own tunnel is up, a pairing node waits at the relay its
// token names, admitting that one key and answering it with this machine's
// own address. It goes — the node shut, the file removed — once that browser
// has said hello to the machine's own node, which is the browser having heard
// the address; and after a week regardless, the week after which the page
// folds its waiting entry away. Its age is its deadline: the line run again
// starts the week again.
//
// Nothing else is granted by it. The browser's key is on the allowlist because
// the same line put it there (--allow); the pairing node's private key is in
// the line, so it is worth the one frame it serves, to the one key that may
// ask, until that key has asked.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const (
	pairingFileName = "pairing"
	pairingTTL      = 7 * 24 * time.Hour
	pairingPoll     = 10 * time.Second
	pairingFileMax  = 8 << 10
)

var errPairingExpired = errors.New("pairing expired")

type pairingFile struct {
	id    transport.PairIdentity
	peer  key.NodePublic
	until time.Time
	// When the line wrote it: only a hello after this ends it.
	at time.Time
	// The file as read — its contents, trimmed, and its identity on disk —
	// what tells this pairing from one a later run of the line wrote over
	// it, even with the same contents.
	sig string
	fi  os.FileInfo
}

// readPairing reads the pairing file, refusing one this user's other
// secrets would be refused for (not a regular file, readable by others).
// An expired file comes back with errPairingExpired and its sig, so the
// caller can remove exactly that one.
func readPairing(dir string, now time.Time) (pairingFile, error) {
	var zero pairingFile
	if dir == "" {
		return zero, fs.ErrNotExist
	}
	path := filepath.Join(dir, pairingFileName)
	fi, err := os.Lstat(path)
	if err != nil {
		return zero, err
	}
	if !fi.Mode().IsRegular() {
		return zero, errString("the pairing file is not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return zero, errString("the pairing file is readable by others; chmod 600 it")
	}
	if fi.Size() > pairingFileMax {
		return zero, errString("the pairing file is too large")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	sig := strings.TrimSpace(string(b))
	until := fi.ModTime().Add(pairingTTL)
	if now.After(until) {
		return pairingFile{sig: sig, until: until, fi: fi}, errPairingExpired
	}
	lines := strings.Split(sig, "\n")
	if len(lines) < 2 {
		return pairingFile{sig: sig, fi: fi}, errString("the pairing file names no browser")
	}
	id, err := transport.ParsePairToken(lines[0])
	if err != nil {
		return pairingFile{sig: sig, fi: fi}, err
	}
	peer, ok := transport.ParseNodeKey(lines[1])
	if !ok {
		return pairingFile{sig: sig, fi: fi}, errString("the pairing file's browser key is not a node key")
	}
	return pairingFile{id: id, peer: peer, until: until, at: fi.ModTime(), sig: sig, fi: fi}, nil
}

// removePairing removes the file if it is still the one pf read — the same
// file on disk, the same modification time, the same contents: a line run
// again meanwhile wrote a new one (renamed into place, so another file), and
// an older pairing's end is not its end (amp review 2026-10-28).
func removePairing(dir string, pf pairingFile) error {
	path := filepath.Join(dir, pairingFileName)
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if pf.fi == nil || !os.SameFile(fi, pf.fi) || !fi.ModTime().Equal(pf.fi.ModTime()) {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(string(b)) != pf.sig {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// When each browser last said hello to this machine's own node (direct.go
// hello): a pairing for that browser written before the hello is over. Only a
// hello AFTER the pairing counts — the line run again on a machine that
// browser already watches writes a pairing the running helper must not take
// for done (amp review 2026-10-28). Bounded, though only admitted keys ever
// reach the hello.
var pairHeard struct {
	sync.Mutex
	keys map[key.NodePublic]time.Time
}

func notePeerHello(k key.NodePublic) {
	pairHeard.Lock()
	defer pairHeard.Unlock()
	if pairHeard.keys == nil {
		pairHeard.keys = map[key.NodePublic]time.Time{}
	}
	if _, ok := pairHeard.keys[k]; ok || len(pairHeard.keys) < 1024 {
		pairHeard.keys[k] = time.Now()
	}
}

// peerHeardSince reports whether k said hello after t.
func peerHeardSince(k key.NodePublic, t time.Time) bool {
	pairHeard.Lock()
	defer pairHeard.Unlock()
	at, ok := pairHeard.keys[k]
	return ok && at.After(t)
}

// stillAllowed reports whether k is on this machine's allowlist now: a
// pairing for a browser struck there is over.
func stillAllowed(k key.NodePublic) bool {
	for _, a := range loadAllowedClients() {
		if a == k {
			return true
		}
	}
	return false
}

// runPairing keeps a pairing node up while the file asks for one, for as long
// as ctx (one carrier of this machine's own tunnel) lives. Each complaint is
// said once, not every ten seconds.
func runPairing(ctx context.Context, conf string, tc *transport.Tailcat) {
	var (
		node    *transport.Pairing
		nodeSig string
		said    string
		wait    time.Duration
		nextTry time.Time
	)
	stop := func() {
		if node != nil {
			node.Close()
			node, nodeSig = nil, ""
		}
	}
	defer stop()
	say := func(s string) {
		if s != said {
			said = s
			warnf("%s", s)
		}
	}
	t := time.NewTicker(pairingPoll)
	defer t.Stop()
	for {
		now := time.Now()
		pf, err := readPairing(conf, now)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			stop()
			said = ""
		case errors.Is(err, errPairingExpired):
			stop()
			if rerr := removePairing(conf, pf); rerr != nil {
				say("direct: could not remove the expired pairing: " + rerr.Error())
			} else {
				say("direct: the install line's pairing ran out after a week; the page can still add this machine by its address")
			}
		case err != nil:
			stop()
			say("direct: pairing: " + err.Error())
		case peerHeardSince(pf.peer, pf.at):
			stop()
			if rerr := removePairing(conf, pf); rerr != nil {
				say("direct: could not remove the finished pairing: " + rerr.Error())
			} else {
				say("direct: paired — the browser that made the install line has this machine's address")
			}
		case !stillAllowed(pf.peer):
			stop()
			if rerr := removePairing(conf, pf); rerr != nil {
				say("direct: could not remove a pairing for a browser no longer allowed: " + rerr.Error())
			} else {
				say("direct: the browser that made the install line is no longer allowed; its pairing is gone")
			}
		default:
			if node != nil && nodeSig != pf.sig {
				stop()
			}
			if node == nil && !now.Before(nextTry) {
				n, serr := transport.StartPairing(transport.PairConfig{
					Identity: pf.id,
					Peer:     pf.peer,
					Port:     directPort,
					Answer:   func() (string, string) { return agentID(), tc.ConnBlob() },
					Allowed:  stillAllowed,
				})
				if ctx.Err() != nil {
					if n != nil {
						n.Close()
					}
					return
				}
				if serr != nil {
					wait = min(max(wait*2, 30*time.Second), 10*time.Minute)
					nextTry = time.Now().Add(wait)
					say("direct: pairing did not start: " + serr.Error())
				} else {
					node, nodeSig, wait = n, pf.sig, 0
					say(fmt.Sprintf("direct: waiting for the browser that made the install line (until %s)", pf.until.Format("2006-01-02 15:04")))
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pairingStatusLine is what `subnsub-helper address` says of a pairing still
// on disk, or "" when there is none. The running helper removes the file once
// the browser has the address, so a file here is a pairing not yet done.
func pairingStatusLine(conf string, now time.Time) string {
	pf, err := readPairing(conf, now)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("pairing: waiting for the browser that made the install line (until %s)", pf.until.Format("2006-01-02 15:04"))
}
