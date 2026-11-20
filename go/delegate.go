package main

// delegate.go — a member helper's side of primary coordination: the
// delegated-keys file (one line: "<b64 ed25519 pub> nodekey:<64hex>
// primary") naming the primary's signing key and the tunnel key the
// coordinator dials this machine from, and the delegate/undelegate commands
// that write it. Trust boundary: the file is written only by a full-key
// signature over the tunnel (or the installer); a delegated signature can
// never run these kinds (they are absent from delegatedKinds).

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"subnsubmonitor/transport"

	"tailscale.com/types/key"
)

const delegatedKeysFile = "delegated-keys"

func delegatedKeysPath() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, delegatedKeysFile)
}

// delegatedKey is one parsed delegated-keys line.
type delegatedKey struct {
	Pub     ed25519.PublicKey
	PubText string
	Node    key.NodePublic
}

// readDelegatedKeys parses the file; a line counts only in the documented
// shape — a base64 Ed25519 public key followed by a nodekey — so a stray
// edit cannot pin a signing key the file never meant to hold.
func readDelegatedKeys() []delegatedKey {
	path := delegatedKeysPath()
	if path == "" {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []delegatedKey
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pub := parsePublicKey(fields[0])
		node, ok := transport.ParseNodeKey(fields[1])
		if pub == nil || !ok {
			continue
		}
		out = append(out, delegatedKey{Pub: pub, PubText: fields[0], Node: node})
	}
	return out
}

// delegatedPublicKeys is the signing half for trust (signing.go): the
// delegated-keys file read on every loadTrust, like trusted-keys.
func delegatedPublicKeys() []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, d := range readDelegatedKeys() {
		out = append(out, d.Pub)
	}
	return out
}

// writeDelegatedKeys replaces the file with the one line, atomically like
// every secret here (put.go putSaveLocked, signing.go untrustKey).
func writeDelegatedKeys(d delegatedKey) error {
	path := delegatedKeysPath()
	if path == "" {
		return errString("no config directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	line := d.PubText + " " + d.Node.String() + " primary\n"
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(line), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func clearDelegatedKeys() error {
	path := delegatedKeysPath()
	if path == "" {
		return errString("no config directory")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// runDelegate pins a primary's signing key and the tunnel key it dials this
// machine from. The node lives only in delegated-keys — it reaches the
// hello and command doors alone (direct.go), never the allowlist's wider
// mux, so there is nothing to strike on replace or undelegate.
func runDelegate(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: c.Kind, Code: -1}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	var a struct {
		Key  string `json:"key"`
		Node string `json:"node"`
	}
	if json.Unmarshal([]byte(c.Cmd), &a) != nil {
		res.Error = "bad-args"
		return res
	}
	pub := parsePublicKey(a.Key)
	node, ok := transport.ParseNodeKey(a.Node)
	if pub == nil || !ok {
		res.Error = "bad-key"
		return res
	}
	if err := writeDelegatedKeys(delegatedKey{Pub: pub, PubText: strings.TrimSpace(a.Key), Node: node}); err != nil {
		res.Error = "save-failed"
		return res
	}
	admitNow(node)
	res.Code, res.Out = 0, "{}"
	return res
}

// runUndelegate removes the delegation. With {"key":…} it removes only a
// line naming that key — a stale page cannot strip a newer delegation it
// never saw; with an empty Cmd it removes whatever is there.
func runUndelegate(c consoleCmd) consoleResult {
	res := consoleResult{ID: c.ID, Kind: c.Kind, Code: -1}
	if !loadTrust().sealed {
		res.Error = "unpinned"
		return res
	}
	var want ed25519.PublicKey
	if strings.TrimSpace(c.Cmd) != "" {
		var a struct {
			Key string `json:"key"`
		}
		if json.Unmarshal([]byte(c.Cmd), &a) != nil {
			res.Error = "bad-args"
			return res
		}
		want = parsePublicKey(a.Key)
		if want == nil {
			res.Error = "bad-key"
			return res
		}
	}
	old := readDelegatedKeys()
	if len(old) == 0 {
		res.Code, res.Out = 0, "{}"
		return res
	}
	if want != nil {
		match := false
		for _, d := range old {
			if d.Pub.Equal(want) {
				match = true
			}
		}
		if !match {
			res.Error = "bad-key"
			return res
		}
	}
	if err := clearDelegatedKeys(); err != nil {
		res.Error = "save-failed"
		return res
	}
	res.Code, res.Out = 0, "{}"
	return res
}

// activeDelegateNodes are the coordinator keys the tunnel admits for the
// coordination door alone (direct.go Allowed): delegated-keys, read fresh
// like every list here.
func activeDelegateNodes() []key.NodePublic {
	var out []key.NodePublic
	for _, d := range readDelegatedKeys() {
		out = append(out, d.Node)
	}
	return out
}

// delegatedPeer reports whether k is a current coordinator key; the door
// asks per request so a replaced or removed node is refused at once.
func delegatedPeer(k key.NodePublic) bool {
	for _, d := range readDelegatedKeys() {
		if d.Node == k {
			return true
		}
	}
	return false
}
