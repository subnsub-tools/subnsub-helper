// Package transport is the helper's carrier-neutral wire layer: the versioned
// frame every carrier moves, the interface a carrier satisfies, and the two
// carriers that exist today — the tailcat tunnel (tailcat.go) and an in-memory
// fake for tests (fake.go).
//
// The HTTP relay is deliberately NOT ported into this package yet. Its push
// loop (transport.go in package main) is entangled with token renewal, the
// console mailbox and the archive sync in ways that a mechanical move would
// only obscure; the plan's Phase 1 asks for that loop to keep behaving exactly
// as it does today, and the honest way to satisfy "unchanged" is to leave it
// unchanged and make the NEW carrier speak this protocol from day one. When
// the relay is migrated, it becomes a third file here and nothing above it
// needs to learn a new shape.
//
// What every carrier promises, whichever bytes it moves:
//
//   - a Frame is versioned, and a reader that does not know a frame's type
//     refuses it rather than guessing — a helper from months ago must never
//     execute a frame type invented after it shipped (plan invariant 3);
//   - a frame has a byte ceiling that is checked BEFORE the body is decoded,
//     so a hostile peer cannot make the reader allocate first and think later;
//   - a frame carries the agent id it is about and a correlation id, so a
//     reply can be matched to its request across any carrier.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Version is the protocol generation this build speaks. A frame with any
// other value is refused: there is exactly one generation in the field, and
// "close enough" is how a newer frame gets fed to older code.
const Version = 1

// Frame types. Wire values: add freely, never repoint an existing name at a
// new meaning. Each type has its own byte ceiling in Limits, because "one
// cap for everything" is either too small for a snapshot or too generous for
// a heartbeat.
const (
	// TypeHello is the first frame in either direction: who this is and what
	// it is willing to do. Its body is Hello.
	TypeHello = "hello"
	// TypeSnapshot carries one full reading — the same document the relay
	// push carries, unchanged, so a consumer renders it with the code it
	// already has.
	TypeSnapshot = "snapshot"
	// TypeSystem carries only the host-health block, for the 1 Hz stream a
	// watcher opens while looking. Quota is deliberately not in it: the
	// providers behind those numbers are rate-limited upstream and a faster
	// carrier cannot make them fresher (plan v3).
	TypeSystem = "system"
	// TypeError is a refusal or a failure, with a machine-readable code. It
	// is the only type a peer may send in answer to a frame it will not
	// honour; silence is never an answer.
	TypeError = "error"
	// TypeCommand is the dashboard asking the machine to do something over
	// the tunnel — the same envelope the relay's mailbox carries (kind, the
	// line or target, the browser's signature), so the machine judges it
	// with the same code (signing.go) whichever road it came by.
	// Its body is Command. POSTed, never streamed.
	TypeCommand = "command"
	// TypeResult is the machine's answer to one TypeCommand: the console
	// result document the relay's /result already carries, unchanged.
	TypeResult = "result"
	// TypeHistory is the machine's own trend archive (history.go),
	// in the dashboard's bucket-row shape; served on request, never streamed.
	TypeHistory = "history"
	// TypePair is the one frame a pairing node serves (pair.go): the
	// machine's own tunnel address, handed to the browser whose key the
	// install line named, over the pairing node's tunnel — the road by which
	// a browser that minted the line learns where the machine it installed
	// actually waits. Its body is Pair. Served on request, never streamed.
	TypePair = "pair"
	// TypeMusic is the machine's shared music library (music.go): which
	// roots it shares and, a page at a time, the tracks in one of them. Served
	// on request over the direct roads only, never streamed and never sent to
	// the relay. The audio itself is not framed: /v1/music/file answers with
	// the file's own bytes.
	TypeMusic = "music"
	// TypePhotos is the pictures in the folders chosen on the machine
	// (photos.go): which folders and, a page at a time, the pictures in one.
	// Served on request over the direct roads only, as music is. The small
	// copies are not framed: /v1/photos/thumb answers with a JPEG.
	TypePhotos = "photos"
	// TypeTailnet is what the machine's own Tailscale knows of its network
	// (tsview.go): the devices, and the access rules the control plane sent
	// this machine. Served on request over the direct roads only, never
	// streamed and never sent to the relay.
	TypeTailnet = "tailnet"
)

// Limits are the byte ceilings per frame type, applied to the SERIALISED
// frame — the thing that actually crosses a wire — and checked by Decode
// before json.Unmarshal is allowed to allocate anything. A type absent from
// this map is unknown and refused outright.
var Limits = map[string]int{
	TypeHello:    4 << 10,
	TypeSnapshot: 512 << 10,
	TypeSystem:   64 << 10,
	TypeError:    4 << 10,
	TypeCommand:  16 << 10,
	TypeResult:   256 << 10,
	TypeHistory:  1 << 20,
	TypePair:     4 << 10,
	// Under the browser module's 1 MiB answer ceiling (tailcat-web
	// maxGetBody), envelope included.
	TypeMusic:   960 << 10,
	TypePhotos:  960 << 10,
	TypeTailnet: 960 << 10,
}

// Capabilities a peer may announce or be granted. Each one is authorised on
// its own (plan invariant 3): a carrier that moves bytes for one grants
// nothing about the others. Only observe exists in this generation; the
// names for the rest are reserved so a later frame cannot collide with them.
const (
	CapObserve  = "observe"
	CapConsole  = "console"
	CapUpdate   = "update"
	CapSessions = "sessions"
	CapArchive  = "archive"
	// CapRename updates only the persisted machine name, with a pinned signature.
	CapRename = "rename"
	// CapInspect: the read-only process list (`inspect` commands). Its own
	// switch at the machine, so its own capability here.
	CapInspect = "inspect"
	// CapTerminal: a shell on a pseudo-terminal, streamed through this
	// tunnel (helper pty.go). The console's switch and a pinned key, on a
	// platform that has pseudo-terminals.
	CapTerminal = "terminal"
	// CapClone: the machine takes a portable copy of this dashboard — a
	// certificate the dashboard signed for a fresh key pair, which the
	// machine then admits for console lines and terminals until it expires
	// (helper clone.go). Named wherever a key is pinned, so a copy can
	// always be revoked; enrolled only where the console is on.
	CapClone = "clone"
	// CapAct: presses on the machine's own tiles — actions an operator wrote
	// in metrics.d next to the tile, run with a bounded value (helper
	// tileaction.go). Named where a key is pinned and an action is declared.
	CapAct = "act"
	// CapMyIP: the My IP check asked from the machine's own way out (helper
	// myip.go) — six fixed requests to the machine's configured origin, the
	// answers handed back. Named where a key is pinned and the check is on.
	CapMyIP = "myip"
	// CapMusic: the machine shares music (music.go) — folders its operator
	// named on the machine, and WebDAV folders a pinned dashboard added —
	// with the browsers on its allowlist, over the direct roads alone.
	CapMusic = "music"
	// CapPhotos: the machine shows the pictures in folders chosen on it
	// (photos.go) to the browsers on its allowlist, over the direct roads
	// alone — under the same switches and grant as music.
	CapPhotos = "photos"
	// CapFiles: the Files tab may look through this machine's disks and read
	// its files (files.go) — named to an allowlisted browser where the
	// console is on, since a console already grants as much.
	CapFiles = "files"
	// CapFilesWrite: the Files tab may also put things on this machine's
	// disks — a file a piece at a time, a folder, a new name, a move, the
	// system's trash (fileswrite.go) — under the same grant as CapFiles. A
	// helper that names files without it only reads.
	CapFilesWrite = "files-write"
	// CapFilesGrant: another of the owner's computers may read files here
	// under a read-only grant a pinned dashboard signed, over this tunnel
	// (filesgrant.go) — named where the tunnel is up to be dialled.
	CapFilesGrant = "files-grant"
	// CapFilesFetch: this machine fetches files from another one itself,
	// under such a grant, and puts them in a folder here (filesfetch.go):
	// a copy between two computers that does not pass through the page.
	CapFilesFetch = "files-fetch"
	// CapSpeed: the Speed tab may measure the road between this browser
	// and the machine (helper speed.go) — bytes down, bytes up, a round
	// trip. Named to an allowlisted browser.
	CapSpeed = "speed"
	// CapSpeedPeer: the machine measures the road to another of the
	// owner's computers itself, and is measured by one, under a grant a
	// pinned dashboard signed (helper speedpeer.go) — where the console
	// is on, as a copy between two computers is.
	CapSpeedPeer = "speed-peer"
	// CapSpeedNet: the machine measures its own road to the internet,
	// against Cloudflare's speed test (helper speednet.go) — where the
	// console is on, as speed-peer is.
	CapSpeedNet = "speed-net"
	// CapTailnetMap: the machine reports what its Tailscale knows of the
	// network, devices and access rules (helper tsview.go), for the map of
	// who reaches whom. Named to an allowlisted browser; read-only.
	CapTailnetMap = "tailnet-map"
	// CapScreen: the machine's own VNC server, carried through this tunnel
	// to the page's viewer (helper screen.go). The console's switch and a
	// pinned key, to an allowlisted browser; MON_SCREEN=off turns it off.
	CapScreen = "screen"
)

// Frame is the envelope. Body is kept as raw JSON so a router can dispatch on
// Type and size without decoding a body it may go on to refuse.
type Frame struct {
	V       int             `json:"v"`
	Type    string          `json:"type"`
	AgentID string          `json:"agent_id,omitempty"`
	ID      string          `json:"id,omitempty"`
	SentAt  int64           `json:"sent_at"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// Hello is the body of a TypeHello frame.
type Hello struct {
	// HelperVersion is the sender's build, in the same YYYY.MM.DD.N shape the
	// relay enforces; a consumer that shows "needs updating" compares this.
	HelperVersion string `json:"helper_version,omitempty"`
	// Caps lists what the sender will do for THIS peer. A consumer offers a
	// control only if its capability is named here.
	Caps []string `json:"caps"`
	// Carrier names how the bytes arrived, for the dashboard's path badge:
	// "tailcat" today, "relay" once that loop is ported.
	Carrier string `json:"carrier,omitempty"`
	// Path is the carrier's own account of the route, when it has one —
	// "derp-<region>" or "direct" for tailcat. Diagnostic only; never the
	// peer's real address (plan: no endpoint metadata in product logs).
	Path string `json:"path,omitempty"`
	// Tailnet is where this machine also answers on its Tailscale network,
	// for a reader to reach it without the tunnel (main package, tailnet.go).
	// Absent when Tailscale is not up here.
	Tailnet *TailnetRoad `json:"tailnet,omitempty"`
}

// TailnetRoad names the machine's listener on its Tailscale network. Host is
// the MagicDNS name, empty when MagicDNS gives none; IP always works. Key is
// the machine's X25519 key in text, which the reader holds it to on that road:
// what told the reader this came through the tunnel, so the network underneath
// is not asked to vouch for who answers.
type TailnetRoad struct {
	Host string `json:"host,omitempty"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Key  string `json:"key"`
}

// Error is the body of a TypeError frame.
type Error struct {
	Code string `json:"code"`
}

// Command is the body of a TypeCommand frame: the relay mailbox's wire shape
// (/commands), field for field, so one verifier serves both
// roads. The frame's own ID is the command id the signature covers.
type Command struct {
	// Kind includes "sh", "update", "inspect", "allow", "refresh", "rename",
	// "pty", "clone" and "unclone".
	Kind string `json:"kind,omitempty"`
	// Cmd is a shell line only for sh; for rename it is the new machine name.
	Cmd string `json:"cmd,omitempty"`
	// Target is the closed typed target (inspect) — never a shell line.
	Target string `json:"target,omitempty"`
	// Sig and At are the browser's Ed25519 signature and its clock, exactly
	// as on the relay road; a machine with a pinned key refuses without them.
	Sig string `json:"sig,omitempty"`
	At  int64  `json:"at,omitempty"`
}

// Pair is the body of a TypePair frame: the machine's own tunnel address
// ("tc…"), which the browser dials from then on.
type Pair struct {
	Addr string `json:"addr"`
}

// Sentinel errors from Decode. Callers switch on these to decide whether the
// peer is hostile (refuse and close), merely newer (refuse this frame, keep
// the connection) or the bytes are simply broken.
var (
	ErrTooLarge    = errors.New("transport: frame exceeds its type's limit")
	ErrVersion     = errors.New("transport: unknown protocol version")
	ErrUnknownType = errors.New("transport: unknown frame type")
	ErrMalformed   = errors.New("transport: malformed frame")
)

// New builds a frame of the given type around body, stamping the version and
// the clock. body is marshalled here so callers never hand over raw JSON they
// did not produce.
func New(typ, agentID, id string, body any) (Frame, error) {
	if _, ok := Limits[typ]; !ok {
		return Frame{}, ErrUnknownType
	}
	var raw json.RawMessage
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return Frame{}, err
		}
		raw = b
	}
	return Frame{
		V:       Version,
		Type:    typ,
		AgentID: agentID,
		ID:      id,
		SentAt:  time.Now().Unix(),
		Body:    raw,
	}, nil
}

// Encode serialises f and enforces the type's ceiling on the result — the
// sender's side of the same rule the reader applies, so a frame this build
// produces is one this build would accept.
func Encode(f Frame) ([]byte, error) {
	if f.V != Version {
		return nil, ErrVersion
	}
	limit, ok := Limits[f.Type]
	if !ok {
		return nil, ErrUnknownType
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrTooLarge, f.Type, len(b), limit)
	}
	return b, nil
}

// maxEnvelope is the most bytes Decode will look at before it knows the
// frame's type: the largest per-type ceiling. Anything longer is refused
// without being parsed at all.
var maxEnvelope = func() int {
	n := 0
	for _, v := range Limits {
		if v > n {
			n = v
		}
	}
	return n
}()

// Decode parses one serialised frame, fail-closed.
//
// The order matters and is the point: length against the global ceiling,
// then a cheap peek at version and type, then the type's own ceiling, and
// only then the full parse. Nothing here allocates in proportion to the input
// until the input has earned it.
func Decode(b []byte) (Frame, error) {
	if len(b) > maxEnvelope {
		return Frame{}, ErrTooLarge
	}
	// json.Decoder with DisallowUnknownFields would refuse a frame carrying
	// a field this build has not heard of — the opposite of what an
	// envelope wants. Unknown FIELDS are ignored; unknown TYPES are refused.
	var head struct {
		V    int    `json:"v"`
		Type string `json:"type"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&head); err != nil {
		return Frame{}, ErrMalformed
	}
	if head.V != Version {
		return Frame{}, ErrVersion
	}
	limit, ok := Limits[head.Type]
	if !ok {
		return Frame{}, ErrUnknownType
	}
	if len(b) > limit {
		return Frame{}, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrTooLarge, head.Type, len(b), limit)
	}
	var f Frame
	if err := json.Unmarshal(b, &f); err != nil {
		return Frame{}, ErrMalformed
	}
	return f, nil
}

// Transport is what a carrier satisfies. Frames go in and come out whole;
// the carrier owns framing, encryption, reconnection and backpressure, and
// says nothing about what a frame means.
//
// Send blocks under backpressure rather than buffering without bound — a
// carrier with an unbounded queue is one that lets a stuck reader turn the
// helper's memory into the reader's problem. Callers that must not block
// (the telemetry push) wrap Send in their own bounded queue.
type Transport interface {
	// Start brings the carrier up. identity is this side's agent id, which
	// every outgoing frame is stamped with.
	Start(ctx context.Context, identity Identity) error
	// Send delivers one frame, or fails. A failure is not retried here.
	Send(ctx context.Context, f Frame) error
	// Receive hands back the channel incoming frames arrive on. It closes
	// when the carrier is done.
	Receive(ctx context.Context) (<-chan Frame, error)
	// Close tears the carrier down. Idempotent.
	Close() error
}

// Identity is what a carrier needs to know about the side it is carrying for.
type Identity struct {
	AgentID       string
	HelperVersion string
}
