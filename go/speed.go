package main

/* ── the speed test, this end of it ──

   The Speed tab measures the road between two of the person's own devices
   (operator request 2026-11-05: measure between tailnet/tailcat nodes): this
   browser and one of its machines, or two machines. Either way the bytes
   come from, and go to, a helper, over whatever road joins the two — the
   tailnet where both are on one, else tailcat, direct where the two can
   reach each other and through DERP where they cannot. This file is the end
   that is measured:

     GET  /v1/speed/ping          an empty answer: one round trip
     GET  /v1/speed/down?n=<b>    n bytes that do not compress
     POST /v1/speed/up            the body read and dropped, answered with
                                  {"n": bytes read, "ms": how long it took}

   WHO MAY. A browser on this machine's allowlist (its tunnel already reads
   everything the machine reports; moving bytes that mean nothing is less),
   not a portable copy, which reads what it was given and nothing more — and
   another of the person's computers measuring the road to here, under a
   grant a pinned dashboard signed for the job (filesgrant.go, caps "speed"),
   which reaches these three paths, its hello and its own end, and nothing
   else. speedpeer.go is that other computer's half.

   What it costs the machine is bounded: speedSlots answers at once, a
   download of speedDownMax and speedDownLife at most, an upload piece of
   speedUpMax read within speedUpRead. */

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"subnsubmonitor/transport"
)

const (
	// Answers moving bytes at once, every road together: four streams each
	// way for one machine measuring another, and room for a browser.
	speedSlots = 8
	// One download's most. A machine measuring another reads for seconds
	// and hangs up; a browser asks a few megabytes at a time. An int64, so
	// a 32-bit build holds it.
	speedDownMax int64 = 2 << 30
	// How long one download may go on, and wait on a reader that has
	// stopped reading: a slot is not held past either.
	speedDownLife = 2 * time.Minute
	speedStall    = 20 * time.Second
	// One upload piece's most. The tunnel's own ceiling for a browser's
	// piece is 4 MiB (helper/tailcat-web maxPutBody), the tailnet's 1 MiB.
	speedUpMax = 64 << 20
	// How long a piece may take to come in: four megabytes through a busy
	// relay outlast the tunnel server's ten seconds.
	speedUpRead = time.Minute
	// The bytes sent, repeated: random, so nothing on the way can make
	// them smaller than they are.
	speedBufSize = 1 << 20
)

var (
	speedSem     = make(chan struct{}, speedSlots)
	speedBufOnce sync.Once
	speedBufData []byte
)

func speedBuf() []byte {
	speedBufOnce.Do(func() {
		b := make([]byte, speedBufSize)
		rand.Read(b)
		speedBufData = b
	})
	return speedBufData
}

// speedPeerAllowed: a browser on the allowlist file, or a caller with no
// peer at all (a test driving the handler).
func speedPeerAllowed(r *http.Request) bool {
	k, ok := transport.PeerFromContext(r.Context())
	if !ok {
		return true
	}
	for _, a := range loadAllowedClients() {
		if a == k {
			return true
		}
	}
	return false
}

// speedPath says whether p is one of this file's.
func speedPath(p string) bool {
	switch p {
	case "/v1/speed/ping", "/v1/speed/down", "/v1/speed/up":
		return true
	}
	return false
}

// speed answers the mux's /v1/speed/ paths for a browser.
func (h *directHandler) speed(w http.ResponseWriter, r *http.Request) {
	if !speedPeerAllowed(r) {
		h.refuse(w, http.StatusForbidden, "not-allowed")
		return
	}
	h.speedServe(w, r)
}

// speedServe is the three answers, to whoever the door let through.
func (h *directHandler) speedServe(w http.ResponseWriter, r *http.Request) {
	want := http.MethodGet
	if r.URL.Path == "/v1/speed/up" {
		want = http.MethodPost
	}
	if !speedPath(r.URL.Path) || r.Method != want {
		h.refuse(w, http.StatusMethodNotAllowed, "unknown-frame")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/v1/speed/ping" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}
	select {
	case speedSem <- struct{}{}:
		defer func() { <-speedSem }()
	default:
		h.refuse(w, http.StatusServiceUnavailable, "busy")
		return
	}
	if r.URL.Path == "/v1/speed/down" {
		s := r.URL.Query().Get("n")
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 || n > speedDownMax || len(s) > 12 {
			h.refuse(w, http.StatusBadRequest, "bad-args")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		// The connection may carry the next request: it gets no deadline
		// of this one's.
		defer rc.SetWriteDeadline(time.Time{})
		speedWrite(w, n, func(d time.Time) { rc.SetWriteDeadline(d) })
		return
	}
	// Up: the clock starts when the request's head is in, and stops when
	// the last byte of its body is.
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(speedUpRead))
	t0 := time.Now()
	got, err := io.CopyBuffer(io.Discard, io.LimitReader(r.Body, speedUpMax+1), make([]byte, 64<<10))
	if got > speedUpMax {
		h.refuse(w, http.StatusRequestEntityTooLarge, "too-large")
		return
	}
	if err != nil {
		h.refuse(w, http.StatusBadRequest, "unreachable")
		return
	}
	b, _ := json.Marshal(map[string]any{"n": got, "ms": float64(time.Since(t0).Microseconds()) / 1000})
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// speedWrite sends n bytes of the buffer, round and round, until n are
// out, the reader has hung up or speedDownLife is over. Each write is given
// until speedStall from now (never past the end) to go out.
func speedWrite(w io.Writer, n int64, deadline func(time.Time)) {
	buf := speedBuf()
	const piece = 64 << 10
	end := time.Now().Add(speedDownLife)
	for off := 0; n > 0; off = (off + piece) % len(buf) {
		now := time.Now()
		if !now.Before(end) {
			return
		}
		if deadline != nil {
			d := now.Add(speedStall)
			if d.After(end) {
				d = end
			}
			deadline(d)
		}
		m := int64(piece)
		if m > n {
			m = n
		}
		if _, err := w.Write(buf[off : off+int(m)]); err != nil {
			return
		}
		n -= m
	}
}
