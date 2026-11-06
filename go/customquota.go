package main

// A quota reading of the operator's own (2026.10.07.8).
//
// The collectors read what a machine holds: the vendor's own credential
// files, its CLI, a server on loopback, a CLI Proxy API. A platform that only
// answers to a browser cookie or a key the operator pastes — OpenCode's Zen
// page, Cursor — is one this helper will never hold a credential for, and was
// dropped from the collectors for exactly that reason. But a command the
// operator writes can hold one, and the dashboard should show its answer as
// what it is: not a gauge in the custom section, but an agent on the quota
// board, drawn by the code that draws Claude and Codex, with its own name
// where the vendor's goes and a monogram where the vendor's mark goes.
//
// So metrics.d/ (custom.go) and the push socket (custompush.go) take a fifth
// tile type, "quota". It rides the same engine — a file, a command on a
// timer, a pushed line; stale after its ttl; errors kept beside the last
// good reading — and leaves it at the snapshot (splitQuota), where it becomes
// a Provider instead of a Tile:
//
//   {"id": "opencode", "name": "OpenCode", "type": "quota", "plan": "Zen",
//    "windows": [{"key": "monthly", "used_percent": 37.5, "minutes": 43200,
//                 "resets_at": "2026-11-01T00:00:00Z",
//                 "used": 7.5, "total": 20, "unit": "usd"}],
//    "balance": "12.50",
//    "exec": "sh ~/bin/opencode-quota.sh", "interval": 300}
//
// Fields, beside the ones every tile takes (id, name, icon, exec, interval,
// timeout, at, ttl):
//
//   plan        the plan's name as the vendor says it ("Zen Pro"), 40 at most
//   windows[]   one per limit, 8 at most:
//     key           [a-z0-9_-]{1,24} — the row's key on the dashboard;
//                   made from the label when absent, "usage" when both are
//     label         words for the row ("30d", "monthly"); defaults to key
//     used_percent  0…100 — a little over is allowed, vendors overshoot;
//                   worked out from used / total when absent
//     used, total, remaining   the figures behind the share, in
//     unit          "usd" or "credits"; "count" (requests, rows — written
//                   short, 2.8M) or "bytes" (written in decimal units,
//                   41.3 GB = 41.3e9 bytes, the way vendors price storage)
//                   for a free allowance read off a bill
//     cost          what the window has cost this period, in US dollars —
//                   an allowance's overage, say; shown beside the figures
//     minutes       the window's length
//     resets_at     unix seconds or an ISO-8601 time; one already past is
//                   not a reset
//   balance     a prepaid balance, a number or a string; with
//   unlimited   true for a plan that has none to run out of
//   error       what the command found instead of a reading ("not signed
//               in"): the agent shows as failed, with these words
//
// A command prints the object above (merged over its entry, as any tile's
// command may), or a bare number, which is one window named "usage" at
// that share. `error` and a reading are exclusive: whichever the newest
// line carries wins.
//
// A bill reads the same way (metrics.d.examples/cloudflare.json): a window
// keyed "bill" in usd is the period's bill against the operator's budget,
// and the folded status bar shows its amount for the agent instead of the
// share of its fullest window; the free allowances are windows in count or
// bytes, and one past its allowance (used_percent over 100) is drawn as
// over it, with its cost.
//
// On the wire the agent's id is custom-<id> — the collectors own the vendor
// ids, and an entry called "claude" must not wear Claude's mark and links —
// its source is "custom" and its collector "operator" (clean.js admits both;
// nothing else about it is trusted further than any custom tile). The
// dashboard says "your own command" where it says "live query" of the
// others, because that is how far the number can be trusted.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	customProviderPrefix = "custom-"
	// The relay cuts a provider id at 24 characters (clean.js). The prefix
	// takes seven; an id that would be cut could collide with another after
	// the cut, so the entry's id is held under the line here.
	quotaIDMax      = 16
	quotaWindowsMax = 8
	quotaPlanMax    = 40
	quotaLabelMax   = 24
	quotaBalanceMax = 24
	quotaErrorMax   = 120
	quotaPercentMax = 1000.0
	// The relay's bound on a window's cost (clean.js cleanLimit).
	quotaCostMax    = 1e9
	quotaMinutesMax = 366 * 1440.0
	// The relay's EPOCH_MAX (clean.js): a reset past it is dropped there,
	// and a page on the direct tunnel would be handed a date it cannot draw.
	quotaEpochMax = 4000000000.0
	// Agents of this kind per machine: the relay keeps 24 providers in all
	// and the collectors can fill 16 of them.
	maxQuotaTiles = 8
)

var quotaKeyRe = regexp.MustCompile(`^[a-z0-9_-]{1,24}$`)

// One window as the operator wrote it. ResetsAt is raw because it takes two
// shapes (a number of seconds, an ISO-8601 string); resets is what it
// parsed to.
type quotaWindowSpec struct {
	Key         string          `json:"key,omitempty"`
	Label       string          `json:"label,omitempty"`
	UsedPercent *float64        `json:"used_percent,omitempty"`
	Used        *float64        `json:"used,omitempty"`
	Total       *float64        `json:"total,omitempty"`
	Remaining   *float64        `json:"remaining,omitempty"`
	Unit        string          `json:"unit,omitempty"`
	Cost        *float64        `json:"cost,omitempty"`
	Minutes     *float64        `json:"minutes,omitempty"`
	ResetsAt    json.RawMessage `json:"resets_at,omitempty"`

	resets *float64 `json:"-"`
}

// One window as the tile carries it (and as `subnsub-helper metrics`
// prints it): the same thing a Limit says, before it is one.
type QuotaWindow struct {
	Key         string   `json:"key"`
	Label       string   `json:"label,omitempty"`
	UsedPercent float64  `json:"used_percent"`
	Used        *float64 `json:"used,omitempty"`
	Total       *float64 `json:"total,omitempty"`
	Remaining   *float64 `json:"remaining,omitempty"`
	Unit        string   `json:"unit,omitempty"`
	Cost        *float64 `json:"cost,omitempty"`
	Minutes     *float64 `json:"minutes,omitempty"`
	ResetsAt    *float64 `json:"resets_at,omitempty"`
}

// normaliseQuota is normaliseTile's quota half: everything a gauge or a
// status has that a quota does not is refused, and the windows are checked
// one by one. A bare `value` is the one-window shorthand, as it is for a
// command that prints a bare number.
func normaliseQuota(t *tileSpec, num *float64, isStr bool) error {
	if t.Min != nil || t.Max != nil || t.Unit != "" || t.Suffix != "" || t.Warn != nil || t.Bad != nil ||
		t.Alerts != nil || t.Invert || t.History != nil || t.Fold != "" || t.Label != "" || t.Tint != "" {
		return errors.New("a quota takes plan, windows, balance and error — not the fields of a gauge")
	}
	if isStr {
		return errors.New("a quota's value is a number: the share used, as one window")
	}
	if num != nil {
		if len(t.Windows) > 0 {
			return errors.New("value or windows, not both")
		}
		t.Windows = []quotaWindowSpec{{Key: "usage", UsedPercent: num}}
	}
	t.Value = nil
	t.Plan = cleanText(t.Plan, quotaPlanMax)
	t.Err = cleanText(t.Err, quotaErrorMax)
	if len(t.Windows) > quotaWindowsMax {
		return fmt.Errorf("at most %d windows", quotaWindowsMax)
	}
	seen := map[string]bool{}
	for i := range t.Windows {
		w := &t.Windows[i]
		w.Label = cleanText(w.Label, quotaLabelMax)
		w.Key = strings.ToLower(strings.TrimSpace(w.Key))
		if w.Key == "" {
			w.Key = slugID(w.Label)
			if w.Key == "" && len(t.Windows) == 1 {
				w.Key = "usage"
			}
		}
		if !quotaKeyRe.MatchString(w.Key) {
			return fmt.Errorf("window %d: key may only use lower-case letters, digits, - and _ (24 at most)", i+1)
		}
		if seen[w.Key] {
			return fmt.Errorf("window %d: key %q is used twice", i+1, w.Key)
		}
		seen[w.Key] = true
		for _, f := range []*float64{w.Used, w.Total, w.Remaining} {
			if f != nil && (!finite(*f) || *f < 0 || *f >= 1e15) {
				return fmt.Errorf("window %q: used, total and remaining are figures, zero or above", w.Key)
			}
		}
		if w.UsedPercent == nil {
			switch {
			case w.Used != nil && w.Total != nil && *w.Total > 0:
				w.UsedPercent = fp(*w.Used / *w.Total * 100)
			case w.Remaining != nil && w.Total != nil && *w.Total > 0:
				w.UsedPercent = fp((*w.Total - *w.Remaining) / *w.Total * 100)
			default:
				return fmt.Errorf("window %q needs used_percent, or used (or remaining) and total", w.Key)
			}
		}
		if !finite(*w.UsedPercent) || *w.UsedPercent < 0 || *w.UsedPercent > quotaPercentMax {
			return fmt.Errorf("window %q: used_percent is 0…100", w.Key)
		}
		w.UsedPercent = fp(math.Round(*w.UsedPercent*100) / 100)
		w.Unit = strings.ToLower(strings.TrimSpace(w.Unit))
		switch w.Unit {
		case "", "usd", "credits", "count", "bytes":
		case "$":
			w.Unit = "usd"
		default:
			return fmt.Errorf("window %q: unit is usd, credits, count or bytes", w.Key)
		}
		if w.Unit == "" && (w.Used != nil || w.Total != nil || w.Remaining != nil) {
			return fmt.Errorf("window %q: figures need a unit (usd, credits, count or bytes)", w.Key)
		}
		if w.Cost != nil {
			if !finite(*w.Cost) || *w.Cost < 0 || *w.Cost >= quotaCostMax {
				return fmt.Errorf("window %q: cost is US dollars, zero or above", w.Key)
			}
			w.Cost = fp(math.Round(*w.Cost*100) / 100)
		}
		if w.Minutes != nil && (!finite(*w.Minutes) || *w.Minutes < 1 || *w.Minutes > quotaMinutesMax) {
			return fmt.Errorf("window %q: minutes is 1…%v", w.Key, quotaMinutesMax)
		}
		at, err := quotaStamp(w.ResetsAt)
		if err != nil {
			return fmt.Errorf("window %q: %v", w.Key, err)
		}
		w.resets = at
	}
	bal, err := quotaBalance(t.Balance)
	if err != nil {
		return err
	}
	t.balance = bal
	if t.Err != "" && (len(t.Windows) > 0 || t.balance != "" || (t.Unlimited != nil && *t.Unlimited)) {
		return errors.New("error or a reading, not both")
	}
	if len(t.Windows) == 0 && t.balance == "" && (t.Unlimited == nil || !*t.Unlimited) && t.Err == "" && !t.hasExec() {
		return errors.New("a quota needs windows, a balance, an error or an exec command")
	}
	return nil
}

// quotaStamp reads resets_at: unix seconds (milliseconds are recognised
// and converted), or an ISO-8601 time. A time already past is no reset.
func quotaStamp(raw json.RawMessage) (*float64, error) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var at float64
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, errors.New("resets_at is unix seconds or an ISO-8601 time")
		}
		ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
		if err != nil {
			if ts, err = time.Parse(time.RFC3339, strings.TrimSpace(s)); err != nil {
				return nil, errors.New("resets_at is unix seconds or an ISO-8601 time")
			}
		}
		at = float64(ts.UnixMilli()) / 1000
	} else {
		if err := json.Unmarshal(raw, &at); err != nil || !finite(at) || at < 0 {
			return nil, errors.New("resets_at is unix seconds or an ISO-8601 time")
		}
		if at > 1e11 {
			at /= 1000
		}
	}
	at = math.Round(at)
	if at > quotaEpochMax {
		return nil, errors.New("resets_at is past 2096")
	}
	if at <= now() {
		return nil, nil
	}
	return &at, nil
}

func quotaBalance(raw json.RawMessage) (string, error) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", errors.New("balance is a number or a string")
		}
		s = cleanText(s, quotaBalanceMax)
		// The relay keeps a balance only with a figure in it (balanceText);
		// one without would make this a reading here and no card there.
		if !strings.ContainsAny(s, "0123456789") {
			return "", errors.New("balance needs a number in it")
		}
		return s, nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || !finite(f) || math.Abs(f) >= 1e15 {
		return "", errors.New("balance is a number or a string")
	}
	return strconv.FormatFloat(f, 'f', -1, 64), nil
}

// What a quota entry carries onto the tile.
func quotaOnTile(spec *tileSpec, tile *Tile) {
	tile.Plan = spec.Plan
	tile.Balance = spec.balance
	tile.Unlimited = spec.Unlimited != nil && *spec.Unlimited
	tile.Fail = spec.Err
	for _, w := range spec.Windows {
		if w.UsedPercent == nil {
			continue
		}
		tile.Windows = append(tile.Windows, QuotaWindow{
			Key: w.Key, Label: w.Label, UsedPercent: *w.UsedPercent,
			Used: w.Used, Total: w.Total, Remaining: w.Remaining, Unit: w.Unit,
			Cost: w.Cost, Minutes: w.Minutes, ResetsAt: w.resets,
		})
	}
}

// The relay keeps this many providers of a reading (clean.js, index.js
// HIST_PROVIDERS_MAX) and cuts the rest from the end — where the operator's
// own go. Nine collectors and a CPA with several accounts of two vendors
// can fill nineteen, so the room left is counted, not assumed.
const relayProvidersMax = 24

func ownRoom(own []Provider, have int) []Provider {
	room := relayProvidersMax - have
	if room < 0 {
		room = 0
	}
	if len(own) > room {
		return own[:room]
	}
	return own
}

// splitQuota takes the quota tiles out of the custom list and gives each
// back as the Provider the dashboard draws as an agent. The custom list
// keeps the rest, in order.
func splitQuota(tiles []Tile, t float64) ([]Tile, []Provider) {
	var rest []Tile
	var own []Provider
	for _, tile := range tiles {
		if tile.Type != "quota" {
			rest = append(rest, tile)
			continue
		}
		if len(own) >= maxQuotaTiles {
			continue
		}
		own = append(own, quotaProvider(tile, t))
	}
	return rest, own
}

func quotaProvider(tile Tile, t float64) Provider {
	p := Provider{
		ID: customProviderPrefix + tile.ID, Name: tile.Name, Source: "custom",
		Collector: collectorProvenance("", "custom"), CapturedAt: t, RecordedAt: tile.At,
	}
	where := "the command for " + tile.ID
	reading := len(tile.Windows) > 0 || tile.Balance != "" || tile.Unlimited
	// The newest run's failure comes first, as it does for a vendor CLI: a
	// reading the engine kept from an earlier run is not what the command
	// says now. Then a reading nobody has refreshed within its ttl, which
	// a pushed line or a file leaves behind when its writer stops.
	switch {
	case tile.Error == "exec-failed":
		p.failWith("cli-failed", "cli-failed", where)
	case tile.Error == "exec-timeout":
		p.failWith("cli-failed", "cli-timeout", where)
	case tile.Error == "bad-output":
		p.failWith("no-readings", "cli-shape", where)
	case tile.Error != "":
		p.failWith("no-readings", "cli-nolines", where)
	case tile.Stale:
		p.Error, p.Detail = "no-readings", "the newest reading is older than the entry allows (ttl)"
	case reading:
		p.OK = true
		if tile.Plan != "" {
			p.PlanType = sp(tile.Plan)
		}
		for _, w := range tile.Windows {
			lim := Limit{Key: w.Key, UsedPercent: w.UsedPercent, WindowMinutes: w.Minutes, ResetsAt: w.ResetsAt,
				UsedAmount: w.Used, TotalAmount: w.Total, RemainingAmount: w.Remaining, Unit: w.Unit, CostUSD: w.Cost}
			if w.Label != "" {
				lim.WindowLabel = sp(w.Label)
			} else {
				lim.WindowLabel = sp(w.Key)
			}
			p.Limits = append(p.Limits, lim)
		}
		if tile.Balance != "" || tile.Unlimited {
			p.Credits = &Credits{HasCredits: true, Unlimited: tile.Unlimited, Balance: tile.Balance}
		}
	case tile.Fail != "":
		// The command's own words, in the sentence slot; no code, so the
		// panel shows the words rather than a translation of something else.
		p.Error, p.Detail = "no-readings", tile.Fail
	default:
		p.failWith("no-readings", "cli-nolines", where)
	}
	return p
}

// What `subnsub-helper metrics` prints for a quota tile.
func quotaValueText(t Tile) string {
	if t.Fail != "" {
		return "error · " + t.Fail
	}
	var parts []string
	if t.Plan != "" {
		parts = append(parts, t.Plan)
	}
	for _, w := range t.Windows {
		label := w.Label
		if label == "" {
			label = w.Key
		}
		part := fmt.Sprintf("%s %s%%", label, strconv.FormatFloat(w.UsedPercent, 'f', -1, 64))
		if w.Cost != nil && *w.Cost > 0 {
			part += fmt.Sprintf(" ($%.2f)", *w.Cost)
		}
		parts = append(parts, part)
	}
	if t.Unlimited {
		parts = append(parts, "unlimited")
	} else if t.Balance != "" {
		parts = append(parts, "balance "+t.Balance)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, " · ")
}
