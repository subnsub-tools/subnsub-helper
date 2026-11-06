package main

// Custom tiles: the operator's own numbers on the dashboard.
//
// Everything else this helper reports it decided to measure. This file is
// the other direction — whatever the operator wants beside those readings
// (a GPU temperature, a UPS charge, last night's backup, a solar yield, the
// build that is live), collected by whatever they already have: a cron job,
// a shell one-liner, a daemon of their own, or a command this helper runs
// for them on a timer.
//
// The input is a directory of JSON files the operator owns:
//
//   ~/.config/subnsub-helper/metrics.d/*.json
//
// Each file is one SOURCE (its stem is the source id the dashboard groups
// errors under) and holds tiles:
//
//   {
//     "name": "Home lab",                         optional label for this file's set
//     "tiles": [
//       {"id": "gpu_temp", "name": "GPU", "type": "gauge", "value": 71,
//        "unit": "celsius", "max": 100, "warn": 80, "bad": 90, "icon": "gpu",
//        "history": true, "ttl": 120},
//       {"id": "ups", "name": "UPS", "type": "gauge", "value": 96, "unit": "percent",
//        "invert": true, "warn": 40, "bad": 15, "icon": "battery"},
//       {"id": "backup", "name": "Nightly backup", "type": "status",
//        "value": "ok", "label": "02:14 · 38 GB", "icon": "shield"},
//       {"id": "solar", "name": "Solar today", "type": "number", "value": 12.4,
//        "suffix": "kWh", "icon": "sun", "history": true},
//       {"id": "build", "name": "Prod build", "type": "text", "value": "v2026.09.17.2", "icon": "tag"},
//       {"id": "fans", "name": "Fan", "type": "number", "unit": "rpm", "icon": "fan",
//        "exec": "sensors | awk '/fan1/{print $2}'", "interval": 30}
//     ]
//   }
//
// A bare array of tiles is accepted too. Fields:
//
//   id        [A-Za-z0-9_-]{1,48}; derived from the name when absent. The
//             history hangs off it, so keep it stable.
//   name      the label the dashboard shows (defaults to the id)
//   group     the section the tile sits in on the card; tiles with no group
//             share one section
//   type      gauge | number | status | text. Defaults to number for a
//             numeric value, text for a string.
//   value     gauge/number: a number. status: ok | warn | bad | pending |
//             unknown. text: the string. Either this or exec.
//   label     status: a few words beside the state ("02:14 · 38 GB")
//   min, max  gauge: the track (default 0…100)
//   unit      how the dashboard formats the number: percent bytes bytes_s
//             bits_s ms s celsius count usd credits watts rpm hz
//   suffix    a unit the list above lacks ("kWh"), printed after the number
//   warn, bad thresholds that colour the value. A gauge gets 75%/90% of its
//             track by default; "alerts": false turns that off. With
//             "invert": true lower is worse (a battery, a hit rate).
//   icon      a name from the dashboard's built-in set (see the README), or
//             "emoji:🔋" for one emoji
//   tint      colour for a number/text value: accent ok warn bad muted blue
//             violet pink orange teal green red
//   at        unix seconds the value was measured; defaults to the file's
//             own mtime
//   ttl       seconds after `at` before the tile is shown as stale. A tile
//             with neither at nor ttl nor exec is a declaration and never
//             goes stale.
//   history   true keeps a two-day trend for the value (at most 8 per
//             machine). A status keeps the worst state of each five minutes.
//   fold      max (default) or min — which extreme a five-minute history
//             bucket keeps. Inverted gauges default to min.
//   tags      free labels shown on the tile (at most 4)
//   exec      a command this helper runs for the value: a string (through
//             the platform shell) or an argv array. Its stdout is
//               · a bare value: the number, the state word (optionally
//                 followed by a label), or the text;
//               · a JSON object of tile fields, merged over this entry;
//               · a JSON array of tiles, each inheriting this entry's
//                 defaults — one command producing several tiles.
//   interval  exec: seconds between runs, 5…3600, default 60
//   timeout   exec: seconds per run, 1…60, default 10
//
// The directory is re-read whenever a file changes; a broken file keeps its
// last good tiles and flags the source as bad-config, and
// `subnsub-helper metrics` on the machine says what is wrong.
// `subnsub-helper metric set ID VALUE …` writes metrics.d/cli.json for
// anyone who would rather not write JSON at all.
//
// The wire (Tile / CustomSource) is a closed vocabulary the relay's clean.js
// rebuilds field by field — a new field here is a field the relay drops until
// it is taught it — and the page renders unknown icons as a monogram.
//
// A fifth type, "quota", is not a tile on the card at all but an agent on the
// quota board — the operator's own reading of a platform this helper holds
// no credential for. It rides this engine and leaves it at the snapshot;
// customquota.go has the fields and the why.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	customDirName   = "metrics.d"
	customCLIFile   = "cli.json"
	customFileMax   = 256 << 10
	maxCustomFiles  = 8
	maxTiles        = 32 // per machine: the relay's CUSTOM_MAX
	maxTileTags     = 4
	maxTileHistory  = 8 // the relay's HIST_CUSTOM_MAX
	tileNameMax     = 48
	tileGroupMax    = 24
	tileTextMax     = 48
	tileSuffixRunes = 8
	tileIconMax     = 32

	tileDefaultTTL = 300.0
	tileMinTTL     = 5.0
	tileMaxTTL     = 30 * 86400.0

	execDefaultEvery   = 60.0
	execMinEvery       = 5.0
	execMaxEvery       = 3600.0
	execDefaultTimeout = 10.0
	execMaxTimeout     = 60.0
	execMaxOutput      = 64 << 10
	execWorkers        = 4
	execWaitDelay      = 2 * time.Second

	customTick        = 5 * time.Second
	customRereadEvery = 300.0
)

var (
	tileIDRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)
	tileIconRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)
	tileTypes  = map[string]bool{"gauge": true, "number": true, "status": true, "text": true, "quota": true}
	tileStates = map[string]bool{"ok": true, "warn": true, "bad": true, "pending": true, "unknown": true}
	tileUnits  = map[string]bool{
		"percent": true, "bytes": true, "bytes_s": true, "bits_s": true, "ms": true, "s": true,
		"celsius": true, "count": true, "usd": true, "credits": true, "watts": true, "rpm": true, "hz": true,
	}
	tileTints = map[string]bool{
		"accent": true, "ok": true, "warn": true, "bad": true, "muted": true, "blue": true,
		"violet": true, "pink": true, "orange": true, "teal": true, "green": true, "red": true,
	}
)

// Tile and CustomSource are the wire shapes for custom metrics.
type Tile struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group,omitempty"`
	Type  string `json:"type"`
	// gauge/number carry Value; status carries State (+ Text as its label);
	// text carries Text.
	Value  *float64 `json:"value,omitempty"`
	Text   string   `json:"text,omitempty"`
	State  string   `json:"state,omitempty"`
	Min    *float64 `json:"min,omitempty"`
	Max    *float64 `json:"max,omitempty"`
	Unit   string   `json:"unit,omitempty"`
	Suffix string   `json:"suffix,omitempty"`
	Warn   *float64 `json:"warn,omitempty"`
	Bad    *float64 `json:"bad,omitempty"`
	Invert bool     `json:"invert,omitempty"`
	Icon   string   `json:"icon,omitempty"`
	Tint   string   `json:"tint,omitempty"`
	// When the value was measured (unix seconds), and whether it is older
	// than the operator said it may be.
	At    *float64 `json:"at,omitempty"`
	Stale bool     `json:"stale,omitempty"`
	// exec-failed | exec-timeout | bad-output: the command behind the tile
	// did not produce a value this round. What it printed stays on the
	// machine (`subnsub-helper metrics`).
	Error   string       `json:"error,omitempty"`
	History bool         `json:"history,omitempty"`
	Fold    string       `json:"fold,omitempty"` // "min", or "" for max
	Source  string       `json:"source"`
	Tags    []ServiceTag `json:"tags,omitempty"`
	// A quota (customquota.go): never on the wire as a tile — splitQuota
	// turns it into a Provider — but printed by `subnsub-helper metrics`.
	Plan      string        `json:"plan,omitempty"`
	Windows   []QuotaWindow `json:"windows,omitempty"`
	Balance   string        `json:"balance,omitempty"`
	Unlimited bool          `json:"unlimited,omitempty"`
	Fail      string        `json:"fail,omitempty"` // the command's own word that there is no reading
	// What a dashboard press may do to it (tileaction.go): the controls'
	// shape only, never the command behind them.
	Actions []TileAction `json:"actions,omitempty"`
	// Where its actions live instead (tileaction.go): another machine's tile
	// on the same board, by that machine's name and the tile's id.
	Via *TileVia `json:"via,omitempty"`
}

type CustomSource struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	OK       bool     `json:"ok"`
	Error    string   `json:"error,omitempty"`
	LastOKAt *float64 `json:"last_ok_at,omitempty"`
}

// ── configuration ──────────────────────────────────────────────────────────

// tileSpec is one entry as the operator wrote it. Value and Exec are raw
// because each takes two JSON shapes.
type tileSpec struct {
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name,omitempty"`
	Group    string            `json:"group,omitempty"`
	Type     string            `json:"type,omitempty"`
	Value    json.RawMessage   `json:"value,omitempty"`
	Label    string            `json:"label,omitempty"`
	Min      *float64          `json:"min,omitempty"`
	Max      *float64          `json:"max,omitempty"`
	Unit     string            `json:"unit,omitempty"`
	Suffix   string            `json:"suffix,omitempty"`
	Warn     *float64          `json:"warn,omitempty"`
	Bad      *float64          `json:"bad,omitempty"`
	Alerts   *bool             `json:"alerts,omitempty"`
	Invert   bool              `json:"invert,omitempty"`
	Icon     string            `json:"icon,omitempty"`
	Tint     string            `json:"tint,omitempty"`
	At       *float64          `json:"at,omitempty"`
	TTL      *float64          `json:"ttl,omitempty"`
	History  *bool             `json:"history,omitempty"`
	Fold     string            `json:"fold,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
	Exec     json.RawMessage   `json:"exec,omitempty"`
	Interval float64           `json:"interval,omitempty"`
	Timeout  float64           `json:"timeout,omitempty"`
	// On an entry, the commands a dashboard press may run; on a tile a command
	// printed, the ids of its entry's that it offers (tileaction.go).
	Actions json.RawMessage `json:"actions,omitempty"`
	// A pointer to the machine and tile whose actions this one offers.
	Via *TileVia `json:"via,omitempty"`
	// A quota's own (customquota.go).
	Plan      string            `json:"plan,omitempty"`
	Windows   []quotaWindowSpec `json:"windows,omitempty"`
	Balance   json.RawMessage   `json:"balance,omitempty"`
	Unlimited *bool             `json:"unlimited,omitempty"`
	Err       string            `json:"error,omitempty"`

	// Filled by normaliseTile, never read from the file.
	num     *float64     `json:"-"`
	state   string       `json:"-"`
	text    string       `json:"-"`
	balance string       `json:"-"`
	shell   string       `json:"-"` // exec as a shell line
	argv    []string     `json:"-"` // exec as argv
	acts    []actionSpec `json:"-"` // actions, parsed (tileaction.go)
}

func (s *tileSpec) hasExec() bool { return s.shell != "" || len(s.argv) > 0 }

type customConfig struct {
	Name  string     `json:"name"`
	Tiles []tileSpec `json:"tiles"`
}

func customDir() string {
	dir := configDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, customDirName)
}

// parseCustomConfig reads one file's document. `present` is false for an
// empty file, which is the same as no file.
func parseCustomConfig(raw []byte) (cfg customConfig, present bool, err error) {
	body := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
	if body == "" {
		return cfg, false, nil
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if strings.HasPrefix(body, "[") {
		err = dec.Decode(&cfg.Tiles)
	} else {
		err = dec.Decode(&cfg)
	}
	if err == nil {
		if _, tail := dec.Token(); tail != io.EOF {
			err = errors.New("trailing data after the JSON document")
		}
	}
	if err != nil {
		return cfg, true, err
	}
	cfg.Name = cleanText(cfg.Name, tileNameMax)
	if len(cfg.Tiles) > maxTiles {
		return cfg, true, fmt.Errorf("%d tiles, the dashboard shows at most %d per machine", len(cfg.Tiles), maxTiles)
	}
	seen := map[string]bool{}
	for i := range cfg.Tiles {
		t := &cfg.Tiles[i]
		if err := normaliseTile(t, nil); err != nil {
			return cfg, true, fmt.Errorf("tile %d (%s): %v", i+1, firstOf(t.Name, t.ID), err)
		}
		if seen[t.ID] {
			return cfg, true, fmt.Errorf("tile %d (%s): id %q is used twice", i+1, t.Name, t.ID)
		}
		seen[t.ID] = true
	}
	return cfg, true, nil
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// slugID makes an id out of a name: "GPU temp (°C)" → "gpu-temp-c".
func slugID(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
			b.WriteRune(r)
			dash = false
		case r == '_':
			b.WriteRune(r)
			dash = false
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
		if b.Len() >= 48 {
			break
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// parseValue reads the two shapes a value may take: a JSON number, or a
// string (a number in quotes, a state word, or text).
func parseValue(raw json.RawMessage) (num *float64, str string, isStr bool, err error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, "", false, nil
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, "", false, errors.New("value: bad string")
		}
		return nil, s, true, nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, "", false, errors.New("value must be a number or a string")
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, "", false, errors.New("value must be finite")
	}
	return &f, "", false, nil
}

// numberOf turns the operator's text into a number: "71.5", "71.5%",
// "  42 ", "1e3" all count; so do "1,234" and "1200 rpm" — the first word
// is the number and whatever follows it is the command's own unit label.
func numberOf(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexFunc(s, unicode.IsSpace); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "%")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) >= 1e15 {
		return 0, false
	}
	return f, true
}

// stateOf reads "ok", "OK  02:14 · 38 GB", "down" (as bad), "up" (as ok).
func stateOf(s string) (state, label string, ok bool) {
	s = strings.TrimSpace(s)
	word, rest, _ := strings.Cut(s, " ")
	word = strings.ToLower(strings.TrimSpace(word))
	switch word {
	case "up", "pass", "passed", "good", "healthy", "success":
		word = "ok"
	case "down", "fail", "failed", "error", "critical":
		word = "bad"
	case "warning", "degraded":
		word = "warn"
	}
	if !tileStates[word] {
		return "", "", false
	}
	return word, strings.TrimSpace(rest), true
}

// normaliseTile fills defaults and refuses what cannot be shown. `parent`
// is the exec entry a tile came out of (its defaults apply), nil for a tile
// written in the file.
func normaliseTile(t *tileSpec, parent *tileSpec) error {
	// exec: a shell line or an argv array.
	if len(bytes.TrimSpace(t.Exec)) > 0 && !bytes.Equal(bytes.TrimSpace(t.Exec), []byte("null")) {
		if parent != nil {
			return errors.New("a tile printed by a command may not name a command itself")
		}
		raw := bytes.TrimSpace(t.Exec)
		if raw[0] == '"' {
			var line string
			if err := json.Unmarshal(raw, &line); err != nil || strings.TrimSpace(line) == "" {
				return errors.New("exec must be a command line or an argv array")
			}
			t.shell = line
		} else {
			var argv []string
			if err := json.Unmarshal(raw, &argv); err != nil || len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
				return errors.New("exec must be a command line or an argv array")
			}
			t.argv = argv
		}
		switch {
		case t.Interval == 0:
			t.Interval = execDefaultEvery
		case t.Interval < execMinEvery || t.Interval > execMaxEvery:
			return fmt.Errorf("interval must be %v…%v seconds", execMinEvery, execMaxEvery)
		}
		switch {
		case t.Timeout == 0:
			t.Timeout = execDefaultTimeout
		case t.Timeout < 1 || t.Timeout > execMaxTimeout:
			return fmt.Errorf("timeout must be 1…%v seconds", execMaxTimeout)
		}
		if t.Timeout > t.Interval {
			t.Timeout = t.Interval
		}
	} else {
		if t.Interval != 0 || t.Timeout != 0 {
			return errors.New("interval and timeout only apply to a tile with exec")
		}
	}

	if parent != nil {
		inherit(t, parent)
	} else {
		// A printed tile's actions are ids of its entry's, resolved by
		// parseExecOutput; an entry's are declarations.
		acts, err := parseActions(t.Actions)
		if err != nil {
			return err
		}
		t.acts = acts
	}

	num, str, isStr, err := parseValue(t.Value)
	if err != nil {
		return err
	}
	t.Type = strings.ToLower(strings.TrimSpace(t.Type))
	if t.Type == "" {
		switch {
		case num != nil:
			t.Type = "number"
		case isStr:
			// "ok" / "warn" / "bad" on its own is a state; anything with
			// more words in it is text unless the entry says status.
			if _, rest, ok := stateOf(str); ok && (rest == "" || t.Label != "") {
				t.Type = "status"
			} else {
				t.Type = "text"
			}
		default:
			t.Type = "number"
		}
	}
	if !tileTypes[t.Type] {
		return errors.New("type must be gauge, number, status, text or quota")
	}
	hasValue := num != nil || isStr
	if t.Type == "quota" && len(t.acts) > 0 {
		return errors.New("actions do not apply to a quota")
	}
	if t.Type == "quota" {
		if err := normaliseQuota(t, num, isStr); err != nil {
			return err
		}
		hasValue, num, isStr = true, nil, false
	} else if t.Plan != "" || len(t.Windows) > 0 || len(bytes.TrimSpace(t.Balance)) > 0 || t.Unlimited != nil || t.Err != "" {
		return errors.New("plan, windows, balance, unlimited and error only apply to a quota")
	}
	if !hasValue && !t.hasExec() {
		return errors.New("needs a value or an exec command")
	}
	if hasValue {
		switch t.Type {
		case "gauge", "number":
			if num == nil {
				f, ok := numberOf(str)
				if !ok {
					return fmt.Errorf("value %q is not a number", str)
				}
				num = &f
			}
			if math.Abs(*num) >= 1e15 {
				return errors.New("value is too large to show")
			}
			t.num = num
		case "status":
			if !isStr {
				return errors.New("a status tile's value is ok, warn, bad, pending or unknown")
			}
			state, label, ok := stateOf(str)
			if !ok {
				return fmt.Errorf("state %q is not ok, warn, bad, pending or unknown", str)
			}
			t.state = state
			if t.Label == "" {
				t.Label = label
			}
		case "text":
			if isStr {
				t.text = str
			} else {
				t.text = strconv.FormatFloat(*num, 'f', -1, 64)
			}
		}
	}
	t.Label = cleanText(t.Label, tileTextMax)
	t.text = cleanText(t.text, tileTextMax)
	if t.Label != "" && t.Type != "status" {
		return errors.New("label only applies to a status tile")
	}

	t.Name = cleanText(t.Name, tileNameMax)
	t.ID = strings.TrimSpace(t.ID)
	if t.ID == "" {
		t.ID = slugID(t.Name)
		if t.ID == "" {
			return errors.New("needs an id (or a name an id can be made from)")
		}
	} else if !tileIDRe.MatchString(t.ID) {
		return errors.New("id may only use letters, digits, - and _ (48 at most)")
	}
	if t.Name == "" {
		t.Name = t.ID
	}
	if t.Type == "quota" && len(t.ID) > quotaIDMax {
		return fmt.Errorf("a quota's id is at most %d characters", quotaIDMax)
	}
	t.Group = cleanText(t.Group, tileGroupMax)

	// The track.
	if t.Type == "gauge" {
		if t.Min == nil {
			t.Min = fp(0)
		}
		if t.Max == nil {
			t.Max = fp(100)
		}
		if !finite(*t.Min) || !finite(*t.Max) || *t.Max <= *t.Min {
			return errors.New("a gauge needs max > min")
		}
	} else if t.Min != nil || t.Max != nil {
		return errors.New("min and max only apply to a gauge")
	}

	t.Unit = strings.ToLower(strings.TrimSpace(t.Unit))
	switch t.Unit {
	case "":
	case "%":
		t.Unit = "percent"
	case "b":
		t.Unit = "bytes"
	case "b/s", "bps_bytes":
		t.Unit = "bytes_s"
	case "bit/s", "bps":
		t.Unit = "bits_s"
	case "c", "°c":
		t.Unit = "celsius"
	case "w":
		t.Unit = "watts"
	case "$":
		t.Unit = "usd"
	}
	if t.Unit != "" && !tileUnits[t.Unit] {
		return fmt.Errorf("unit %q is not one the dashboard formats (use suffix for a free one)", t.Unit)
	}
	t.Suffix = cleanText(t.Suffix, 4*tileSuffixRunes)
	if strings.ContainsFunc(t.Suffix, unicode.IsSpace) || utf8.RuneCountInString(t.Suffix) > tileSuffixRunes {
		return errors.New("suffix is at most 8 characters and has no spaces")
	}
	if t.Unit != "" && t.Suffix != "" {
		return errors.New("unit or suffix, not both")
	}
	if (t.Unit != "" || t.Suffix != "") && (t.Type == "status" || t.Type == "text") {
		return errors.New("unit and suffix only apply to a gauge or a number")
	}

	// Thresholds.
	if t.Alerts != nil && !*t.Alerts {
		if t.Warn != nil || t.Bad != nil {
			return errors.New("alerts: false and warn/bad do not go together")
		}
	} else if t.Type == "gauge" && t.Warn == nil && t.Bad == nil {
		span := *t.Max - *t.Min
		if t.Invert {
			t.Warn, t.Bad = fp(*t.Min+span*0.25), fp(*t.Min+span*0.10)
		} else {
			t.Warn, t.Bad = fp(*t.Min+span*0.75), fp(*t.Min+span*0.90)
		}
	}
	if (t.Warn != nil || t.Bad != nil) && t.Type != "gauge" && t.Type != "number" {
		return errors.New("warn and bad only apply to a gauge or a number")
	}
	if (t.Warn != nil && !finite(*t.Warn)) || (t.Bad != nil && !finite(*t.Bad)) {
		return errors.New("warn and bad must be finite")
	}
	if t.Warn != nil && t.Bad != nil {
		if !t.Invert && *t.Bad < *t.Warn {
			return errors.New("bad must be at or above warn (set invert for a value where lower is worse)")
		}
		if t.Invert && *t.Bad > *t.Warn {
			return errors.New("with invert, bad must be at or below warn")
		}
	}

	// Looks.
	t.Icon = strings.TrimSpace(t.Icon)
	if t.Icon != "" && !validIcon(t.Icon) {
		return fmt.Errorf("icon %q is not a built-in name or emoji:X", t.Icon)
	}
	t.Tint = strings.ToLower(strings.TrimSpace(t.Tint))
	if t.Tint != "" && !tileTints[t.Tint] {
		return fmt.Errorf("tint %q is not one of the palette", t.Tint)
	}

	// Freshness.
	if t.At != nil && (!finite(*t.At) || *t.At < 1600000000 || *t.At > 4000000000) {
		return errors.New("at must be unix seconds")
	}
	if t.TTL != nil && (!finite(*t.TTL) || *t.TTL < tileMinTTL || *t.TTL > tileMaxTTL) {
		return fmt.Errorf("ttl must be %v…%v seconds", tileMinTTL, tileMaxTTL)
	}
	if t.At != nil && t.TTL == nil {
		t.TTL = fp(tileDefaultTTL)
	}

	// History.
	t.Fold = strings.ToLower(strings.TrimSpace(t.Fold))
	switch t.Fold {
	case "", "max":
		if t.Invert {
			t.Fold = "min"
		} else {
			t.Fold = ""
		}
	case "min":
	default:
		return errors.New("fold must be max or min")
	}
	if t.History != nil && *t.History && t.Type == "text" {
		return errors.New("history only applies to a gauge, a number or a status")
	}
	if t.Type == "status" {
		// A status keeps the WORST state of each bucket; there is no trough.
		t.Fold = ""
	}
	if t.Via != nil {
		if err := normaliseVia(t.Via); err != nil {
			return err
		}
		if t.Type == "quota" {
			return errors.New("via does not apply to a quota")
		}
	}
	if len(t.Tags) > maxTileTags*2 {
		return fmt.Errorf("at most %d tags", maxTileTags)
	}
	return nil
}

// inherit gives a tile printed by a command the defaults its entry set.
func inherit(t, p *tileSpec) {
	if t.Group == "" {
		t.Group = p.Group
	}
	if t.Type == "" {
		t.Type = p.Type
	}
	if t.Min == nil {
		t.Min = p.Min
	}
	if t.Max == nil {
		t.Max = p.Max
	}
	if t.Unit == "" && t.Suffix == "" {
		t.Unit, t.Suffix = p.Unit, p.Suffix
	}
	if t.Warn == nil && t.Bad == nil && t.Alerts == nil {
		t.Warn, t.Bad, t.Alerts = p.Warn, p.Bad, p.Alerts
	}
	if !t.Invert {
		t.Invert = p.Invert
	}
	if t.Icon == "" {
		t.Icon = p.Icon
	}
	if t.Tint == "" {
		t.Tint = p.Tint
	}
	if t.TTL == nil {
		t.TTL = p.TTL
	}
	if t.History == nil {
		t.History = p.History
	}
	if t.Fold == "" {
		t.Fold = p.Fold
	}
	if len(t.Tags) == 0 {
		t.Tags = p.Tags
	}
}

// validIcon: a built-in name, or emoji: followed by one emoji (a single
// grapheme, judged loosely here — the page falls back to a monogram for
// anything it cannot draw).
func validIcon(s string) bool {
	if tileIconRe.MatchString(s) {
		return true
	}
	if !strings.HasPrefix(s, "emoji:") || len(s) > tileIconMax {
		return false
	}
	e := s[len("emoji:"):]
	n := 0
	for _, r := range e {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r < 0x80 {
			return false
		}
		n++
	}
	return n >= 1 && n <= 8
}

// tileTags: the operator's labels, cleaned and bounded, in key order. These
// are the operator's own words about their own number, so nothing is
// filtered by key here — unlike a probe, a tile knows no target to leak.
func tileTags(m map[string]string) []ServiceTag {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]ServiceTag, 0, len(keys))
	for _, raw := range keys {
		k := cleanText(raw, 24)
		v := cleanText(m[raw], 48)
		if k == "" {
			continue
		}
		out = append(out, ServiceTag{k, v})
		if len(out) == maxTileTags {
			break
		}
	}
	return out
}

// ── one command ────────────────────────────────────────────────────────────

type execResult struct {
	at    float64
	ok    bool
	code  string // exec-failed | exec-timeout | bad-output
	out   string // what it printed, for the operator's terminal only
	tiles []tileSpec
}

func runExec(ctx context.Context, spec tileSpec) execResult {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.Timeout*float64(time.Second)))
	defer cancel()
	var cmd *exec.Cmd
	if spec.shell != "" {
		cmd = consoleCommand(ctx, spec.shell)
		cmd.Cancel = func() error { return consoleKill(cmd) }
	} else {
		cmd = exec.CommandContext(ctx, spec.argv[0], spec.argv[1:]...)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cmd.Dir = home
	}
	cmd.WaitDelay = execWaitDelay
	out := &capWriter{max: execMaxOutput}
	errOut := &capWriter{max: 4 << 10}
	cmd.Stdout = out
	cmd.Stderr = errOut
	err := cmd.Start()
	if err == nil {
		if spec.shell != "" {
			consoleAdopt(cmd)
		}
		err = cmd.Wait()
	}
	if spec.shell != "" {
		consoleKill(cmd)
	}
	res := execResult{at: now(), out: strings.TrimSpace(out.buf.String())}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.code = "exec-timeout"
		res.out = "timed out after " + strconv.FormatFloat(spec.Timeout, 'f', -1, 64) + " s"
		return res
	case err != nil:
		res.code = "exec-failed"
		msg := err.Error()
		if s := strings.TrimSpace(errOut.buf.String()); s != "" {
			msg += ": " + s
		}
		if res.out != "" {
			msg += " (stdout: " + res.out + ")"
		}
		res.out = msg
		return res
	}
	tiles, perr := parseExecOutput(spec, res.out)
	if perr != nil {
		res.code = "bad-output"
		res.out = perr.Error() + " (stdout: " + res.out + ")"
		return res
	}
	res.ok = true
	res.tiles = tiles
	return res
}

// parseExecOutput reads what a command printed: a JSON object of tile
// fields over this entry, a JSON array of tiles under it, or a bare value.
func parseExecOutput(spec tileSpec, out string) ([]tileSpec, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, errors.New("printed nothing")
	}
	base := spec
	base.Exec, base.shell, base.argv, base.Interval, base.Timeout = nil, "", nil, 0, 0
	switch out[0] {
	case '{':
		var over tileSpec
		dec := json.NewDecoder(strings.NewReader(out))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&over); err != nil {
			return nil, fmt.Errorf("printed JSON this helper cannot read: %v", err)
		}
		merged := base
		mergeOver(&merged, &over)
		if err := normaliseTile(&merged, nil); err != nil {
			return nil, err
		}
		acts, err := printedActions(over.Actions, merged.acts)
		if err != nil {
			return nil, err
		}
		merged.acts = acts
		merged.ID = base.ID // the entry names the tile, whatever the command says
		return []tileSpec{merged}, nil
	case '[':
		var list []tileSpec
		dec := json.NewDecoder(strings.NewReader(out))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&list); err != nil {
			return nil, fmt.Errorf("printed JSON this helper cannot read: %v", err)
		}
		if len(list) == 0 {
			return nil, errors.New("printed an empty list")
		}
		if len(list) > maxTiles {
			return nil, fmt.Errorf("printed %d tiles, the dashboard shows at most %d", len(list), maxTiles)
		}
		seen := map[string]bool{}
		for i := range list {
			t := &list[i]
			if len(bytes.TrimSpace(t.Exec)) > 0 {
				return nil, fmt.Errorf("tile %d: a printed tile may not name a command", i+1)
			}
			if err := normaliseTile(t, &base); err != nil {
				return nil, fmt.Errorf("tile %d: %v", i+1, err)
			}
			acts, err := printedActions(t.Actions, base.acts)
			if err != nil {
				return nil, fmt.Errorf("tile %d: %v", i+1, err)
			}
			if t.Type == "quota" && len(acts) > 0 {
				return nil, fmt.Errorf("tile %d: actions do not apply to a quota", i+1)
			}
			t.acts = acts
			if seen[t.ID] {
				return nil, fmt.Errorf("tile %d: id %q is used twice", i+1, t.ID)
			}
			seen[t.ID] = true
		}
		return list, nil
	}
	// A bare value. The first line is the value; anything after it is
	// ignored so a chatty command still works.
	line := out
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	merged := base
	switch base.Type {
	case "status":
		merged.Value, _ = json.Marshal(line)
	case "text":
		merged.Value, _ = json.Marshal(line)
	default:
		f, ok := numberOf(line)
		if !ok {
			return nil, fmt.Errorf("printed %q, not a number", line)
		}
		merged.Value, _ = json.Marshal(f)
	}
	if err := normaliseTile(&merged, nil); err != nil {
		return nil, err
	}
	return []tileSpec{merged}, nil
}

// mergeOver lays what a command printed over its entry: every field the
// command set wins.
func mergeOver(t, o *tileSpec) {
	if len(bytes.TrimSpace(o.Value)) > 0 {
		t.Value = o.Value
	}
	if o.Name != "" {
		t.Name = o.Name
	}
	if o.Group != "" {
		t.Group = o.Group
	}
	if o.Type != "" {
		t.Type = o.Type
	}
	if o.Label != "" {
		t.Label = o.Label
	}
	if o.Min != nil {
		t.Min = o.Min
	}
	if o.Max != nil {
		t.Max = o.Max
	}
	if o.Unit != "" {
		t.Unit, t.Suffix = o.Unit, ""
	}
	if o.Suffix != "" {
		t.Suffix, t.Unit = o.Suffix, ""
	}
	if o.Warn != nil {
		t.Warn = o.Warn
	}
	if o.Bad != nil {
		t.Bad = o.Bad
	}
	if o.Alerts != nil {
		t.Alerts = o.Alerts
	}
	if o.Invert {
		t.Invert = true
	}
	if o.Icon != "" {
		t.Icon = o.Icon
	}
	if o.Tint != "" {
		t.Tint = o.Tint
	}
	if o.At != nil {
		t.At = o.At
	}
	if o.TTL != nil {
		t.TTL = o.TTL
	}
	if o.History != nil {
		t.History = o.History
	}
	if o.Fold != "" {
		t.Fold = o.Fold
	}
	if o.Via != nil {
		t.Via = o.Via
	}
	if len(o.Tags) > 0 {
		t.Tags = o.Tags
	}
	// A quota's reading and its error are exclusive: the newest line wins.
	// `value` is the one-window shorthand, so it is a reading too (and a
	// reading laid over the shorthand replaces it).
	if o.Plan != "" {
		t.Plan = o.Plan
	}
	if len(bytes.TrimSpace(o.Value)) > 0 {
		t.Err, t.Windows = "", nil
	}
	if len(o.Windows) > 0 || len(bytes.TrimSpace(o.Balance)) > 0 || o.Unlimited != nil {
		t.Err = ""
		if len(o.Windows) > 0 {
			t.Value = nil
		}
		if len(o.Windows) > 0 {
			t.Windows = o.Windows
		}
		if len(bytes.TrimSpace(o.Balance)) > 0 {
			t.Balance = o.Balance
		}
		if o.Unlimited != nil {
			t.Unlimited = o.Unlimited
		}
	}
	if o.Err != "" {
		t.Err, t.Windows, t.Balance, t.Unlimited, t.Value = o.Err, nil, nil, nil, nil
	}
}

// ── the engine ─────────────────────────────────────────────────────────────

type execRun struct {
	spec    tileSpec
	gen     int
	next    float64
	running bool
	wake    bool // a dashboard press asked for this read: wake the push when it lands
	again   bool // ...and it came while a read was running: read once more after it
	last    *execResult
	lastOK  *execResult
}

type customSource struct {
	id      string
	path    string
	cfg     customConfig
	err     string // "" or bad-config
	okAt    *float64
	fileMod time.Time
	fileLen int64
	readAt  float64
	detail  string // why, for the terminal
}

var custom struct {
	sync.Mutex
	on      bool
	checked bool
	listAt  float64
	sources []*customSource     // in file-name order
	runs    map[string]*execRun // source id + "/" + tile id
	sem     chan struct{}
}

// startCustom begins the background reader and the exec scheduler.
// Idempotent, like startProbes, and called from the same places.
func startCustom() {
	custom.Lock()
	if custom.on {
		custom.Unlock()
		return
	}
	custom.on = true
	custom.sem = make(chan struct{}, execWorkers)
	custom.runs = map[string]*execRun{}
	custom.Unlock()
	customReload(true)
	startCustomPush()
	go func() {
		t := time.NewTicker(customTick)
		defer t.Stop()
		for range t.C {
			customReload(false)
			customRunDue()
		}
	}()
}

// listCustomFiles: the *.json files in metrics.d, by name, capped. The
// stem is the source id and has to have the id's shape.
func listCustomFiles() []string {
	dir := customDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		stem := strings.TrimSuffix(name, ".json")
		if !tileIDRe.MatchString(stem) {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	if len(out) > maxCustomFiles {
		out = out[:maxCustomFiles]
	}
	return out
}

func sourceIDOf(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".json")
}

// customReload re-lists the directory and re-reads every file that changed
// (or all of them on `force` and on a slow clock), rebuilding the exec table
// so a run that survived keeps its schedule and its last value.
func customReload(force bool) {
	custom.Lock()
	defer custom.Unlock()
	t := now()
	paths := listCustomFiles()
	byID := map[string]*customSource{}
	for _, s := range custom.sources {
		byID[s.id] = s
	}
	var next []*customSource
	for _, path := range paths {
		id := sourceIDOf(path)
		s := byID[id]
		if s == nil || s.path != path {
			s = &customSource{id: id, path: path}
		}
		var mod time.Time
		var size int64
		if fi, err := os.Lstat(path); err == nil {
			mod, size = fi.ModTime(), fi.Size()
		}
		if force || s.readAt == 0 || !mod.Equal(s.fileMod) || size != s.fileLen || t-s.readAt >= customRereadEvery {
			s.fileMod, s.fileLen, s.readAt = mod, size, t
			raw, err := readPrivateFile(path, customFileMax)
			var cfg customConfig
			present := false
			if err == nil {
				cfg, present, err = parseCustomConfig(raw)
			}
			if err != nil {
				s.err = "bad-config"
				s.detail = err.Error()
				warnf("metrics: %s: %v (the last good tiles stay up)", filepath.Base(path), err)
			} else {
				s.err, s.detail = "", ""
				ok := t
				s.okAt = &ok
				if !present {
					cfg = customConfig{}
				}
				s.cfg = cfg
			}
		}
		next = append(next, s)
	}
	custom.sources = next
	custom.checked = true
	custom.listAt = t

	keep := map[string]*execRun{}
	for _, s := range custom.sources {
		for _, spec := range s.cfg.Tiles {
			if !spec.hasExec() {
				continue
			}
			key := s.id + "/" + spec.ID
			r := custom.runs[key]
			if r == nil {
				r = &execRun{}
			}
			if !reflect.DeepEqual(r.spec, spec) {
				r.gen++
				r.next = 0
				r.last, r.lastOK = nil, nil
			}
			r.spec = spec
			keep[key] = r
		}
	}
	custom.runs = keep
}

func customRunDue() {
	t := now()
	custom.Lock()
	type due struct {
		key  string
		r    *execRun
		spec tileSpec
		gen  int
	}
	var list []due
	for key, r := range custom.runs {
		if r.running || r.next > t {
			continue
		}
		r.running = true
		// The spec and its generation are read under the lock, together: a
		// press can run this beside the ticker's reload (tileaction.go), and
		// a spec from before a reload paired with the generation after it
		// would publish an old read as current.
		list = append(list, due{key, r, r.spec, r.gen})
	}
	custom.Unlock()
	for _, d := range list {
		d := d
		spec, gen := d.spec, d.gen
		go func() {
			custom.sem <- struct{}{}
			res := runExec(context.Background(), spec)
			<-custom.sem
			custom.Lock()
			d.r.running = false
			// A press that landed while this read was already running wants
			// the read AFTER it, not this one: go round again at once and keep
			// the wake for that one (tileaction.go customRerun).
			again := d.r.again
			d.r.again = false
			wake := d.r.wake && !again
			if wake {
				d.r.wake = false
			}
			if custom.runs[d.key] == d.r && d.r.gen == gen {
				d.r.next = now() + spec.Interval
				if again {
					d.r.next = 0
				}
				d.r.last = &res
				if res.ok {
					d.r.lastOK = &res
				} else {
					warnf("metrics: %s: %s: %s", d.key, res.code, res.out)
				}
			}
			custom.Unlock()
			if wake {
				wakePush()
			}
			if again {
				customRunDue()
			}
		}()
	}
}

// tileOf is the wire's view of one entry: the spec's fields, the value the
// file or the command gave, and whether it is still fresh.
func tileOf(spec *tileSpec, source string, fileMod time.Time, t float64) Tile {
	tile := Tile{
		ID: spec.ID, Name: spec.Name, Group: spec.Group, Type: spec.Type,
		Min: spec.Min, Max: spec.Max, Unit: spec.Unit, Suffix: spec.Suffix,
		Warn: spec.Warn, Bad: spec.Bad, Invert: spec.Invert, Icon: spec.Icon, Tint: spec.Tint,
		History: spec.History != nil && *spec.History, Fold: spec.Fold, Source: source, Tags: tileTags(spec.Tags),
		Actions: wireActions(spec.acts),
	}
	// A tile offers its own actions or another's, never both: its own win.
	if len(tile.Actions) == 0 && spec.Via != nil {
		v := *spec.Via
		tile.Via = &v
	}
	switch spec.Type {
	case "gauge", "number":
		tile.Value = spec.num
	case "status":
		tile.State, tile.Text = spec.state, spec.Label
	case "text":
		tile.Text = spec.text
	case "quota":
		quotaOnTile(spec, &tile)
	}
	at := spec.At
	if at == nil && !fileMod.IsZero() {
		at = fp(float64(fileMod.Unix()))
	}
	tile.At = at
	if spec.TTL != nil && at != nil && t-*at > *spec.TTL {
		tile.Stale = true
	}
	return tile
}

// tilesOfRun: what an exec entry shows — its last good tiles, marked stale
// when the command has not succeeded for three intervals, and carrying the
// error of the newest run when that failed.
func tilesOfRun(s *customSource, r *execRun, t float64) []Tile {
	var out []Tile
	ttl := math.Max(3*r.spec.Interval, tileDefaultTTL)
	if r.spec.TTL != nil {
		ttl = *r.spec.TTL
	}
	if r.lastOK != nil {
		for i := range r.lastOK.tiles {
			spec := &r.lastOK.tiles[i]
			tile := tileOf(spec, s.id, time.Time{}, t)
			if spec.At == nil {
				tile.At = fp(r.lastOK.at)
			}
			tile.Stale = tile.At != nil && t-*tile.At > ttl
			if r.last != nil && !r.last.ok {
				tile.Error = r.last.code
			}
			out = append(out, tile)
		}
		return out
	}
	// Never succeeded: the entry itself, valueless, with the reason.
	tile := tileOf(&r.spec, s.id, time.Time{}, t)
	tile.Value, tile.Text, tile.State, tile.At = nil, "", "", nil
	if r.last != nil {
		tile.Error = r.last.code
		tile.At = fp(r.last.at)
	}
	return []Tile{tile}
}

// collectCustom is what the snapshot carries. With the engine running it is
// a read of the table; without one (a one-shot `subnsub-helper`) it reads
// the files and runs every command once.
func collectCustom() ([]Tile, []CustomSource) {
	custom.Lock()
	on := custom.on
	custom.Unlock()
	if !on {
		return collectCustomOnce()
	}
	custom.Lock()
	defer custom.Unlock()
	t := now()
	var tiles []Tile
	var sources []CustomSource
	seen := map[string]bool{}
	hist := 0
	// Pushed tiles (custompush.go) come after every file's, so a file that
	// names the same id wins; they need a seat in the source list the relay
	// caps at eight, or it would drop them as tiles of a source it never saw.
	addPushed := func() {
		hasPush := false
		for _, s := range sources {
			hasPush = hasPush || s.ID == pushSourceID
		}
		if !hasPush && len(sources) >= maxCustomFiles {
			return
		}
		list, newest := pushedTiles(t, seen)
		if len(list) == 0 {
			return
		}
		if !hasPush {
			sources = append(sources, CustomSource{ID: pushSourceID, OK: true, LastOKAt: newest})
		}
		for _, tile := range list {
			if len(tiles) >= maxTiles {
				break
			}
			if tile.History {
				if hist >= maxTileHistory {
					tile.History = false
				} else {
					hist++
				}
			}
			tiles = append(tiles, tile)
		}
	}
	for _, s := range custom.sources {
		sources = append(sources, CustomSource{ID: s.id, Name: s.cfg.Name, OK: s.err == "", Error: s.err, LastOKAt: s.okAt})
		for i := range s.cfg.Tiles {
			spec := &s.cfg.Tiles[i]
			var list []Tile
			if spec.hasExec() {
				if r := custom.runs[s.id+"/"+spec.ID]; r != nil {
					list = tilesOfRun(s, r, t)
				}
			} else {
				list = []Tile{tileOf(spec, s.id, s.fileMod, t)}
			}
			for _, tile := range list {
				if seen[tile.ID] || len(tiles) >= maxTiles {
					continue
				}
				seen[tile.ID] = true
				if tile.History {
					if hist >= maxTileHistory {
						tile.History = false
					} else {
						hist++
					}
				}
				tiles = append(tiles, tile)
			}
		}
	}
	addPushed()
	return tiles, sources
}

func collectCustomOnce() ([]Tile, []CustomSource) {
	paths := listCustomFiles()
	if len(paths) == 0 {
		return nil, nil
	}
	var tiles []Tile
	var sources []CustomSource
	seen := map[string]bool{}
	hist := 0
	for _, path := range paths {
		s := readCustomSource(path)
		sources = append(sources, CustomSource{ID: s.id, Name: s.cfg.Name, OK: s.err == "", Error: s.err, LastOKAt: s.okAt})
		for _, tile := range customRound(s) {
			if seen[tile.ID] || len(tiles) >= maxTiles {
				continue
			}
			seen[tile.ID] = true
			if tile.History {
				if hist >= maxTileHistory {
					tile.History = false
				} else {
					hist++
				}
			}
			tiles = append(tiles, tile)
		}
	}
	return tiles, sources
}

// readCustomSource reads one file for a one-shot round.
func readCustomSource(path string) *customSource {
	s := &customSource{id: sourceIDOf(path), path: path}
	if fi, err := os.Lstat(path); err == nil {
		s.fileMod, s.fileLen = fi.ModTime(), fi.Size()
	}
	t := now()
	s.readAt = t
	raw, err := readPrivateFile(path, customFileMax)
	var cfg customConfig
	if err == nil {
		cfg, _, err = parseCustomConfig(raw)
	}
	if err != nil {
		s.err, s.detail = "bad-config", err.Error()
		return s
	}
	s.cfg = cfg
	s.okAt = &t
	return s
}

// customRound runs every command in one source once, in parallel, and
// returns the source's tiles in file order.
func customRound(s *customSource) []Tile {
	t := now()
	results := make([]execResult, len(s.cfg.Tiles))
	sem := make(chan struct{}, execWorkers)
	var wg sync.WaitGroup
	for i := range s.cfg.Tiles {
		spec := s.cfg.Tiles[i]
		if !spec.hasExec() {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			results[i] = runExec(context.Background(), spec)
			<-sem
		}(i)
	}
	wg.Wait()
	var out []Tile
	for i := range s.cfg.Tiles {
		spec := &s.cfg.Tiles[i]
		if !spec.hasExec() {
			out = append(out, tileOf(spec, s.id, s.fileMod, t))
			continue
		}
		r := &execRun{spec: *spec, last: &results[i]}
		if results[i].ok {
			r.lastOK = &results[i]
		}
		out = append(out, tilesOfRun(s, r, now())...)
	}
	return out
}

// ── the terminal ───────────────────────────────────────────────────────────

// `subnsub-helper metrics [--json]`: read every file, say what is wrong,
// run each command once and print every tile — WITH what a failed command
// printed, because this is the operator's own terminal.
func runMetricsCLI(args []string) int {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		default:
			warnf("usage: subnsub-helper metrics [--json]")
			return 2
		}
	}
	paths := listCustomFiles()
	live := pushedFromSocket()
	if len(paths) == 0 && len(live) == 0 {
		warnf("no custom tiles: write %s/<name>.json (see the helper README), or run `subnsub-helper metric set ID VALUE`", customDir())
		return 2
	}
	code := 0
	var all []Tile
	for _, path := range paths {
		s := readCustomSource(path)
		if s.err != "" {
			warnf("%s: %s", filepath.Base(path), s.detail)
			code = 2
			continue
		}
		tiles := customRound(s)
		all = append(all, tiles...)
		if asJSON {
			continue
		}
		for _, tile := range tiles {
			line := fmt.Sprintf("%-8s %-10s %-32s %s", s.id, tile.Type, tile.Name, tileValueText(tile))
			if tile.Error != "" {
				line += "  " + tile.Error
				if code == 0 {
					code = 1
				}
			}
			if tile.Stale {
				line += "  (stale)"
			}
			fmt.Println(line)
		}
	}
	// What processes have pushed into the running helper (custompush.go).
	all = append(all, live...)
	if !asJSON {
		for _, tile := range live {
			line := fmt.Sprintf("%-8s %-10s %-32s %s", pushSourceID, tile.Type, tile.Name, tileValueText(tile))
			if tile.Stale {
				line += "  (stale)"
			}
			fmt.Println(line)
		}
	}
	if asJSON {
		fmt.Println(string(dumpIndent(all)))
	}
	return code
}

// pushedFromSocket asks the running helper what has been pushed to it. Nil
// when there is no helper listening, which is not an error for `metrics`.
func pushedFromSocket() []Tile {
	path := pushSockPath()
	if path == "" {
		return nil
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "list\n"); err != nil {
		return nil
	}
	r := bufio.NewReaderSize(c, 1<<20)
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil
	}
	var tiles []Tile
	if json.Unmarshal(bytes.TrimSpace(line), &tiles) != nil {
		return nil
	}
	return tiles
}

func tileValueText(t Tile) string {
	switch t.Type {
	case "quota":
		return quotaValueText(t)
	case "status":
		if t.State == "" {
			return "—"
		}
		if t.Text != "" {
			return t.State + " · " + t.Text
		}
		return t.State
	case "text":
		return t.Text
	}
	if t.Value == nil {
		return "—"
	}
	s := strconv.FormatFloat(*t.Value, 'f', -1, 64)
	if t.Unit != "" {
		s += " " + t.Unit
	} else if t.Suffix != "" {
		s += " " + t.Suffix
	}
	if t.Type == "gauge" && t.Min != nil && t.Max != nil {
		s += fmt.Sprintf(" (%s…%s)", strconv.FormatFloat(*t.Min, 'f', -1, 64), strconv.FormatFloat(*t.Max, 'f', -1, 64))
	}
	return s
}

// `subnsub-helper metric set|rm|ls`: the file metrics.d/cli.json, edited
// for people who would rather not write JSON. set upserts one tile by id
// and stamps `at` now; fields not named keep what they had.
func runMetricCLI(args []string) int {
	usage := func() int {
		warnf("usage: subnsub-helper metric set ID VALUE [--name N] [--group G] [--type gauge|number|status|text]")
		warnf("           [--unit U | --suffix S] [--min N] [--max N] [--warn N] [--bad N] [--no-alerts] [--invert]")
		warnf("           [--icon I] [--tint T] [--label TEXT] [--ttl SEC] [--history|--no-history] [--fold max|min] [--tag k=v]...")
		warnf("       subnsub-helper metric rm ID")
		warnf("       subnsub-helper metric ls")
		warnf("       subnsub-helper metric push [JSON-LINE]...   (or lines on stdin) to the running helper's socket")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	if args[0] == "push" {
		return runMetricPush(args[1:])
	}
	dir := customDir()
	if dir == "" {
		warnf("no home directory")
		return 1
	}
	path := filepath.Join(dir, customCLIFile)
	cfg := customConfig{}
	if raw, err := readPrivateFile(path, customFileMax); err != nil {
		warnf("%s: %v", path, err)
		return 1
	} else if raw != nil {
		var parsed customConfig
		body := strings.TrimSpace(string(raw))
		if strings.HasPrefix(body, "[") {
			err = json.Unmarshal(raw, &parsed.Tiles)
		} else if body != "" {
			err = json.Unmarshal(raw, &parsed)
		}
		if err != nil {
			warnf("%s: %v — fix or remove it first", path, err)
			return 1
		}
		cfg = parsed
	}
	switch args[0] {
	case "ls":
		if len(args) != 1 {
			return usage()
		}
		if len(cfg.Tiles) == 0 {
			fmt.Println("(no tiles set from the command line)")
			return 0
		}
		for _, t := range cfg.Tiles {
			v := strings.TrimSpace(string(t.Value))
			fmt.Printf("%-24s %-8s %s\n", t.ID, firstOf(t.Type, "-"), v)
		}
		return 0
	case "rm":
		if len(args) != 2 {
			return usage()
		}
		kept := cfg.Tiles[:0]
		found := false
		for _, t := range cfg.Tiles {
			if t.ID == args[1] {
				found = true
				continue
			}
			kept = append(kept, t)
		}
		if !found {
			warnf("no tile %q in %s", args[1], path)
			return 1
		}
		cfg.Tiles = kept
		if err := writeCustomCLI(path, cfg); err != nil {
			warnf("%v", err)
			return 1
		}
		fmt.Println("removed", args[1])
		return 0
	case "set":
		if len(args) < 3 {
			return usage()
		}
		id, value := args[1], args[2]
		if !tileIDRe.MatchString(id) {
			warnf("id may only use letters, digits, - and _ (48 at most)")
			return 2
		}
		var spec *tileSpec
		for i := range cfg.Tiles {
			if cfg.Tiles[i].ID == id {
				spec = &cfg.Tiles[i]
			}
		}
		if spec == nil {
			cfg.Tiles = append(cfg.Tiles, tileSpec{ID: id})
			spec = &cfg.Tiles[len(cfg.Tiles)-1]
		}
		tags := map[string]string{}
		for k, v := range spec.Tags {
			tags[k] = v
		}
		rest := args[3:]
		num := func(s string) (*float64, bool) {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil || !finite(f) {
				return nil, false
			}
			return &f, true
		}
		for i := 0; i < len(rest); i++ {
			flag := rest[i]
			needs := func() (string, bool) {
				if i+1 >= len(rest) {
					warnf("%s needs a value", flag)
					return "", false
				}
				i++
				return rest[i], true
			}
			var v string
			var ok bool
			switch flag {
			case "--invert":
				spec.Invert = true
				continue
			case "--history":
				spec.History = bp(true)
				continue
			case "--no-history":
				spec.History = bp(false)
				continue
			case "--no-alerts":
				f := false
				spec.Alerts = &f
				spec.Warn, spec.Bad = nil, nil
				continue
			case "--name", "--group", "--type", "--unit", "--suffix", "--min", "--max", "--warn", "--bad",
				"--icon", "--tint", "--label", "--ttl", "--fold", "--tag":
				if v, ok = needs(); !ok {
					return 2
				}
			default:
				warnf("unknown flag %s", flag)
				return usage()
			}
			switch flag {
			case "--name":
				spec.Name = v
			case "--group":
				spec.Group = v
			case "--type":
				spec.Type = v
			case "--unit":
				spec.Unit, spec.Suffix = v, ""
			case "--suffix":
				spec.Suffix, spec.Unit = v, ""
			case "--icon":
				spec.Icon = v
			case "--tint":
				spec.Tint = v
			case "--label":
				spec.Label = v
			case "--fold":
				spec.Fold = v
			case "--tag":
				k, val, found := strings.Cut(v, "=")
				if !found || strings.TrimSpace(k) == "" {
					warnf("--tag takes key=value")
					return 2
				}
				tags[strings.TrimSpace(k)] = strings.TrimSpace(val)
			case "--min", "--max", "--warn", "--bad", "--ttl":
				f, ok := num(v)
				if !ok {
					warnf("%s takes a number", flag)
					return 2
				}
				switch flag {
				case "--min":
					spec.Min = f
				case "--max":
					spec.Max = f
				case "--warn":
					spec.Warn = f
					spec.Alerts = nil
				case "--bad":
					spec.Bad = f
					spec.Alerts = nil
				case "--ttl":
					spec.TTL = f
				}
			}
		}
		if len(tags) > 0 {
			spec.Tags = tags
		}
		// The value: a number unless the tile is a status or a text, or the
		// text is not a number at all.
		if f, ok := numberOf(value); ok && spec.Type != "text" && spec.Type != "status" {
			spec.Value, _ = json.Marshal(f)
		} else {
			spec.Value, _ = json.Marshal(value)
		}
		// A value typed by hand is measured now — the file's mtime would say
		// the same, but a later `set` of ANOTHER tile must not refresh this
		// one. Stamped only when a ttl says freshness matters: a value
		// somebody typed otherwise stays true until they type another.
		if spec.TTL != nil {
			spec.At = fp(math.Floor(now()))
		} else {
			spec.At = nil
		}
		// Validate the whole file as the daemon will read it.
		check := *spec
		if err := normaliseTile(&check, nil); err != nil {
			warnf("%s: %v", id, err)
			return 2
		}
		if spec.Type == "" {
			spec.Type = check.Type
		}
		if err := writeCustomCLI(path, cfg); err != nil {
			warnf("%v", err)
			return 1
		}
		fmt.Printf("%s = %s  (%s; the dashboard shows it within a minute)\n", id, tileValueText(tileOf(&check, "cli", time.Time{}, now())), path)
		return 0
	}
	return usage()
}

func writeCustomCLI(path string, cfg customConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if cfg.Name == "" {
		cfg.Name = "Command line"
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
