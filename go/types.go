// Package main — subnsub-helper, the shipping helper.
//
// Ported from the Python reference implementation, which stays as the
// reference: the Python
// found the file formats, the endpoint, and every trap five review rounds
// turned up.
//
// On "same wire format", which an earlier version of this comment overstated:
// the two produce payloads the relay and the page treat identically, not
// byte-identical JSON. Known differences, all of them absorbed by the relay's
// field-by-field rebuild — Go omits some keys where Python emits an explicit
// null (an omitted key and a null key mean the same thing to every consumer
// here), Go's Claude limits carry window_minutes:null where Python omits the
// key entirely, and Go does not send the Python's raw extra_usage block,
// which the relay drops anyway — Claude's extra usage reaches the page as an
// `extra` window instead (adapters.json), its amounts in the vendor's own
// currency or not at all. Anything a consumer actually reads matches.
package main

import (
	"strings"
	"sync"
	"time"
)

// A quota window. Providers name their windows differently (Codex says
// primary/secondary, Claude says session/weekly/weekly_scoped) so Key is
// passed through rather than forced into one vocabulary.
//
// Pointers where the Python emits null: a missing reset time and a reset time
// of zero mean very different things, and the page checks for null.
type Limit struct {
	Key           string   `json:"key"`
	UsedPercent   float64  `json:"used_percent"`
	WindowLabel   *string  `json:"window_label"`
	WindowMinutes *float64 `json:"window_minutes"`
	// Unix SECONDS. Claude's API speaks ISO-8601 and its credential file
	// speaks milliseconds; both are converted before they get here, because
	// one unit reaching the page unconverted looks entirely plausible and is
	// entirely wrong.
	ResetsAt *float64 `json:"resets_at"`
	Severity *string  `json:"severity"`
	Scope    *string  `json:"scope"`
	Active   *bool    `json:"active"`

	// The absolute figures behind UsedPercent, when the provider actually
	// supplies them. These stay optional because many APIs expose only a
	// percentage; deriving a fake denominator would make the extra precision
	// actively misleading. Unit is a small semantic vocabulary enforced again
	// by the relay: "usd" and "credits" from the vendors, and "count" and
	// "bytes" for the free allowances an operator's own command reads off a
	// bill (customquota.go).
	UsedAmount      *float64 `json:"used_amount,omitempty"`
	TotalAmount     *float64 `json:"total_amount,omitempty"`
	RemainingAmount *float64 `json:"remaining_amount,omitempty"`
	Unit            string   `json:"unit,omitempty"`
	// What the window has cost this period, in US dollars — the part of a
	// bill an operator's command puts against one allowance (customquota.go
	// `cost`). No collector of the helper's own sets it.
	CostUSD *float64 `json:"cost_usd,omitempty"`
}

type Credits struct {
	HasCredits bool   `json:"has_credits"`
	Unlimited  bool   `json:"unlimited"`
	Balance    string `json:"balance"`
}

type Amount struct {
	Amount float64 `json:"amount"`
	Unit   string  `json:"unit"`
}

// Reset credits: what a vendor grants an account to clear a quota window
// early — Codex's "rate limit reset credits", Claude's reset grants. A count
// and when the ones held lapse; never an id, never anything to spend one with.
// Total is the grant's size where the vendor names one (Claude's "1 of 1");
// Expires is each held credit's lapse, soonest first, Unix SECONDS.
//
// And what can be done with them now (2026.10.07.3), where the vendor says:
// Usable is how many could be used at once (Codex's applicable count;
// Claude's grants that are usable, not paused and not waiting on a limit);
// NeedsLimit, that the ones that cannot are waiting for a window to reach
// its limit; WaitUntil, a cooldown before the next one (Unix SECONDS); and
// Clears, which windows one clears, by length ("5h", "7d") as the windows
// are labelled. Still nothing that could spend one.
type ResetCredits struct {
	Left       float64   `json:"left"`
	Total      *float64  `json:"total,omitempty"`
	Expires    []float64 `json:"expires,omitempty"`
	Usable     *float64  `json:"usable,omitempty"`
	NeedsLimit bool      `json:"needs_limit,omitempty"`
	WaitUntil  *float64  `json:"wait_until,omitempty"`
	Clears     []string  `json:"clears,omitempty"`
}

// Provider activity is not quota. Requests and tokens must not be turned into
// a percentage bar: there is no denominator, and more activity is not a state
// that gets worse as it rises. A bounded typed block keeps those useful totals
// without opening a bag of arbitrary provider-specific fields on the wire.
type Activity struct {
	WindowLabel *string  `json:"window_label,omitempty"`
	Requests    *float64 `json:"requests,omitempty"`
	Tokens      *float64 `json:"tokens,omitempty"`
	Saved       *Amount  `json:"saved,omitempty"`
}

// Reference names reviewed upstream code that informed this collector. It is
// provenance, not another executable: the helper never downloads or runs the
// referenced project. Commit is always a full immutable Git commit, never a
// branch or tag, so a later upstream push cannot silently change what this
// build claims to have reviewed.
type Reference struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
	Role   string `json:"role"`
}

// CollectorProvenance keeps two meanings that used to be easy to conflate
// separate on the wire: Source/Method says HOW the native collector obtained a
// reading, while References say WHICH fixed upstream implementations informed
// selected protocol, parser, or behaviour decisions. A reference is not a
// collector and must never be presented as one.
type CollectorProvenance struct {
	ID         string      `json:"id"`
	Method     string      `json:"method,omitempty"`
	References []Reference `json:"references,omitempty"`
}

// One provider's answer. A provider reports its own failure rather than
// sinking the snapshot — an expired Claude token must not blank out Codex.
type Provider struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Source string `json:"source"` // "local-log", "local-api", "api", "cli", "cpa", or "custom" (the operator's own command)
	// Which account this reading belongs to, by the name it is known by: a
	// CPA credential's (cpa.go) or the local rung's (local.go), else the
	// e-mail or login its tool is signed in with (accountkey.go
	// stampAccountKeys). The tile shows it; empty where nothing names one.
	Account string `json:"account,omitempty"`
	// Which account, as a key the fleet shares and nobody else can read
	// (accountkey.go): an HMAC of the identity under the relay token's
	// account part, so the page folds one account's readings from several
	// machines into one row without the identity itself travelling.
	// Empty where this build cannot name the account, and everywhere when
	// there is no token to key it with.
	AccountKey string `json:"account_key,omitempty"`
	// This helper's collector produced the reading. Reference entries, when
	// present, are fixed-commit review provenance only; see the types above.
	Collector *CollectorProvenance `json:"collector,omitempty"`

	// Why there is no reading, said twice. Detail is an English sentence, for
	// the readers with no translation layer — raw JSON, a self-hosted
	// dashboard, this helper's own console. DetailCode (plus at most one
	// argument spliced into it) is the same sentence in machine form, which is
	// what the panel translates. See detail.go.
	Error      string `json:"error,omitempty"`
	Detail     string `json:"detail,omitempty"`
	DetailCode string `json:"detail_code,omitempty"`
	DetailArg  string `json:"detail_arg,omitempty"`

	CapturedAt float64  `json:"captured_at"`
	RecordedAt *float64 `json:"recorded_at,omitempty"`

	PlanType      *string   `json:"plan_type,omitempty"`
	RateLimitTier *string   `json:"rate_limit_tier,omitempty"`
	Limits        []Limit   `json:"limits,omitempty"`
	Credits       *Credits  `json:"credits,omitempty"`
	Activity      *Activity `json:"activity,omitempty"`
	// The account's reset credits (see ResetCredits), read by the table
	// (adapters.json `resets`), so far from CPA's Codex and Claude answers.
	Resets *ResetCredits `json:"resets,omitempty"`
	// The plan's one date (Unix SECONDS, only ever a date still ahead), in
	// one of three keys by what the vendor says of it (2026.10.07.6; table
	// `renews` / `ends` / `until`): it renews then; it ends then and does
	// not renew; or its current period runs until then, renewing or not —
	// Codex's subscription answer says which of the first two, its
	// credential's claim and Devin's plan end say only the third. At most one
	// is set (setPlanDate). Before 2026.10.07.6 every one of them was
	// RenewsAt.
	RenewsAt    *float64 `json:"renews_at,omitempty"`
	EndsAt      *float64 `json:"ends_at,omitempty"`
	ActiveUntil *float64 `json:"active_until,omitempty"`
	// The vendor says the account is at its limit now (2026.10.07.4; table
	// `limited`): Codex's rate_limit.limit_reached or allowed:false, Claude's
	// cedar_ember.at_limit. Its own word, so it can say so while the windows'
	// shares still read a little under 100 — and only ever a yes: a vendor
	// that says nothing is not saying "no".
	Limited bool `json:"limited,omitempty"`
	// The plan's date came from the credential's own claim rather than a
	// live answer (adapterKeep ranks the two). Never on the wire.
	planClaim bool

	SourceFile string `json:"source_file,omitempty"`
	Truncated  bool   `json:"truncated"`
	Capped     bool   `json:"capped"`
}

// Netns: how many network namespaces this machine shows and which the
// helper runs in — "init" (pid 1's), a named one, or "unnamed".
type Netns struct {
	Count int      `json:"count"`
	Own   string   `json:"own"`
	Names []string `json:"names,omitempty"`
}

type Snapshot struct {
	OK         bool       `json:"ok"`
	CapturedAt float64    `json:"captured_at"`
	Providers  []Provider `json:"providers"`
	// Which machine this came from. One token is pasted on every machine an
	// account watches, so without this they all push into one slot and the
	// page shows whichever pushed last. Random, never derived from hardware —
	// see agent.go. The label is optional and operator-set; omitted when
	// unset, so the page falls back to the id rather than inventing a name.
	AgentID    string `json:"agent_id,omitempty"`
	AgentLabel string `json:"agent_name,omitempty"`
	Rename     bool   `json:"rename"`
	// Which build is reporting. The dashboard is the only place anyone can
	// find out that a machine is running a helper from before some provider
	// existed — nothing else on a box you have no route to will tell you — and
	// without this the page cannot tell a current helper from a year-old one.
	//
	// Not a fingerprint: it is the same string for everyone on a given build,
	// says nothing about the machine, and is the one piece of self-description
	// here that the user can act on.
	HelperVersion string `json:"helper_version,omitempty"`
	// Which adapter table (adapters.json `version`) read the CPA rung this
	// time; zero until the rung is configured. Operating a table that
	// travels on its own needs one place that says which one a machine is on.
	AdaptersVersion int `json:"adapters_v,omitempty"`
	// Whether this machine will run a command the dashboard sends it. Always
	// present, never omitted: the page has to be able to tell "this helper
	// says no" from "this helper is too old to have an opinion", and an
	// omitted key reads as the first when it means the second. See console.go
	// for what turns it on — which is a file on this machine and nothing else.
	Console bool `json:"exec"`
	// Whether this machine will replace its own binary when the dashboard asks
	// it to. Always present for the same reason `exec` is: the page has to tell
	// "this helper says no" apart from "this helper predates the question".
	//
	// A separate key rather than a second meaning for `exec`, even though the
	// console implies this one — see update.go. Folding them together would
	// make turning the console off also turn off a switch nobody set, and would
	// leave the console-off machine that DID opt in with no way to say so.
	Update bool `json:"upd"`
	// Whether this machine replaces its own binary on a timer, unasked
	// (update.go: autoupdate). Informational — the page shows it beside the
	// other two — and only ever true alongside `upd`.
	AutoUpdate bool `json:"auto"`
	// Read-only on-demand diagnostics. A separate, always-present capability
	// because neither the shell nor remote-update switches grant it. The only
	// current target is a bounded Linux process resource summary; see inspect.go.
	Diagnostics bool `json:"diag"`
	// Whether this machine has been told WHO may command it, and therefore
	// requires a signature the relay cannot produce (signing.go). True as soon
	// as a trusted-keys file exists — including one too damaged to read, which
	// refuses everything rather than reverting to unsigned; what this reports
	// is what the machine will DEMAND, not how many keys it holds.
	//
	// Reported because the difference is invisible from the dashboard
	// otherwise, and the two states are not equally safe: a machine with no
	// pinned key runs what the relay hands it. A card that showed both the same
	// way would let the weaker one pass for the stronger.
	Signed bool `json:"sgn"`
	// Whether a pinned browser may press this machine's tiles: an action
	// declared in metrics.d and a key pinned (tileaction.go). The relay
	// queues an `act` only for a machine that says so.
	Act bool `json:"act"`
	// Whether this machine takes the `myip` command (myip.go): an origin to
	// ask and a mailbox switch on. The relay queues one only for a machine
	// that says so; always present, for the reason `exec` is.
	MyIP bool `json:"myip"`
	// The direct road's address (a tailcat ConnBlob, `tc…`) while the tunnel
	// is up, absent otherwise. It travels in the relay reading so a dashboard
	// that already watches this machine through the relay can open the tunnel
	// too without anybody copying a line. A bearer of
	// reachability, not of access: the allowlist still decides who gets an
	// answer, and the relay already carries everything else this machine
	// says about itself.
	DirectAddr string `json:"direct_addr,omitempty"`
	// The console's spare road, where this machine opened it: its own
	// X25519 key in text, for the dashboard to seal a line to (econ.go).
	Econ string `json:"econ,omitempty"`
	// Machine health. A pointer so a platform that can measure nothing at all
	// omits the key rather than shipping a shell of nulls — see system.go for
	// what each platform can actually read, and why.
	System         *System         `json:"system,omitempty"`
	Services       []Service       `json:"services,omitempty"`
	ServiceSources []ServiceSource `json:"service_sources,omitempty"`

	// The operator's own numbers (custom.go): tiles written to
	// ~/.config/subnsub-helper/metrics.d/ by whatever they like, and the
	// state of each file they came from. Same shape discipline as Services:
	// a closed vocabulary the relay's clean.js rebuilds field by field.
	Custom        []Tile         `json:"custom,omitempty"`
	CustomSources []CustomSource `json:"custom_sources,omitempty"`

	// The agents' command-line tools on this machine and the release of
	// each, read off the disk and never by running them (clis.go): the
	// Agent usage card's versions. A closed vocabulary like the tiles'.
	CLIs []CLI `json:"cli,omitempty"`

	// What the coding agents spent here, by hour and day, tool and model
	// (tokens.go): the Agent usage card's token section. Counts only.
	Tokens *TokenUsage `json:"tok,omitempty"`

	// The exits of this machine's other network namespaces (spaces.go).
	Spaces []Space `json:"spaces,omitempty"`

	// The machine's network namespaces and the helper's own (spaces_linux.go
	// netnsInfo): the card names each and says where the helper is.
	Netns *Netns `json:"netns,omitempty"`

	// Every way out measured against the release host (roads.go): the
	// helper's own namespace ("") and each named one. The card shows them
	// under the Exit groups; the updater takes the fastest.
	Roads []Road `json:"roads,omitempty"`

	// The machine's public IPv4 address, as a public "what is my IP"
	// service answered it (ipv4.go) — the one address the helper reports
	// for itself, for when the relay sees the machine over IPv6 or there is
	// no relay. Absent until a lookup succeeds, or with MON_IPV4=off.
	PublicIPv4 string `json:"public_ipv4,omitempty"`
	// And the country the lookup placed that address in (ISO 3166-1
	// alpha-2), when the service said one: the flag on the card's strip.
	// Never without PublicIPv4.
	PublicCC string `json:"public_cc,omitempty"`

	// The auto-update timer (update.go): when its next pass is due, as unix
	// seconds, and how its last pass ended. Absent while the timer is off.
	UpdateNext int64       `json:"update_next,omitempty"`
	UpdateLast *updateLast `json:"update_last,omitempty"`

	// The most recent rebuild of the machine underneath this state, as
	// [start_s, end_s] (outages.go `wipe`, hostid.go), absent while there
	// has been none. The one outage the relay is TOLD about: it saw the
	// same stretch as a silence, and this is what lets it file that
	// silence as a wipe in its own durable record rather than as "no
	// heartbeat" — a record that must outlive the machine, since the
	// machine's own file was on the disk that was wiped.
	Wiped []int64 `json:"wiped,omitempty"`

	// The rows of the machine's own outage record the relay has not yet
	// acknowledged (outages.go outagePending), and the earliest moment that
	// record reaches back to; the relay files them beside its own record of
	// silences and the page reads the two as one. Absent on an ordinary
	// push: the relay's answer says how far its copy reaches (hint.go
	// `outages_until`) and only what is newer travels.
	Outages      []outageRow `json:"outages,omitempty"`
	OutagesSince int64       `json:"outages_since,omitempty"`

	// The rows of the reach record (reach.go) the relay has not yet
	// acknowledged: stretches this machine was online while its push was
	// failing, which the page takes out of the relay's silences. Absent on
	// an ordinary push (hint.go `reach_until`).
	Reach []outageRow `json:"reach,omitempty"`
}

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func sp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func fp(f float64) *float64 { return &f }
func bp(b bool) *bool       { return &b }

// The plan's date and what the vendor says of it: "renews", "ends" or
// "until" (see Provider.RenewsAt), or nil.
func (p *Provider) planDate() (*float64, string) {
	switch {
	case p.RenewsAt != nil:
		return p.RenewsAt, "renews"
	case p.EndsAt != nil:
		return p.EndsAt, "ends"
	case p.ActiveUntil != nil:
		return p.ActiveUntil, "until"
	}
	return nil, ""
}

// Sets the plan's one date under the key its kind names, clearing the others.
func (p *Provider) setPlanDate(at *float64, kind string) {
	p.RenewsAt, p.EndsAt, p.ActiveUntil = nil, nil, nil
	if at == nil {
		return
	}
	switch kind {
	case "renews":
		p.RenewsAt = at
	case "ends":
		p.EndsAt = at
	case "until":
		p.ActiveUntil = at
	}
}

// Every provider this build ships, in display order. Codex is a local file —
// no credential, no network. Antigravity is a request to a server already
// running on this machine or its own CLI's report — no credential either way.
// Amp is a subprocess that talks to Amp on our behalf, so we hold no key. The
// rest are the credential rung: each reads the credential its own CLI left on
// disk and
// calls that vendor and nobody else. Claude was the first; provhttp.go
// carries the rules they all inherit.
//
// Ids match CodexBar's registry on purpose — the site's coverage endpoint
// diffs the two lists by these exact strings, and a test holds this table and
// that endpoint's SUPPORTED array to being the same list.
var collectors = []struct {
	id string
	fn func() Provider
}{
	{"codex", collectCodex},
	// Antigravity: the table's local rung where agy left its token file
	// (Linux), and behind it — on any failure, collectLocalElse — the
	// loopback probe or the CLI's own report.
	{"antigravity", func() Provider { return collectLocalElse("antigravity", collectAntigravity) }},
	{"amp", collectAmp},
	// Claude, Kimi and Grok read by the table (local.go) when it knows their
	// credential file, and by their native collector otherwise or when the
	// table's answer held nothing — the first three to move; the rest follow
	// as their rows are written.
	{"claude", func() Provider { return collectLocalOr("claude", collectClaude) }},
	{"copilot", collectCopilot},
	{"kimi", func() Provider { return collectLocalOr("kimi", collectKimi) }},
	{"grok", func() Provider { return collectLocalOr("grok", collectGrok) }},
	{"kilo", collectKilo},
	// CLI subprocesses last: they are the heaviest, and concurrency means
	// their cost is hidden behind the network collectors rather than added.
	{"kiro", collectKiro},
}

const codexBarReferenceCommit = "7749f7b94ae8f1b84b9ffb2046643cec810f4078"

// The CLI Proxy API Management Center commit whose quota page the CPA rung's
// adapters.json was worked out from (protocol: endpoints, headers, fields).
// Lockstep with the relay's REFERENCE_COMMITS and the coverage registry;
// coverage_test.go checks all three.
const cpamcReferenceCommit = "64b4f5aed19b8f791eb21eb9e785ea379ea05b44"

// Only mark a reference where the collector's source documents what was
// actually taken from it. Codex and Claude, for example, do not get a blanket
// CodexBar badge merely because CodexBar supports those products too. That
// would turn project coverage into false per-reading provenance.
var codexBarReferenceRoles = map[string]string{
	"antigravity": "protocol-reference",
	"copilot":     "protocol-reference",
	"kimi":        "protocol-reference",
	"grok":        "parser-reference",
	"kilo":        "parser-reference",
	"kiro":        "parser-reference",
}

func collectorProvenance(providerID, method string) *CollectorProvenance {
	if method == "custom" {
		// The operator's own command (customquota.go): not this helper's
		// collector, and no project's reading either.
		return &CollectorProvenance{ID: "operator", Method: "custom"}
	}
	c := &CollectorProvenance{ID: "subnsub-native", Method: method}
	if method == "cpa" {
		// Read through CLI Proxy API by the console's protocol; CodexBar had
		// no hand in it whichever vendor it is.
		c.References = []Reference{{
			ID: "cpamc", Commit: cpamcReferenceCommit, Role: "protocol-reference",
		}}
		return c
	}
	if role := codexBarReferenceRoles[providerID]; role != "" {
		c.References = []Reference{{
			ID: "codexbar", Commit: codexBarReferenceCommit, Role: role,
		}}
	}
	return c
}

// Collect every provider. A collector that panics is contained and reported —
// these run on other people's machines against files this program does not
// control, and one bad rollout should not take the helper down.
func collectAll() Snapshot { return collectAllOpts(true) }

// collectAllOpts is collectAll with one knob: whether this reading may take
// the sampler's accumulated series with it. The relay push does (that series
// is the trend strip's live tail); the direct tunnel must not, because it
// streams host health at full rate on its own and consuming the series here
// would leave the next relay push with a fraction of the thirty seconds it
// expects.
func collectAllOpts(consumeSeries bool) Snapshot {
	snap := Snapshot{CapturedAt: now(), AgentID: agentID(), AgentLabel: agentLabel(),
		Rename:        loadTrust().sealed,
		HelperVersion: helperVersion, Console: consoleEnabled(), Update: updateAllowed(), AutoUpdate: autoUpdateEnabled(),
		AdaptersVersion: adaptersVersion(),
		Diagnostics:     diagnosticsEnabled(), Signed: loadTrust().sealed, Act: tileActionsOn(), MyIP: myipAvailable(),
		DirectAddr: directAddress(), Econ: econPublic(), Wiped: outageLastWipe(),
		Outages: outagePending(time.Now()), OutagesSince: outageSince(), Reach: reachPending(time.Now())}
	// Concurrently, holding the registry's order for the output. Serial was
	// fine at four collectors; at eight, five of them making real requests
	// with ten-second deadlines, a bad network day could stack past the
	// relay's 90-second offline threshold — a machine marked dead for being
	// thorough. Each collector still serialises against ITSELF (every one has
	// a mutex over its cache), so two pushes racing costs nothing extra.
	results := make([]Provider, len(collectors))
	var services []Service
	var serviceSources []ServiceSource
	var wg sync.WaitGroup
	for i, c := range collectors {
		wg.Add(1)
		go func(i int, id string, fn func() Provider) {
			defer wg.Done()
			p := safeCollect(id, fn)
			p.Collector = collectorProvenance(id, p.Source)
			results[i] = p
		}(i, c.id, c.fn)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		services, serviceSources = collectProbes()
	}()
	var custom []Tile
	var customSources []CustomSource
	wg.Add(1)
	go func() {
		defer wg.Done()
		custom, customSources = collectCustom()
	}()
	var cpa cpaResult
	wg.Add(1)
	go func() {
		defer wg.Done()
		cpa = collectCPA()
	}()
	// The transcripts' token counts: at most one pass a minute, the last
	// answer between (tokens.go), so the tunnel's rate costs nothing here.
	var tokens *TokenUsage
	wg.Add(1)
	go func() {
		defer wg.Done()
		tokens = tokenSnapshot()
	}()
	wg.Wait()
	snap.Tokens = tokens
	snap.Providers = mergeCPA(results, cpa)
	snap.Services = services
	snap.ServiceSources = serviceSources
	// The operator's own quota readings leave the custom list here and join
	// the agents (customquota.go), after every collector's.
	var own []Provider
	custom, own = splitQuota(custom, snap.CapturedAt)
	snap.Providers = append(snap.Providers, ownRoom(own, len(snap.Providers))...)
	snap.Custom, snap.CustomSources = custom, customSources
	// Which account each reading belongs to, after every road has spoken
	// (accountkey.go): the key the page folds by, and the name it shows.
	stampAccountKeys(snap.Providers)
	// Machine health rides along with the quota. Deliberately NOT part of
	// snap.OK: a box with no AI tooling installed still reports its own health,
	// but "ok" has always meant "at least one provider answered", and widening
	// it here would flip every no-provider machine from a visible failure to a
	// silent success.
	// The sampler, when one is running, is the only thing allowed to call
	// collectSystem — every rate in there is a difference against the previous
	// call, so a second caller silently steals the interval (see sampler.go).
	if !consumeSeries {
		if sys := latestSystem(); sys != nil {
			if sys.OK || len(sys.Missing) > 0 {
				snap.System = sys
			}
		} else if sys := collectSystem(); sys.OK || len(sys.Missing) > 0 {
			snap.System = &sys
		}
	} else if sys, series := sampledSystem(); sys != nil {
		if sys.OK || len(sys.Missing) > 0 {
			sys.Series = series
			snap.System = sys
		}
	} else if sys := collectSystem(); sys.OK || len(sys.Missing) > 0 {
		snap.System = &sys
	}
	for _, p := range snap.Providers {
		if p.OK {
			snap.OK = true
		}
	}
	snap.Spaces = spacesSnapshot()
	snap.Netns = netnsInfo()
	snap.Roads = roadsSnapshot()
	snap.PublicIPv4, snap.PublicCC = ipv4Snapshot()
	snap.UpdateNext, snap.UpdateLast = updateSnapshot()
	snap.CLIs = cliSnapshot()
	historyRecord(&snap)
	return snap
}

// The CPA rung folded into the native readings, in the registry's order.
// A vendor CPA holds a credential for is CPA's to report — its readings, all
// of them, stand where the native one stood and the native one is set aside.
// A vendor CPA knows nothing about keeps its native collector. When CPA
// itself could not be asked, nothing native moves and nothing is added: the
// proxy is a channel, and its trouble goes to this program's log (cpaSay),
// not onto the board.
func mergeCPA(native []Provider, c cpaResult) []Provider {
	// Which tiles are CPA's in this reading, for a press on one (pace.go).
	tiles := make([]string, 0, len(c.providers))
	if c.configured {
		for _, p := range c.providers {
			tiles = append(tiles, p.ID)
		}
	}
	noteCPATiles(tiles)
	if !c.configured {
		return native
	}
	byVendor := map[string][]Provider{}
	order := []string{}
	for _, p := range c.providers {
		p.Collector = collectorProvenance(p.ID, "cpa")
		base := p.ID
		if i := strings.IndexByte(base, '@'); i > 0 {
			base = base[:i]
		}
		if _, seen := byVendor[base]; !seen {
			order = append(order, base)
		}
		byVendor[base] = append(byVendor[base], p)
	}
	out := make([]Provider, 0, len(native)+len(c.providers)+1)
	for _, p := range native {
		if cp, ok := byVendor[p.ID]; ok {
			out = append(out, cp...)
			delete(byVendor, p.ID)
			continue
		}
		out = append(out, p)
	}
	// A vendor with no native collector at all: appended, still in CPA's order.
	for _, base := range order {
		if cp, ok := byVendor[base]; ok {
			out = append(out, cp...)
		}
	}
	return out
}

func safeCollect(id string, fn func() Provider) (p Provider) {
	defer func() {
		if r := recover(); r != nil {
			// Type/message of a panic can quote whatever it was handed, and
			// these collectors handle credentials. Say nothing about it.
			p = Provider{ID: id, OK: false, CapturedAt: now()}
			p.failWith("collector-crashed", "collector-panic")
		}
	}()
	return fn()
}
