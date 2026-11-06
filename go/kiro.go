package main

// Kiro: quota via the vendor's own CLI, Amp's cost rung exactly.
//
// kiro-cli answers a non-interactive usage question in plain text (verified
// against the real CLI on this machine, not just against CodexBar's parser):
//
//	$ kiro-cli chat --no-interactive /usage
//	Estimated Usage | resets on 2026-09-01 | KIRO FREE
//	Credits (0.00 of 50 covered in plan)
//	████████████████████ 0%
//	Overages: Disabled
//
// Newer CLIs open with a summary line instead — "Plan: KIRO PRO MAX | 1
// usage breakdowns" — and a managed plan may print nothing but that: a
// reading with the plan and no gauge, which is what it says (CodexBar
// KiroStatusProbe, steipete/CodexBar@28b8dcbe8d). "Credits used: N" under
// an "Overages:" line is overage spend, not the plan's usage, and is not
// read as the plan's (same probe: overageCreditsUsed).
//
// No credential is opened or held — kiro-cli talks to its own service with
// its own login. Same parsing philosophy as amp.go: every pattern is anchored
// and literal-prefixed, spacing is [ \t] never \s, numbers carry the grouping
// grammar, and a line that stops matching contributes nothing rather than a
// wrong number.
//
// OFFLINE, THE CLI IS NOT RUN. On a network without internet kiro-cli does not
// fail: it opens Kiro's and Google's sign-in pages in the browser, and this
// collector asks on every push it is due — a desktop would collect a tab per
// attempt. --no-interactive turns off the chat loop, not that sign-in. So the
// usage host is asked first, unauthenticated and bodiless (HEAD, four
// seconds); any HTTP answer at all says the network is there, and a transport
// failure skips the run, leaving the last reading standing as provCache does
// for any failure (CodexBar KiroUsageLimitsAPI.ensureReachable,
// steipete/CodexBar@49e7581587). CodexBar asks only on background refreshes
// and reads the profile's region from kiro-cli's private SQLite state; every
// collection here is unattended, so it is always asked, and the state
// database is never opened: the two regions' hosts CodexBar knows (us-east-1
// and eu-central-1) are asked at once and either answering is enough, so a
// network that lets only one of them through does not stop a working CLI
// (review 2026-10-24). Any answer counts, a redirect included — it is
// answered, not followed.

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	kiroBinEnv       = "MON_KIRO_BIN"
	kiroReachTimeout = 4 * time.Second
)

// The usage hosts of the two regions CodexBar knows, us-east-1 first, its
// default when the region is unknown (KiroUsageLimitsAPI.profileEndpoints).
var kiroReachURLs = []string{
	"https://codewhisperer.us-east-1.amazonaws.com/",
	"https://q.eu-central-1.amazonaws.com/",
}

// Whether Kiro's service answers at all. A variable so a test can say no
// without a network.
var kiroReachable = func() bool { return kiroAnswers(kiroReachURLs, kiroReachTimeout) }

// kiroAnswers asks each URL at once, unauthenticated and bodiless, through
// the environment's proxy as every provider request goes; true as soon as
// one answers with any HTTP status.
func kiroAnswers(urls []string, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	got := make(chan bool, len(urls))
	for _, u := range urls {
		go func(u string) {
			req, err := http.NewRequest(http.MethodHead, u, nil)
			if err != nil {
				got <- false
				return
			}
			req.Header.Set("User-Agent", "subnsub-helper")
			resp, err := client.Do(req)
			if err != nil {
				got <- false
				return
			}
			resp.Body.Close()
			got <- true
		}(u)
	}
	for range urls {
		if <-got {
			return true
		}
	}
	return false
}

var kiroCache = provCache{pace: paceMark{id: "kiro"}}

func collectKiro() Provider {
	return kiroCache.collect(fetchKiro)
}

var (
	// "Estimated Usage | resets on 2026-09-01 | KIRO FREE" — the reset date is
	// either yyyy-MM-dd or a bare MM/DD (older CLI), and the plan is whatever
	// sits after the last pipe.
	kiroResetRE = regexp.MustCompile(`(?i)resets on[ \t]+(\d{4}-\d{2}-\d{2}|\d{2}/\d{2})`)
	kiroHeadRE  = regexp.MustCompile(`(?im)^[ \t]*Estimated Usage[ \t]*\|[^\r\n|]*\|[ \t]*([A-Za-z][A-Za-z0-9 ]+?)[ \t]*$`)
	// "Plan: KIRO PRO MAX | 1 usage breakdowns" — the summary line, whose
	// plan stops at the pipe and is shouted like the header's.
	kiroSummaryRE = regexp.MustCompile(`(?im)^[ \t]*Plan:[ \t]*([^|\r\n]+?)[ \t]*\|[ \t]*[0-9]+[ \t]+usage breakdowns?[ \t]*$`)
	// "Plan: Q Developer Pro" — the shape CodexBar records for paid seats.
	kiroPlanRE = regexp.MustCompile(`(?im)^[ \t]*Plan:[ \t]*([^|\r\n]+?)[ \t]*$`)
	// "Credits (0.00 of 50 covered in plan)" — anchored to the Credits label
	// (allowing the box-drawing/whitespace the CLI pads with) so a stray
	// "(N of M …)" elsewhere in the output cannot be mistaken for it.
	kiroCreditsOfRE = regexp.MustCompile(`(?im)^[ \t│┃]*Credits\b[^\r\n(]*\([ \t]*` + amount + `[ \t]+of[ \t]+` + amount + `[ \t]+covered`)
	// The gauge line: a run of block characters followed by "N%". Requiring
	// the bar to be a RUN (2+) and to sit at the line start keeps a lone
	// glyph in a download/spinner from being read as a quota gauge.
	kiroPctRE       = regexp.MustCompile(`(?im)^[ \t│┃]*[█▉▊▋▌▍▎▏]{2,}[ \t]*(\d+)[ \t]*%`)
	kiroSignedOutRE = regexp.MustCompile(`(?i)not (?:signed|logged) in|login required|failed to initialize auth portal|kiro-cli login|oauth error`)
)

// A Kiro reset date: yyyy-MM-dd read as local midnight, or a bare MM/DD taken
// as this year unless that is already past, then next year — the CLI's own
// convention (KiroStatusProbe rolls MM/DD forward). Local, not UTC: the CLI
// prints a local date and a UTC reading would be off by up to a day.
func kiroReset(s string) *float64 {
	if len(s) == 10 {
		if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
			return fp(float64(t.Unix()))
		}
		return nil
	}
	// MM/DD
	moStr, dStr, ok := strings.Cut(s, "/")
	if !ok {
		return nil
	}
	mo, e1 := strconv.Atoi(moStr)
	d, e2 := strconv.Atoi(dStr)
	if e1 != nil || e2 != nil || mo < 1 || mo > 12 || d < 1 || d > 31 {
		return nil
	}
	nowT := time.Now()
	t := time.Date(nowT.Year(), time.Month(mo), d, 0, 0, 0, 0, time.Local)
	// time.Date normalises 02/31 to March 3 rather than rejecting it; a date
	// that changed under construction was never a real date.
	if int(t.Month()) != mo || t.Day() != d {
		return nil
	}
	if t.Before(nowT) {
		t = t.AddDate(1, 0, 0)
	}
	return fp(float64(t.Unix()))
}

// The window behind a reset date: the calendar month that ends on it, in
// minutes. Kiro's credits are monthly and the CLI prints only the day they
// return, which CodexBar reads as a monthly window paced over the calendar
// month (KiroStatusProbe's monthlyWindowSentinelMinutes and
// KiroProviderDescriptor's calendarMonthResetWindow, steipete/CodexBar@3386b0ad).
// Without a length the page would walk a reset already behind us forward a
// DAY at a time and could draw no pace mark. The month begins on the same
// day of the month before, or that month's last day when it has no such
// day (Mar 31 began Feb 28 — ampRenewal's rule, run backwards), and its
// length is the real elapsed time, in the zone kiroReset read the date in.
// No reset, no window.
func kiroMonthWindow(reset *float64) *float64 {
	if reset == nil || !finite(*reset) {
		return nil
	}
	end := time.Unix(int64(*reset), 0).In(time.Local)
	y, mo, d := end.Date()
	first := time.Date(y, mo-1, 1, 0, 0, 0, 0, time.Local)
	if last := first.AddDate(0, 1, -1).Day(); d > last {
		d = last
	}
	start := time.Date(first.Year(), first.Month(), d, end.Hour(), end.Minute(), end.Second(), 0, time.Local)
	mins := end.Sub(start).Minutes()
	if mins <= 0 || !finite(mins) {
		return nil
	}
	return fp(round2(mins))
}

func fetchKiro() Provider {
	p := Provider{ID: "kiro", Name: "Kiro", Source: "cli", CapturedAt: now()}
	fail := func(err, code string, arg ...string) Provider {
		p.failWith(err, code, arg...)
		return p
	}

	bin := vendorBinary(kiroBinEnv, vendorCandidates("kiro-cli"))
	if bin == "" {
		return fail("not-installed", "cli-missing", "kiro-cli")
	}
	if !kiroReachable() {
		return fail("unreachable", "req-failed")
	}
	out, exited, err := runVendorCLI(bin, []string{"chat", "--no-interactive", "/usage"},
		[]string{"KIRO_", "AWS_", "Q_"}, 30*time.Second)
	if err != nil {
		if err == errAmpTimeout {
			return fail("unreachable", "cli-timeout", "kiro-cli")
		}
		return fail("cli-failed", "cli-failed", "kiro-cli")
	}
	return parseKiroUsage(p, out, exited)
}

// What the CLI printed, read into a Provider — split from fetchKiro so the
// shapes can be tested without a CLI.
func parseKiroUsage(p Provider, out string, exited bool) Provider {
	fail := func(err, code string, arg ...string) Provider {
		p.failWith(err, code, arg...)
		return p
	}
	text := ansiRE.ReplaceAllString(out, "")

	var resets *float64
	if m := kiroResetRE.FindStringSubmatch(text); m != nil {
		resets = kiroReset(m[1])
	}
	var plan string
	summary := false
	if m := kiroHeadRE.FindStringSubmatch(text); m != nil {
		plan = kiroDisplayPlan(m[1])
	}
	if m := kiroSummaryRE.FindStringSubmatch(text); m != nil {
		summary = true
		if plan == "" {
			plan = kiroDisplayPlan(m[1])
		}
	}
	if plan == "" {
		if m := kiroPlanRE.FindStringSubmatch(text); m != nil {
			plan = tame(m[1], 32)
		}
	}

	// used% comes from the "N of M covered" line when present (exact), else
	// from the gauge bar's own percent. The two agree; the credits line is
	// preferred because it also yields the balance.
	var pct *float64
	var balance string
	if m := kiroCreditsOfRE.FindStringSubmatch(text); m != nil {
		used, ok1 := ampNum(m[1])
		total, ok2 := ampNum(m[2])
		if ok1 && ok2 && total > 0 {
			v := used / total * 100
			if v < 0 {
				v = 0
			}
			if v > 100 {
				v = 100
			}
			pct = fp(round2(v))
			rem := total - used
			if rem < 0 {
				rem = 0
			}
			balance = trimAmount(rem) + " / " + trimAmount(total)
		}
	}
	if pct == nil {
		if m := kiroPctRE.FindStringSubmatch(text); m != nil {
			if v, ok := ampNum(m[1]); ok && v >= 0 && v <= 100 {
				pct = fp(round2(v))
			}
		}
	}
	if pct != nil {
		p.Limits = append(p.Limits, Limit{
			Key: "credits", UsedPercent: *pct,
			WindowLabel: sp("plan"), WindowMinutes: kiroMonthWindow(resets), ResetsAt: resets,
		})
		if balance != "" {
			p.Credits = &Credits{HasCredits: true, Balance: balance}
		}
	}

	if len(p.Limits) == 0 && p.Credits == nil {
		switch {
		case kiroSignedOutRE.MatchString(text):
			return fail("not-signed-in", "cli-signin", "kiro-cli login")
		case exited:
			return fail("cli-failed", "cli-exit", "kiro-cli")
		case summary && plan != "":
			// The summary line with no gauge under it: a managed plan the
			// CLI has no usage for. The plan is the reading — not a 0%.
		default:
			return fail("no-readings", "cli-nolines", "kiro-cli")
		}
	}

	p.OK = true
	p.RecordedAt = fp(now())
	if plan != "" {
		p.PlanType = sp(plan)
	}
	return p
}

// "KIRO FREE" -> "Kiro Free": title-case the shouty plan name the CLI prints,
// matching KiroStatusProbe.displayPlanName.
func kiroDisplayPlan(s string) string {
	s = tame(s, 32)
	if s == "" {
		return ""
	}
	words := strings.Fields(strings.ToLower(s))
	for i, w := range words {
		if w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
