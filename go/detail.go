package main

import "strings"

/* ── why a provider has no reading ────────────────────────────────────────
   A failed collector says the same thing twice.

   `detail` on the wire is an English sentence. Everything that reads a
   snapshot without a translation layer — raw JSON, the self-hosted dashboard,
   this helper's own console — needs a line a person can read, and picking one
   language for those is unavoidable.

   `detail_code` (plus at most one argument spliced into it) is that sentence in
   machine form. The panel has locales; handed a code it renders its own
   translation and never shows the English at all. Before the split the
   sentences were written in one language and printed verbatim underneath every
   other one, which is exactly the bug this exists to stop.

   The phrases below are the ONLY place the English is written — call sites
   pass a code, not prose. Two rules follow from a code being a wire value:

     - Keep the set closed and small. Every code costs a `mon.d…` entry in
       monitor.js and a string per locale in translations.js, and an unknown
       code drops the panel back to the English sentence.
     - Never rename one to mean something new. Old helpers keep sending the old
       code for as long as they run, and a rename that changes the meaning is a
       silent mistranslation rather than a missing string.

   detail_test.go fails the build if a code used in this package has no phrase
   here, or if a phrase here is used nowhere. */

// How much of an argument survives. Long enough for a credential path or a
// dial error, short enough that no error line becomes a paragraph.
const detailArgMax = 120

var detailPhrases = map[string]string{
	// A vendor CLI we shell out to. {a} is the command, never the resolved
	// path: an absolute path names the home directory it was found in, and
	// this text travels to the relay.
	"cli-missing": "no usable {a} command was found",
	"cli-timeout": "{a} timed out",
	"cli-failed":  "{a} could not be run",
	"cli-exit":    "{a} exited with a non-zero status",
	"cli-shape":   "{a} answered in a shape this build does not recognize",
	"cli-nolines": "{a} printed no quota line this build recognizes",
	"cli-signin":  "run {a} once to sign in",

	// Credential files the vendor's own tool wrote. {a} is the path for
	// creds-missing and the command to re-run for the rest.
	"creds-missing":   "{a} holds no usable credential",
	"creds-expired":   "the stored credential has expired — run {a} once to renew it",
	"no-subscription": "this GitHub account has no Copilot subscription",

	// Talking to the vendor's endpoint.
	"req-build":     "the request could not be built",
	"req-failed":    "the request did not go through",
	"http-401":      "the endpoint answered 401",
	"http-403":      "the endpoint refused access (403)",
	"http-429":      "the endpoint is rate limiting (429)",
	"http-status":   "the endpoint answered {a}",
	"http-redirect": "the endpoint tried to redirect",
	"http-shape":    "the endpoint answered in a shape this build does not recognize",
	"http-parse":    "the response could not be parsed",
	"rate-hold":     "the quota endpoint is rate limiting; this backs off and retries",

	// The call worked and carried nothing usable.
	"no-window": "no usable quota window came back",
	"no-usage":  "the response carries no usable usage figure",

	// Codex reads session logs off the disk rather than calling anything.
	"no-home":            "this account has no home directory",
	"no-session-dir":     "~/.codex/sessions does not exist — is the Codex CLI installed and signed in?",
	"session-dir-closed": "the sessions directory could not be opened",
	"scan-none":          "the session files carry no quota reading yet",
	"scan-cut":           "the scan was cut short, so this is not a settled no",
	"sessions-linked":    "every one of the {a} session files this opened has more than one name on disk, and this build will not read a file it cannot prove is only itself — something has hard-linked ~/.codex/sessions",
	"latest-no-window":   "the newest record holds no usable quota window",

	// Provider-specific enough to be worth their own line.
	"ls-none":     "no Antigravity language server is listening",
	"ls-no-quota": "the Antigravity language server did not return a quota: {a}",

	// CLI Proxy API (cpa.go). {a} is a field name or a host, never the key.
	"cpa-url":        "MON_CPA_URL is not a valid loopback or HTTPS address, or MON_CPA_KEY is missing",
	"cpa-down":       "no CLI Proxy API answered at the configured address",
	"cpa-key":        "the CLI Proxy API refused the management key",
	"cpa-off":        "the CLI Proxy API's management API is switched off (404)",
	"cpa-shape":      "the CLI Proxy API answered in a shape this build does not recognize",
	"cpa-cred-field": "the credential lists no {a}, which the quota endpoint needs",
	"adapter-host":   "the quota adapter names {a}, which is outside this build's allow-list",

	"collector-panic": "the collector panicked",
}

// The English sentence for a code, with the argument spliced in. An unknown
// code yields nothing rather than a half-written line — the panel still has
// the error code to show, and detail_test.go keeps this from happening.
func detailText(code, arg string) string {
	phrase, ok := detailPhrases[code]
	if !ok {
		return ""
	}
	return strings.ReplaceAll(phrase, "{a}", arg)
}

// What can be spliced into a phrase. This is published, so it is cut by RUNE
// (a byte cut can split a character in half) and stripped of the control
// characters that would otherwise ride into somebody else's DOM.
func detailArgText(s string) string {
	s = strings.TrimSpace(s)
	out := make([]rune, 0, detailArgMax)
	for _, r := range s {
		if len(out) >= detailArgMax {
			break
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			r = ' '
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}

// One failure written into all four fields at once. Collectors call this (via
// their own `fail` closure) instead of assigning Detail by hand, so the
// sentence and the code can never drift apart.
func (p *Provider) failWith(err, code string, arg ...string) {
	a := ""
	if len(arg) > 0 {
		a = detailArgText(arg[0])
	}
	p.Error, p.DetailCode, p.DetailArg = err, code, a
	p.Detail = detailText(code, a)
}
