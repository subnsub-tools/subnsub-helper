package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

// Where warnf writes — which is this machine's own record of what was done to
// it, and the one account of a console command that does not pass through us.
//
// An interface rather than *os.File because on Windows there is nowhere for a
// background process's stderr to go: systemd has the journal and launchd has a
// log, Task Scheduler discards both streams. log_windows.go tees this into a
// file beside the config so the promise console.go makes holds on every
// platform rather than on two of them.
var stderr io.Writer = os.Stderr

const usage = `subnsub-monitor — AI coding quota for machines you can't reach

  subnsub-monitor                        one snapshot as JSON, exit
  subnsub-monitor watch [SEC]            reprint every SEC seconds
  subnsub-monitor serve [PORT]           serve /quota + /events on 127.0.0.1
  subnsub-monitor connect URL [TOKEN]    dial out and push to the relay
  subnsub-monitor unregister URL         archive this installed machine at the relay
  subnsub-monitor name [LABEL]           show or set this machine's dashboard name
  subnsub-monitor console [on|off]       show or set whether the dashboard may run commands here
  subnsub-monitor update [on|off]        show or set whether the dashboard may replace this helper
  subnsub-monitor autoupdate [on|off]    show or set whether this helper replaces itself, hourly, unasked
  subnsub-monitor diagnostics            report whether program names are read here (always, where /proc allows)
  subnsub-monitor autostart              OpenWrt: arrange (or report) starting at boot
  subnsub-monitor spaces [RELAY]         probe the other network namespaces' exits once and print
  subnsub-monitor netns                  say how many network namespaces this machine shows and which one this helper runs in
  subnsub-monitor roads                  measure every way out against the release host once and print
  subnsub-monitor probes [--json]        check the services in probes.json once and print each verdict
  subnsub-monitor metrics [--json]       read metrics.d/, run each command once and print every tile
  subnsub-monitor temps                  print this machine's temperature sensors as JSON
  subnsub-monitor metric set ID VALUE    put your own number on this machine's card (metric rm / ls too)
  subnsub-monitor sessions search TEXT   search this machine's coding-agent sessions
  subnsub-monitor sessions recent        list the newest coding-agent sessions here
  subnsub-monitor sessions open --id ID  print one session's messages, a page at a time
  subnsub-monitor sessions sync [on|off] show or set whether sessions go to the account archive
  subnsub-monitor trust [KEY]            list, or add, a dashboard key allowed to command this machine
  subnsub-monitor untrust KEY            stop accepting commands signed by that key
  subnsub-monitor direct [on|off]        show or set whether a browser may reach this machine directly
  subnsub-monitor allow [KEY]            list, or add, a browser key allowed through the direct tunnel
  subnsub-monitor disallow KEY           stop serving that browser key
  subnsub-monitor address                print this machine's direct address and node key
  subnsub-monitor transfer [on|off]      show or set whether an allowed browser may route one of its
                                         own file transfers through this machine's tunnel
  subnsub-monitor music [on|off|add|...] show or set the music this machine shares with the browsers
                                         on its direct allowlist (tailnet and tailcat only)
  subnsub-monitor clone [use|forget]     show, save, or delete a portable terminal access copy
  subnsub-monitor run MACHINE -- CMD     run a command on a machine using a portable copy
  subnsub-monitor shell MACHINE          open an interactive terminal on a machine using a portable copy
  subnsub-monitor clones [revoke ID]     list or revoke portable copies admitted on this machine
  subnsub-monitor version                print this build's version and exit
  subnsub-monitor selftest               show what the collectors can and cannot open

serve only ever shows you THIS machine. connect is the real shape:
outbound-only, so a browser anywhere can watch a box it has no route to.
The token may also come from SUBNSUB_MONITOR_TOKEN, or from the file the
installer wrote — both keep it out of ps and out of the task's arguments.

Every machine you paste the same token on gets its own dashboard, told apart
by a random id created on first run. Give it a name and the dashboard says
that instead; the name is yours to type and is never taken from the hostname.

console is OFF until you turn it on here, on this machine. With it on, the
dashboard can run a command as this user and show you the output; each command
is its own /bin/sh -c, so nothing persists between them, and every one of them
is written to this machine's own log before it runs. Turn it off with
'console off' and the helper stops asking the relay for work at all.

update is how a helper gets replaced without a shell here. The dashboard says
WHEN; what gets installed comes from the release bucket and is checked against
the published checksum, so the relay cannot point this machine at anything else.
Turning the console on implies it — a console can already run the installer —
and 'update on' is for a machine that wants the button and no console. Nothing
is downloaded until somebody presses it — unless 'autoupdate on' as well: then
this helper looks at the bucket once an hour and installs a newer release by
itself, the same way the button would. autoupdate counts only while update is
on; 'update off' switches the timer off with it.

trust is who may command this machine, as opposed to whether it takes commands
at all. The installer pins the dashboard's public key when you paste its line;
after that, 'trust <key>' adds another (a second browser, a colleague) and
'untrust' removes one. With at least one key pinned, a command must carry a
signature made by the matching private key — which lives in a browser and never
reaches the relay — so a relay can drop or delay a command but cannot write one.
With no key pinned this machine takes the closed-form commands the relay hands
it unsigned — update (if allowed), refresh, inspect, myip — and nothing else: a
shell line never arrives by the relay road at all, sealed lines and tunnel
commands are refused until a key is pinned. Both states are shown on the
dashboard, because they are not equally safe.

diagnostics is on wherever /proc shows other processes (Linux; Android as shell
or root) and is not a switch. It is read-only and independent of the console:
the dashboard may request a bounded top-process resource list, but receives no
command lines, environment, working directories or open files. The helper also
keeps the five busiest program names beside each five-minute bucket of this
machine's own history (30 days, in history.jsonl here), so the CPU chart can
say whose CPU it was. Names only, served over the direct tunnel to browsers you
allowed, never sent to the relay.

On Linux, a machine with other NAMED network namespaces (ip netns add — a VPN
exit on a router, say) gets each one's exit on its card as well: every five
minutes the helper makes one request to the relay from inside each namespace,
and the relay reports the address it saw. The helper itself never moves. It
needs the privilege to enter a namespace (root, in practice) and says nothing
about one it cannot enter. MON_NETNS=off turns it off; MON_NETNS=a,b limits it
to those names.

direct is the road with no relay on it: with it on, a browser holding this
machine's address reaches it through an end-to-end encrypted tunnel that
meets at a DERP relay (Tailscale's public one unless you point it at your own
with MON_DERPMAP), and nothing about this machine is stored anywhere but here
and in that browser. Off by default. Only browsers whose key you 'allow' get
in, the tunnel does not start while none is allowed, and being allowed is a
read-only view. Commands travel this road only from a browser whose key this
machine has pinned, under the same switches as the relay road; the console's
shell lines travel ONLY this road. It runs
beside the relay push when there is a token and alone when there is not;
MON_TRANSPORT=relay or =tailcat forces one or the other. On a machine that is
on a Tailscale network the same view also answers on its Tailscale address, to
a browser on that network whose key is allowed, sealed so the network does not
have to be trusted; MON_TAILNET=off keeps that port closed.

A portable copy is a dashboard's access lent to a command line for a while
(the Monitor page: a machine's terminal → Create a copy). On the computer that
should have it: 'clone use' keeps the copied line, 'run <machine> -- <command>'
runs one console line there and returns its output and exit status, 'shell
<machine>' opens a terminal, 'clone' says what it covers and until when, and
'clone forget' deletes it. A copy reaches machines over tailcat, as the
dashboard's console does, signed with keys of its own; each machine admits it
for console lines and terminals only, and refuses it once it expires. On a
machine, 'clones' lists the copies it admits and 'clones revoke <id>' ends one.

transfer is ON by default once direct is: a browser this machine allows may
invite one other browser, for one file transfer, to meet it here when the two
cannot reach each other — the Transfer tool's last resort. The machine
couples the two streams and forwards bytes it cannot read (they are encrypted
between the browsers); the guest is admitted for that session only and can
reach nothing but the pipe. 'transfer off' refuses new invites at once.

sessions sync is OFF until you turn it on here, and it is the one switch that
sends something OUT rather than answering a question: with it on, this machine's
agent conversations are parsed, redacted and pushed to your account's archive,
where the dashboard can search and read them while this machine is asleep or
gone. It is independent of the console — neither implies the other — and only
the message text travels: no transcript file, no paths, no tool plumbing.
`

func main() {
	// Android first: name resolution and TLS roots have to be arranged before
	// the first request, whichever verb follows (android_linux.go).
	androidInit()
	args := os.Args[1:]
	if len(args) == 0 {
		// The person who ran this is the reader (pace.go): ask the vendors.
		paceAlways()
		fmt.Println(string(dumpIndent(collectAll())))
		return
	}

	switch args[0] {
	case "watch":
		every := 30.0
		if len(args) > 1 {
			if v, err := strconv.ParseFloat(args[1], 64); err == nil {
				// ParseFloat accepts "NaN" and "-1"; both make time.Sleep
				// return immediately and turn this into a hot loop.
				every = clampInterval(v)
			}
		}
		// Same series the daemon pushes, so what `watch` prints is what the
		// relay would receive rather than a second, thinner shape of it.
		paceAlways()
		startSysSampler()
		startProbes()
		startCustom()
		startIPv4()
		for {
			fmt.Println(string(dump(collectAll())))
			time.Sleep(time.Duration(every * float64(time.Second)))
		}

	case "serve":
		port := 8787
		if len(args) > 1 {
			if v, err := strconv.Atoi(args[1]); err == nil {
				port = v
			}
		}
		paceAlways()
		serve(port)

	case "token":
		fmt.Println(newToken())

	case "unregister":
		if len(args) != 2 {
			warnf("usage: subnsub-monitor unregister URL")
			os.Exit(2)
		}
		if err := unregisterMachine(args[1], nil); err != nil {
			warnf("relay was not notified: %v", err)
			os.Exit(1)
		}
		fmt.Println("relay notified")

	case "connect":
		// A router with no service manager learns to start this at boot
		// (autostart.go). Every daemon start, so an auto-update carries it.
		startAutostart()
		if len(args) < 2 {
			fmt.Print(usage)
			os.Exit(2)
		}
		// The adapter table looks after itself for the life of the daemon;
		// see adapterfeed.go for why a timer is right here and wrong for
		// binaries.
		startAdapterFeed(context.Background())
		// A fork that never reached exec spins on a core until something
		// kills it — macOS only; the other builds' version is a no-op
		// (reaper_darwin.go).
		startForkReaper()
		token := os.Getenv(tokenEnv)
		if token == "" && len(args) >= 3 {
			token = args[2]
		}
		if token == "" {
			// The file the installer wrote, which on Windows is the ordinary
			// path rather than a fallback: Task Scheduler runs a program with
			// arguments and carries no environment, and the two places a token
			// could otherwise go there — the command line, or the user's
			// persistent environment — are both readable by every other program
			// that user runs. See installedEnv.
			token = installedEnv()[tokenEnv]
		}
		if token == "" {
			// No relay credential, but a tunnel switched on: that is direct
			// mode's whole shape, and the daemon runs the tunnel alone. The
			// unit file says `connect <relay>` either way, so an install that
			// later gains a token needs no rewrite.
			if directEnabled() && transportMode() != "relay" {
				startAutoUpdate()
				// No relay push collects on this road, so the archive keeps
				// itself on the push's own clock (direct.go).
				go directRecordLoop(context.Background())
				runDirect(context.Background())
				return
			}
			warnf("no token: pass one, or set SUBNSUB_MONITOR_TOKEN (or turn direct mode on)")
			os.Exit(2)
		}
		if transportMode() == "tailcat" {
			// Forced tunnel-only: the token stays where it is and is simply
			// not used this run. A migration knob, not a setting.
			if !directEnabled() {
				warnf("MON_TRANSPORT=tailcat but direct mode is off; nothing to run")
				os.Exit(2)
			}
			startAutoUpdate()
			runDirect(context.Background())
			return
		}
		// A token renewed on an earlier run outlives that run. The installed one
		// is the bootstrap and stays where the service manager put it; whichever
		// of the two lasts longer is the one to push with, which is also what
		// lets a reinstall override a renewal rather than be ignored by it.
		//
		// Scoped to the relay being dialled, and only consulted for a relay we
		// could have renewed for: `connect` takes any URL, and a credential
		// obtained for one relay must not be presented to another.
		// No interval argument: the cadence is the relay's (transport.go).
		connect(args[1], resolveStartToken(args[1], token))

	case "name":
		if len(args) > 1 {
			if err := setLabel(args[1]); err != nil {
				warnf("could not save the name")
				os.Exit(1)
			}
		}
		// Printed from the loader rather than from the argument, so what you
		// see is what the dashboard will show after cleaning — a name that got
		// trimmed should say so here, not surprise you on the page.
		if label := agentLabel(); label != "" {
			fmt.Printf("%s  (%s)\n", label, agentID())
		} else {
			fmt.Printf("unnamed  (%s)\n", agentID())
		}

	case "console":
		if len(args) > 1 && args[1] == "relay" {
			// The spare road (econ.go) follows the console's own switch since
			// 2026.10.11.6; the dashboard decides per machine whether to take
			// it. This subcommand only reports.
			if len(args) > 2 {
				warnf("the relay road follows 'console on|off' and is taken or not from the dashboard; there is nothing to set here")
			}
			if consoleRelayEnabled() {
				fmt.Printf("relay on   (%s)\n", agentID())
				if !consoleEnabled() {
					fmt.Println("note: the console itself is off; 'console on' before any line can arrive.")
				}
				if !loadTrust().sealed {
					fmt.Println("note: no dashboard key is pinned here, so the road is not offered: a sealed line\n" +
						"      has to come from a browser this machine trusts. Run the install line from the page.")
				}
			} else {
				fmt.Printf("relay off  (%s)\n", agentID())
			}
			return
		}
		if len(args) > 1 {
			on := args[1] == "on" || args[1] == "1" || args[1] == "true" || args[1] == "yes"
			off := args[1] == "off" || args[1] == "0" || args[1] == "false" || args[1] == "no"
			if !on && !off {
				// Not guessed. "console maybe" turning it ON because the word
				// was not "off" is the failure mode this whole file is built
				// to avoid.
				warnf("say 'console on' or 'console off'")
				os.Exit(2)
			}
			if err := setConsole(on); err != nil {
				warnf("could not change the console setting")
				os.Exit(1)
			}
		}
		// Printed from the same reader the loop consults, so what you see is
		// what the running helper will do — including the case where MON_CONSOLE
		// in the environment overrides the file you just wrote.
		on := consoleEnabled()
		if on {
			fmt.Printf("on   (%s)\n", agentID())
		} else {
			fmt.Printf("off  (%s)\n", agentID())
		}
		// The unit's sandbox was decided at install time and this switch cannot
		// change it. Saying so here is the difference between a console that
		// obviously needs one more step and one that appears to work until the
		// first command that writes something.
		if note := consoleSandboxNote(on); note != "" {
			fmt.Println(note)
		}
		// The console rides the direct tunnel alone, so the one setting that
		// keeps the tunnel down keeps the console shut too.
		if on && transportMode() == "relay" {
			fmt.Println("note: MON_TRANSPORT=relay keeps the direct tunnel down, and the console\n" +
				"      runs only over it, so no command can reach this machine.")
		}

	case "update":
		if len(args) > 1 {
			on := args[1] == "on" || args[1] == "1" || args[1] == "true" || args[1] == "yes"
			off := args[1] == "off" || args[1] == "0" || args[1] == "false" || args[1] == "no"
			if !on && !off {
				// Not guessed, for the same reason `console` does not guess.
				warnf("say 'update on' or 'update off'")
				os.Exit(2)
			}
			if err := setRemoteUpdate(on); err != nil {
				warnf("could not change the update setting")
				os.Exit(1)
			}
		}
		// From the same reader the loop consults, so what is printed is what
		// the running helper will do — including the two cases where the answer
		// does not come from the file just written: MON_UPDATE in the
		// environment, and a console that is on and therefore already grants
		// this.
		on := updateAllowed()
		if on {
			fmt.Printf("on   (%s)\n", agentID())
			if consoleEnabled() {
				fmt.Println("note: the console is on, which allows this on its own —\n" +
					"      a console can already run the installer. 'update off' will not\n" +
					"      take that away; 'console off' is what does.")
			}
		} else {
			fmt.Printf("off  (%s)\n", agentID())
		}
		// The unit's sandbox was decided at install time and this switch cannot
		// change it, exactly as with the console.
		if note := updateSandboxNote(on); note != "" {
			fmt.Println(note)
		}

	case "autoupdate":
		if len(args) > 1 {
			on := args[1] == "on" || args[1] == "1" || args[1] == "true" || args[1] == "yes"
			off := args[1] == "off" || args[1] == "0" || args[1] == "false" || args[1] == "no"
			if !on && !off {
				warnf("say 'autoupdate on' or 'autoupdate off'")
				os.Exit(2)
			}
			if err := setAutoUpdate(on); err != nil {
				warnf("could not change the autoupdate setting")
				os.Exit(1)
			}
		}
		// From the same reader the timer consults: the file just written
		// says nothing on a machine where update is off, and this says so.
		if autoUpdateEnabled() {
			fmt.Printf("on   (%s)\n", agentID())
		} else {
			fmt.Printf("off  (%s)\n", agentID())
			if !updateAllowed() {
				fmt.Println("note: remote updates are off here, and the timer counts only with them on —\n" +
					"      'update on' (or 'console on') first.")
			}
		}
		if note := updateSandboxNote(autoUpdateEnabled()); note != "" {
			fmt.Println(note)
		}

	case "spaces":
		// The daemon's five-minute pass, once, in the open: which namespaces
		// were found, which could be entered, what the relay answered. The
		// token is found the way connect finds it.
		relay := officialRelay
		if len(args) >= 2 {
			relay = args[1]
		}
		token := os.Getenv(tokenEnv)
		if token == "" {
			token = installedEnv()[tokenEnv]
		}
		token = resolveStartToken(relay, token)
		found := spacesFound()
		fmt.Printf("namespaces found: %v (in %v)\n", found, spacesDirs)
		fmt.Printf("to probe:         %v\n", spacesPick(found))
		if token == "" {
			fmt.Println("no relay token: cannot ask the relay who it sees (set SUBNSUB_MONITOR_TOKEN, or install)")
			os.Exit(2)
		}
		if spacesPass(relay, token) {
			fmt.Println("the relay has no /whoami: nothing to report from any namespace")
			os.Exit(1)
		}
		for _, sp := range spacesSnapshot() {
			stamp := sp.Stamp
			if len(stamp) > 24 {
				stamp = stamp[:24] + "… (" + strconv.Itoa(len(sp.Stamp)) + " bytes, opened by the relay)"
			}
			rtt := "-"
			if sp.RTTMs != nil {
				rtt = fmt.Sprintf("%.0f ms", *sp.RTTMs)
			}
			fmt.Printf("  %-16s ok=%-5v rtt=%-8s error=%-12q stamp=%s\n", sp.Name, sp.OK, rtt, sp.Error, stamp)
		}
		if len(spacesSnapshot()) == 0 {
			fmt.Println("  (none reported: nothing found, or none could be entered — that needs root)")
		}

	case "autostart":
		// Said out loud, and done even when MON_AUTOSTART=off: that switch
		// stops the helper doing this UNASKED, and this is being asked.
		_, note := ensureAutostart()
		fmt.Println(note)

	case "diagnostics":
		// Not a switch any more: `on` is what it already is, `off` is
		// refused out loud so an old script or note does not believe it
		// did something.
		if len(args) > 1 && (args[1] == "off" || args[1] == "0" || args[1] == "false" || args[1] == "no") {
			warnf("diagnostics cannot be turned off: program names are read wherever /proc shows other processes")
			os.Exit(1)
		}
		if !diagnosticsAvailable() {
			fmt.Printf("unsupported  (%s)\n", agentID())
		} else {
			fmt.Printf("on   (%s)\n", agentID())
		}

	case "netns":
		fmt.Println(netnsSay())

	case "roads":
		// Every way out — own namespace and each named one — against the
		// release host: first byte, rate, and which the updater would take.
		list := roadsPass(updateBaseURL())
		if len(list) == 0 {
			fmt.Println("no road could be measured")
			os.Exit(1)
		}
		pick := roadsRanked()
		for _, r := range list {
			ttfb, rate := "-", "-"
			if r.TTFBMs != nil {
				ttfb = fmt.Sprintf("%.0f ms", *r.TTFBMs)
			}
			if r.KBps != nil {
				rate = fmt.Sprintf("%.0f KiB/s", *r.KBps)
			}
			mark := ""
			if len(pick) > 0 && pick[0] == r.Name {
				mark = "  ← updates"
			}
			fmt.Printf("  %-18s ok=%-5v first-byte=%-9s rate=%-12s error=%q%s\n", roadLabel(r.Name), r.OK, ttfb, rate, r.Error, mark)
		}

	case "trust":
		// Granting authority is a thing you do AT the machine, like every other
		// switch here. There is deliberately no way to add a key over the
		// network: an endpoint that could would hand back the property this
		// whole mechanism buys.
		if len(args) < 2 {
			t := loadTrust()
			keys := t.keys
			if len(keys) == 0 {
				if t.sealed {
					// Not the same sentence as "nothing pinned", because this
					// machine is refusing every command right now and the reason
					// is a file somebody can look at.
					fmt.Printf("a trusted-keys file exists but holds no usable key,\n"+
						"so EVERY command is being refused. Fix or remove %s\n", trustedKeysPath())
					break
				}
				fmt.Println("no keys trusted — this machine runs what the relay hands it")
				break
			}
			fmt.Printf("%d key(s) trusted; commands must be signed by one of them\n", len(keys))
			for _, k := range keys {
				fmt.Println("  " + base64.StdEncoding.EncodeToString(k))
			}
			break
		}
		if err := trustKey(args[1]); err != nil {
			warnf("could not trust that key: %v", err)
			os.Exit(1)
		}
		fmt.Printf("trusted; this machine now runs only commands signed by a trusted key (%s)\n", agentID())

	case "untrust":
		if len(args) < 2 {
			warnf("say 'untrust <key>' — 'trust' with no argument lists them")
			os.Exit(2)
		}
		if err := untrustKey(args[1]); err != nil {
			warnf("could not remove that key: %v", err)
			os.Exit(1)
		}
		if !loadTrust().sealed {
			fmt.Println("removed; NO keys are trusted now — this machine runs what the relay hands it")
		} else {
			fmt.Println("removed")
		}

	case "direct":
		os.Exit(runDirectCLI(args[1:]))

	case "allow":
		os.Exit(runAllowCLI(args[1:]))

	case "disallow":
		os.Exit(runDisallowCLI(args[1:]))

	case "address":
		os.Exit(runAddressCLI())

	case "clones":
		os.Exit(runClonesCLI(args[1:]))

	case "clone":
		os.Exit(runCloneCLI(args[1:]))

	case "run":
		os.Exit(runRunCLI(args[1:]))

	case "shell":
		os.Exit(runShellCLI(args[1:]))

	case "transfer":
		os.Exit(runTransferCLI(args[1:]))

	case "music":
		os.Exit(runMusicCLI(args[1:]))

	case "probes":
		os.Exit(runProbesCLI(args[1:]))

	case "metrics":
		os.Exit(runMetricsCLI(args[1:]))

	case "metric":
		os.Exit(runMetricCLI(args[1:]))

	case "sessions":
		// The dashboard's fleet search and its session reader, answered
		// locally. `sessions search` reads the coding agents' own transcript
		// files under this account and prints matched snippets; `recent` lists
		// the newest transcripts; `open` prints one bounded page of a single
		// transcript's messages; `where` names the directory one ran in, so
		// the dashboard's terminal can resume it there. No index is
		// built, no daemon starts, nothing is downloaded, and no byte of any
		// transcript leaves this process except what these verbs print. Which
		// tools are read is sessionsources.go's list, every one a local
		// transcript tree this machine already has.
		if len(args) >= 2 {
			switch args[1] {
			case "search":
				os.Exit(runSessionsSearchCLI(args[2:]))
			case "recent":
				os.Exit(runSessionsRecentCLI(args[2:]))
			case "open":
				os.Exit(runSessionsOpenCLI(args[2:]))
			case "where":
				os.Exit(runSessionsWhereCLI(args[2:]))
			case "sync":
				os.Exit(runSessionsSyncCLI(args[2:]))
			}
		}
		warnf("usage: subnsub-monitor sessions search [--limit N] [--json] [--project NAME] [--since WHEN] [--until WHEN] [--] TEXT...")
		warnf("       subnsub-monitor sessions recent [--limit N] [--json] [--project NAME] [--since WHEN] [--until WHEN]")
		warnf("       (WHEN is 7d, 24h, 30m, 4w, 2026-08-01 or a full RFC3339 stamp; both bound the session's LAST activity)")
		warnf("       search also takes --term TEXT (a phrase, spaces and all), --not TEXT (must NOT appear),")
		warnf("       --re PATTERN and --not-re PATTERN; all repeatable, all case-insensitive")
		warnf("       and --role user|assistant|tool, which narrows to who said it (search only —")
		warnf("       every session holds a user message, so a LISTING narrowed by role is not narrowed)")
		warnf("       subnsub-monitor sessions open --id ID [--around N | --before N | --after N] [--json]")
		warnf("       subnsub-monitor sessions where --id ID [--json]   (the directory it ran in, to resume it there)")
		warnf("       subnsub-monitor sessions sync [on|off] [--dry-run] [--json]")
		warnf("(reads the coding-agent sessions on this machine; the dashboard's fleet search runs the same verbs)")
		os.Exit(2)

	case "temps":
		// Nothing but the rows: on macOS the collector runs this and parses
		// what it prints (mactemps.go). Never null — an empty list is a
		// machine with no sensors, and nothing at all is a child that died.
		rows := localTemps()
		if rows == nil {
			rows = []Temp{}
		}
		if len(rows) > maxTempRowsIn {
			rows = rows[:maxTempRowsIn]
		}
		b, err := json.Marshal(rows)
		if err != nil {
			os.Exit(1)
		}
		fmt.Println(string(b))

	case "version":
		// Deliberately nothing but the version, on one line. The update path
		// runs this on a freshly downloaded binary and compares the output
		// against what the release claimed to be — a banner, a warning, or a
		// trailing note would all have to be parsed around, and every one of
		// those is a way for the check to start passing by accident.
		fmt.Println(helperVersion)

	case "selftest":
		selftest()

	case "-h", "--help", "help":
		fmt.Print(usage)

	default:
		fmt.Print(usage)
		os.Exit(2)
	}
}

// A token is a bearer secret: whoever holds it can push readings and read
// them. Long, from a CSPRNG, in the relay's accepted alphabet.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not something to paper over with a weaker
		// source — a predictable token is worse than no token.
		warnf("cannot generate a token: system RNG unavailable")
		os.Exit(1)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
