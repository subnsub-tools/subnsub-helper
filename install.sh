#!/bin/sh
# subnsub-monitor installer.
#
#   curl -fsSL https://tools.subnsub.com/monitor/install.sh | sh -s -- <TOKEN>
#
# Paste the same token on every machine you want to watch — each one gets its
# own dashboard, told apart by a random id it creates on first run. To name
# one, add it after the token (or set MON_NAME):
#
#   curl -fsSL .../install.sh | sh -s -- <TOKEN> --name "tokyo build box"
#
# The dashboard can also run commands on a machine, and that is OFF unless you
# ask for it right here — add --console, or turn it on later with
# `subnsub-monitor console on`. With it on, this machine runs what you type on
# the dashboard, as this user, and writes every command to its own log first.
# Those commands never pass through the relay: they come only through the
# end-to-end encrypted tunnel (see DIRECT MODE below), and only from a browser
# whose key this machine has pinned — the install line copied from your
# account's dashboard carries one.
#
# And it can update the helper for you, so a new release does not mean logging
# into every box. Also off by default: add --remote-update, or turn it on later
# with `subnsub-monitor update on`. --console implies it — a console can
# already run this installer. Nothing is downloaded until you press the button,
# and what gets installed comes from the release bucket and is checked against
# its published checksum, so the dashboard chooses only WHEN.
#
# Or let the helper press it: add --auto-update (or `subnsub-monitor autoupdate
# on` later) and it looks at the bucket once an hour and installs a newer
# release by itself. That switch counts only with remote updates on.
#
# Read-only host details — a top-process table on the card, and beside each
# five-minute bucket of the CPU history the names of the programs that used
# it — are always on where /proc shows other processes (Linux; Android as
# shell or root). Names only, no shell (go/inspect.go, prochist.go).
# --diagnostics is still accepted for compatibility and
# changes nothing.
#
# The dashboard can also SEARCH this machine's coding-agent sessions — a
# built-in part of the helper, nothing extra to install. The search runs over
# the console channel, so it reaches this machine only when --console is on;
# it reads the agents' own transcript files right where they are, and only
# matching snippets and the pages you open ever leave the machine.
#
# And it can keep them, so a machine that is asleep — or gone — still answers.
# That one is off unless you ask: add --sessions-sync, or turn it on later with
# `subnsub-monitor sessions sync on`. With it on, this machine parses its own
# transcripts, redacts them, and pushes the message text to YOUR account's
# archive over the same connection it already uses. It needs no console and
# implies none; it is the one switch here that sends something out rather than
# answering a question, which is why it has a switch of its own.
#
# DIRECT MODE — no account, no relay, no token. Add --direct and one or more
# --allow <nodekey:…> (the browser keys shown on the Monitor page), and the
# helper opens an end-to-end encrypted tunnel that the page reaches through
# a DERP relay — Tailscale's public tailcat relay unless you point it at your
# own with --derpmap <https URL>. Nothing about the machine is stored anywhere
# but here and in that browser; the page is a static display. Without a
# dashboard key pinned it is read-only: a command travels this tunnel only
# from a browser whose key the machine has pinned (MON_PUBKEY), which a
# --direct line alone does not do. A token may still be given beside it, in
# which case both run — and then this tunnel is the one road the console
# takes, since no command ever travels through the relay.
#
#   curl -fsSL .../install.sh | sh -s -- --direct --allow nodekey:…
#
# The self-hosted page's line adds --pair <token>: a one-time identity that
# page made for this machine, so it can find the machine without anybody
# carrying its address back. The helper waits under that identity, for that
# one browser key, and hands it this machine's own address over the
# encrypted tunnel; then the pairing is deleted (and after a week regardless).
# The machine's own key and address are made here as always and never travel
# in a line. Until the pairing is done, treat the line like a password: whoever
# runs it first is the machine that page will show.
#
# Source: https://github.com/subnsub-tools/subnsub-monitor (Apache-2.0)
#
# …and if you would rather look first, which is the reasonable instinct for
# anything that installs a background process:
#
#   curl -fsSL https://tools.subnsub.com/monitor/install.sh -o install.sh
#   less install.sh && sh install.sh <TOKEN>
#
# Installs a single static binary to ~/.local/bin and registers it to run at
# login — systemd user unit on Linux, LaunchAgent on macOS. No sudo, nothing
# written outside your home directory.
#
# ANDROID is not installed with this line. Run in a Termux session the helper
# is an app, and Android lets an app see much less of the machine than Linux
# does — no CPU percentage, load, disk throughput, network counters, process
# count or temperature, all refused by the platform's own policy. This script
# stops on Android and says where to go instead, which is the Monitor page on
# a computer — it installs the helper on a phone over USB and starts it as the
# shell user, which reads all of it. A helper installed under Termux earlier
# keeps running, and --uninstall still removes it (it is handled before the
# platform is looked at).
#
# Uninstall:  sh install.sh --uninstall
set -eu

RELAY="${MON_RELAY:-https://monitor.subnsub.com}"
# The dashboard key allowed to command this machine, if the line you copied
# carries one. It is a PUBLIC key: the private half never leaves the browser
# that made it, and the relay never sees either. Pinning it here is what lets
# that browser open the console over the encrypted tunnel at all — a machine
# with nothing pinned takes no command over it, and none ever comes through
# the relay — and what makes the requests the relay does carry (an update, a
# new name) ones it cannot forge. See go/signing.go.
PUBKEY="${MON_PUBKEY:-}"
BASE="${MON_BASE:-https://tools.subnsub.com/monitor}"   # where the binaries live
NAME=subnsub-monitor
BINDIR="${MON_BINDIR:-$HOME/.local/bin}"
LABEL=com.subnsub.monitor   # shows up in `launchctl list`; brand domain there too

# Expected SHA-256 of each published binary, baked in.
#
# This is the whole point of the script being readable before you run it. A
# checksum fetched from the same host the binary came from proves nothing —
# whoever can swap one can swap both. These live here, in the file you were
# invited to read, and are regenerated alongside each upload by the release
# script that publishes the binaries. A binary that does not match is not installed, and a swapped binary
# would otherwise be free to read ~/.claude/.credentials.json and post it
# somewhere, which no amount of care in the Go source can prevent.
SUM_linux_amd64=0763401484b27a67cedee5733a37e4809dc6e05e48eca5a0ccd1bccd2f837c8e
SUM_linux_arm64=656f92e32c0e17117296ea52226a983288cc37c8e0ee5ee1e423f9ee89cea561
SUM_linux_arm=3ff7fed1a471a80c60840879956de4a941bff41155dea471ad8aec4fb9c06b7b
SUM_darwin_amd64=3a80e3d2e7fbcb07cc8288057ab9f1c78760093ff1ada9a3fb68d76746f5c7e5
SUM_darwin_arm64=a90ad7c3834b6fbc9bd5bc1a9bd9c6b9daba8dbc8fc5062b5d65ac05466222db
SUM_freebsd_amd64=041b7a826ce89ccb18b227a63ed517ccb71422c083a6937924223d10cf2bdb73
SUM_freebsd_arm64=f57bd90b16201006490d09434a6726b640e0f0a7530c60022641c5b8758502c7
SUM_android_arm64=7b482c0c5d18169c851bc8a8946469f74f67bb81a3f9a25d5c867bba2269b1fa

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# Quote a value so a shell can read it back as exactly this string.
#
# The keeper script below is GENERATED, and $HOME and MON_BINDIR are not
# character-restricted anywhere — a path holding a quote, a backtick or a $()
# would otherwise be re-parsed as syntax, or as a command, the next time that
# script runs. Single quotes take everything literally, and the sed is the one
# case they cannot cover: a literal ' is closed, escaped and reopened.
shquote() {
    printf "'"
    printf '%s' "$1" | sed "s/'/'\\\\''/g"
    printf "'"
}

# Is that PID the process we think it is?
#
# PIDs are recycled, and `kill -0` only says "something answers to this
# number" — which on a long-lived box is regularly something else entirely.
# Killing on that answer alone is how an installer shoots an unrelated
# process. The command line settles it wherever the system will show one, and
# a system that shows neither /proc nor ps gets the weak answer rather than a
# wrong one.
pid_is() {
    kill -0 "$1" 2>/dev/null || return 1
    if [ -r "/proc/$1/cmdline" ]; then
        tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null | grep -Fxq "$2"
        return $?
    fi
    if command -v ps >/dev/null 2>&1; then
        ps -p "$1" -o args= 2>/dev/null | grep -Fq "$2"
        return $?
    fi
    return 0
}

# Stop a helper nobody is supervising — one started by hand, from a shell.
#
# That is not a hypothetical: until this release, an install on a machine with
# no systemctl printed "run manually: <bin> connect <relay>" and left it there,
# so a hand-started helper is a shape THIS SCRIPT taught people to make. It is
# recorded nowhere, so keeper_stop cannot see it, and leaving it running beside
# a freshly supervised one means the same machine pushes twice and takes two
# relay seats.
#
# The previous version of this file swept them with
# `pkill -f "^$BINDIR/$NAME connect "`, which is why that line existed — and
# also why it had to go: pkill takes the pattern as a REGULAR EXPRESSION, and
# the default ~/.local/bin already holds a '.' that matches any character. So
# the sweep stays and the regex does not. /proc is read directly and argv[0] is
# compared for EQUALITY, which cannot over-match by construction. Processes
# belonging to other users simply fail the kill, as they should.
helper_stop_strays() {
    _sbin="${INSTALLED_BIN:-${BINDIR:-$HOME/.local/bin}/$NAME}"
    [ -d /proc ] || return 0
    for _proc in /proc/[0-9]*; do
        _spid=${_proc#/proc/}
        [ "$_spid" = "$$" ] && continue
        [ -r "$_proc/cmdline" ] || continue
        _argv0=$(tr '\0' '\n' < "$_proc/cmdline" 2>/dev/null | head -n 1)
        [ "$_argv0" = "$_sbin" ] || continue
        kill "$_spid" 2>/dev/null || true
    done
}

# Stop the keep-alive loop and whatever it was keeping alive.
#
# Called from three places and it matters that all three go through here: the
# keeper branch (so a reinstall does not leave two loops racing to restart the
# same helper, which is how one machine takes two relay seats), the systemd
# branch (so a box that GAINS a real systemd does not end up supervised twice),
# and uninstall (where the order is the whole point — killing the helper while
# the loop still runs just starts another one thirty seconds later, leaving an
# "uninstalled" machine still reporting to the dashboard).
#
# The PID comes from the lock directory rather than a plain PID file, because
# the loop may have been started by cron's @reboot rather than by this script,
# and only the loop itself can know its own PID. See keeper_start.
# OpenWrt: the helper arranges its own start at boot as a procd service that
# runs the keeper loop (go/autostart.go; `subnsub-monitor autostart`).
# The marker is how a file is known to be that one and not somebody's own
# init script under the same name.
PROCD_INIT="/etc/init.d/$NAME"
procd_is_ours() {
    [ -f "$PROCD_INIT" ] && grep -q '^# subnsub-monitor-autostart ' "$PROCD_INIT" 2>/dev/null
}

keeper_stop() {
    # procd first: it respawns the loop it started, and would bring back the
    # very process the lines below are about to stop.
    if procd_is_ours; then
        "$PROCD_INIT" stop >/dev/null 2>&1 || true
    fi
    _kconf="$HOME/.config/$NAME"
    _keeper="$_kconf/keeper.sh"
    _lock="$_kconf/keeper.lock"

    _kpid=$(cat "$_lock/pid" 2>/dev/null || echo '')
    case "$_kpid" in ''|*[!0-9]*) _kpid='' ;; esac
    # Read BEFORE the loop is stopped: a loop that stops cleanly deletes this
    # file on its way out, and then there would be nothing left to check
    # against in the case where it did not.
    _cpid=$(cat "$_lock/child" 2>/dev/null || echo '')
    case "$_cpid" in ''|*[!0-9]*) _cpid='' ;; esac
    _bin="${INSTALLED_BIN:-${BINDIR:-$HOME/.local/bin}/$NAME}"

    if [ -n "$_kpid" ] && pid_is "$_kpid" "$_keeper"; then
        # TERM first: the loop traps it and stops the helper it is watching. A
        # KILL straight away would leave that helper orphaned and running.
        kill "$_kpid" 2>/dev/null || true
        _i=0
        while [ "$_i" -lt 5 ] && kill -0 "$_kpid" 2>/dev/null; do
            sleep 1
            _i=$((_i + 1))
        done
        # And KILL if it did not go. Returning with the loop still alive is the
        # worst outcome available: the caller starts a replacement, and this one
        # wakes up later to restart a helper nobody is expecting.
        if kill -0 "$_kpid" 2>/dev/null; then
            kill -9 "$_kpid" 2>/dev/null || true
            sleep 1
        fi
    fi
    # The helper itself, if it outlived the loop — a keeper that was KILLed
    # before its trap could run. Recorded by PID and checked by identity, never
    # matched by command line: `pkill -f` would take $BINDIR as a REGULAR
    # EXPRESSION, and the default ~/.local/bin already holds a '.' that matches
    # anything.
    if [ -n "$_cpid" ] && pid_is "$_cpid" "$_bin"; then
        kill "$_cpid" 2>/dev/null || true
    fi
    rm -rf "$_lock"
    # And its @reboot line. -F, so a path with a '.' or a '[' in it is matched
    # as the string it is rather than as a pattern.
    if command -v crontab >/dev/null 2>&1; then
        crontab -l 2>/dev/null | grep -vF "$_keeper" | crontab - 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------- uninstall
uninstall() {
    # Where the install actually put things, not where a default would guess.
    # Without this, uninstalling after `MON_BINDIR=/opt/bin sh install.sh` would
    # delete an unrelated ~/.local/bin/subnsub-monitor and leave the real one
    # running.
    manifest="$HOME/.config/$NAME/manifest"
    if [ -f "$manifest" ]; then
        # shellcheck disable=SC1090
        . "$manifest"
        [ -n "${INSTALLED_BIN:-}" ] && BINDIR=$(dirname "$INSTALLED_BIN")
    fi
    case "$(uname -s)" in
      Darwin)
        plist="$HOME/Library/LaunchAgents/${INSTALLED_LABEL:-$LABEL}.plist"
        [ -f "$plist" ] && launchctl unload "$plist" 2>/dev/null || true
        rm -f "$plist"
        ;;
      Linux)
        systemctl --user disable --now "$NAME.service" 2>/dev/null || true
        rm -f "$HOME/.config/systemd/user/$NAME.service"
        systemctl --user daemon-reload 2>/dev/null || true
        # And the keep-alive loop, on a machine that got one instead of a
        # unit — the loop before the helper, or the loop restarts it.
        keeper_stop
        # Then anything still running that no supervisor claims.
        helper_stop_strays
        # And the boot entry the helper wrote for itself on OpenWrt.
        if procd_is_ours; then
            "$PROCD_INIT" disable >/dev/null 2>&1 || true
            rm -f "$PROCD_INIT"
        fi
        # And the one this script wrote for Termux:Boot on Android.
        rm -f "$HOME/.termux/boot/$NAME"
        ;;
    esac
    # The daemon and every supervisor are down before this one-shot request, so
    # no late push can recreate the card after the relay archives it. Keep the
    # binary and credentials until it has been attempted. Older binaries do not
    # know this command; report that honestly but never block local removal.
    _unreg_bin="${INSTALLED_BIN:-$BINDIR/$NAME}"
    _unreg_relay="${INSTALLED_RELAY:-$RELAY}"
    if [ -x "$_unreg_bin" ] && [ -f "$HOME/.config/$NAME/agent-id" ]; then
        if ! "$_unreg_bin" unregister "$_unreg_relay"; then
            say "warning: relay was not notified; removing the local installation anyway"
        fi
    fi
    # agent-id and name go too: leaving the id behind means a reinstall
    # silently reclaims the same dashboard card, which is surprising when the
    # point of uninstalling was to stop watching this machine.
    # token.current is the renewed token the helper writes for itself; it is a
    # bearer secret like the installed one and has to go with it. Leaving it
    # behind would also mean a later reinstall silently resurrecting the old
    # credential instead of using the token just pasted.
    # token.current.new too: it is the write-then-rename staging name, and a
    # crash between the two steps leaves a readable bearer secret under it that
    # nothing else would ever clean up.
    rm -f "${INSTALLED_BIN:-$BINDIR/$NAME}" "$HOME/.config/$NAME/token" \
          "$HOME/.config/$NAME/service.env" "$HOME/.config/$NAME/service.env.new" \
          "$HOME/.config/$NAME/token.current" "$HOME/.config/$NAME/token.current.new" \
          "$HOME/.config/$NAME/agent-id" "$HOME/.config/$NAME/name" \
          "$HOME/.config/$NAME/console" "$HOME/.config/$NAME/update" \
          "$HOME/.config/$NAME/autoupdate" \
          "$HOME/.config/$NAME/diagnostics" "$HOME/.config/$NAME/sessions-sync" \
          "$HOME/.config/$NAME/sessions-sync.json" "$manifest" \
          "$HOME/.config/$NAME/direct" "$HOME/.config/$NAME/allowed-clients" \
          "$HOME/.config/$NAME/allowed-clients.new" "$HOME/.config/$NAME/derpmap" \
          "$HOME/.config/$NAME/tailcat.key" "$HOME/.config/$NAME/tailcat.region" \
          "$HOME/.config/$NAME/keeper.sh" "$HOME/.config/$NAME/keeper.sh.new" \
          "$HOME/.config/$NAME/keeper.log" \
          "$HOME/.config/$NAME/probes-state.json" "$HOME/.config/$NAME/probes-state.json.new" \
          "$HOME/.config/$NAME/probes.key" "$HOME/.config/$NAME/probes.key.new" \
          "$HOME/.config/$NAME/tailcat.region.new" "$HOME/.config/$NAME/address" \
          "$HOME/.config/$NAME/address.new" \
          "$HOME/.config/$NAME/tailcat.psk" "$HOME/.config/$NAME/tailcat.psk.new" \
          "$HOME/.config/$NAME/clones" "$HOME/.config/$NAME/clones.new" \
          "$HOME/.config/$NAME/clone-access" "$HOME/.config/$NAME/clone-access.new" \
          "$HOME/.config/$NAME/pairing" "$HOME/.config/$NAME/pairing.new"
    # The binary the last self-update moved aside. Left behind it would be an
    # unreferenced few megabytes under a name nothing else will ever clean up.
    rm -f "${INSTALLED_BIN:-$BINDIR/$NAME}.prev"
    rmdir "$HOME/.config/$NAME" 2>/dev/null || true
    say "removed $NAME"
    exit 0
}
[ "${1:-}" = "--uninstall" ] && uninstall

# -------------------------------------------------------------- token / name
# The token is the first bare argument, or the environment. Checked for a
# leading dash first: with SUBNSUB_MONITOR_TOKEN already set,
# `sh install.sh --name box` would otherwise take "--name" as the token and
# fail with a bewildering complaint about the characters in it.
TOKEN=""
case "${1:-}" in
  ''|-*) TOKEN="${SUBNSUB_MONITOR_TOKEN:-}" ;;
  *)     TOKEN=$1; shift ;;
esac
# Checked AFTER the switches are parsed: --direct is the one shape of this
# script that needs no token at all.

# What this machine is called on the dashboard. Optional, and deliberately not
# guessed: the helper never reads the hostname, so an unnamed machine shows up
# under its own random id rather than under whatever the box calls itself.
NAME_ARG="${MON_NAME:-}"
# Whether the dashboard may run commands on this machine. OFF unless asked for
# here, on the machine, by whoever is running this script — see console.go for
# why that is the only place the decision can honestly be made.
CONSOLE_ARG=""
# Whether the dashboard may replace this helper's binary. Same rule, same
# place, and a separate switch from the console even though the console implies
# it — see go/update.go. A machine that wants the button and no shell is
# the case this exists for.
UPDATE_ARG=""
# Whether the helper replaces itself on a timer, unasked — see update.go. Its
# own file, meaningful only beside the update switch above (or a console).
AUTO_ARG=""
# Whether the dashboard may read a bounded process table here, and whether the
# helper keeps program names beside its own CPU history — inspect.go and
# prochist.go. Read-only, Linux only, and independent of the console.
# Whether this machine's agent conversations are pushed to the account's
# archive. Same rule and same place as the two above, and independent of both:
# the console decides whether the dashboard may ASK this machine something, and
# this decides whether the machine SENDS something without being asked. Neither
# implies the other, in either direction.
SYNC_ARG=""
# Direct mode: the tunnel switch, the browser keys it admits, and an optional
# DERP map of your own. Keys accumulate — each --allow is one browser — and
# are APPENDED to the machine's list, never used to replace it.
DIRECT_ARG=""
ALLOW_KEYS=""
DERPMAP_ARG="${MON_DERPMAP:-}"
# The self-hosted page's pairing token (helper/go/pairing.go): for the last
# --allow key on the line, the browser that made it.
PAIR_ARG=""
# A second helper on a machine that already runs one under ANOTHER user.
# Refused by default — see the guard below the switches for why.
SECOND_ARG="${MON_SECOND:-}"
while [ $# -gt 0 ]; do
    case "$1" in
      --second) SECOND_ARG=on; shift ;;
      --direct) DIRECT_ARG=on; shift ;;
      --direct=on|--direct=yes|--direct=1) DIRECT_ARG=on; shift ;;
      --direct=off|--direct=no|--direct=0) DIRECT_ARG=off; shift ;;
      --allow) [ $# -ge 2 ] || die "--allow needs a nodekey"; ALLOW_KEYS="$ALLOW_KEYS $2"; shift 2 ;;
      --allow=*) ALLOW_KEYS="$ALLOW_KEYS ${1#--allow=}"; shift ;;
      --derpmap) [ $# -ge 2 ] || die "--derpmap needs an https URL"; DERPMAP_ARG=$2; shift 2 ;;
      --derpmap=*) DERPMAP_ARG=${1#--derpmap=}; shift ;;
      --pair) [ $# -ge 2 ] || die "--pair needs a pairing token"; PAIR_ARG=$2; shift 2 ;;
      --pair=*) PAIR_ARG=${1#--pair=}; shift ;;
      --name) [ $# -ge 2 ] || die "--name needs a value"; NAME_ARG=$2; shift 2 ;;
      --name=*) NAME_ARG=${1#--name=}; shift ;;
      --console) CONSOLE_ARG=on; shift ;;
      --console=on|--console=yes|--console=1) CONSOLE_ARG=on; shift ;;
      --console=off|--console=no|--console=0) CONSOLE_ARG=off; shift ;;
      --remote-update) UPDATE_ARG=on; shift ;;
      --remote-update=on|--remote-update=yes|--remote-update=1) UPDATE_ARG=on; shift ;;
      --remote-update=off|--remote-update=no|--remote-update=0) UPDATE_ARG=off; shift ;;
      --auto-update) AUTO_ARG=on; shift ;;
      --auto-update=on|--auto-update=yes|--auto-update=1) AUTO_ARG=on; shift ;;
      --auto-update=off|--auto-update=no|--auto-update=0) AUTO_ARG=off; shift ;;
      --diagnostics|--diagnostics=on|--diagnostics=yes|--diagnostics=1) shift ;;
      --diagnostics=off|--diagnostics=no|--diagnostics=0)
        echo "note: --diagnostics=off no longer does anything; program names are read wherever /proc shows other processes" >&2; shift ;;
      --sessions-sync) SYNC_ARG=on; shift ;;
      --sessions-sync=on|--sessions-sync=yes|--sessions-sync=1) SYNC_ARG=on; shift ;;
      --sessions-sync=off|--sessions-sync=no|--sessions-sync=0) SYNC_ARG=off; shift ;;
      --sessions|--sessions=*) die "--sessions is gone: session search is built into the helper now; turning --console on is all a machine needs (--sessions-sync is the archive, which is a different thing)" ;;
      *) die "unexpected argument: $1" ;;
    esac
done

# What an earlier install left, read BEFORE the road check so that a run
# which only adds a browser key (--allow) or only flips --direct=off on a
# machine that already has a token or a tunnel is an ordinary reinstall
# rather than a refusal. A recovered token goes through the same shape
# check below as a pasted one: it is about to be written into a unit file
# and a plist, and "it was on disk" is not a reason to skip that.
conf="$HOME/.config/$NAME"
if [ -z "$TOKEN" ] && [ -f "$conf/token" ]; then
    TOKEN=$(sed -n 's/^SUBNSUB_MONITOR_TOKEN=//p' "$conf/token" | head -n 1)
fi
DIRECT_ON=no
[ "$DIRECT_ARG" = on ] && DIRECT_ON=yes
[ -f "$conf/direct" ] && [ "$DIRECT_ARG" != off ] && DIRECT_ON=yes
# A machine needs a road to be watched on: a token (the relay) or the tunnel.
# Neither is an install that reports to nobody, and it says so here rather
# than starting a service that exits with "no token" in a log nobody reads.
# --allow without a tunnel is refused for the same reason: a key on a list
# the tunnel never consults is a switch that looks set.
if [ -z "$TOKEN" ] && [ "$DIRECT_ON" != yes ]; then
    die "no token and no --direct. Usage: sh install.sh <TOKEN> [--name LABEL] [--console] [--remote-update] [--auto-update] [--diagnostics] [--sessions-sync] [--second]
       sh install.sh --direct --allow nodekey:... [--pair TOKEN] [--derpmap https://...]  (no account needed)"
fi
if [ -n "$ALLOW_KEYS" ] && [ "$DIRECT_ON" != yes ]; then
    die "--allow needs --direct (or a machine where direct mode is already on)"
fi
# A tailcat node key is 'nodekey:' and 64 hex characters, nothing else. Each
# one is written into the allowed-clients file the helper reads on every
# request, so a value the helper cannot parse must be refused here, while a
# person is watching, rather than sit in the file granting nothing.
for k in $ALLOW_KEYS; do
    case "$k" in
      nodekey:*) ;;
      *) die "--allow: not a tailcat node key (want nodekey:<64 hex>): $k" ;;
    esac
    hex=${k#nodekey:}
    [ "${#hex}" -eq 64 ] || die "--allow: not a tailcat node key (want 64 hex characters after nodekey:)"
    case "$hex" in
      *[!0-9a-fA-F]*) die "--allow: not a tailcat node key (non-hex characters)" ;;
    esac
done
# The DERP map URL is written to a file the helper reads; https only, and
# the same character rule as the relay URL since it is data, not shell.
if [ -n "$DERPMAP_ARG" ]; then
    case "$DERPMAP_ARG" in
      https://*) ;;
      *) die "--derpmap must be an https:// URL" ;;
    esac
    case "$DERPMAP_ARG" in
      *[!A-Za-z0-9:/._-]*) die "--derpmap URL has unexpected characters" ;;
    esac
fi
# The pairing token: 64 lowercase hex characters (the pairing node's private
# key), a dot, and its tailcat address. Shape only — the helper checks that
# the two halves belong together — but refused here, while a person is
# watching, rather than left in a file that pairs with nobody. It is for the
# browser whose key the same line allows, so a line without one is refused.
PAIR_FOR=""
if [ -n "$PAIR_ARG" ]; then
    [ "$DIRECT_ON" = yes ] || die "--pair needs --direct (or a machine where direct mode is already on)"
    [ -n "$ALLOW_KEYS" ] || die "--pair needs the browser key it is for (--allow nodekey:...)"
    [ "${#PAIR_ARG}" -le 2120 ] || die "--pair: not a pairing token (too long)"
    pair_key=${PAIR_ARG%%.*}
    pair_addr=${PAIR_ARG#*.}
    [ "$pair_key" != "$PAIR_ARG" ] || die "--pair: not a pairing token (want <64 hex>.<tc address>)"
    [ "${#pair_key}" -eq 64 ] || die "--pair: not a pairing token (want 64 hex characters before the dot)"
    case "$pair_key" in
      *[!0-9a-f]*) die "--pair: not a pairing token (non-hex characters before the dot)" ;;
    esac
    case "$pair_addr" in
      tc?*) ;;
      *) die "--pair: not a pairing token (the address after the dot starts with tc)" ;;
    esac
    case "${pair_addr#tc}" in
      *[!A-Za-z0-9_-]*) die "--pair: not a pairing token (unexpected characters in the address)" ;;
    esac
    for k in $ALLOW_KEYS; do PAIR_FOR=$k; done
fi

# ----------------------------------------------------------- one per machine
# This installer is per HOME: it keeps everything under ~/.config and
# ~/.local/bin, and a re-run by the same user is a reinstall — the keeper is
# stopped first, the agent id is kept, the dashboard card stays the same. Run
# by a DIFFERENT user (a root shell, a sudo) it finds no manifest, installs a
# second copy, mints a second agent id and takes a second relay seat: two
# cards for one box, which is exactly what happened on 2026-09-14 (an install
# as `box` on the 1st, the same line pasted into a root shell on the 13th).
# So before anything is written, the other users' helpers are looked for —
# their processes, which is the one evidence any user can see: another
# user's ~/.config is 0700 — and a running one is a refusal that names the
# user, so the fix is "become that user", not "guess". --second (or
# MON_SECOND=1) is the deliberate way past it, for the person who really
# wants two accounts watching one machine.
#
# Both shapes the machine can be in are matched — the helper itself
# (`…/subnsub-monitor connect …`) and its keep-alive loop
# (`sh …/.config/subnsub-monitor/keeper.sh`), since the loop may be between
# restarts of the helper at the moment this runs. The loop is only a loop
# when a SHELL is running the file: `less` or an editor on keeper.sh is
# somebody reading it. On Linux the processes are read from /proc, argv by
# argv (NUL-separated, so a home with a space in it is one argument, and it
# works the same under busybox, whose ps has no -o). Elsewhere it is
# `ps axwwo` — the BSD spelling macOS and FreeBSD share, ww for the full
# command line — matched by the shape of the whole line rather than by
# splitting it on spaces. A kernel with hidepid, or no way to list processes
# at all, shows nothing here and the install goes ahead with a note: the
# guard is a courtesy against a slip of the hand, not a lock.
case "$SECOND_ARG" in on|1|yes|true) SECOND_ARG=on ;; esac
helper_seen() {
    # $1 uid, $2 argv0, $3 argv1: prints "user<TAB>path" for a helper or its loop.
    _path=""
    case "${2##*/}" in
      "$NAME") [ "${3:-}" = connect ] && _path=$2 ;;
      sh|dash|bash|ash|ksh|zsh)
        case "${3:-}" in */.config/"$NAME"/keeper.sh) _path=$3 ;; esac ;;
    esac
    [ -n "$_path" ] || return 0
    # busybox's id takes no uid argument; the passwd file says the same.
    _who=$(id -nu "$1" 2>/dev/null || true)
    [ -n "$_who" ] || _who=$(getent passwd "$1" 2>/dev/null | cut -d: -f1)
    [ -n "$_who" ] || _who=$(awk -F: -v u="$1" '$3 == u { print $1; exit }' /etc/passwd 2>/dev/null)
    printf '%s\t%s\n' "${_who:-uid $1}" "$_path"
}
other_helpers() {
    _me=$(id -u)
    _seen=0
    if [ -r /proc/self/status ]; then
        for _p in /proc/[0-9]*; do
            [ -r "$_p/status" ] && [ -r "$_p/cmdline" ] || continue
            _uid=$(sed -n 's/^Uid:[[:space:]]*\([0-9]*\).*/\1/p' "$_p/status" 2>/dev/null)
            [ -n "$_uid" ] || continue
            _seen=1
            [ "$_uid" = "$_me" ] && continue
            _a0=$(tr '\0' '\n' < "$_p/cmdline" 2>/dev/null | sed -n 1p)
            _a1=$(tr '\0' '\n' < "$_p/cmdline" 2>/dev/null | sed -n 2p)
            [ -n "$_a0" ] || continue
            helper_seen "$_uid" "$_a0" "$_a1"
        done
    else
        # `read -r _uid _rest` keeps the whole command line in _rest, spaces
        # and all; the two shapes are recognised by their suffixes. A path
        # with a space is still one path here, only split by nothing. The
        # helper's line has to START with its path: `sudo -u x …/subnsub-monitor
        # connect` is the wrapper, not the helper, and would name the wrong
        # user (its child is caught on its own line).
        ps axwwo uid=,args= 2>/dev/null | while read -r _uid _rest; do
            case "$_uid" in ''|*[!0-9]*) continue ;; esac
            _seen=1
            [ "$_uid" = "$_me" ] && continue
            case "$_rest" in
              /*/"$NAME"\ connect|/*/"$NAME"\ connect\ *)
                helper_seen "$_uid" "${_rest%% connect*}" connect ;;
              */.config/"$NAME"/keeper.sh)
                _i0=${_rest%% *}
                helper_seen "$_uid" "$_i0" "${_rest#* }" ;;
            esac
        done
        # The pipeline hid whether ps could list anything at all.
        [ "$(ps axwwo uid= 2>/dev/null | wc -l)" -gt 1 ] && _seen=1
    fi
    [ "$_seen" = 1 ] || echo "note: could not list this machine's processes; skipping the other-user check" >&2
}
if [ "$SECOND_ARG" != on ]; then
    others=$(other_helpers | sort -u)
    if [ -n "$others" ]; then
        printf 'error: this machine already runs the helper under another user:\n' >&2
        printf '%s\n' "$others" | while IFS="$(printf '\t')" read -r _who _what; do
            printf '         %s  (%s)\n' "$_who" "$_what" >&2
        done
        die "run this installer as that user (an update needs no reinstall: the dashboard's Update button, or 'subnsub-monitor update'), or add --second to knowingly install a second helper here"
    fi
fi

# Same shape the relay accepts. Beyond catching typos this is what keeps a
# token with a newline in it from adding arbitrary lines to the systemd
# EnvironmentFile, or one with a '<' from breaking out of a plist string.
# Everything downstream interpolates this value into a config file.
if [ -n "$TOKEN" ]; then
    case "$TOKEN" in
      *[!A-Za-z0-9_-]*) die "token has characters outside [A-Za-z0-9_-]" ;;
    esac
    len=${#TOKEN}
    [ "$len" -ge 24 ] && [ "$len" -le 128 ] || die "token must be 24-128 characters"
fi

# Base64, and the length Ed25519 public keys have. Checked here rather than
# only in the helper because this value is written into a config file, and
# "whatever was in the environment" is not a thing to write into one.
# A 32-byte key in standard base64 is exactly 43 characters and one trailing
# '=' — nothing else is that shape. Checking the shape rather than "44 of the
# right characters" matters because everything that gets past here is written
# into the trusted-keys file, and a value the HELPER cannot decode leaves that
# file existing with no usable key in it: the machine then refuses every
# command until somebody fixes it by hand. Better to refuse the install line
# that carried it, here, while there is a person watching.
if [ -n "$PUBKEY" ]; then
  case "$PUBKEY" in
    *[!A-Za-z0-9+/=]*) die "MON_PUBKEY has characters outside base64" ;;
  esac
  case "$PUBKEY" in
    *=) ;;
    *) die "MON_PUBKEY is not a 32-byte Ed25519 key in base64" ;;
  esac
  case "${PUBKEY%=}" in
    *[!A-Za-z0-9+/]*) die "MON_PUBKEY is not a 32-byte Ed25519 key in base64" ;;
  esac
  [ "${#PUBKEY}" -eq 44 ] || die "MON_PUBKEY is not a 32-byte Ed25519 key in base64"
fi

# The relay URL is interpolated into the same files. Keep it to an https URL
# made of characters that cannot terminate an XML string or a unit directive.
case "$RELAY" in
  https://*) ;;
  *) die "relay must be an https:// URL" ;;
esac
case "$RELAY" in
  *[!A-Za-z0-9:/._-]*) die "relay URL has unexpected characters" ;;
esac

# Where tokens get renewed, for people running their own relay.
#
# The helper renews only against the site this build ships with, or one named
# here — it will not offer a token minted by somebody else's issuer to ours. So
# a custom relay needs this, and it has to survive into the SERVICE: the value
# was only ever in the installing shell's environment, and the unit and the
# plist below carry nothing but the token, so without persisting it the
# background process would come up with renewal quietly switched off. An
# install that looked like it worked and stopped reporting a month later.
SITE="${SUBNSUB_MONITOR_SITE:-}"
if [ -n "$SITE" ]; then
    case "$SITE" in
      https://*) ;;
      *) die "SUBNSUB_MONITOR_SITE must be an https:// URL" ;;
    esac
    # Same interpolation-safety rule as the relay: this value is written into a
    # systemd EnvironmentFile and an XML string.
    case "$SITE" in
      *[!A-Za-z0-9:/._-]*) die "SUBNSUB_MONITOR_SITE has unexpected characters" ;;
    esac
fi

# ------------------------------------------------------------ os / arch
os=$(uname -s)
arch=$(uname -m)
# Android calls itself Linux to uname, and is: the same kernel, a different
# userland. What tells the two apart is bionic's property store, which every
# Android since 5.0 has and no Linux distribution does — the same test the
# helper makes at run time (go/android_linux.go). Termux is how people
# get a shell on it, and exports TERMUX_VERSION into every session.
android=""
termux=""
if [ "$os" = Linux ]; then
    if [ -e /dev/__properties__ ] || [ -n "${TERMUX_VERSION:-}" ]; then
        android=1
    fi
    if [ -n "${TERMUX_VERSION:-}" ]; then
        termux=1
    else
        case "${PREFIX:-}" in */com.termux/*) termux=1 ;; esac
    fi
    [ -n "$android" ] || termux=""
fi
case "$os" in
  Linux)
    # Said before anything is fetched or written (see the head of this file).
    [ -z "$android" ] || die "Android is not installed with this line.
Open the Monitor page on a computer in Chrome or Edge, plug the phone in with
USB debugging on, and install it from the install card (the Android robot).
A helper installed under Termux earlier is removed with: sh install.sh --uninstall"
    goos=linux ;;
  Darwin)  goos=darwin  ;;
  FreeBSD) goos=freebsd ;;
  # Somebody running this inside Git Bash, MSYS2, Cygwin or the like. Named
  # separately from the catch-all below so the answer can be the true one:
  # Windows is not a platform this is published for, rather than one nobody
  # thought about. The port exists and is not being offered.
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    die "Windows is not supported. No binary is published for it, and this
installer would not register anything that survives a reboot there." ;;
  *) die "unsupported OS: $os (Linux, macOS and FreeBSD; Android is installed from the Monitor page over USB)" ;;
esac
case "$arch" in
  x86_64|amd64)  goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  # 32-bit ARM: a Raspberry Pi running the 32-bit OS, and a fair number of
  # cheap boxes. armv6 is NOT accepted — the published build is ARMv7 and would
  # fault on a Pi 1 or a Zero W, which is a worse outcome than being told so.
  armv7l|armv7|armhf) goarch=arm ;;
  *) die "unsupported architecture: $arch" ;;
esac
# Android is published for arm64 alone — see go/build.sh.
if [ "$goos" = android ] && [ "$goarch" != arm64 ]; then
    die "Android: only arm64 is published, and this device reports $arch"
fi
asset="$NAME-$goos-$goarch"

# ----------------------------------------------------------------- fetch
mkdir -p "$BINDIR"
# Termux sets TMPDIR under its prefix; a bare Android shell sets nothing and
# has no /tmp, so the download lands beside the things it is about to join.
tmpdir="${TMPDIR:-/tmp}"
if [ ! -d "$tmpdir" ] || [ ! -w "$tmpdir" ]; then
    tmpdir="$HOME"
fi
tmp=$(mktemp "$tmpdir/$NAME.XXXXXX")
# Clean up on any exit path, including the failure ones below.
trap 'rm -f "$tmp"' EXIT INT TERM

if [ -n "${MON_LOCAL:-}" ]; then
    # Install from a binary you already have — used while the download host
    # is still being set up, and handy for testing a build before publishing.
    say "installing from $MON_LOCAL"
    cp "$MON_LOCAL" "$tmp"
else
    say "downloading $asset"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$BASE/$asset" -o "$tmp" || die "download failed: $BASE/$asset"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$tmp" "$BASE/$asset" || die "download failed: $BASE/$asset"
    else
        die "need curl or wget"
    fi
fi

[ -s "$tmp" ] || die "downloaded file is empty"

# Verify before anything is made executable. Skipped only for MON_LOCAL, where
# you supplied the file yourself and there is nothing to authenticate.
if [ -z "${MON_LOCAL:-}" ]; then
    eval "want=\${SUM_${goos}_${goarch}}"
    case "$want" in
      PLACEHOLDER_*) die "this installer has no checksum for $goos/$goarch — refusing to run an unverified binary" ;;
    esac
    if command -v sha256sum >/dev/null 2>&1; then
        got=$(sha256sum < "$tmp" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        got=$(shasum -a 256 < "$tmp" | cut -d' ' -f1)
    else
        die "need sha256sum or shasum to verify the download"
    fi
    [ "$got" = "$want" ] || die "checksum mismatch — expected $want, got $got. NOT installing."
    say "checksum ok"
fi

# Run it BEFORE it replaces anything. A binary that downloads and verifies but
# cannot execute here (wrong libc, wrong arch reported by uname) must not take
# out a working install on its way past.
chmod 0755 "$tmp"
if ! "$tmp" token >/dev/null 2>&1; then
    if [ -n "$termux" ]; then
        # The Google Play build of Termux targets a recent Android and so may
        # not execute a file it downloaded (Android's W^X rule for apps
        # targeting 10+); the F-Droid build may. Say which door is shut.
        die "the downloaded binary does not run here. On the Google Play build of Termux, downloaded programs cannot be executed; install Termux from F-Droid instead"
    fi
    die "the downloaded binary does not run on this machine"
fi

# Land it in the target directory first so the final step is a rename within
# one filesystem — atomic, and it cannot leave a half-written binary behind.
staged="$BINDIR/.$NAME.new.$$"
mkdir -p "$BINDIR"
cp "$tmp" "$staged"
chmod 0755 "$staged"
mv -f "$staged" "$BINDIR/$NAME"
rm -f "$tmp"
trap - EXIT INT TERM
say "installed $BINDIR/$NAME"

# ----------------------------------------------------------------- token file
# Kept out of the service definition and out of the process arguments, so it
# does not show up in `ps` or in a world-readable unit file.
#
# This is the BOOTSTRAP token and it is not the last word. Tokens expire after
# 30 days, and the helper trades its own in for a fresh one before that, writing
# the replacement to `token.current` beside this file — a place it reads itself.
# Linux gets a separate, token-only EnvironmentFile below, while macOS inlines
# the bootstrap token in its plist. Keeping the CLI Proxy API values out of the
# systemd file lets keys remain data rather than systemd quoting syntax.
# Re-running this installer with a newly pasted token still wins: the helper
# picks whichever of the two lasts longer, and a just-issued one always does.
mkdir -p "$conf"
umask 077
# Owner-only, whatever umask the shell above ran mkdir under: the tunnel
# identity (tailcat.key) lives here and the helper tightens or refuses a
# wider directory (transport/tailcat.go). Every earlier install made this
# directory 0755 under the login umask, so this is also the repair.
chmod 0700 "$conf"
# Write to a fresh name and rename over the target. A plain `>` redirect
# follows an existing symlink to wherever it points, blocks forever on a FIFO,
# and keeps whatever mode the old file had until the chmod lands — by which
# time the secret has already been written under it.
rm -f "$conf/token.new"
# Extra settings are data, never shell. Reject line/control characters before
# placing them in the private line-oriented config. A plain reinstall preserves
# earlier lines unless that key is present in this process's environment.
# (Service checks are NOT configured here: they live in probes.json beside the
# token, written by the operator and read by the helper alone — see
# go/probes.go and the README.)
valid_config_value() {
    [ -z "$1" ] && return 0
    # grep sees lines without their separators, so it cannot detect the one
    # control character that could inject another KEY=VALUE row by itself.
    case "$1" in
      *'
'*) return 1 ;;
    esac
    ! LC_ALL=C printf '%s' "$1" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null 2>&1
}
# CLI Proxy API settings take the same road: data in the private config,
# never shell, preserved across a plain reinstall. MON_CPA_KEY is the
# proxy's management key — it is written 0600 beside the token and read by
# nothing but the helper (go/cpa.go).
for cpa_value in "${MON_CPA_URL-}" "${MON_CPA_KEY-}"; do
    valid_config_value "$cpa_value" || die "CLI Proxy API configuration contains a control character"
done
# MON_IPV4 (go/ipv4.go) the same way: "off" to stop the helper asking a
# public service for the machine's IPv4, or the https URL of another one. The
# service never sees this shell, so the value has to be in the config it reads.
valid_config_value "${MON_IPV4-}" || die "MON_IPV4 contains a control character"
case "${MON_IPV4-}" in
  ''|off|OFF|0|false|no|https://*) ;;
  *) die "MON_IPV4 must be off or an https:// URL" ;;
esac
# (A direct-only run keeps whichever token an earlier install wrote — it
# was recovered and shape-checked above, so adding a tunnel to a machine
# never signs it out of the relay.)
{
    [ -n "$TOKEN" ] && printf 'SUBNSUB_MONITOR_TOKEN=%s\n' "$TOKEN"
    # Renewal site, when one was named. It stays beside the bootstrap token so
    # the helper can recover it consistently on every supported platform.
    [ -n "$SITE" ] && printf 'SUBNSUB_MONITOR_SITE=%s\n' "$SITE"
    if [ -f "$conf/token" ]; then
        while IFS= read -r oldline || [ -n "$oldline" ]; do
            oldkey=${oldline%%=*}; oldvalue=${oldline#*=}
            case "$oldkey" in
              MON_CPA_URL)       [ "${MON_CPA_URL+x}" ] && continue ;;
              MON_CPA_KEY)       [ "${MON_CPA_KEY+x}" ] && continue ;;
              MON_IPV4)          [ "${MON_IPV4+x}" ] && continue ;;
              *) continue ;;
            esac
            valid_config_value "$oldvalue" && printf '%s=%s\n' "$oldkey" "$oldvalue"
        done < "$conf/token"
    fi
    [ "${MON_CPA_URL+x}" ] && [ -n "$MON_CPA_URL" ] && printf 'MON_CPA_URL=%s\n' "$MON_CPA_URL"
    [ "${MON_CPA_KEY+x}" ] && [ -n "$MON_CPA_KEY" ] && printf 'MON_CPA_KEY=%s\n' "$MON_CPA_KEY"
    [ "${MON_IPV4+x}" ] && [ -n "$MON_IPV4" ] && printf 'MON_IPV4=%s\n' "$MON_IPV4"
    true
} > "$conf/token.new"
chmod 0600 "$conf/token.new"
mv -f "$conf/token.new" "$conf/token"

# Record what this run actually installed, so --uninstall removes THIS
# install rather than whatever the defaults would point at today.
rm -f "$conf/manifest.new"
{
    printf 'INSTALLED_BIN=%s\n' "$BINDIR/$NAME"
    printf 'INSTALLED_LABEL=%s\n' "$LABEL"
    printf 'INSTALLED_RELAY=%s\n' "$RELAY"
} > "$conf/manifest.new"
chmod 0644 "$conf/manifest.new"
mv -f "$conf/manifest.new" "$conf/manifest"

# ------------------------------------------------------------------ name file
# Written as a file rather than passed through the service definition on
# purpose: a name is free text — spaces, quotes, CJK — and interpolating that
# into a systemd unit or a plist is how a label becomes a parse error, or
# worse. The helper reads it, trims it and drops control characters; nothing
# here has to be escaped because nothing here is a template.
if [ -n "$NAME_ARG" ]; then
    rm -f "$conf/name.new"
    printf '%s\n' "$NAME_ARG" > "$conf/name.new"
    chmod 0600 "$conf/name.new"
    mv -f "$conf/name.new" "$conf/name"
fi

# --------------------------------------------------------------- console file
# The switch that lets the dashboard run commands here. Its EXISTENCE is the
# setting; nothing reads what is in it. Written only when asked for, and
# removed only when explicitly turned off — a reinstall without --console
# leaves an operator's earlier decision alone rather than silently reversing it
# in either direction.
case "$CONSOLE_ARG" in
  on)  : > "$conf/console"; chmod 0600 "$conf/console" ;;
  off) rm -f "$conf/console" ;;
esac

# ---------------------------------------------------------------- update file
# The same shape for the same reasons. Note it is NOT written when --console is
# given: the console allows this on its own, and writing a second file would
# mean `console off` later left behind a switch the operator never set.
case "$UPDATE_ARG" in
  on)  : > "$conf/update"; chmod 0600 "$conf/update" ;;
  off) rm -f "$conf/update" ;;
esac

# ------------------------------------------------------------ autoupdate file
# The timer's switch, same shape. Written whenever asked — it is harmless on
# its own, since the helper counts it only beside the update switch — but
# said out loud when that switch is not on, so nobody walks away thinking a
# machine will keep itself current when it will not.
case "$AUTO_ARG" in
  on)  : > "$conf/autoupdate"; chmod 0600 "$conf/autoupdate"
       if [ "$UPDATE_ARG" != on ] && [ "$CONSOLE_ARG" != on ] && [ ! -f "$conf/update" ] && [ ! -f "$conf/console" ]; then
           echo "note: --auto-update counts only with remote updates on; add --remote-update, or run 'subnsub-monitor update on'" >&2
       fi ;;
  off) rm -f "$conf/autoupdate" ;;
esac

# ----------------------------------------------------------- diagnostics file
# Until 2026-10-13 a marker file here switched the read-only diagnostics on
# (inspect.go, prochist.go). The helper no longer reads it — program names
# are kept wherever /proc shows other processes — so a leftover is removed.
rm -f "$conf/diagnostics"

# --------------------------------------------------------- sessions-sync file
# The switch that sends this machine's agent conversations to the account's
# archive. Same shape as the two above; note that turning it OFF here leaves
# sessions-sync.json alone, because that file records what the ARCHIVE already
# holds and discarding it would make a later --sessions-sync re-upload
# everything from the beginning.
case "$SYNC_ARG" in
  on)  : > "$conf/sessions-sync"; chmod 0600 "$conf/sessions-sync" ;;
  off) rm -f "$conf/sessions-sync" ;;
esac

# --------------------------------------------------------- trusted key file
# APPENDED, never overwritten: re-running the installer from a second browser
# is how a second key gets added, and truncating here would silently revoke the
# first one — locking whoever is not at this keyboard out of their own machine.
# Duplicates are harmless; the helper matches any pinned key.
if [ -n "$PUBKEY" ]; then
  if ! grep -qxF "$PUBKEY" "$conf/trusted-keys" 2>/dev/null; then
    printf '%s\n' "$PUBKEY" >> "$conf/trusted-keys"
  fi
  chmod 0600 "$conf/trusted-keys"
fi

# --------------------------------------------------------- direct mode files
# The tunnel switch — same shape as the console's: existence is the setting.
# Written only when asked, removed only when explicitly turned off.
case "$DIRECT_ARG" in
  on)  : > "$conf/direct"; chmod 0600 "$conf/direct" ;;
  off) rm -f "$conf/direct" ;;
esac
# The browsers allowed in. APPENDED, never overwritten, for the same reason
# trusted-keys is: a second browser's line must not revoke the first.
for k in $ALLOW_KEYS; do
    if ! grep -qxF "$k" "$conf/allowed-clients" 2>/dev/null; then
        printf '%s\n' "$k" >> "$conf/allowed-clients"
    fi
    chmod 0600 "$conf/allowed-clients"
done
# A DERP map of your own. Replaces any earlier one; an empty argument leaves
# an earlier choice alone rather than silently switching back to the public
# relay.
if [ -n "$DERPMAP_ARG" ]; then
    rm -f "$conf/derpmap.new"
    printf '%s\n' "$DERPMAP_ARG" > "$conf/derpmap.new"
    chmod 0600 "$conf/derpmap.new"
    mv -f "$conf/derpmap.new" "$conf/derpmap"
fi
# The pairing (go/pairing.go): replaces an earlier one, and a line run again
# starts its week again. Owner-only from the first byte (umask 077 above): it
# holds the pairing node's private key until the browser has the address.
if [ -n "$PAIR_ARG" ]; then
    rm -f "$conf/pairing.new"
    printf '%s\n%s\n' "$PAIR_ARG" "$PAIR_FOR" > "$conf/pairing.new"
    chmod 0600 "$conf/pairing.new"
    mv -f "$conf/pairing.new" "$conf/pairing"
fi
# The address changes if the tunnel identity does, and a stale one from a
# previous install would be printed below as though it were current.
[ "$DIRECT_ARG" = on ] && rm -f "$conf/address"

# Materialise this machine's dashboard id now, out here, rather than leaving it
# to the first run of the service. The service is sandboxed (see the unit
# below) and on a host where that sandbox is actually enforced it cannot write
# to $HOME — so the id would be regenerated on every start and the machine
# would arrive at the relay as a brand new one after each restart. Creating it
# here means the ordinary path never needs a runtime write at all.
"$BINDIR/$NAME" name >/dev/null 2>&1 || true

# ------------------------------------------------------------- supervision
# Is there a service manager on this machine, or only something that answers
# to the name?
#
# `command -v systemctl` is not that question, and answering it as though it
# were is how a machine ends up dead and quiet. docker-systemctl-replacement
# is a Python script shipped as /usr/bin/systemctl in a great many container
# images — its own docstring says it runs `systemctl start` "without a systemd
# daemon running in the system". It accepts daemon-reload, accepts enable
# --now, forks the process, writes a PID file, and exits 0. Nothing is left
# watching. `Restart=always` in the unit above is a line that program never
# reads, so the first time the helper exits for any reason — a crash, or the
# ordinary exit at the end of a self-update — it simply stays gone.
#
# What separates the real thing from a stand-in is runtime state a script
# cannot fake, because only PID 1 and a running user manager create it:
#
#   /run/systemd/system        exists only when systemd is PID 1
#   $XDG_RUNTIME_DIR/systemd   exists only when THIS user's manager is running
#
# Both, or this is not a systemd host, whatever /usr/bin/systemctl says. The
# `show` call last is belt and braces: it is the cheapest property there is,
# and it proves the socket answers rather than merely existing.
have_systemd_user() {
    [ -d /run/systemd/system ] || return 1
    command -v systemctl >/dev/null 2>&1 || return 1
    _rt="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    [ -d "$_rt/systemd" ] || return 1
    systemctl --user show --property=Version >/dev/null 2>&1
}

# No service manager here, so the helper gets one: a shell loop that starts it,
# waits for it to exit, and starts it again.
#
# This is not a systemd replacement and does not pretend to be. It is the
# smallest thing that makes the one promise the helper depends on — something
# restarts me if I die — on a box where nothing else will make it. Note what it
# is NOT for: since the helper re-execs itself in place after an update
# (go/restart.go), the loop does not even observe an update happening.
# The PID it is waiting on is the same PID, now running the new binary. What
# the loop is really here for is the crash.
#
# Two things are generated rather than assumed, and both were bugs first:
#
#   - The loop records its OWN pid, into a lock directory, at the moment it
#     starts. A PID file written by THIS script would be a lie after the first
#     reboot, because the @reboot line below starts the loop without this
#     script ever running — leaving a stale number that a later reinstall would
#     either kill something innocent with, or fail to stop the real loop with.
#   - Every path is single-quoted through shquote. $HOME and MON_BINDIR are not
#     character-restricted, and a path containing a quote or a $() would
#     otherwise be re-parsed as syntax by the very script being written.
keeper_start() {
    keeper="$conf/keeper.sh"
    keeperlog="$conf/keeper.log"
    lock="$conf/keeper.lock"

    # Whatever was supervising this install before, whichever kind it was —
    # and then whatever is running under no supervisor at all.
    keeper_stop
    helper_stop_strays

    # Written with the values injected ABOVE a fully quoted heredoc, so nothing
    # in the body below is expanded by this shell — the body is the program,
    # the four lines above it are the only data.
    # Which shell runs the loop. Android has no /bin/sh of its own: Termux's
    # is under its prefix, the system's is /system/bin/sh, and the LD_PRELOAD
    # rewrite Termux does for scripts does not reach a loop started at boot.
    ksh=/bin/sh
    if [ -n "$termux" ]; then
        ksh="$PREFIX/bin/sh"
    elif [ -n "$android" ]; then
        ksh=/system/bin/sh
    fi
    {
        printf '#!%s\n' "$ksh"
        printf '# Generated by the subnsub-monitor installer on a machine with no service\n'
        printf '# manager to start the helper. Do not edit: reinstalling overwrites it.\n'
        printf 'KEEPER=%s\n' "$(shquote "$keeper")"
        printf 'CONF=%s\n'   "$(shquote "$conf")"
        printf 'BIN=%s\n'    "$(shquote "$BINDIR/$NAME")"
        printf 'RELAY=%s\n'  "$(shquote "$RELAY")"
        cat <<'KEEPEREOF'

LOCK="$CONF/keeper.lock"

# One loop per install, and mkdir is the test-and-set: it is atomic on every
# POSIX filesystem, unlike "test -f then write", which is exactly the race two
# @reboot lines or a reboot-plus-reinstall would lose.
if ! mkdir "$LOCK" 2>/dev/null; then
    other=$(cat "$LOCK/pid" 2>/dev/null || echo '')
    case "$other" in
        ''|*[!0-9]*) other='' ;;
    esac
    # A live loop already holds it: leave, quietly and successfully. Anything
    # else means the holder is gone and the directory outlived it.
    if [ -n "$other" ] && kill -0 "$other" 2>/dev/null; then
        if [ ! -r "/proc/$other/cmdline" ] ||
           tr '\0' '\n' < "/proc/$other/cmdline" 2>/dev/null | grep -Fxq "$KEEPER"; then
            exit 0
        fi
    fi
    rm -rf "$LOCK"
    mkdir "$LOCK" 2>/dev/null || exit 0
fi
echo $$ > "$LOCK/pid"

child=''

# Only tear down the lock if it is still OURS. A stop that timed out may have
# given up on this loop and let a newer one take the directory, and removing
# that one's lock would leave it running with nothing recording it — the next
# install would then start a second loop beside it.
release() {
    if [ "$(cat "$LOCK/pid" 2>/dev/null || echo '')" = "$$" ]; then
        rm -rf "$LOCK"
    fi
}
# TERM stops whatever is running under us too. Without this the loop dies and
# leaves the helper it started orphaned — an "uninstalled" machine still
# reporting to the dashboard.
trap 'if [ -n "$child" ]; then kill "$child" 2>/dev/null; fi; release; exit 0' TERM INT HUP
trap 'release' EXIT

while :; do
    # Re-read on every pass rather than once at the top, so a token renewed on
    # disk is picked up by the next restart instead of needing this loop to be
    # restarted too. set -a exports what it reads without naming anything here.
    if [ -r "$CONF/service.env" ]; then
        set -a
        . "$CONF/service.env"
        set +a
    fi
    # Backgrounded and waited on, rather than run in the foreground, so the
    # trap above has a PID to stop. `wait` returns as soon as a trapped signal
    # arrives, which is what makes that work.
    "$BIN" connect "$RELAY" &
    child=$!
    echo "$child" > "$LOCK/child"
    wait "$child"
    child=''
    rm -f "$LOCK/child"
    # Matches the unit's RestartSec=30. A helper that cannot reach the relay
    # should not spin, and a machine this loop runs on is usually one whose CPU
    # is shared with something that matters more.
    #
    # BACKGROUNDED AND WAITED ON, not a plain `sleep 30`, and that is not a
    # style choice. A POSIX shell runs a trap only after the current foreground
    # command finishes — `wait` is the documented exception — so a plain sleep
    # would sit on a TERM for up to thirty seconds. The stop would time out,
    # give the lock to a replacement loop, and this one would wake up and tear
    # that replacement's lock down. Measured: a foreground sleep left the keeper
    # alive through a full keeper_stop.
    sleep 30 &
    child=$!
    wait "$child"
    child=''
done
KEEPEREOF
    } > "$keeper.new"
    chmod 0700 "$keeper.new"
    mv -f "$keeper.new" "$keeper"

    # setsid where it exists, so the loop survives the shell that ran the
    # installer going away — an install piped from curl in an SSH session that
    # then closes is the ordinary case, not the exotic one.
    # Who starts the loop. On OpenWrt, procd does: the helper writes and
    # enables its own init script (see PROCD_INIT above), and starting THAT
    # is both the launch and the promise of the next boot. Found on a stock
    # OpenWrt 23.05, which has neither setsid nor nohup — the two lines below
    # were the whole launch, so the installer there "succeeded" and started
    # nothing.
    started_by=''
    # The switch that stops the helper arranging this unasked stops the
    # installer too: `autostart` typed by a person ignores it on purpose, and
    # a reinstall is not that person. Off means the loop is launched the old
    # way below and nothing is registered for the next boot.
    autostart_off=''
    case "$(printf '%s' "${MON_AUTOSTART:-}" | tr 'A-Z' 'a-z')" in
      0|off|false|no) autostart_off=1 ;;
    esac
    [ -f "$conf/autostart-off" ] && autostart_off=1
    if [ -z "$autostart_off" ] && [ -f /etc/openwrt_release ] && [ "$(id -u)" = 0 ]; then
        "$BINDIR/$NAME" autostart >/dev/null 2>&1 || true
        if procd_is_ours && "$PROCD_INIT" start >/dev/null 2>&1; then
            started_by=procd
        fi
    fi
    if [ -n "$started_by" ]; then
        :
    elif command -v setsid >/dev/null 2>&1; then
        setsid "$keeper" >>"$keeperlog" 2>&1 </dev/null &
    elif command -v nohup >/dev/null 2>&1; then
        nohup "$keeper" >>"$keeperlog" 2>&1 </dev/null &
    else
        # Neither. A plain background job, detached from this script's
        # input and output: best effort — the loop traps HUP for its own
        # clean exit (measured on BusyBox ash: an inherited ignore does not
        # survive that), so a hangup that reaches it ends it. It rarely does:
        # by then this script has exited and the loop is nobody's job.
        ( trap '' HUP; exec "$keeper" ) >>"$keeperlog" 2>&1 </dev/null &
    fi

    # Best effort at surviving a reboot. Quoted through shquote for the shell
    # cron hands the line to, and '%' escaped for cron itself, which reads it
    # as "end of command, rest is stdin" before any shell sees it. Matched with
    # -F on the way out, so a path with a '.' in it is a string and not a
    # pattern.
    # Not on Android: a crontab there (Termux's cronie) runs only while
    # somebody started crond, which nothing does at boot. Termux:Boot is the
    # road there, arranged by the android branch below.
    if [ -z "$started_by" ] && [ -z "$android" ] && command -v crontab >/dev/null 2>&1; then
        cronline=$(printf '@reboot %s >>%s 2>&1' \
            "$(shquote "$keeper")" "$(shquote "$keeperlog")" | sed 's/%/\\%/g')
        (crontab -l 2>/dev/null | grep -vF "$keeper"; printf '%s\n' "$cronline") \
          | crontab - 2>/dev/null || true
    fi

    if [ "$started_by" = procd ]; then
        say "OpenWrt: the helper runs as a procd service and starts at boot:"
        say "  $PROCD_INIT  (start | stop | disable)"
        say "  log:  logread -e keeper"
        return 0
    fi
    say "no service manager here (systemd is absent or is a stand-in), so a"
    say "keep-alive loop was started instead:  $keeper"
    say "  log:  $keeperlog"
    say "  stop: kill \$(cat $lock/pid)"
    # What brings it back after a reboot on Android is the android branch's
    # to say — Termux:Boot, or nothing.
    [ -n "$android" ] && return 0
    if ! command -v crontab >/dev/null 2>&1; then
        say "note: no crontab here either, so this does not survive a reboot."
        say "      Run install.sh again, or start the helper from whatever"
        say "      starts this machine's other services."
    fi
}

# ------------------------------------------------------------------ service
case "$goos" in
  android)
    # No systemd, no cron, and on a phone no login to start anything at. The
    # keeper loop is written and started as on any other machine without a
    # service manager; what differs is the next boot. Under Termux that is
    # Termux:Boot's job — a companion app that runs whatever is in
    # ~/.termux/boot/ once the device has been unlocked — so a script that
    # starts the loop is left there, after taking Termux's wake lock, without
    # which the CPU sleeps and the pushes stop. Outside Termux (a shell over
    # adb, a rooted shell) nothing can be registered from here, and the line
    # that brings it back is printed instead. Doze and the phantom-process
    # limit are Android's, not this script's to lift; they are said out loud.
    rm -f "$conf/service.env.new"
    {
        [ -n "$TOKEN" ] && printf 'SUBNSUB_MONITOR_TOKEN=%s\n' "$TOKEN"
        [ -n "$SITE" ] && printf 'SUBNSUB_MONITOR_SITE=%s\n' "$SITE"
        true
    } > "$conf/service.env.new"
    chmod 0600 "$conf/service.env.new"
    mv -f "$conf/service.env.new" "$conf/service.env"
    keeper_start
    if [ -n "$termux" ]; then
        bootdir="$HOME/.termux/boot"
        mkdir -p "$bootdir"
        rm -f "$bootdir/$NAME.new"
        {
            printf '#!%s\n' "$PREFIX/bin/sh"
            printf '# Generated by the subnsub-monitor installer; Termux:Boot runs it at boot.\n'
            printf '# Do not edit: reinstalling overwrites it.\n'
            printf 'termux-wake-lock 2>/dev/null || true\n'
            printf 'nohup %s >>%s 2>&1 </dev/null &\n' \
                "$(shquote "$conf/keeper.sh")" "$(shquote "$conf/keeper.log")"
        } > "$bootdir/$NAME.new"
        chmod 0700 "$bootdir/$NAME.new"
        mv -f "$bootdir/$NAME.new" "$bootdir/$NAME"
        # Termux's own wake lock for THIS session too: a loop started from an
        # interactive session is otherwise suspended with the screen.
        if command -v termux-wake-lock >/dev/null 2>&1; then
            termux-wake-lock 2>/dev/null || true
        fi
        say ""
        say "Termux: starts at boot through Termux:Boot — $bootdir/$NAME"
        say "  1. install the Termux:Boot app (F-Droid) and open it once, or nothing runs at boot"
        say "  2. Settings → Apps → Termux → Battery → Unrestricted, or Doze pauses the pushes"
        say "  3. Android 12+ kills an app's child processes past 32 in total; over adb:"
        say "       adb shell settings put global settings_enable_monitor_phantom_procs false"
    else
        say ""
        say "Android without Termux: nothing here can start this at boot. After a reboot:"
        say "  nohup $conf/keeper.sh >>$conf/keeper.log 2>&1 </dev/null &"
    fi
    ;;

  linux)
    unitdir="$HOME/.config/systemd/user"
    mkdir -p "$unitdir"
    # systemd parses EnvironmentFile values with its own quote/backslash
    # grammar. The CLI Proxy API key may legitimately contain those characters,
    # so only the already shape-checked Monitor token and site belong here; the
    # helper reads the raw values from the private token config itself.
    rm -f "$conf/service.env.new"
    {
        [ -n "$TOKEN" ] && printf 'SUBNSUB_MONITOR_TOKEN=%s\n' "$TOKEN"
        [ -n "$SITE" ] && printf 'SUBNSUB_MONITOR_SITE=%s\n' "$SITE"
        true
    } > "$conf/service.env.new"
    chmod 0600 "$conf/service.env.new"
    mv -f "$conf/service.env.new" "$conf/service.env"
    # How much of the machine this service can touch, and it depends on whether
    # the console is on — because those are two different programs in every way
    # that matters to a sandbox.
    #
    # Without the console it reads two files and makes one outbound request, so
    # it is confined to almost nothing. With the console it runs commands the
    # operator types, and a confinement that made `mkdir` fail would not be
    # security, it would be a console that does not work. The operator asked
    # for a shell on this box; giving them one that cannot write anything and
    # not saying so is the dishonest option.
    #
    # ProtectHome/ProtectSystem apply to the WHOLE cgroup, children included,
    # so there is no version of this where the helper stays confined and the
    # commands it spawns do not. Hence the either/or.
    if [ -f "$conf/console" ]; then
        SANDBOX="# The console is on: commands you type on the dashboard run in this
# service's cgroup, so the filesystem confinement below is deliberately the
# ordinary one for a user service. NoNewPrivileges still holds — nothing here
# can gain privileges this user does not already have — and turning the console
# off (subnsub-monitor console off, then reinstall) puts the strict sandbox back.
NoNewPrivileges=true
ProtectKernelTunables=true
RestrictSUIDSGID=true"
    else
        # The strict sandbox, with one hole — or two, when this machine is
        # allowed to update itself.
        #
        # ProtectHome=read-only means the helper cannot write its own binary,
        # which is the correct default and is also exactly what a self-update
        # has to do. So the second hole is opened only for a machine whose
        # operator asked for that, and it is opened as narrowly as the
        # directory allows: $BINDIR, not \$HOME.
        #
        # This is a real widening and worth being clear-eyed about — it makes
        # the one file the service executes writable by the service. What keeps
        # that honest is on the other side: the payload comes from the release
        # bucket over TLS and must match the published checksum, and nothing
        # downloads until somebody presses a button. See go/update.go.
        UPD_HOLE=""
        [ -f "$conf/update" ] && UPD_HOLE="
# This machine may update itself, so the directory holding the binary it
# replaces has to be writable by it. Nothing else in \$HOME is.
ReadWritePaths=-$BINDIR"
        SANDBOX="# It reads two files and makes one outbound request; it needs nothing else.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
# …with one hole, and only this one: the directory holding this machine's
# dashboard id. Without it, a host that actually enforces the sandbox above
# gives the helper a read-only \$HOME, the id cannot be written, and every
# restart shows up at the relay as a different machine. The leading '-' makes
# it optional, so deleting the directory downgrades the helper rather than
# leaving a unit that refuses to start.
ReadWritePaths=-$conf$UPD_HOLE
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true"
    fi
    cat > "$unitdir/$NAME.service" <<EOF
[Unit]
Description=subnsub-monitor — pushes AI coding quota to $RELAY
After=network-online.target

[Service]
Type=simple
EnvironmentFile=$conf/service.env
ExecStart=$BINDIR/$NAME connect $RELAY
Restart=always
RestartSec=30
$SANDBOX
[Install]
WantedBy=default.target
EOF
    if have_systemd_user; then
        # A box that GAINED a real systemd — an image rebuilt on a systemd
        # base, a container promoted to a VM — still has the keep-alive loop
        # and the @reboot line an earlier install left. Without this the unit
        # below starts a SECOND helper beside the one the loop is already
        # restarting, and the machine arrives at the relay twice.
        keeper_stop
        helper_stop_strays
        systemctl --user daemon-reload
        systemctl --user enable --now "$NAME.service"
        # `enable --now` starts a stopped unit but leaves a running one alone,
        # so reinstalling over an existing install would keep the OLD binary,
        # token and relay URL running while reporting success.
        systemctl --user restart "$NAME.service"
        say "started (systemctl --user status $NAME)"
        # Without lingering, the user manager stops at logout and takes the
        # helper with it — exactly wrong on a VPS you SSH into occasionally.
        if command -v loginctl >/dev/null 2>&1; then
            loginctl enable-linger "$(id -un)" 2>/dev/null \
              || say "note: could not enable lingering; it will stop when you log out."
        fi
    else
        # The unit FILE above is still written, and deliberately: it costs
        # nothing, it documents what this install is, and a machine that later
        # gains a real systemd is then one `systemctl --user enable` away from
        # being an ordinary install.
        #
        # Its ENABLEMENT is the opposite case and has to go. A unit left
        # enabled from a previous install is a supervisor waiting to happen:
        # the day this box gets a real systemd, it starts a helper of its own
        # beside the keep-alive loop below. The symlink goes, the file stays.
        # A stand-in systemctl will make a noise or a traceback here rather
        # than doing anything, which is why nothing is checked.
        systemctl --user disable --now "$NAME.service" >/dev/null 2>&1 || true
        keeper_start
    fi
    ;;

  darwin)
    plistdir="$HOME/Library/LaunchAgents"
    mkdir -p "$plistdir"
    cat > "$plistdir/$LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BINDIR/$NAME</string>
    <string>connect</string>
    <string>$RELAY</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>$([ -n "$TOKEN" ] && printf '<key>SUBNSUB_MONITOR_TOKEN</key><string>%s</string>' "$TOKEN")$([ -n "$SITE" ] && printf '<key>SUBNSUB_MONITOR_SITE</key><string>%s</string>' "$SITE")</dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
</dict>
</plist>
EOF
    chmod 0600 "$plistdir/$LABEL.plist"
    launchctl unload "$plistdir/$LABEL.plist" 2>/dev/null || true
    launchctl load "$plistdir/$LABEL.plist"
    say "started (launchctl list | grep $LABEL)"
    ;;

  freebsd)
    # NOTHING IS REGISTERED HERE, and that is a decision rather than an
    # omission worth being explicit about.
    #
    # FreeBSD has no per-user service manager. The two ways to start something
    # at boot are an rc.d script, which lives in /usr/local/etc/rc.d and needs
    # root, and the user's crontab, which is not inside this script's promise
    # that nothing is written outside your home directory. Quietly doing
    # neither would be the worst of the three: an install that reports success
    # and stops the next time the machine reboots.
    #
    # So the binary, the token and the machine id are all in place, and the two
    # commands that finish the job are printed.
    say ""
    say "FreeBSD: no per-user service manager, so nothing was registered."
    say "start it now:     daemon -f $BINDIR/$NAME connect $RELAY"
    say "keep it at boot:  as root, drop this in /usr/local/etc/rc.d/subnsubmonitor"
    say "                  and add subnsubmonitor_enable=\"YES\" to /etc/rc.conf:"
    say ""
    say "                    #!/bin/sh"
    say "                    # PROVIDE: subnsubmonitor"
    say "                    # REQUIRE: NETWORKING"
    say "                    # KEYWORD: shutdown"
    say "                    . /etc/rc.subr"
    say "                    name=subnsubmonitor"
    say "                    rcvar=subnsubmonitor_enable"
    say "                    command=$BINDIR/$NAME"
    say "                    command_args=\"connect $RELAY\""
    say "                    subnsubmonitor_user=$(id -un)"
    # HOME has to be set explicitly: rc.subr keeps root's environment when it
    # drops privileges, and everything this helper owns — the token, the machine
    # id, the name — is under ~/.config. Without it the service comes up as a
    # brand new unnamed machine on every boot, or does not authenticate at all.
    say "                    subnsubmonitor_env=\"HOME=$HOME\""
    say "                    load_rc_config \$name"
    say "                    run_rc_command \"\$1\""
    ;;
esac

say ""
if [ -n "$TOKEN" ]; then
    say "pushing to $RELAY every 30s."
else
    say "no relay token: this machine is reachable through the direct tunnel only."
fi
say "check locally:  $BINDIR/$NAME"
# Direct mode, stated on every install whichever way it is set, like the
# grants above: a machine that a browser can reach without any server of ours
# is something the person standing here should hear about. The address is
# published by the running tunnel a few seconds after it starts, so wait for
# it briefly and print it — that is the one thing the person needs to carry
# back to the page.
if [ -f "$conf/direct" ]; then
    if [ -f "$conf/derpmap" ]; then
        say "direct:         ON — tunnelled via your own DERP map ($(cat "$conf/derpmap"))."
    else
        say "direct:         ON — tunnelled via the public tailcat DERP (best effort, no guarantee)."
    fi
    if [ ! -s "$conf/allowed-clients" ]; then
        say "                no browser is allowed yet, so the tunnel is not running:"
        say "                  $BINDIR/$NAME allow <nodekey:...>   (the key is on the Monitor page)"
    else
        if [ -n "$PAIR_ARG" ]; then
            say "                paired by this line: the machine appears by itself on the Monitor"
            say "                page that made it, within a minute of that page being open, for a week."
        fi
        n=0
        while [ $n -lt 20 ] && [ ! -s "$conf/address" ]; do sleep 1; n=$((n+1)); done
        if [ -s "$conf/address" ] && [ -n "$PAIR_ARG" ]; then
            say "                address — only if it does not appear, paste it on that page:"
            say ""
            say "                  $(cat "$conf/address")"
            say ""
        elif [ -s "$conf/address" ]; then
            say "                address — paste it on the Monitor page:"
            say ""
            say "                  $(cat "$conf/address")"
            say ""
        else
            say "                the address is printed by:  $BINDIR/$NAME address"
        fi
        say "                add another browser with:  $BINDIR/$NAME allow <nodekey:...>"
    fi
    say "                off with:  $BINDIR/$NAME direct off   (then restart)"
fi
# Stated on every install, not only when it was just switched on: a machine
# that can be typed at from a web page is something the person standing here
# should be told about, including when they inherited the setting from whoever
# installed it last.
if [ -f "$conf/console" ]; then
    say "console:        ON — the dashboard can run commands here as $(id -un),"
    say "                over the encrypted direct tunnel only, never through the relay."
    say "                off with:  $BINDIR/$NAME console off"
else
    # Deliberately does not say "turn it on and you are done". On Linux the
    # unit written above is sandboxed read-only, and this switch cannot change
    # that — a console turned on afterwards can look but not write until the
    # installer runs again. `console on` says the same thing at the machine.
    say "console:        off. Turn it on with:  $BINDIR/$NAME console on"
    case "$goos" in
      linux) say "                (on Linux, re-run this installer with --console for a console that can write)" ;;
    esac
fi
# Stated on every install too, and for the same reason: "the dashboard can
# replace the program running here" is something the person standing at the
# machine should be told, not only the person who asked for it.
if [ -f "$conf/console" ]; then
    say "update:         ON — implied by the console, which can already run this installer."
elif [ -f "$conf/update" ]; then
    say "update:         ON — the dashboard can replace this helper. Nothing downloads"
    say "                until you press it, and only a checksummed release will install."
    say "                off with:  $BINDIR/$NAME update off"
else
    say "update:         off. Turn it on with:  $BINDIR/$NAME update on"
    case "$goos" in
      linux) say "                (on Linux, re-run this installer with --remote-update — the strict" ;;
    esac
    case "$goos" in
      linux) say "                 sandbox will not let the helper write its own binary otherwise)" ;;
    esac
fi
# The read-only one, said out loud like the others. Not a switch: wherever
# /proc shows other processes the names are read.
case "$goos" in
  linux|android)
    say "diagnostics:    on — the dashboard can read a top-process table here, and the"
    say "                CPU history keeps program names. Read-only, names only." ;;
esac
# How many network namespaces the machine shows and which one this helper is
# in: a router with a VPN in a namespace of its own has two, and the card
# names them (go/spaces_linux.go netnsInfo).
case "$goos" in
  linux|android)
    ns=$("$BINDIR/$NAME" netns 2>/dev/null || true)
    [ -n "$ns" ] && say "namespaces:     $ns" ;;
esac
# Session search ships inside the helper itself, so the only question is
# whether the channel it rides is open on this machine.
if [ -f "$conf/console" ]; then
    say "sessions:       searchable from the dashboard (built into the helper; console is on)."
fi
# And the archive, stated on every install whichever way it is set: this is the
# one switch that sends conversations off the machine, so the person standing
# here is told what it is doing, not only the person who asked for it.
if [ -f "$conf/sessions-sync" ]; then
    say "session archive: ON — this machine's agent conversations are redacted and kept"
    say "                in your account's archive, readable from the dashboard while"
    say "                this machine is offline."
    say "                off with:  $BINDIR/$NAME sessions sync off"
else
    say "session archive: off. Turn it on with:  $BINDIR/$NAME sessions sync on"
fi
say "uninstall:      sh install.sh --uninstall"
