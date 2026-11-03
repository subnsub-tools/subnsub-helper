# subnsub-monitor

The open-source host agent for [SUB&SUB Monitor](https://tools.subnsub.com/monitor) — a single static Go binary that runs on remote machines, collects AI coding tool quotas and system health metrics, and reports them outbound without opening any inbound ports.

```
  Remote machine                                       Browser
  ┌──────────────────┐                           ┌─────────────────┐
  │  subnsub-monitor │── HTTPS push ──▶ Relay ◀──│  Monitor page   │  Relay mode (with account)
  │                  │                           │                 │
  │                  │◀══ WireGuard (tailcat) ══▶│                 │  Direct mode (no account,
  └──────────────────┘    via DERP relay         └─────────────────┘  no relay, no token)
```

Nothing listens on the machine for the internet. The helper dials out: either pushing snapshots over HTTPS to the relay, or establishing an end-to-end encrypted WireGuard tunnel (via a DERP relay) that only authorized browsers can open. The one exception is direct mode on a machine that is on a Tailscale network, which also answers on its Tailscale address (see [Tailnet road](#tailnet-road)).

This repository contains the Go helper (`go/`), the installation scripts (`install.sh`, `install.ps1`), ready-to-use custom metric definitions (`metrics.d.examples/`), and the single-file Python reference implementation (`reference/monitor.py`). For a complete breakdown of what leaves the machine, what the relay stores, and how command signing works, see the [Trust & Security Model](https://tools.subnsub.com/monitor-security).

## Contents

- [Installation](#installation)
  - [Android over USB](#android-over-usb)
- [Direct mode](#direct-mode)
  - [Pairing](#pairing)
- [Supported providers](#supported-providers)
  - [Subprocess execution rules](#subprocess-execution-rules)
- [Security & privacy model](#security--privacy-model)
- [System metrics](#system-metrics)
- [Machine identity & naming](#machine-identity--naming)
- [Remote console & command signing](#remote-console--command-signing)
  - [Command signing (`trust`)](#command-signing-trust)
  - [Portable terminal access (`clone`)](#portable-terminal-access-clone)
- [Updates](#updates)
- [Coding-agent sessions](#coding-agent-sessions)
- [Service checks](#service-checks)
- [Custom metrics (`metrics.d`)](#custom-metrics-metricsd)
  - [Command-backed tiles (`exec`)](#command-backed-tiles-exec)
  - [Tile actions](#tile-actions)
  - [Built-in icons](#built-in-icons)
  - [Pushing metrics over `metrics.sock`](#pushing-metrics-over-metricssock)
  - [Custom quota cards](#custom-quota-cards)
  - [Example definitions](#example-definitions)
- [CLI Proxy API](#cli-proxy-api)
- [CLI reference](#cli-reference)
- [Environment variables](#environment-variables)
- [Configuration & state files](#configuration--state-files)
- [Building from source](#building-from-source)
- [Reference implementation](#reference-implementation)
- [Attribution](#attribution)
- [Reporting issues](#reporting-issues)
- [License](#license)

## Installation

**Supported platforms:** `linux/amd64`, `linux/arm64`, `linux/arm` (ARMv7), `darwin/amd64`, `darwin/arm64`, `freebsd/amd64`, `freebsd/arm64`, and `android/arm64` (installed over USB).

```sh
curl -fsSL https://tools.subnsub.com/monitor/install.sh | sh -s -- <TOKEN>
```

To inspect the script before running it:

```sh
curl -fsSL https://tools.subnsub.com/monitor/install.sh -o install.sh
less install.sh && sh install.sh <TOKEN>
```

The installer places a single static binary in `~/.local/bin/subnsub-monitor` and registers it to start at login — a systemd **user** unit on Linux (or a `crontab @reboot` keep-alive loop where user systemd is unavailable), and a LaunchAgent on macOS. It requires no `sudo` and writes nothing outside your home directory.

To uninstall:

```sh
sh install.sh --uninstall
```

Uninstalling stops the service, notifies the relay that the machine has been removed, and deletes the binary and credentials while preserving local configuration you may want to keep (`trusted-keys`, `econ-key`, `history.jsonl`, and `metrics.d/`). Remove `~/.config/subnsub-monitor` manually for a complete wipe.

The `<TOKEN>` comes from your signed-in Monitor dashboard. You can use the same token on every machine you want to watch; each machine generates its own random `agent_id` on first run and appears as a separate card. All flags below are optional:

| Flag | Description |
|---|---|
| `--name "tokyo build box"` | Set the display name shown on the machine card (never inferred from the hostname) |
| `--console` | Allow the dashboard to run shell commands on this machine (off by default; see [Remote console & command signing](#remote-console--command-signing)) |
| `--remote-update` | Allow the dashboard to trigger binary updates (implied by `--console`) |
| `--auto-update` | Check hourly for newer releases and install automatically (requires remote updates enabled) |
| `--sessions-sync` | Redact and sync local coding-agent transcripts to your account archive |
| `--direct --allow nodekey:…` | Enable direct mode for the specified browser node key (no account or token required; see [Direct mode](#direct-mode)) |
| `--pair <token>` | Pair with the self-hosted Monitor page that made the line, for the last `--allow` key on it, so the machine shows up there without its address being pasted back (see [Pairing](#pairing)) |
| `--derpmap https://…` | Use a custom DERP map URL instead of the default public map |
| `--music` | With `--direct`, share this account's Music folder with the browsers on the direct allowlist; on a machine that already runs the helper, the same line switches it on there (`--music=off` stops sharing; see [Music](#music)) |
| `--music-dir PATH` | Share this folder instead (repeatable; implies `--music`) |

When copied from a signed-in dashboard, the install command also sets `MON_PUBKEY=…` to pin your dashboard's Ed25519 public key in `~/.config/subnsub-monitor/trusted-keys` (see [Command signing (`trust`)](#command-signing-trust)).

**Inline checksum verification:** `install.sh` embeds the expected SHA-256 checksums for every published binary directly in the script (`SUM_*`). Verify downloaded scripts against [`install.sh`](install.sh) in this repository or build from source to confirm binary reproducibility.

**Platform notes:**
- **FreeBSD:** Because FreeBSD has no default per-user service manager, `install.sh` installs the binary and token without modifying system files, then prints a ready-to-use `daemon(8)` command and an `/etc/rc.d` script you can install if desired.
- **OpenWrt:** When run as `root`, the helper registers `/etc/init.d/subnsub-monitor` (`procd`) via `subnsub-monitor autostart` so it survives router reboots.
- **Windows:** Windows support is maintained in the Go source tree behind `//go:build windows` tags, but prebuilt Windows binaries are not currently published (`install.ps1` declines with placeholder checksums).

### Android over USB

Android devices are installed from a desktop browser (Chrome or Edge) over USB rather than from Termux. Running inside Termux executes under an Android app UID, where SELinux and `/proc` restrictions hide system CPU usage, load average, disk I/O, network counters, process counts, and thermal sensors.

With **USB debugging** enabled on the phone, open the [Monitor page](https://tools.subnsub.com/monitor) on a desktop computer and choose **Android phone over USB** in the install card:
1. The browser speaks ADB over WebUSB, downloads `subnsub-monitor-android-arm64`, verifies its SHA-256 against `SHA256SUMS`, pushes it to `/data/local/tmp`, and starts it as the `shell` user (UID 2000), which has read access to system health metrics without root.
2. Standard ADB shell processes do not survive a reboot. On rooted devices with **Magisk**, enabling the root option in the dialog installs the helper under `/data/adb/subnsub-monitor` with a `/data/adb/service.d` boot script.
3. Supported on Android 11 and later. Set `MON_DNS=<ip>[,<ip>]` if the device blocks the shell user from querying the system DNS resolver. Run `subnsub-monitor selftest` to inspect what the device allows the helper to read.

## Direct mode

Direct mode connects your browser straight to the machine without an account, a relay token, or any SUB&SUB server storing your metrics:

```sh
curl -fsSL https://tools.subnsub.com/monitor/install.sh | sh -s -- --direct --allow nodekey:<YOUR_BROWSER_KEY>
```

The Direct card on the Monitor page generates a browser node key and prints this command. When installation completes, the helper opens an end-to-end encrypted WireGuard tunnel (using the tailcat data plane over a DERP relay) and prints its `tc1:…` address. Paste that address into the Monitor page to connect directly.

- **Zero server-side storage:** The DERP relay forwards encrypted WireGuard packets only. By default the helper uses the public tailcat DERP map; pass `--derpmap` / `MON_DERPMAP` to use your own DERP server. All metrics and 30-day history stay on the machine and in your browser.
- **Relay features not present in standalone direct mode:** Cloud presence history, relay-stored trends while the machine is unreachable, cloud session archiving, web push notifications, and cross-machine account folding require an account and relay connection.
- **Read-only by default:** The tunnel only starts when at least one browser key is listed in `~/.config/subnsub-monitor/allowed-clients` (`subnsub-monitor allow <key>` / `disallow <key>`). Allowing a browser node key grants **read-only** observation (`hello`, snapshots, 1 Hz health stream, and local history). Commands and interactive terminals require the browser's Ed25519 signing key to be pinned in `trusted-keys` (`MON_PUBKEY` or `subnsub-monitor trust <key>`).
- **Hybrid mode (Relay + Direct):** When configured with both a relay token and `--direct`, both transports run side by side. Interactive terminals and plaintext shell commands always travel exclusively over the direct tunnel, never through the relay. Set `MON_TRANSPORT=relay` or `MON_TRANSPORT=tailcat` to force a single transport.
- **CLI controls:** `subnsub-monitor direct on|off`, `allow`, `disallow`, `address` (prints the direct address and node key, and a pairing still waiting), and `transfer on|off` (allows an authorized browser to relay an end-to-end encrypted peer-to-peer file transfer stream through the tunnel when direct WebRTC fails; enabled by default when direct mode is on).

### Tailnet road

From helper 2026.11.03.1, a machine in direct mode that is on a Tailscale network also listens on its Tailscale address (normally port 8126), so a browser on a computer that runs Tailscale reaches it through the operating system's Tailscale, directly over UDP whenever Tailscale can manage it, instead of through DERP. The page tries this road first, then the tunnel, then the relay.

- **Found without the CLI:** the address comes from the machine's interfaces and the name from Tailscale's resolver at `100.100.100.100` (`tailnet.go`). Nothing listens while Tailscale is down or no browser key is allowed. `MON_TAILNET=off` keeps the port closed.
- **The network is not trusted:** anything on the tailnet can reach the port. A browser takes the machine's X25519 key from a hello that came through the tunnel, its own key must be on `allowed-clients`, and a session is derived from both plus a fresh key on each side (HKDF-SHA256). Every request and answer is AES-256-GCM to that session, numbered so none can be replayed, cut short or moved. A struck key is refused on its next request.
- **What it carries:** the same read-only view, commands, terminals and music as the tunnel. Transfers stay on the tunnel.
- **Browsers:** Chrome, which can reach a local network address from an https page once the user allows local network access. Other browsers stay on the tunnel. See [the Monitor docs](https://tools.subnsub.com/monitor-docs) for the API.

### Music

From helper 2026.11.04.1, a machine in direct mode can share the music on it with the browsers on its `allowed-clients` list. The Monitor page's music player reads it over the tailnet road or the tunnel, never through the relay: no music route is reachable from the relay's mailbox, and the `music` command kind is refused there (`music.go`).

- **Switched on at the machine:** `subnsub-monitor music on` (with nothing shared yet, it shares the account's Music folder), `music add FOLDER`, `music add-webdav URL [--user NAME]` (the password comes from `MON_WEBDAV_PASSWORD` or is asked for), `music remove ID|FOLDER|URL`, `music rescan`, `music off`, and `music` to list what is shared. At install, `--music` turns it on (`--music-dir PATH`, repeatable, names folders; `--music=off` turns it off); rerunning the install line with `--music` on a machine that already has the helper switches it on there. `MON_MUSIC=off` keeps it off for a run.
- **Only what the walk indexed:** a folder is walked for audio files (MP3, AAC/M4A, FLAC, Ogg/Opus, WAV, AIFF, WebM, CAF), at most 16 folders per machine, 100,000 tracks per folder and 24 levels deep. A request names a track by its path in that folder's index and is answered only if the index holds it; local reads go through `os.Root`, which refuses any path that leaves the folder. Tags, durations and covers are read on the machine (`musictags.go`); covers are scaled there (128, 256, 512 or 1024 px).
- **What travels:** `GET /v1/music` (the folders, their track counts and revisions), `/v1/music/index` (one page of a folder's tracks), `/v1/music/file` (a range of a track's bytes, at most 4 MiB per request) and `/v1/music/art` (a scaled cover), all over the tunnel or the tailnet road, sealed as everything else there is.
- **WebDAV:** a WebDAV folder (a NAS, Nextcloud) is listed with `PROPFIND` and read by range by the helper itself (`musicdav.go`). A browser whose signing key the machine has pinned may add one, look through any folder again, or stop sharing one, by a signed `music` command over the tunnel; it cannot name a local folder, which is added only at the machine. The account and password are kept in `music.json` (mode `0600`) on the machine and nowhere else. A server whose certificate the system does not trust is refused until its SHA-256 fingerprint is pinned (`cert-untrusted` carries the fingerprint for the page to show); a changed certificate is refused as `cert-changed`.

### Pairing

From helper 2026.10.28.1 the self-hosted Monitor page (`/monitor`) adds `--pair <token>` to its line, and pins its own signing key with `MON_PUBKEY`. The token is a one-time tailcat identity that page made for this machine: 64 hex characters of a node private key, a dot, and that node's `tc…` address, which names one DERP region. The installer writes it, with the browser key it is for, to `~/.config/subnsub-monitor/pairing` (mode `0600`).

While the file is there and the machine's own tunnel is up, the helper starts a second, short-lived node under that identity (`pairing.go`, `transport/pair.go`). It admits only that one browser key, re-checked against `allowed-clients` on every request, and serves one frame: `GET /v1/pair` answers with the machine's own tunnel address. The page then dials that address like any other. The pairing is deleted once that browser says hello to the machine's own node after the pairing was written, once its key is disallowed, or a week after the file was written, whichever comes first.

The machine's own node key, pre-shared key and region are generated on the machine as always and never travel in a line. Until the pairing is done, treat the line like a password: whoever runs it first is the machine the page shows.

## Supported providers

The helper collects AI coding quotas across four collection methods, plus custom quota scripts:

| Collection method | Providers | How it works | Credentials read by helper |
|---|---|---|---|
| **Vendor CLI** | Codex (`codex app-server`, JSON-RPC over stdio), Amp (`amp usage`), Kiro (`kiro-cli chat --no-interactive /usage`) | Runs the official CLI and parses its output; network requests are made by the vendor CLI itself, except that before running `kiro-cli` the helper sends one credential-less `HEAD` to each of `codewhisperer.us-east-1.amazonaws.com` and `q.eu-central-1.amazonaws.com` and skips the CLI when neither answers (offline, `kiro-cli` opens sign-in pages in a browser) | None |
| **Loopback server** | Antigravity (IDE language server, or `agy -p /usage` CLI fallback) | Connects to the local language server on `127.0.0.1` using its process `--csrf_token` (or falls back to `~/.gemini/antigravity-cli` / `agy` on Linux) | Local token only; nothing sent to third parties |
| **Local credential file** | Claude Code (`~/.claude/.credentials.json` or macOS Keychain), GitHub Copilot (`~/.config/github-copilot/apps.json`), Kimi (`~/.kimi-code/credentials/kimi-code.json`), Grok (`~/.grok/auth.json`), Kilo (`~/.local/share/kilo/auth.json`) | Reads the access token stored by the CLI and queries the vendor's official usage endpoint directly (read-only) | Held in memory for a single HTTPS request to the vendor |
| **CLI Proxy API** | Any credential managed by CLI Proxy API | Queries the proxy's local management API (see [CLI Proxy API](#cli-proxy-api)) | Proxy management key only |

For **Codex**, if no executable Codex binary is available, the helper falls back to reading the latest rate-limit envelope recorded in `~/.codex/sessions/**/rollout-*.jsonl`. From `~/.codex/auth.json`, only the non-secret `id_token` claims (email and account ID) are decoded to label the account; `access_token` and `refresh_token` are never parsed.

Every reading reports the quota windows (used percentage, window duration, reset timestamp, and monetary/credit amounts), the plan label, and the **account identifier** (email or handle) so the dashboard can deduplicate shared accounts across multiple machines. Providers that are not installed on a machine report `not-signed-in` and are folded into a single summary line.

### Subprocess execution rules

For collectors that invoke a local CLI (`codex`, `amp`, `kiro-cli`, `agy`), the helper enforces strict execution boundaries (`go/clirun.go`):

- Binaries are resolved against a fixed list of known installation paths and standard package manager prefixes rather than trusting an arbitrary `PATH` entry first (`MON_AMP_BIN`, `MON_AGY_BIN`, `MON_CODEX_BIN`, and `MON_KIRO_BIN` override the path; an invalid override fails closed).
- World-writable binaries and parent directories are refused.
- Subprocesses run with `stdin` connected to `/dev/null`, a strict execution timeout, bounded output buffers, and a minimal environment.
- Error messages never echo the executable file path, preventing local OS usernames in home directory paths from appearing in published error states.

## Security & privacy model

**Reading a credential locally never means transmitting it.**

- **Credentials stay on the machine:** OAuth and API tokens read from disk or the macOS Keychain are used for a single HTTPS request to the issuing vendor's hardcoded endpoint and immediately discarded from memory. They are never logged, cached on disk, or sent to the relay. In `~/.claude/.credentials.json`, only the four scalar fields under `claudeAiOauth` are read; `mcpOAuth` entries are untouched.
- **Read-only credential access:** The helper never refreshes tokens or modifies credential files. If a token expires, the helper reports `token-expired` until the vendor CLI renews it.
- **Sanitized error reporting:** Because collector error codes are included in snapshots, raw HTTP library errors, URLs, and headers are never interpolated into published output. All failures map to a closed vocabulary of error and detail codes (`go/detail.go`).
- **No intrusive host access:** The helper never reads browser cookies, shell history, SSH keys, or arbitrary environment variables, and never requests macOS Full Disk Access.
- **Music only when shared:** nothing in a music folder is read until music is switched on at the machine; then only the audio files and covers in the shared folders, and only for the browsers on the direct allowlist, over the tunnel or the tailnet road, never through the relay (see [Music](#music)).
- **Quota request pacing:** Remote vendor APIs are queried on demand when you click refresh (or at most once every 10 minutes while actively watching a machine configured for automatic refresh), preventing background rate-limit exhaustion (`go/pace.go`).

**What is included in a snapshot (`go/types.go`):**
- Provider quota percentages, window lengths, reset times, plan labels, and account email/handle.
- System health metrics (with kernel version truncated to `major.minor`, e.g., `6.8` rather than `6.8.0-1050-oracle`, to avoid fingerprinting cloud images).
- Network interface names and addresses, plus public IPv4 (queried every 30 minutes via `https://1.1.1.1/cdn-cgi/trace`; disable with `MON_IPV4=off`).
- Sanitized mount paths (paths under `/home/...`, `/Users/...`, `/run/media/...`, or `/media/...` collapse to their root prefix so OS usernames are never sent). A Mac's external disks are sent as `/Volumes/<name>`, one row each; the system's own volumes (`/System/...`, simulator runtimes, read-only hidden mounts) are not sent, and the root figure counts the whole APFS container.
- Installed coding-agent CLI versions, read directly from package manifests on disk without executing `--version` (`go/clis.go`; disable with `MON_CLIS=off`).
- Token counts for Claude Code, Codex, Antigravity and Amp: by UTC hour (the last 25) and UTC day (the last 32), per tool and model, in five kinds (input, output, cache read, cache write, reasoning) with a reply count. Numbers and model names only, never a prompt, a reply, a path or a session id (`go/tokens.go`; disable with `MON_TOKENS=off`). Where they come from:
  - Claude Code and Codex: their transcripts on disk.
  - Antigravity: its conversation databases on disk (`~/.gemini/antigravity-cli/conversations/*.db`, and the editor extension's `~/.gemini/antigravity/conversations/*.db`), opened read-only by a small SQLite file-format reader of the helper's own (`go/sqliteread.go`, `go/tokens_agy.go`; no SQLite library is linked in). The read follows the `-wal` file to its last commit and is taken only when no commit landed while it ran.
  - Amp: its threads live on Amp's servers, so the helper runs Amp's own CLI in the background, at most every 10 minutes: `amp threads list --json --include-archived`, then `amp threads export <id>` for a thread whose `updated` moved, with the same trimmed environment and output caps as `amp usage` (`go/tokens_amp.go`). Only threads that ran on this machine count (matched by Amp's installation id in `device-id.json`, or by the hostname a thread records), so one account on two machines is not counted twice. Only the counts are kept, in `amp-usage.json` beside the helper's token. Amp's legacy local thread files are read for threads the CLI does not name.
  These readers follow [Tokscale](https://github.com/junhoyeo/tokscale) (MIT).

Run `subnsub-monitor` with no arguments to inspect the exact JSON snapshot produced on your machine.

## System metrics

| Metric | Linux | macOS | FreeBSD | Windows (source only) |
|---|---|---|---|---|
| CPU usage & split | user / system / **iowait** / **steal** | user / sys | — | user / system |
| Memory (total / available / cached) | Yes | Yes | — | Yes |
| Swap & page in/out rates | Yes | — | — | — |
| Filesystems & mount usage | Yes | Yes | — | System volume |
| Disk read / write throughput | Yes | — | — | — |
| Network throughput, totals, errors, drops | Yes | Throughput & totals | — | — |
| Network interfaces & addresses | Yes | Yes | Yes | Yes |
| TCP established / `TIME_WAIT` / retransmits | Yes | — | — | — |
| Process count | Yes | Yes | — | — |
| Hardware temperatures | Yes (`hwmon` / `thermal_zone`) | Yes (SMC / HID) | — | — |
| Load average | Yes | Yes | — | — |
| Uptime, CPU cores, architecture, kernel | Yes | Yes | Partial | Yes |
| Virtio balloon host memory pressure | Yes | — | — | — |

- **Process diagnostics:** On Linux (and Android running as `shell` or `root`), the dashboard can request a read-only top-20 process resource table (PID, executable name, CPU%, memory%, and age — never command-line arguments, environment variables, or open files). The helper also records the top 5 process names alongside each 5-minute CPU bucket in its local 30-day history (`history.jsonl`), served only over the direct tunnel.
- **Outage & wipe detection:** The helper maintains a local heartbeat timestamp and records intervals when the machine was powered down, suspended, or wiped and re-provisioned (distinguishing a fresh OS install from a reboot via `/etc/machine-id`, `/etc/hostid`, or macOS root APFS volume UUID in `host-id`, which never leaves the machine).
- **Reach while the relay is unreachable:** While its pushes to the relay are failing, the helper records the stretches the machine was demonstrably online anyway: a browser was receiving its tailcat stream and acknowledging it, or a TLS connection to the tunnel's DERP region succeeded (dialed exactly as the tunnel's own DERP client dials it, every 30 seconds, and only while pushes fail). The stretches (`reach.json`, start, end and which evidence) are sent with the next accepted push, so the dashboard does not count the relay's own silence as the machine's downtime (`go/reach.go`).

## Machine identity & naming

Each machine generates a 12-character random base64url `agent_id` on first run and stores it in `~/.config/subnsub-monitor/agent-id`. It is never derived from hardware identifiers, MAC addresses, or `/etc/machine-id`. Deleting `agent-id` creates a new identity; setting `MON_AGENT_ID` pins a fixed ID (useful for stateless containers).

Display names are optional and never taken from the system hostname:

```sh
sh install.sh <TOKEN> --name "tokyo build box"   # set during installation
subnsub-monitor name "tokyo build box"           # set or update anytime
subnsub-monitor name                             # print current name
```

Names are stripped of control characters and bidirectional overrides and capped at 24 characters.

## Remote console & command signing

The remote console is **disabled by default** and can only be enabled locally on the machine:

```sh
sh install.sh <TOKEN> --console     # enable at install time
subnsub-monitor console on          # enable later (takes effect within one poll)
subnsub-monitor console off         # disable immediately
```

Enabling the console creates `~/.config/subnsub-monitor/console` (`MON_CONSOLE=1` overrides it for a single run). When enabled, commands run via `/bin/sh -c` under the helper's user account in `$HOME`, with a 30-second timeout, a 16 KiB output cap, process-group cleanup on exit, and mandatory pre-execution logging to stderr (systemd journal on Linux, launchd log on macOS).

**Transport paths for commands:**
- **Direct tunnel (`direct.go`, `pty.go`):** Interactive PTY terminals (`>_`) and standard shell commands travel exclusively over the end-to-end encrypted WireGuard tunnel. The relay's command mailbox refuses plaintext shell commands outright (`mailboxRefusal`).
- **End-to-end encrypted relay console (`econ.go`):** For machines that can only make outbound HTTPS requests and cannot establish a direct tunnel, the browser can seal a command to the machine's X25519 public key (`econ-key`) using `X25519 + HKDF-SHA256 + AES-256-GCM` (with the command ID bound as AAD). The relay transports only ciphertext and cannot decrypt either the command or its sealed output. Requires both `console on` and a pinned signing key.

On Linux, when installed **without** `--console`, the systemd user unit runs under `ProtectSystem=strict` and `ProtectHome=read-only` (with write access limited to `~/.config/subnsub-monitor`).

### Command signing (`trust`)

Enabling the console controls *whether* the machine accepts commands; `trusted-keys` controls *who* is authorized to issue them (`go/signing.go`):

```sh
subnsub-monitor trust                 # list pinned Ed25519 public keys
subnsub-monitor trust <KEY>           # trust an additional browser/operator key
subnsub-monitor untrust <KEY>         # revoke a key
```

The install command copied from a signed-in dashboard automatically pins your account's public key via `MON_PUBKEY`. **No network command can add or remove a trusted key.**

Once at least one key is pinned (`sealed` trust state):
- Every command must carry a valid Ed25519 signature over the canonical signing payload (`mon-cmd-v1` / `mon-cmd-v2`), generated in your browser by a private key that never leaves the browser.
- Signatures expire 5 minutes from `issued_at`, and command IDs are deduplicated within the freshness window to prevent replay.
- Shell commands, sealed console commands, tunnel commands, renames, custom tile actions, and portable copy enrollments all require a pinned key.

### Portable terminal access (`clone`)

You can delegate temporary CLI access to a machine from the Monitor page (**Terminal → Create a copy**, valid for 1 hour, 1 day, or 7 days). On the client computer:

```sh
pbpaste | subnsub-monitor clone use          # import the delegated access credential
subnsub-monitor run <machine> -- <command>   # execute a command over tailcat and return exit status
subnsub-monitor shell <machine>              # open an interactive PTY session over tailcat
subnsub-monitor clone                        # inspect covered machines and expiration time
subnsub-monitor clone forget                 # delete local credential
```

A portable copy consists of a fresh Ed25519 signing keypair, a tailcat node key, and an authorization certificate (`mon-clone-v1`) signed by your dashboard's pinned key. Target machines verify the certificate signature, machine scope, and expiration against their own clock before admitting any command, and can revoke an active copy at any time via `subnsub-monitor clones revoke <id>`.

## Updates

When remote updates are enabled (`--remote-update`, `--console`, or `subnsub-monitor update on`), the dashboard can instruct the helper to update itself, or the helper can check hourly when `autoupdate on` is also set:

```sh
sh install.sh <TOKEN> --remote-update
subnsub-monitor update on|off
subnsub-monitor autoupdate on|off
```

**Update security invariants (`go/update.go`):**
- **The dashboard chooses *when*; the release bucket chooses *what*.** The update command envelope contains no version string, URL, or checksum field.
- The helper fetches `VERSION` and `SHA256SUMS` from the compiled-in HTTPS release base (`https://tools.subnsub.com/monitor`, overridable only locally via `MON_UPDATE_BASE`), refuses redirects, validates the `YYYY.MM.DD.N` version format, and refuses downgrades.
- After verifying the downloaded binary's SHA-256 against `SHA256SUMS`, the helper runs `<new-binary> version` and verifies that the binary reports the exact expected version before atomically replacing itself (keeping `<binary>.prev` as a backup).
- On Linux hosts with multiple named network namespaces (such as VPN exits on a router), `subnsub-monitor roads` benchmarks reachability across namespaces and downloads updates over the fastest route.

## Coding-agent sessions

When `--console` is enabled, the dashboard can search and read local transcripts from **Claude Code, Codex, Cursor, Grok, Kiro, and Amp** on demand (`go/sessions.go`, `go/sessionsread.go`). Transcripts are scanned directly in place — no background indexer daemon is started, no database is built, and only matching redacted snippets or requested message pages leave the machine:

```sh
subnsub-monitor sessions search <query>
subnsub-monitor sessions recent
subnsub-monitor sessions open --id <session-id>
```

**Optional cloud archive (`sessions sync`):** To search sessions while a machine is offline, enable session syncing locally (`--sessions-sync` or `subnsub-monitor sessions sync on`). The helper incrementally parses local transcripts, redacts common secret patterns (API keys, bearer tokens, JWTs, PEM private keys, and `KEY=VALUE` secret assignments), truncates messages to 4,000 characters, and uploads them to your account's archive. Run `subnsub-monitor sessions sync --dry-run` to preview what would be synced without network traffic.

## Service checks

Configure local HTTP, TCP, and DNS uptime probes in `~/.config/subnsub-monitor/probes.json` (mode `0600`). The helper reloads the file automatically whenever it changes:

```json
{
  "name": "Home services",
  "probes": [
    {"name": "Blog", "type": "http", "url": "https://blog.example.com"},
    {"name": "API", "type": "http", "url": "https://api.example.com/health",
     "expect": [200, 204], "keyword": "\"ok\"", "interval": 30, "retries": 2},
    {"name": "Postgres", "type": "tcp", "host": "10.0.0.5", "port": 5432},
    {"name": "Zone", "type": "dns", "host": "example.com", "tags": {"env": "prod"}}
  ]
}
```

| Field | Description |
|---|---|
| `type` | `http`, `tcp`, or `dns` |
| `url` | For `http`: `http://` or `https://` target URL (must not contain embedded credentials) |
| `host`, `port` | For `tcp`: target host and port; for `dns`: hostname to resolve |
| `name` | Display label shown on the dashboard (defaults to `id`) |
| `id` | Optional `[A-Za-z0-9_-]{1,48}`; defaults to an HMAC of the target using `~/.config/subnsub-monitor/probes.key` |
| `interval` | Seconds between checks (`15`–`3600`, default `60`) |
| `timeout` | Seconds per check (`1`–`60`, default `10`) |
| `retries` | Consecutive failures tolerated before reporting `down` (reported as `pending` meanwhile; default `0`) |
| `maintenance` | When `true`, pauses probing and reports state as `maintenance` |
| `expect` | For `http`: list of acceptable HTTP status codes (default `200`–`299`) |
| `keyword` | For `http`: substring that must appear in the first 1 MiB of the response body |
| `method` | For `http`: `GET` (default) or `HEAD` |
| `insecure` | For `http`: skip TLS chain verification and check certificate expiration dates only |
| `tags` | Key-value labels shown on the card (keys resembling targets or secrets are stripped) |

Up to 64 probes per machine. Target URLs, IP addresses, hostnames, ports, and failure messages never leave the machine — only the probe label, type, state, latency, 24h/30d/365d uptime percentages (tracked in `probes-state.json`), and TLS certificate expiry days are published. Test your configuration anytime with `subnsub-monitor probes` (or `subnsub-monitor probes --json`).

## Custom metrics (`metrics.d`)

Publish custom gauges, counters, status indicators, text badges, or custom quota cards onto a machine's card using either the CLI or JSON files in `~/.config/subnsub-monitor/metrics.d/`:

```sh
subnsub-monitor metric set gpu_temp 71 --name GPU --type gauge --unit celsius --warn 80 --bad 90 --icon gpu --history
subnsub-monitor metric set ups 96 --type gauge --unit percent --invert --warn 40 --bad 15 --icon battery
subnsub-monitor metric set backup ok --label "02:14 · 38 GB" --icon shield
subnsub-monitor metric set solar 12.4 --suffix kWh --icon sun --history
subnsub-monitor metric set build v2026.09.17.2 --type text --icon tag --tint muted
subnsub-monitor metric ls
subnsub-monitor metric rm build
```

You can also place `<source>.json` files directly in `~/.config/subnsub-monitor/metrics.d/`:

```json
{
  "name": "Home lab",
  "tiles": [
    {"id": "gpu_temp", "name": "GPU", "type": "gauge", "value": 71,
     "unit": "celsius", "max": 100, "warn": 80, "bad": 90, "icon": "gpu",
     "history": true, "ttl": 120},
    {"id": "ups", "name": "UPS", "type": "gauge", "value": 96, "unit": "percent",
     "invert": true, "warn": 40, "bad": 15, "icon": "battery", "group": "Power"},
    {"id": "backup", "name": "Nightly backup", "type": "status",
     "value": "ok", "label": "02:14 · 38 GB", "icon": "shield"},
    {"id": "fan", "name": "Fan", "type": "number", "unit": "rpm", "icon": "fan",
     "exec": "sensors | awk '/fan1/{print $2}'", "interval": 30}
  ]
}
```

| Field | Description |
|---|---|
| `id` | `[A-Za-z0-9_-]{1,48}`; derived from `name` if omitted |
| `name` | Display label shown on the card |
| `group` | Optional section header on the card |
| `type` | `gauge`, `number`, `status`, `text`, or `quota` |
| `value` | Numeric value for `gauge`/`number`, state word (`ok`, `warn`, `bad`, `pending`, `unknown`) for `status`, or string for `text` |
| `label` | Secondary text displayed beside a `status` state |
| `min`, `max` | Gauge range (default `0`–`100`) |
| `unit` | Built-in unit formatter: `percent`, `bytes`, `bytes_s`, `bits_s`, `ms`, `s`, `celsius`, `count`, `usd`, `credits`, `watts`, `rpm`, `hz` |
| `suffix` | Custom unit suffix up to 8 characters (e.g., `kWh`, `ppm`); mutually exclusive with `unit` |
| `warn`, `bad` | Alert thresholds (gauges default to 75% / 90% unless `"alerts": false`) |
| `invert` | Set `true` when lower values are worse (e.g., battery charge or cache hit rate) |
| `icon` | Built-in icon name (below) or `emoji:<char>` |
| `tint` | Color for `number`/`text` tiles: `accent`, `ok`, `warn`, `bad`, `muted`, `blue`, `violet`, `pink`, `orange`, `teal`, `green`, `red` |
| `at`, `ttl` | Measurement Unix timestamp and staleness TTL in seconds |
| `history` | Set `true` to record a 48-hour sparkline trend (up to 8 history tiles per machine) |
| `fold` | Aggregation for 5-minute history buckets: `max` (default) or `min` |
| `tags` | Up to 4 short labels shown in the tile footer |
| `exec` | Shell command string or argv array executed periodically to produce the tile |
| `interval`, `timeout` | Execution interval (`5`–`3600`s, default `60`s) and timeout (`1`–`60`s, default `10`s) for `exec` |

Each machine supports up to 8 source files and 32 tiles. Run `subnsub-monitor metrics` (or `subnsub-monitor metrics --json`) to validate all files and execute each command once.

### Command-backed tiles (`exec`)

An `exec` command runs under the helper's user account from `$HOME` and can print:
1. **A plain value** on its first line (`42`, `71.5%`, `ok`, `DOWN since 02:14`).
2. **A JSON object** overriding fields of the tile (`{"value": 71, "label": "…"}`).
3. **A JSON array of tile objects**, allowing a single command (such as `nvidia-smi` or `zpool list`) to emit multiple tiles dynamically while inheriting default properties (`group`, `unit`, `icon`, thresholds) from the parent entry.

### Tile actions

Tiles in `metrics.d/` can declare interactive `actions` that run predefined local commands when clicked on the dashboard (`go/tileaction.go`):

```json
{"id": "weights", "exec": ["/home/me/weights.sh", "show"], "interval": 15, "group": "Weights",
 "actions": [
   {"id": "set", "label": "Set", "exec": ["/home/me/weights.sh", "set"],
    "input": {"min": 0, "max": 20, "step": 1}},
   {"id": "reset", "label": "Reset", "exec": ["/home/me/weights.sh", "reset"], "confirm": true}
 ]}
```

The dashboard never sends a command string — only the action `id` and, if `input` is declared, a validated numeric value on the `[min, max, step]` grid. The helper passes `SUBNSUB_TILE`, `SUBNSUB_ACTION`, `SUBNSUB_VALUE`, and `SUBNSUB_SOURCE` via environment variables, requires an Ed25519 signature from a pinned key in `trusted-keys`, logs every invocation, and immediately refreshes the tile after execution.

### Built-in icons

`gpu` `thermometer` `fan` `battery` `plug` `bolt` `database` `container` `cloud` `clock` `calendar` `timer` `dollar` `users` `mail` `shield` `lock` `camera` `home` `bulb` `sun` `moon` `leaf` `wind` `snow` `gear` `chart` `check` `warning` `bell` `file` `printer` `globe` `heart` `star` `download` `upload` `percent` `hash` `terminal` `code` `git` `rocket` `car` `video` `phone` `radio` `pin` `coffee` `game` `music` `cpu` `memory` `disk` `server` `storage` `network` `wifi` `swap` `gauge` `pulse` `drop` `key` `tag` `list` `flag` `city` `office` `palette` (or `emoji:<char>`).

### Pushing metrics over `metrics.sock`

High-frequency daemons can stream updates over the Unix domain socket `~/.config/subnsub-monitor/metrics.sock` without writing to disk:

```sh
subnsub-monitor metric push '{"id":"bench","name":"Bench","type":"gauge","value":41.5,"unit":"celsius"}'
subnsub-monitor metric push '{"id":"bench","value":42.1}'
subnsub-monitor metric push '{"id":"bench","remove":true}'
```

Orchestration tools can also declare known downtime or rebuild windows over the socket (or by writing `~/.config/subnsub-monitor/declared-outage` before boot):

```sh
subnsub-monitor metric push '{"declare":{"kind":"wipe","at":1790371049,"end":1790371965,"by":"restore-service"}}'
```

### Custom quota cards

For platforms whose billing or usage requires your own API key or script (e.g., Cloudflare Workers, OpenCode, or internal gateways), set `"type": "quota"` to render the tile on the main Agent Quota board:

```json
{"tiles": [
  {"id": "opencode", "name": "OpenCode", "type": "quota",
   "exec": "sh ~/.config/subnsub-monitor/opencode-quota.sh", "interval": 300, "timeout": 20}
]}
```

The command prints a JSON object matching the quota schema:

```json
{"plan": "Zen Pro",
 "windows": [
   {"key": "monthly", "label": "30d", "used": 7.5, "total": 20, "unit": "usd",
    "minutes": 43200, "resets_at": "2026-11-01T00:00:00Z"},
   {"key": "weekly", "used_percent": 62}
 ],
 "balance": "12.50"}
```

### Example definitions

See [`metrics.d.examples/`](metrics.d.examples/) for ready-to-copy configurations covering NVIDIA GPUs (`nvidia-smi`), `lm-sensors`, NUT UPS (`upsc`), Docker containers, failed `systemd` units, SMART disk health (`smartctl`), ZFS pools (`zpool`), Pi-hole v6, network latency, a custom quota template (`quota-demo.json`), and Cloudflare Workers Paid billing (`cloudflare.json` + `cloudflare-bill.sh`).

## CLI Proxy API

If the host runs [CLI Proxy API](https://github.com/router-for-me/CLIProxyAPI), the helper can query quotas for every credential managed by the proxy (Claude, Codex, Antigravity, Kimi, and Grok — one tile per account) through the proxy's management API without the credentials ever entering the helper process:

```sh
export MON_CPA_URL='http://127.0.0.1:8317'   # default loopback address
export MON_CPA_KEY='<MANAGEMENT_KEY>'         # remote-management.secret-key

curl -fsSL https://tools.subnsub.com/monitor/install.sh | sh -s -- '<MONITOR_TOKEN>'
```

- When CLI Proxy API holds a credential for a vendor, its readings take precedence over the native single-account collector for that vendor; vendors not present in the proxy continue using their native collectors.
- `MON_CPA_URL` permits plain HTTP only on loopback (`127.0.0.1` / `::1` / `localhost`); remote addresses require HTTPS.
- Vendor request templates and response paths are defined in [`go/adapters.json`](go/adapters.json). The running daemon periodically checks for newer Ed25519-signed adapter tables (`adapters.json` + `adapters.sig`, verified against `adapterFeedPubKey` in [`go/adapterfeed.go`](go/adapterfeed.go)) so vendor response format changes can be adapted without rebuilding the binary. Set `MON_ADAPTERS=off` to disable hot-updates and use only the embedded table.

## CLI reference

```
subnsub-monitor                        Print one JSON snapshot to stdout and exit
subnsub-monitor watch [SEC]            Continuously print snapshots every SEC seconds
subnsub-monitor serve [PORT]           Serve /quota and /events on 127.0.0.1
subnsub-monitor connect URL [TOKEN]    Dial out and push snapshots to the relay (daemon mode)
subnsub-monitor unregister URL         Notify the relay that this machine is being removed
subnsub-monitor name [LABEL]           Show or set this machine's display name
subnsub-monitor console [on|off]       Show or set whether the dashboard may run commands here
subnsub-monitor update [on|off]        Show or set whether the dashboard may update this binary
subnsub-monitor autoupdate [on|off]    Show or set hourly automatic binary updates
subnsub-monitor diagnostics            Report whether read-only process diagnostics are available
subnsub-monitor autostart              OpenWrt: install or report the /etc/init.d procd boot service
subnsub-monitor spaces [RELAY]         Probe public exit IPs across named Linux network namespaces
subnsub-monitor netns                  Report network namespace count and current namespace
subnsub-monitor roads                  Benchmark reachability to the release host across exits
subnsub-monitor probes [--json]        Run all service checks in probes.json once and print results
subnsub-monitor metrics [--json]       Run all custom metrics in metrics.d/ once and print tiles
subnsub-monitor metric set ID VALUE    Create or update a custom tile (also: metric rm / ls / push)
subnsub-monitor temps                  Print hardware temperature sensors as JSON
subnsub-monitor sessions search TEXT   Search local coding-agent session transcripts
subnsub-monitor sessions recent        List recent coding-agent sessions on this machine
subnsub-monitor sessions open --id ID  Print messages from a session transcript (paginated)
subnsub-monitor sessions sync [on|off] Show or set transcript archiving (--dry-run to preview)
subnsub-monitor trust [KEY]            List or add a trusted Ed25519 command-signing public key
subnsub-monitor untrust KEY            Remove a trusted command-signing public key
subnsub-monitor direct [on|off]        Show or set direct browser tunnel mode
subnsub-monitor allow [KEY]            List or add a browser tailcat node key for direct mode
subnsub-monitor disallow KEY           Revoke a browser tailcat node key
subnsub-monitor address                Print this machine's direct tunnel address and node key
subnsub-monitor transfer [on|off]      Show or set encrypted peer-to-peer transfer relay on tunnel
subnsub-monitor music [on|off]         List what is shared with direct-mode browsers, or switch it on or off
subnsub-monitor music add FOLDER       Share a local folder (only at the machine, never from a page)
subnsub-monitor music add-webdav URL   Share a WebDAV folder (--user NAME; password from MON_WEBDAV_PASSWORD)
subnsub-monitor music remove ID        Stop sharing a folder, named by its ID, its path or its URL
subnsub-monitor music rescan           Have the running helper walk every shared folder again
subnsub-monitor clone [use|forget]     Show, import, or delete a delegated terminal access copy
subnsub-monitor run MACHINE -- CMD     Run a single command on a remote machine via a delegated copy
subnsub-monitor shell MACHINE          Open an interactive terminal on a remote machine
subnsub-monitor clones [revoke ID]     List or revoke delegated copies admitted by this machine
subnsub-monitor version                Print build version and exit
subnsub-monitor selftest               Inspect collector paths and local permissions
```

## Environment variables

Every persistent toggle is stored as a file in `~/.config/subnsub-monitor/`; environment variables override file settings for a single process run:

| Variable | Description |
|---|---|
| `SUBNSUB_MONITOR_TOKEN` | Relay authentication token (overrides `~/.config/subnsub-monitor/token`) |
| `SUBNSUB_MONITOR_SITE` | Custom HTTPS origin for automatic token renewal |
| `MON_NAME` | Machine display label (if `~/.config/subnsub-monitor/name` is not set) |
| `MON_AGENT_ID` | Pin a specific `agent_id` instead of `~/.config/subnsub-monitor/agent-id` |
| `MON_CONSOLE` | `1` or `0`: override the `console` switch for this run |
| `MON_UPDATE`, `MON_AUTOUPDATE` | `1` or `0`: override the `update` and `autoupdate` switches |
| `MON_UPDATE_BASE` | Override the HTTPS release bucket URL used by self-update |
| `MON_ADAPTERS` | Set `off` to disable signed `adapters.json` hot-updates |
| `MON_SYNC` | `1` or `0`: override the `sessions-sync` switch |
| `MON_DIRECT` | `1` or `0`: override the `direct` tunnel switch |
| `MON_DERPMAP` | Custom HTTPS URL for the tailcat DERP map |
| `MON_TRANSPORT` | `relay` or `tailcat`: force a single transport mode |
| `MON_TRANSFER` | `1` or `0`: allow/disallow encrypted file transfer piping over the direct tunnel |
| `MON_MUSIC` | Set `off` to share no music for this run, whatever `music.json` says |
| `MON_WEBDAV_PASSWORD` | The password `music add-webdav` stores for the folder (asked for when unset) |
| `MON_BEACON` | Set `off` to keep sending full snapshots to the relay while a direct tunnel is active |
| `MON_IPV4` | `off`, or a custom `cdn-cgi/trace`-compatible HTTPS URL for public IPv4 lookup |
| `MON_MYIP` | `off`, or a custom HTTPS origin for on-demand exit IP checks |
| `MON_NETNS` | `off`, or comma-separated namespace names (`a,b`) to probe on Linux |
| `MON_ROADS` | Set `off` to skip multi-exit speed probing before binary updates |
| `MON_CLIS` | Set `off` to disable reporting installed coding-agent CLI versions |
| `MON_TOKENS` | Set `off` to disable reporting coding-agent token counts |
| `MON_CPA_URL`, `MON_CPA_KEY` | CLI Proxy API management base URL and secret key |
| `MON_COPILOT_TOKEN`, `MON_GROK_TOKEN`, `MON_KILO_TOKEN`, `MON_KIMI_TOKEN` | Provide a vendor token via environment instead of reading the CLI's file |
| `MON_AMP_BIN`, `MON_AGY_BIN`, `MON_CODEX_BIN`, `MON_KIRO_BIN` | Explicit absolute path to the respective vendor CLI binary |
| `MON_AUTOSTART` | Set `off` on OpenWrt to prevent creating `/etc/init.d/subnsub-monitor` |
| `MON_DNS` | Android: comma-separated DNS resolver IPs when the system resolver is restricted |
| `MON_PUBKEY`, `MON_RELAY`, `MON_BASE`, `MON_BINDIR` | Used by `install.sh` during installation |

## Configuration & state files

All state lives in `~/.config/subnsub-monitor/` (mode `0700`):

| File | Purpose |
|---|---|
| `token`, `token.current`, `service.env` | Installed relay token, renewed token, and service environment configuration |
| `agent-id`, `name`, `host-id` | Random machine ID, display label, and local OS installation UUID (never transmitted) |
| `console`, `update`, `autoupdate`, `direct`, `sessions-sync`, `derpmap` | Feature switches (file presence enables the feature) |
| `trusted-keys`, `econ-key` | Pinned Ed25519 command-signing public keys and the machine's X25519 sealing key |
| `allowed-clients`, `tailcat.key`, `tailcat.psk`, `address` | Authorized browser node keys and WireGuard/tailcat tunnel credentials |
| `pairing` | A pairing token from the self-hosted page's line and the browser key it is for, until that browser has the address (at most a week) |
| `music.json`, `music-index.json` | The shared music folders, with a WebDAV folder's account and password (mode `0600`), and the index of their tracks |
| `clone-access`, `clones`, `clones.revoked` | Client-side delegated access credential and host-side admitted/revoked copy records |
| `probes.json`, `probes.key`, `probes-state.json` | Service probe definitions, target HMAC key, and rolling uptime buckets |
| `metrics.d/`, `metrics.sock` | Custom metric definitions and the local Unix domain push socket |
| `history.jsonl`, `outages.json`, `reach.json`, `declared-outage` | Local 30-day 5-minute metric archive, outage records, and reach records |
| `adapters.json`, `adapters.sig` | Cached hot-updated adapter table and its Ed25519 signature |

## Building from source

```sh
cd go && sh build.sh          # builds dist/subnsub-monitor-<goos>-<goarch>, SHA256SUMS, VERSION
go test ./...
```

Builds are reproducible (`CGO_ENABLED=0 -trimpath -buildvcs=false`). Compiling the same release commit produces byte-for-byte identical binaries matching `SHA256SUMS` and the `SUM_*` constants in [`install.sh`](install.sh):

```sh
cd go && sh build.sh && sha256sum dist/*
```

> **Note:** Building requires Go 1.21 or newer on `PATH`; `build.sh` automatically fetches the pinned Go 1.27 toolchain via `GOTOOLCHAIN=auto`. Cross-repo lockstep tests (`coverage_test.go`, `clis_test.go`, `detail_test.go`) automatically skip when run outside the monorepo.

## Reference implementation

[`reference/monitor.py`](reference/monitor.py) is the original single-file, zero-dependency Python 3 implementation of the local Codex and Claude Code quota collectors. It produces the same `Snapshot` JSON schema and is preserved as an auditable reference alongside the production Go binary in `go/`.

## Attribution

The concept of surfacing local AI coding tool quotas from the files and CLIs already on your machine was inspired by **[CodexBar](https://github.com/steipete/CodexBar)** by [Peter Steinberger](https://github.com/steipete) (MIT). `subnsub-monitor` is an independent headless implementation and contains no CodexBar source code.

## Reporting issues

Found a bug, a broken vendor adapter, or a platform compatibility issue? Please open an issue on [subnsub-tools/subnsub-monitor](https://github.com/subnsub-tools/subnsub-monitor/issues) or in our community tracker at [subnsub-tools/community-tools](https://github.com/subnsub-tools/community-tools/issues).

## License

Licensed under the [Apache License 2.0](LICENSE). See [`NOTICE`](NOTICE) for third-party software attributions, including the BSD-3-Clause tailcat/Tailscale WireGuard transport packages.
