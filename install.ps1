<#
subnsub-helper installer for Windows.

⚠ WINDOWS BINARIES ARE NOT CURRENTLY PUBLISHED, AND THIS SCRIPT WILL NOT INSTALL ANYTHING.

Windows support is present in the Go source tree (`go/`, behind `//go:build windows`),
but prebuilt Windows binaries are not currently published:

  - no Windows binary is served from the release bucket;
  - the checksums below are placeholders so this script declines cleanly rather
    than accepting an unverifiable binary.

Everything past this notice describes how the Scheduled Task installer works
when Windows binaries are enabled.

  & ([scriptblock]::Create((irm https://tools.subnsub.com/monitor/install.ps1))) -Token <TOKEN>

Paste the same token on every machine you want to watch — each one gets its own
dashboard, told apart by a random id it creates on first run. To name one, add
-Name:

  … -Token <TOKEN> -Name "tokyo build box"

The dashboard can also run commands on a machine, and that is OFF unless you ask
for it right here — add -Console, or turn it on later with
`subnsub-helper console on`. With it on, this machine runs what you type on the
dashboard, as this user, and writes every command to its own log first.

And it can update the helper for you, so a new release does not mean logging
into every box. Also off by default: add -RemoteUpdate, or turn it on later with
`subnsub-helper update on`. -Console implies it — a console can already run this
installer. Nothing is downloaded until you press the button: there is no timer,
and what gets installed comes from the release bucket and is checked against its
published checksum, so the dashboard chooses only WHEN.

Source: https://github.com/subnsub-tools/subnsub-helper (Apache-2.0)

…and if you would rather look first, which is the reasonable instinct for
anything that installs a background process:

  irm https://tools.subnsub.com/monitor/install.ps1 -OutFile install.ps1
  notepad install.ps1
  .\install.ps1 -Token <TOKEN>

Installs a single binary to %USERPROFILE%\.local\bin and registers a scheduled
task that runs it at logon. No administrator rights, nothing written outside
your profile, no service and no driver.

Uninstall:  .\install.ps1 -Uninstall

WHY A SCHEDULED TASK AND NOT A SERVICE. A Windows service has to answer the
service control manager, which means either a second executable or a Go
dependency this project does not carry — and registering one needs
administrator rights that nothing else about this install needs. A task runs as
you, is visible in a tool everybody already has, and is removed by deleting it.
The cost is that it starts at logon rather than at boot; -RemoteUpdate and
-Console both work either way, and the note at the end says which trigger this
machine ended up with.
#>
[CmdletBinding()]
param(
    [string]$Token = $env:SUBNSUB_MONITOR_TOKEN,
    [string]$Name = $env:MON_NAME,
    [string]$CpaUrl = $env:MON_CPA_URL,
    [string]$CpaKey = $env:MON_CPA_KEY,
    [switch]$Console,
    [switch]$RemoteUpdate,
    [switch]$Uninstall,
    # Install from a binary you already have, for testing a build before it is
    # published. The checksum step is skipped: you supplied the file, so there
    # is nothing here to authenticate.
    [string]$LocalBinary
)

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest draws a progress bar by repainting the console on every
# chunk, which makes a 10 MB download take minutes on Windows PowerShell.
$ProgressPreference = 'SilentlyContinue'

$Relay    = if ($env:MON_RELAY) { $env:MON_RELAY } else { 'https://monitor.subnsub.com' }
$Base     = if ($env:MON_BASE)  { $env:MON_BASE }  else { 'https://tools.subnsub.com/monitor' }
$AppName  = 'subnsub-helper'
$TaskName = 'subnsub-helper'
$BinDir   = if ($env:MON_BINDIR) { $env:MON_BINDIR } else { Join-Path $HOME '.local\bin' }
# The same directory the helper itself reads, and the same one the Unix
# installer writes: ~/.config/subnsub-helper. Not %APPDATA%, which is where a
# Windows program would ordinarily put this — one path for all platforms is what
# lets a single -Uninstall, and a single reader in the helper, be correct
# everywhere. The helper looks here and nowhere else.
$ConfDir  = Join-Path $HOME '.config\subnsub-helper'

# Expected SHA-256 of each published binary, baked in.
#
# This is the whole point of the script being readable before you run it. A
# checksum fetched from the same host the binary came from proves nothing —
# whoever can swap one can swap both. These live here, in the file you were
# invited to read, and are regenerated alongside each upload by the release
# script that publishes the binaries. A binary that does not match is not
# installed, and a swapped binary would otherwise be free to read
# ~/.claude/.credentials.json and post it somewhere, which no amount of care in
# the Go source can prevent.
$SUM_windows_amd64 = 'PLACEHOLDER_windows_amd64'
$SUM_windows_arm64 = 'PLACEHOLDER_windows_arm64'

function Say([string]$m) { Write-Host $m }
function Die([string]$m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# UTF-8 with NO byte-order mark, and this is not a preference.
#
# Set-Content -Encoding UTF8 writes a BOM on Windows PowerShell. The token file
# is read by the helper as KEY=VALUE lines, and a BOM prefixes the first KEY —
# so the name stops matching, the token is not found, and the machine installs
# perfectly and never appears on the dashboard. The helper strips one defensively
# now; this side still writes none.
function Write-TextFile([string]$Path, [string]$Text) {
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

# The Windows equivalent of chmod 0600 on a file holding a bearer secret.
#
# A profile directory is already out of reach of other standard users, so this
# is the second lock rather than the first — but the first one is a default, and
# defaults are what an inherited ACL from a redirected or shared profile
# directory quietly changes. Inheritance is switched OFF and the list rebuilt
# from nothing: this user, and the administrators who could read it anyway.
function Protect-File([string]$Path) {
    try {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $false)   # no inheritance, no copy
        foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $me, 'FullControl', 'None', 'None', 'Allow')))
        $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $admins, 'FullControl', 'None', 'None', 'Allow')))
        Set-Acl -Path $Path -AclObject $acl
    } catch {
        # A filesystem without ACLs at all (a FAT-formatted removable disk, a
        # network redirector). Said out loud rather than swallowed: the file
        # holds a bearer secret and the operator should know it is sitting
        # somewhere its permissions could not be set.
        Say "note: could not restrict permissions on $Path ($($_.Exception.Message))"
    }
}

function Read-Manifest {
    $p = Join-Path $ConfDir 'manifest'
    $out = @{}
    if (Test-Path $p) {
        foreach ($line in Get-Content -LiteralPath $p) {
            $k, $v = $line -split '=', 2
            if ($v) { $out[$k.Trim()] = $v.Trim() }
        }
    }
    return $out
}

# Stop whatever is running from this path, so the file can be replaced.
#
# Windows will not let a running image be overwritten, which the Unix installer
# never has to think about. Both the task and any copy someone started by hand
# have to go, and then the file has to actually become free — Stop-Process
# returns before the process is gone.
function Stop-Helper([string]$BinPath) {
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        }
    } catch {}
    Get-Process -Name $AppName -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -eq $BinPath } |
        ForEach-Object {
            try { $_.Kill(); $_.WaitForExit(5000) } catch {}
        }
}

# ---------------------------------------------------------------- uninstall
if ($Uninstall) {
    $man = Read-Manifest
    $bin = if ($man['INSTALLED_BIN']) { $man['INSTALLED_BIN'] } else { Join-Path $BinDir "$AppName.exe" }
    Stop-Helper $bin
    try {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    } catch {}
    # Stop first, but retain the binary and credentials for this one attempt.
    # An older helper may not have the command; say so without blocking local
    # uninstall, and never print the credential or put it in process arguments.
    $relay = if ($man['INSTALLED_RELAY']) { $man['INSTALLED_RELAY'] } else { $Relay }
    if ((Test-Path -LiteralPath $bin) -and (Test-Path -LiteralPath (Join-Path $ConfDir 'agent-id'))) {
        try {
            & $bin unregister $relay
            if ($LASTEXITCODE -ne 0) { throw "helper returned $LASTEXITCODE" }
        } catch {
            Say "warning: relay was not notified; removing the local installation anyway"
        }
    }
    # agent-id and name go too: leaving the id behind means a reinstall silently
    # reclaims the same dashboard card, which is surprising when the point of
    # uninstalling was to stop watching this machine.
    #
    # token.current is the renewed token the helper writes for itself; it is a
    # bearer secret like the installed one and has to go with it. token.current.new
    # too — it is the write-then-rename staging name, and a crash between the two
    # steps leaves a readable bearer secret under it that nothing else would ever
    # clean up.
    #
    # The .prev binary is what the last self-update moved aside, and the log is
    # this machine's own record — the one thing here that is not a secret, and
    # still not something to leave behind after an uninstall.
    foreach ($f in @($bin, "$bin.prev",
                     (Join-Path $ConfDir 'token'), (Join-Path $ConfDir 'token.current'),
                     (Join-Path $ConfDir 'token.current.new'), (Join-Path $ConfDir 'agent-id'),
                     (Join-Path $ConfDir 'name'), (Join-Path $ConfDir 'console'),
                     (Join-Path $ConfDir 'update'), (Join-Path $ConfDir 'diagnostics'),
                     (Join-Path $ConfDir 'log'),
                     (Join-Path $ConfDir 'log.1'), (Join-Path $ConfDir 'manifest'))) {
        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $ConfDir -Force -ErrorAction SilentlyContinue
    Say "removed $AppName"
    exit 0
}

# -------------------------------------------------------------- token / name
if (-not $Token) {
    Die "no token. Usage: .\install.ps1 -Token <TOKEN> [-Name LABEL] [-Console] [-RemoteUpdate]"
}
# Same shape the relay accepts. Beyond catching typos this is what keeps a token
# with a quote in it from becoming part of a task definition, which is XML.
if ($Token -notmatch '^[A-Za-z0-9_-]+$') { Die "token has characters outside [A-Za-z0-9_-]" }
if ($Token.Length -lt 24 -or $Token.Length -gt 128) { Die "token must be 24-128 characters" }

# The relay URL is interpolated into the task's arguments. Keep it to an https
# URL made of characters that cannot end an argument and start another.
if ($Relay -notmatch '^https://[A-Za-z0-9:/._-]+$') { Die "relay must be an https:// URL" }

# Where tokens get renewed, for people running their own relay. It has to
# survive into the TASK — a task carries no environment at all, so this goes in
# the same file as the token and the helper reads both from there.
$Site = $env:SUBNSUB_MONITOR_SITE
if ($Site -and $Site -notmatch '^https://[A-Za-z0-9:/._-]+$') {
    Die "SUBNSUB_MONITOR_SITE must be an https:// URL"
}

# ------------------------------------------------------------ os / arch
if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
    Die "this needs the ScheduledTasks module (Windows 8 / Server 2012 or newer)"
}

# RuntimeInformation first, because the environment variables lie in the one
# case that matters: an x64 PowerShell emulated on an ARM64 machine reports
# AMD64, and would install the emulated build on hardware that can run the
# native one.
$goarch = $null
try {
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        'X64'   { $goarch = 'amd64' }
        'Arm64' { $goarch = 'arm64' }
    }
} catch {}
if (-not $goarch) {
    $a = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($a) {
        'AMD64' { $goarch = 'amd64' }
        'ARM64' { $goarch = 'arm64' }
    }
}
if (-not $goarch) { Die "unsupported architecture: $env:PROCESSOR_ARCHITECTURE (64-bit x64 or ARM64 only)" }
$asset = "$AppName-windows-$goarch.exe"

# ----------------------------------------------------------------- fetch
New-Item -ItemType Directory -Force -Path $BinDir  | Out-Null
New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("$AppName-" + [System.IO.Path]::GetRandomFileName() + '.exe')

try {
    if ($LocalBinary) {
        Say "installing from $LocalBinary"
        Copy-Item -LiteralPath $LocalBinary -Destination $tmp -Force
    } else {
        Say "downloading $asset"
        try {
            # Windows PowerShell defaults to whatever SecurityProtocol the
            # machine was configured with, and on an unpatched build that can
            # still be TLS 1.0 — which the download host refuses.
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch {}
        try {
            Invoke-WebRequest -Uri "$Base/$asset" -OutFile $tmp -UseBasicParsing
        } catch {
            Die "download failed: $Base/$asset ($($_.Exception.Message))"
        }
    }
    if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) { Die "downloaded file is empty" }

    # Verify before anything is made runnable. Skipped only for -LocalBinary.
    if (-not $LocalBinary) {
        $want = (Get-Variable -Name "SUM_windows_$goarch" -ValueOnly)
        if ($want -like 'PLACEHOLDER_*') {
            Die "this installer has no checksum for windows/$goarch — refusing to run an unverified binary"
        }
        $got = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $want.ToLower()) {
            Die "checksum mismatch — expected $want, got $got. NOT installing."
        }
        Say "checksum ok"
    }

    # Run it BEFORE it replaces anything. A binary that downloads and verifies
    # but cannot execute here must not take out a working install on its way past.
    & $tmp token *> $null
    if ($LASTEXITCODE -ne 0) { Die "the downloaded binary does not run on this machine" }

    $bin = Join-Path $BinDir "$AppName.exe"
    # Land the verified bytes in the TARGET directory first, so the step that
    # replaces anything is a rename within one filesystem.
    #
    # $tmp is in the system temp directory, which is very often a different
    # volume — and `Move-Item` across volumes silently degrades into a copy.
    # A copy is not atomic: interrupt it and the service path holds half a
    # binary, which is worse than holding the old one, and worse still because
    # the old process has already been stopped by then.
    $staged = Join-Path $BinDir ".$AppName.new"
    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $tmp -Destination $staged -Force
    # Windows will not overwrite a running image, so whatever is running from
    # this path has to stop first. The Unix installer can skip this entirely.
    Stop-Helper $bin
    # The same order the agent uses to replace itself, for the same reason: the
    # running image can be RENAMED but not replaced in place, so it moves aside
    # and the new one takes the name. Both steps are renames inside one
    # directory, and the previous binary is kept — `.prev` is what somebody
    # reaches for when an install goes wrong on a machine they cannot see.
    $prev = "$bin.prev"
    $done = $false
    foreach ($try in 1..10) {
        try {
            if (Test-Path -LiteralPath $bin) {
                Remove-Item -LiteralPath $prev -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $bin -Destination $prev -Force
            }
            try {
                Move-Item -LiteralPath $staged -Destination $bin -Force
            } catch {
                # Put the working one back before giving up. Without this the
                # service path is left empty by a failure the operator is about
                # to be told was survivable.
                if (Test-Path -LiteralPath $prev) {
                    Move-Item -LiteralPath $prev -Destination $bin -Force -ErrorAction SilentlyContinue
                }
                throw
            }
            $done = $true; break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $done) {
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        Die "could not replace $bin — something is still running it"
    }
    Say "installed $bin"
} finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

# ----------------------------------------------------------------- token file
# Kept out of the task definition and out of the process arguments, so it does
# not show up in a process list.
#
# This matters more here than on Linux, where systemd reads a separate
# token-only EnvironmentFile and the token never reaches a command line. A
# scheduled task carries NO environment: the only two other places a token could
# go on this platform are the task's arguments — readable by every process on
# the machine — or the user's persistent environment, which would hand it to
# every program that user ever starts. So the helper reads this file itself.
#
# This is the BOOTSTRAP token and it is not the last word. Tokens expire after
# 30 days, and the helper trades its own in for a fresh one before that, writing
# the replacement to `token.current` beside this file. Re-running this installer
# with a newly pasted token still wins: the helper picks whichever of the two
# lasts longer, and a just-issued one always does.
$tokenFile = Join-Path $ConfDir 'token'
# Extra settings (the CLI Proxy API today) ride in the same private file; a
# plain reinstall preserves earlier lines unless the parameter is given again.
# Service checks are not configured here: they live in probes.json beside the
# token, written by the operator and read by the helper alone.
$extra = @{}
if (Test-Path -LiteralPath $tokenFile -PathType Leaf) {
    foreach ($line in [IO.File]::ReadAllLines($tokenFile)) {
        if ($line -match '^(MON_CPA_URL|MON_CPA_KEY)=(.*)$') {
            $extra[$Matches[1]] = $Matches[2]
        }
    }
}
foreach ($pair in @(@('MON_CPA_URL',$CpaUrl), @('MON_CPA_KEY',$CpaKey))) {
    if ($null -ne $pair[1] -and $pair[1] -ne '') { $extra[$pair[0]] = [string]$pair[1] }
}
foreach ($value in $extra.Values) {
    if ($value -match '[\x00-\x1F\x7F]') { Die 'CLI Proxy API configuration contains a control character' }
}
$lines = "SUBNSUB_MONITOR_TOKEN=$Token`n"
if ($Site) { $lines += "SUBNSUB_MONITOR_SITE=$Site`n" }
foreach ($key in @('MON_CPA_URL','MON_CPA_KEY')) {
    if ($extra.ContainsKey($key)) { $lines += "$key=$($extra[$key])`n" }
}
Write-TextFile $tokenFile $lines
Protect-File $tokenFile

# Record what this run actually installed, so -Uninstall removes THIS install
# rather than whatever the defaults would point at today.
Write-TextFile (Join-Path $ConfDir 'manifest') "INSTALLED_BIN=$bin`nINSTALLED_LABEL=$TaskName`nINSTALLED_RELAY=$Relay`n"

# ------------------------------------------------------------------ name file
# Written as a file rather than passed through the task definition on purpose: a
# name is free text — spaces, quotes, CJK — and a task definition is XML. The
# helper reads it, trims it and drops control characters; nothing here has to be
# escaped because nothing here is a template.
if ($Name) {
    $nameFile = Join-Path $ConfDir 'name'
    Write-TextFile $nameFile "$Name`n"
    Protect-File $nameFile
}

# --------------------------------------------------------- console / update
# The switches that let the dashboard run commands here and replace this binary.
# Their EXISTENCE is the setting; nothing reads what is in them. Written only
# when asked for, and never removed by a plain reinstall — an operator's earlier
# decision is left alone rather than silently reversed in either direction.
if ($Console) {
    $f = Join-Path $ConfDir 'console'
    Write-TextFile $f "on`n"
    Protect-File $f
}
# NOT written when -Console is given: the console allows this on its own, and a
# second file would mean `console off` later left behind a switch nobody set.
if ($RemoteUpdate -and -not $Console) {
    $f = Join-Path $ConfDir 'update'
    Write-TextFile $f "on`n"
    Protect-File $f
}

# Materialise this machine's dashboard id now rather than leaving it to the
# first run of the task.
& $bin name *> $null

# ------------------------------------------------------------------ task
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $bin -Argument "connect $Relay" -WorkingDirectory $HOME

# Two triggers, and the second one is what stands in for `Restart=always`.
#
# A task that fails can be restarted, but a task that EXITS CLEANLY has simply
# finished — and exiting cleanly is exactly what a helper does after replacing
# its own binary. So the restart cannot hang off failure. A trigger that fires
# every minute, combined with IgnoreNew below, does the job with no timer and no
# state: while the helper is running the trigger starts nothing at all, and the
# minute it is not, one starts.
$triggers = @(New-ScheduledTaskTrigger -AtLogOn -User $me)
try {
    $triggers += New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration ([TimeSpan]::MaxValue)
} catch {
    # Some builds refuse an unbounded duration on this cmdlet. The fallback is
    # DAILY, not a single 24-hour window, and the difference is the whole point:
    # a one-shot trigger repeating for a day stops repeating after a day, and a
    # machine that stays logged in — a server, which is most of them — would
    # then have no restart path at all. Task Scheduler only repeats within the
    # duration it was given, so the duration has to be re-armed by something,
    # and a daily trigger is the something.
    $triggers += New-ScheduledTaskTrigger -Daily -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Hours 24)
}

$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
# Deliberately NOT -Hidden. A background process that phones out belongs in the
# list the machine's owner sees when they go looking for background processes
# that phone out.

# S4U runs the task whether or not anybody is signed in, which is what a server
# needs and what a laptop does not care about. It also needs a privilege a
# standard user usually does not have, so it is tried and not required.
$registered = $false
$whenever = $false
foreach ($logon in @('S4U', 'Interactive')) {
    try {
        $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType $logon -RunLevel Limited
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
            -Settings $settings -Principal $principal -Force `
            -Description "subnsub-helper - pushes AI coding quota to $Relay" | Out-Null
        $registered = $true
        $whenever = ($logon -eq 'S4U')
        break
    } catch { }
}
if (-not $registered) {
    Die "could not register the scheduled task. Run manually:  $bin connect $Relay"
}
Start-ScheduledTask -TaskName $TaskName
Say "started (Get-ScheduledTask $TaskName)"
if ($whenever) {
    Say "runs:           whether or not you are signed in"
} else {
    # The same warning `loginctl enable-linger` exists for on Linux, and the
    # same consequence: on a box you sign into occasionally, signing out stops
    # the thing that was supposed to be watching it.
    Say "runs:           while you are signed in (signing out stops it)"
    Say "                for a headless machine, re-run this from an elevated"
    Say "                PowerShell to register it to run whether or not you are."
}

Say ""
Say "pushing to $Relay every 30s."
Say "check locally:  & '$bin'"
# Stated on every install, not only when it was just switched on: a machine that
# can be typed at from a web page is something the person standing here should
# be told about, including when they inherited the setting from whoever
# installed it last.
if (Test-Path (Join-Path $ConfDir 'console')) {
    Say "console:        ON - the dashboard can run commands here as $me."
    Say "                off with:  & '$bin' console off"
} else {
    # No caveat about a sandbox here, unlike Linux: there is no confinement on
    # this platform for the switch to disagree with, so turning it on later is
    # the whole procedure.
    Say "console:        off. Turn it on with:  & '$bin' console on"
}
if (Test-Path (Join-Path $ConfDir 'console')) {
    Say "update:         ON - implied by the console, which can already run this installer."
} elseif (Test-Path (Join-Path $ConfDir 'update')) {
    Say "update:         ON - the dashboard can replace this helper. Nothing downloads"
    Say "                until you press it, and only a checksummed release will install."
    Say "                off with:  & '$bin' update off"
} else {
    Say "update:         off. Turn it on with:  & '$bin' update on"
}
Say "log:            $(Join-Path $ConfDir 'log')"
Say "uninstall:      .\install.ps1 -Uninstall"
