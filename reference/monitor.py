#!/usr/bin/env python3
"""subnsub-helper — AI coding quota for machines you can't reach.

   Two providers, and they get their numbers in fundamentally different ways.

   CODEX — free of charge, no credential, no network. Codex writes the
   rate-limit envelope the server hands back into its own session logs:

     ~/.codex/sessions/<Y>/<M>/<D>/rollout-*.jsonl
       {"type":"event_msg","payload":{"type":"token_count","rate_limits":{…}}}

   …so the numbers a menu-bar app shows are already sitting in a plain file.
   Reads go through _open_beneath, which walks down from a directory fd on
   SESSIONS_ROOT one component at a time, refusing a symlink at every hop and a
   hard link at the end. Two attacks motivate that machinery: a rollout-*.jsonl
   hard-linked onto auth.json is a genuine name inside the tree and defeats any
   path check, and swapping a PARENT directory for a symlink after the check
   defeats an O_NOFOLLOW that only guards the final component.

   CLAUDE CODE — costs a credential. Claude records no quota on disk at all
   (verified by walking every nested key in recent transcripts: token counts
   and a service_tier, nothing more), so the numbers must be asked for. This
   reads exactly one field out of ~/.claude/.credentials.json and calls the
   usage endpoint with it. See the section above collect_claude for the rules
   that come with holding a credential — chiefly that the same file also holds
   OAuth tokens for whatever third-party services the user has connected, and
   that this code has no business anywhere near those.

   THE LINE THAT STILL HOLDS: reading a credential is not shipping one. The
   token is used for one request and never logged, never cached, never sent
   anywhere — including via exception text, which is the sharp edge here: a
   token containing CR/LF makes the http layer raise an error whose message
   quotes the whole header, and this collector's failures are published. What
   does travel is quota numbers plus the plan and tier they belong to. So the
   claim is "no credential leaves the machine", not "only percentages leave".

   What none of this can do is constrain a malicious BUILD of this program —
   declining to use an ability is not the same as not having it. That takes an
   OS sandbox (landlock on Linux, sandbox_init on macOS), which the shipping
   binary should enter at startup. Everything above is a statement about this
   source, verifiable by reading it, not a guarantee about somebody else's
   binary.

   Single-file Python 3 reference implementation — zero dependencies, standard
   library only. The shipping helper in go/ is a single static Go binary built
   on the same collection model (using os.Root where this walks by hand).

   Usage:
     ./monitor.py                        one snapshot as JSON, exit
     ./monitor.py --watch [SEC]          reprint every SEC seconds
     ./monitor.py --serve [PORT]         serve /quota + /events locally
     ./monitor.py --connect URL TOKEN    dial out and push to the relay
     ./monitor.py --selftest             show exactly which paths get opened

   --serve only ever shows you THIS machine. --connect is the real shape:
   outbound-only, so a browser anywhere can watch a box it has no route to.
"""

import json
import math
import os
import stat
import sys
import time
from datetime import datetime
from pathlib import Path

SESSIONS_ROOT = (Path.home() / '.codex' / 'sessions').resolve()

# Cap on how far back from a file's end we hunt for a rate_limits record.
# These rollouts reach tens of MB; the record we want is essentially always in
# the last few KB. Reading a whole multi-MB file every 30s would make the
# helper the heaviest thing on an otherwise idle box.
TAIL_BUDGET = 1 << 22       # 4 MiB
TAIL_CHUNK = 1 << 16        # 64 KiB

# Backstop on how many rollouts one collect() will open. Bounds the
# pathological case of thousands of never-used sessions. When it bites, the
# reading carries `capped` so nobody reads the answer as exhaustive.
MAX_FILES = 400

# Slack on the mtime early exit.
#
# The stop rule leans on "a file's mtime is never earlier than the last record
# inside it". That is true of a well-behaved filesystem under a monotonic
# clock, and it is NOT a proof. The mtimes come from a snapshot taken before
# the walk, so a rollout appended to mid-walk carries a stale one; coarse
# timestamp granularity, restored backups, utime() and clock steps break it
# from the other side. The margin turns an assertion into a forgiving
# heuristic — when it is wrong the cost is opening a few more files, not
# silently serving a stale number.
MTIME_SLACK = 600

# Bounds on --connect's push interval. The ceiling is the relay's own
# offline threshold minus a margin: push slower than that and a healthy
# helper reads as silent between pushes.
MIN_INTERVAL = 5.0
MAX_INTERVAL = 60.0


def _inside_sessions(path):
    """Path-level check: is this under the sessions tree at all?

       First gate only, and the weakest one. It answers a question about a
       NAME; _open_beneath answers the question about the file that name
       actually reached, which is the one that matters."""
    try:
        return SESSIONS_ROOT in path.resolve().parents
    except OSError:
        return False


def _open_beneath(path):
    """Open a rollout for reading, refusing to leave SESSIONS_ROOT.

       Walks the relative path one component at a time from a directory fd on
       the root, each hop O_NOFOLLOW. O_NOFOLLOW on the final open alone is not
       enough — it only refuses a symlinked LAST component, so replacing any
       parent directory between the path check and the open still lands the
       read outside the tree. Linux has openat2(RESOLVE_BENEATH) for exactly
       this; CPython doesn't expose it, hence the manual walk.

       The st_nlink check at the end is a separate concern: a hard link needs
       no race at all, because it is a real name inside the tree pointing at
       someone else's inode."""
    try:
        rel = path.relative_to(SESSIONS_ROOT)
    except ValueError:
        return None
    parts = rel.parts
    if not parts:
        return None

    dir_fd = os.open(SESSIONS_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nxt
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            os.close(fd)
            return None
        return os.fdopen(fd, 'rb')
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _finite(x):
    """Numbers we're willing to put in a payload.

       json.loads happily returns NaN and Infinity (and 1e999 overflows to
       inf). Left alone those crash _window_label's int() and re-serialise as
       bare NaN/Infinity tokens, which the browser's JSON.parse rejects — one
       weird log line would take the whole panel down."""
    return (isinstance(x, (int, float)) and not isinstance(x, bool)
            and math.isfinite(x))


def _tail_records(path):
    """Parsed JSON objects from the end of a .jsonl, newest first.

       Returns (records, truncated). Seeks backwards in chunks rather than
       reading forwards, so cost is bounded by how far back the answer is, not
       by file size.

       `truncated` matters: on hitting TAIL_BUDGET we stop with the partial
       line still unresolved, so anything earlier in the file is unread. A
       caller that treats that as "no rate_limits here" states a negative it
       never established."""
    records = []
    truncated = False
    fh = _open_beneath(path)
    if fh is None:
        return records, truncated
    try:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        tail = b''
        read = 0
        while pos > 0:
            if read >= TAIL_BUDGET:
                truncated = True
                break
            step = min(TAIL_CHUNK, pos)
            pos -= step
            read += step
            fh.seek(pos)
            tail = fh.read(step) + tail
            lines = tail.split(b'\n')
            # The first element may be a partial line whose head is still
            # further back in the file — hold it over for the next chunk.
            keep = lines[0] if pos > 0 else b''
            body = lines[1:] if pos > 0 else lines
            tail = keep
            for raw in reversed(body):
                if not raw.strip():
                    continue
                try:
                    obj = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    continue
                # A JSONL line may legally decode to a list, string or null.
                # Only dicts can carry the payload we're after, and letting a
                # stray scalar reach .get() would take down the whole read.
                if isinstance(obj, dict):
                    records.append(obj)
    finally:
        fh.close()
    return records, truncated


def _rate_limits_in(path):
    """Newest rate_limits payload in one rollout, or None.

       Within a file the physical order IS the chronological order — these are
       append-only logs — so the last matching record wins."""
    if not _inside_sessions(path):
        return None
    records, truncated = _tail_records(path)
    for obj in records:
        payload = obj.get('payload')
        if not isinstance(payload, dict):
            continue
        if payload.get('type') != 'token_count':
            continue
        rl = payload.get('rate_limits')
        if isinstance(rl, dict):
            info = payload.get('info')
            return {'rate_limits': rl,
                    'info': info if isinstance(info, dict) else {},
                    'timestamp': obj.get('timestamp'),
                    'file': path.name,
                    'truncated': truncated}
    return {'truncated': truncated} if truncated else None


def _iso_to_epoch(ts):
    """Rollout timestamps are ISO-8601 Zulu. Returns 0 when unparseable so a
       malformed record sorts last instead of blowing up the scan."""
    if not isinstance(ts, str):
        return 0
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()
    except ValueError:
        return 0


def _window_label(minutes):
    """10080 -> '7d'. Codex expresses windows in minutes; humans do not."""
    if not _finite(minutes) or minutes <= 0:
        return None
    if minutes % 1440 == 0:
        return '%dd' % (minutes // 1440)
    if minutes % 60 == 0:
        return '%dh' % (minutes // 60)
    return '%dm' % int(minutes)


def _candidates():
    """(path, mtime) for every rollout, newest first.

       Deliberately uncapped. An earlier version took the twelve most recent
       files, which is a correctness bug rather than an optimisation: twelve
       sessions opened but never used carry no rate_limits at all, and would
       hide the real reading sitting in the thirteenth."""
    if not SESSIONS_ROOT.is_dir():
        return []
    out = []
    for p in SESSIONS_ROOT.rglob('rollout-*.jsonl'):
        try:
            st = p.stat()
        except OSError:
            continue            # rotated away mid-scan; not our problem
        if stat.S_ISREG(st.st_mode):
            out.append((p, st.st_mtime))
    out.sort(key=lambda t: t[1], reverse=True)
    return out


def collect():
    """One reading, as the JSON the page consumes."""
    now = time.time()
    if not SESSIONS_ROOT.is_dir():
        return {'ok': False, 'error': 'no-sessions',
                'detail': 'No %s — is the Codex CLI installed and signed in?' % SESSIONS_ROOT,
                'captured_at': now}

    best = None
    scanned = 0
    truncated = False
    capped = False
    for path, mtime in _candidates():
        # Stop once the reading in hand is comfortably newer than the next
        # file could possibly be. See MTIME_SLACK — this is a heuristic with a
        # margin, not the exact bound an earlier version claimed.
        if best is not None and best['epoch'] >= mtime + MTIME_SLACK:
            break
        if scanned >= MAX_FILES:
            capped = True
            break
        scanned += 1
        try:
            hit = _rate_limits_in(path)
        except OSError:
            continue            # deleted or replaced mid-read
        if not hit:
            continue
        if hit.get('truncated'):
            truncated = True
        if 'rate_limits' not in hit:
            continue            # truncated-only marker
        hit['epoch'] = _iso_to_epoch(hit['timestamp'])
        if best is None or hit['epoch'] > best['epoch']:
            best = hit

    # Carried on EVERY answer, not just the empty ones. A newer file whose tail
    # was cut short can hide a newer reading behind an older file's hit — the
    # result still looks like a clean success, so the uncertainty has to travel
    # with it rather than only surfacing when nothing at all was found.
    incomplete = {'truncated': truncated, 'capped': capped}

    if best is None:
        detail = 'Scanned %d session file(s), none carried a rate_limits record yet.' % scanned
        if truncated or capped:
            why = ('some files were only read back %d MiB from the end'
                   % (TAIL_BUDGET >> 20)) if truncated else (
                   'the %d-file scan cap was reached' % MAX_FILES)
            detail = ('Scanned %d session file(s) but the search was cut short (%s), '
                      'so this is not a confirmed negative.' % (scanned, why))
        return dict({'ok': False, 'error': 'no-readings', 'detail': detail,
                     'captured_at': now, 'scanned': scanned}, **incomplete)

    rl = best['rate_limits']
    limits = []
    for key in ('primary', 'secondary'):
        w = rl.get(key)
        if not isinstance(w, dict):
            continue
        used = w.get('used_percent')
        if not _finite(used):
            continue
        minutes = w.get('window_minutes')
        resets = w.get('resets_at')
        limits.append({
            'key': key,
            'used_percent': round(float(used), 2),
            'window_minutes': minutes if _finite(minutes) else None,
            'window_label': _window_label(minutes),
            # NOTE: resets_at is unix SECONDS, not milliseconds. Multiplying in
            # the page is the one bug guaranteed to look plausible.
            'resets_at': resets if _finite(resets) else None,
        })

    if not limits:
        # A rate_limits dict with no usable window is not a reading. Returning
        # ok:true here would leave the page showing its previous gauge, freshly
        # stamped "live" — worse than showing nothing.
        return dict({'ok': False, 'error': 'no-readings',
                     'detail': 'Newest rate_limits record carried no usable window.',
                     'captured_at': now, 'scanned': scanned}, **incomplete)

    usage = best['info'].get('total_token_usage')
    usage = usage if isinstance(usage, dict) else {}
    tokens = {k: (usage.get(v) if _finite(usage.get(v)) else None) for k, v in (
        ('total', 'total_tokens'), ('input', 'input_tokens'),
        ('cached', 'cached_input_tokens'), ('output', 'output_tokens'),
        ('reasoning', 'reasoning_output_tokens'))}

    credits = rl.get('credits')
    if isinstance(credits, dict):
        credits = {'has_credits': bool(credits.get('has_credits')),
                   'unlimited': bool(credits.get('unlimited')),
                   'balance': str(credits.get('balance'))}
    else:
        credits = None

    ctx = best['info'].get('model_context_window')
    plan = rl.get('plan_type')
    return dict({
        'ok': True,
        'captured_at': now,             # when the helper looked
        'recorded_at': best['epoch'],   # when Codex wrote the number down
        'stale_seconds': max(0, int(now - best['epoch'])) if best['epoch'] else None,
        'plan_type': plan if isinstance(plan, str) else None,
        'limit_id': rl.get('limit_id') if isinstance(rl.get('limit_id'), str) else None,
        'limits': limits,
        'credits': credits,
        'session_tokens': tokens,
        'context_window': ctx if _finite(ctx) else None,
        'source': best['file'],
        'scanned': scanned,
    }, **incomplete)


# --------------------------------------------------------------------------
# Claude Code.
#
# Unlike Codex, Claude records no quota anywhere on disk — its transcripts
# carry token counts and a service_tier, and that is all (checked by walking
# every nested key in recent transcripts, not just the obvious ones). So the
# numbers have to be asked for, which means using the credential.
#
# The rules that come with that:
#   · Read four scalars out of claudeAiOauth and nothing else.
#     ~/.claude/.credentials.json also holds MCP OAuth tokens for whatever
#     third-party services the user has connected — entirely unrelated
#     credentials with no business being anywhere near this code path. Of the four, the token
#     stays local; subscriptionType and rateLimitTier DO travel, because a
#     panel that shows quota without saying which plan it belongs to is not
#     much use. So the honest claim is "no credential leaves", not "only
#     percentages leave".
#   · Never refresh, never write back. An expired token is reported as such and
#     left for Claude Code to renew; rewriting a user's credential file to keep
#     a status panel green is not a trade worth making.
#   · The token is used to make one request and is never logged, never cached,
#     and never leaves the machine. Only the resulting numbers go to the relay.
# --------------------------------------------------------------------------

CLAUDE_CREDS = Path.home() / '.claude' / '.credentials.json'
CLAUDE_USAGE_URL = 'https://api.anthropic.com/api/oauth/usage'


class _NoRedirect(__import__('urllib.request', fromlist=['request']).HTTPRedirectHandler):
    """Refuse every redirect on the credentialed request.

       Python's default handler copies request headers onto the redirected
       request, Authorization included, so a 302 is enough to hand the token to
       whatever host the response names."""

    def redirect_request(self, *_a, **_kw):
        return None

# What each limit kind is called, and how long its window is. The API gives a
# kind and a reset timestamp but no window length, so the labels come from here.
CLAUDE_KINDS = {
    'session': ('session', '5h'),
    'weekly_all': ('weekly', '7d'),
    'weekly_scoped': ('weekly_scoped', '7d'),
}


def _tame(s, limit=32):
    """A string from the credential file that we intend to publish.

       subscriptionType and rateLimitTier travel to the relay and onto other
       people's screens, and they come out of a file this program does not
       control the contents of. Nothing weird is expected there — but "nothing
       weird is expected" is not a reason to forward arbitrary bytes out of a
       credential store. Keep the shape a plan name plausibly has."""
    if not isinstance(s, str):
        return None
    s = s.strip()[:limit]
    return s if s and all(c.isalnum() or c in '-_. ' for c in s) else None


def _claude_auth():
    """(access_token, subscription, tier, expires_at) or (None, …) if absent.

       Pulls the four fields we need out of claudeAiOauth and lets the rest of
       the document fall out of scope immediately. Of these the token stays
       local; subscription and tier are published, hence _tame."""
    try:
        doc = json.load(open(CLAUDE_CREDS))
    except (OSError, ValueError):
        return None, None, None, None
    oauth = doc.get('claudeAiOauth')
    if not isinstance(oauth, dict):
        return None, None, None, None
    tok = oauth.get('accessToken')
    return (tok if isinstance(tok, str) and tok else None,
            _tame(oauth.get('subscriptionType')),
            _tame(oauth.get('rateLimitTier')),
            oauth.get('expiresAt') if _finite(oauth.get('expiresAt')) else None)


def _iso_z_to_epoch(ts):
    """The usage API returns ISO-8601 with an offset, unlike Codex's unix
       seconds. Normalise here so everything downstream speaks one unit."""
    if not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()
    except ValueError:
        return None


def collect_claude(timeout=8.0):
    """Live quota for Claude Code, or a reported failure."""
    now = time.time()
    token, sub, tier, expires = _claude_auth()
    if not token:
        # Literal path, not CLAUDE_CREDS — that one is absolute and carries the
        # local username, which would then travel to the relay and onto every
        # watcher's screen.
        return {'id': 'claude', 'name': 'Claude Code', 'ok': False,
                'error': 'not-signed-in', 'source': 'api',
                'detail': 'No claudeAiOauth in ~/.claude/.credentials.json.',
                'captured_at': now}
    # expiresAt is MILLISECONDS here — Codex's resets_at is seconds. Same-named
    # concept, different unit, one of the easier ways to be quietly wrong.
    if expires and expires / 1000 < now:
        return {'id': 'claude', 'name': 'Claude Code', 'ok': False,
                'error': 'token-expired', 'source': 'api',
                'detail': 'Token expired; run Claude Code once to refresh it.',
                'captured_at': now}

    import urllib.error
    import urllib.request

    def fail(err, detail):
        return {'id': 'claude', 'name': 'Claude Code', 'ok': False, 'error': err,
                'source': 'api', 'detail': detail, 'captured_at': now}

    try:
        # Building the Request is INSIDE the guard on purpose. A token carrying
        # a CR/LF makes the http layer raise "Invalid header value b'Bearer
        # <the whole token>'" right here — and this function's failures are
        # published: they ride to the relay, land in the page, and show up in
        # the raw payload panel. Nothing derived from an exception's text may
        # escape this block.
        req = urllib.request.Request(CLAUDE_USAGE_URL, headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'User-Agent': 'subnsub-helper/poc',
        })
        # Default urlopen follows redirects and Python's redirect handler keeps
        # the Authorization header while doing it — a redirect from the usage
        # endpoint, hostile or merely misconfigured, would hand the token to
        # another origin (and http:// at that). One request, no forwarding.
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # e.code is a number we produced expectations about; safe to report.
        if e.code in (301, 302, 303, 307, 308):
            return fail('api-error', 'usage endpoint tried to redirect')
        return fail('token-expired' if e.code == 401 else 'api-error',
                    'usage endpoint returned %s' % e.code)
    except Exception as e:                          # noqa: BLE001
        # Type name only. str(e) is exactly the thing that can carry the token.
        return fail('unreachable', 'request failed (%s)' % type(e).__name__)

    limits = []
    for l in (data.get('limits') if isinstance(data.get('limits'), list) else []):
        if not isinstance(l, dict):
            continue
        pct = l.get('percent')
        if not _finite(pct):
            continue
        key, label = CLAUDE_KINDS.get(l.get('kind'), (str(l.get('kind'))[:24], None))
        scope = None
        sc = l.get('scope')
        if isinstance(sc, dict) and isinstance(sc.get('model'), dict):
            name = sc['model'].get('display_name')
            scope = name if isinstance(name, str) else None
        limits.append({
            'key': key,
            'used_percent': round(float(pct), 2),
            'window_label': label,
            'resets_at': _iso_z_to_epoch(l.get('resets_at')),
            'severity': l.get('severity') if l.get('severity') in ('normal', 'warning', 'critical') else None,
            'scope': scope,
            'active': l.get('is_active') is True,
        })
    if not limits:
        return {'id': 'claude', 'name': 'Claude Code', 'ok': False,
                'error': 'no-readings', 'source': 'api',
                'detail': 'usage endpoint returned no usable limits',
                'captured_at': now}

    extra = data.get('extra_usage') if isinstance(data.get('extra_usage'), dict) else {}
    return {
        'id': 'claude', 'name': 'Claude Code', 'ok': True, 'source': 'api',
        'captured_at': now,
        # Live from the API, so the reading IS current — no staleness gap of
        # the kind Codex has, where the numbers are only as fresh as your last
        # actual call.
        'recorded_at': now,
        'plan_type': sub,
        'rate_limit_tier': tier,
        'limits': limits,
        'extra_usage': {
            'enabled': extra.get('is_enabled') is True,
            'utilization': extra.get('utilization') if _finite(extra.get('utilization')) else None,
        } if extra else None,
    }


def collect_codex():
    """The Codex reader, in the same shape every provider reports."""
    r = collect()
    p = {'id': 'codex', 'name': 'Codex', 'source': 'local-log',
         'ok': r.get('ok') is True, 'captured_at': r.get('captured_at')}
    if not p['ok']:
        p['error'] = r.get('error')
        p['detail'] = r.get('detail')
        return p
    p.update({
        'recorded_at': r.get('recorded_at'),
        'plan_type': r.get('plan_type'),
        'credits': r.get('credits'),
        'truncated': r.get('truncated'),
        'capped': r.get('capped'),
        'source_file': r.get('source'),
        'limits': [{
            'key': l['key'],
            'used_percent': l['used_percent'],
            'window_label': l.get('window_label'),
            'window_minutes': l.get('window_minutes'),
            'resets_at': l.get('resets_at'),
            # Codex reports no severity of its own; the page colours these by
            # percentage. Claude does report one, and it wins where present.
            'severity': None,
            'scope': None,
            'active': None,
        } for l in r.get('limits', [])],
    })
    return p


# Order is the display order. Codex first because its numbers come free — no
# credential, no network — and Claude second because its do not.
PROVIDERS = (collect_codex, collect_claude)


def collect_all():
    """One snapshot across every provider.

       A provider that fails reports its own failure rather than sinking the
       snapshot: an expired Claude token should not blank out Codex."""
    providers = []
    for fn in PROVIDERS:
        try:
            providers.append(fn())
        except Exception as e:                      # noqa: BLE001
            # Type name, never str(e). This backstop catches collectors that
            # handle credentials, and an exception's text is precisely where a
            # credential can end up. Everything appended here gets published.
            providers.append({'id': getattr(fn, '__name__', '?').replace('collect_', ''),
                              'ok': False, 'error': 'collector-crashed',
                              'detail': 'collector raised %s' % type(e).__name__,
                              'captured_at': time.time()})
    return {
        'ok': any(p.get('ok') for p in providers),
        'captured_at': time.time(),
        'providers': providers,
    }


def _dump(payload):
    """Serialise, refusing to emit NaN/Infinity.

       allow_nan=False turns a value that slipped past _finite into an
       exception here rather than a token no browser can parse. Belt for the
       fields we pass through without inspecting."""
    try:
        return json.dumps(payload, allow_nan=False)
    except ValueError:
        return json.dumps({'ok': False, 'error': 'bad-values',
                           'detail': 'Reading contained non-finite numbers.',
                           'captured_at': time.time()})


# --------------------------------------------------------------------------
# Local server for the demo page.
#
# The shipping design has the helper DIAL OUT over WSS to a Durable Object, so
# a browser can watch a machine it has no route to. This local listener exists
# only so the PoC can be driven from a demo page with no server deployed; the
# collection half above is unchanged either way.
#
# Origin is allow-listed even here. A wide-open localhost port would let ANY
# page you happen to visit read your plan and quota.
# --------------------------------------------------------------------------

ALLOWED_ORIGINS = {
    'http://localhost:8124', 'http://127.0.0.1:8124',
    'http://localhost:8125', 'http://127.0.0.1:8125',
    'https://www.200000.live', 'https://200000.live',
    'https://tools.subnsub.com', 'https://tool.subnsub.com',
}

# Concurrent /events streams, and why /events is stricter than /quota:
# a request with no Origin (curl, a plain navigation) cannot READ the response
# cross-origin, but it can still hold a stream open, and eight of them starve
# the real page into permanent 503s. /quota stays open to curl for debugging —
# it answers and hangs up. /events demands an allow-listed Origin, which every
# real EventSource sends anyway.
MAX_STREAMS = 8
_streams = [0]


def _serve(port):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_a):
            pass    # the default logger writes a line per SSE keepalive

        def _origin_ok(self):
            origin = self.headers.get('Origin')
            if origin is None:
                return True         # curl and friends send none
            return origin in ALLOWED_ORIGINS

        def _cors(self):
            origin = self.headers.get('Origin')
            if origin in ALLOWED_ORIGINS:
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Vary', 'Origin')

        def _empty(self, code):
            self.send_response(code)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors()
            self.send_header('Access-Control-Allow-Headers', 'content-type')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def do_GET(self):
            path = self.path.split('?')[0]
            if not self._origin_ok():
                self._empty(403)
                return
            if path == '/quota':
                body = _dump(collect_all()).encode()
                self.send_response(200)
                self._cors()
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == '/events':
                if self.headers.get('Origin') not in ALLOWED_ORIGINS:
                    self._empty(403)
                    return
                with lock:
                    if _streams[0] >= MAX_STREAMS:
                        self._empty(503)
                        return
                    _streams[0] += 1
                try:
                    self.send_response(200)
                    self._cors()
                    self.send_header('Content-Type', 'text/event-stream')
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    while True:
                        self.wfile.write(('data: %s\n\n' % _dump(collect_all())).encode())
                        self.wfile.flush()
                        time.sleep(10)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    with lock:
                        _streams[0] -= 1
                return
            self._empty(404)

    # 127.0.0.1, never 0.0.0.0 — this must not be reachable from the network.
    srv = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    srv.daemon_threads = True
    print('subnsub-helper serving on http://127.0.0.1:%d  (/quota, /events)' % port,
          file=sys.stderr)
    srv.serve_forever()


def _connect(base, token, every=30.0):
    """Dial out and push readings to the relay, forever.

       This is the shape that actually matters: the machine you want to watch
       is usually one you cannot reach — behind NAT, behind a cloud firewall,
       on a laptop that moves. Nothing here listens; it only makes outbound
       HTTPS, which is the one thing that works everywhere.

       Deliberately a POST loop rather than a socket. The stdlib has no
       WebSocket client, and this way the helper keeps its zero dependencies.
       The relay infers "gone" from how long since the last push, so the cost
       of not holding a socket open is detection latency, not correctness."""
    import urllib.error
    import urllib.request

    # Keep the push interval inside the window the relay considers "alive".
    # Zero would make every sleep — including the backoff — a no-op and turn
    # the retry loop into a hot loop against the relay. Anything past the
    # offline threshold means a perfectly healthy helper gets reported as
    # silent between pushes.
    every = max(MIN_INTERVAL, min(float(every), MAX_INTERVAL))

    url = base.rstrip('/') + '/push'
    fails = 0
    while True:
        body = _dump(collect_all()).encode()
        req = urllib.request.Request(
            url, data=body, method='POST',
            headers={'Content-Type': 'application/json',
                     # Bearer, not a query parameter: a token in the URL ends
                     # up in the relay's request logs and every proxy between.
                     'Authorization': 'Bearer ' + token,
                     'User-Agent': 'subnsub-helper/poc'})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp.read()
            if fails:
                print('reconnected', file=sys.stderr)
            fails = 0
            wait = every
        except urllib.error.HTTPError as e:
            # 4xx means this client is wrong (bad token, malformed reading) and
            # retrying at speed won't fix it. 429 is the relay explicitly
            # pacing us. Either way, back off rather than hammer.
            fails += 1
            print('push rejected: %s %s' % (e.code, e.reason), file=sys.stderr)
            wait = every * min(2 ** fails, 10)
        except Exception as e:                      # noqa: BLE001 - network is a swamp
            fails += 1
            print('push failed: %s' % e, file=sys.stderr)
            wait = every * min(2 ** fails, 10)
        time.sleep(wait)


def _new_token():
    """A token is a bearer secret: whoever has it can push readings and read
       them. Long and from a CSPRNG, in the relay's accepted alphabet."""
    import secrets
    print(secrets.token_urlsafe(32))


def _hardlink_probe():
    """Prove the open-time guard refuses a hard link.

       Deliberately links a file WE created and filled with nothing, never the
       real auth.json. Linking the credential file is how the previous version
       demonstrated this, and it was a genuinely bad idea: a SIGKILL between
       link and unlink leaves a second name for the credentials sitting in the
       sessions tree, where a backup agent may pick it up — and once the real
       auth.json is later replaced atomically, the orphan's link count falls
       back to 1 and the collector would happily read it. The guard under test
       counts links; it does not care whose inode it is."""
    import tempfile
    target = link = None
    try:
        fd, target = tempfile.mkstemp(dir=SESSIONS_ROOT, prefix='.probe-target-')
        os.close(fd)
        link = str(Path(SESSIONS_ROOT) / ('rollout-probe-%d.jsonl' % os.getpid()))
        os.link(target, link)
        refused = _open_beneath(Path(link)) is None
        print('  %-22s nlink=2 refused: %s' % ('hardlink probe', refused))
    except OSError as e:
        print('  hardlink probe skipped: %s' % e)
    finally:
        # Only ever removes paths this function created.
        for p in (link, target):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass


def _symlink_probe():
    """Prove the walk refuses a symlinked PARENT directory.

       This is the case an O_NOFOLLOW on the final open alone cannot see: the
       last component is a perfectly ordinary file, it just happens to be
       reached through a directory that was swapped for a link to somewhere
       else. Points at a throwaway temp dir, never anything sensitive — the
       guard refuses based on the link, not on where it leads."""
    import shutil
    import tempfile
    outside = link = None
    try:
        outside = tempfile.mkdtemp(prefix='subnsub-helper-probe-')
        (Path(outside) / 'rollout-outside.jsonl').write_text('{}\n')
        link = Path(SESSIONS_ROOT) / ('probe-dir-%d' % os.getpid())
        os.symlink(outside, link)
        try:
            refused = _open_beneath(link / 'rollout-outside.jsonl') is None
        except OSError:
            refused = True      # ELOOP from the O_NOFOLLOW hop counts
        print('  %-22s parent symlink refused: %s' % ('symlink probe', refused))
    except OSError as e:
        print('  symlink probe skipped: %s' % e)
    finally:
        if link:
            try:
                os.unlink(link)     # unlink the LINK, never follow into it
            except OSError:
                pass
        if outside:
            shutil.rmtree(outside, ignore_errors=True)


def _selftest():
    print('sessions root : %s' % SESSIONS_ROOT)
    print('exists        : %s' % SESSIONS_ROOT.is_dir())
    cands = _candidates()
    print('rollouts found: %d (scan stops on mtime, usually after 1)' % len(cands))
    for p, _m in cands[:4]:
        try:
            fh = _open_beneath(p)
            verified = fh is not None
            if fh:
                fh.close()
        except OSError as e:
            verified = 'error: %s' % e
        print('  %s\n    path-gate=%s  open-beneath=%s'
              % (p, _inside_sessions(p), verified))
    print('\nrefusal checks:')
    for forbidden in ('auth.json', '.credentials.json', 'config.toml'):
        p = Path.home() / '.codex' / forbidden
        print('  %-22s path-gate=%s' % (forbidden, _inside_sessions(p)))
    _hardlink_probe()
    _symlink_probe()


def main():
    args = sys.argv[1:]
    if not args:
        print(json.dumps(json.loads(_dump(collect_all())), indent=2))
        return
    cmd = args[0]
    if cmd == '--selftest':
        _selftest()
    elif cmd == '--watch':
        every = float(args[1]) if len(args) > 1 else 30.0
        while True:
            print(_dump(collect_all()), flush=True)
            time.sleep(every)
    elif cmd == '--serve':
        _serve(int(args[1]) if len(args) > 1 else 8787)
    elif cmd == '--new-token':
        _new_token()
    elif cmd == '--connect':
        # SUBNSUB_MONITOR_TOKEN keeps the secret off the command line, where any
        # other user on the box can read it out of `ps`. The positional form
        # still works for a quick try.
        env_token = os.environ.get('SUBNSUB_MONITOR_TOKEN', '').strip()
        if len(args) < 2:
            print('usage: --connect <relay-url> [token] [seconds]\n'
                  '       SUBNSUB_MONITOR_TOKEN=<token> --connect <relay-url> [seconds]')
            sys.exit(2)
        if env_token:
            rest = args[2:]
        else:
            if len(args) < 3:
                print('no token: pass one, or set SUBNSUB_MONITOR_TOKEN')
                sys.exit(2)
            env_token = args[2]
            rest = args[3:]
        _connect(args[1], env_token, float(rest[0]) if rest else 30.0)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
