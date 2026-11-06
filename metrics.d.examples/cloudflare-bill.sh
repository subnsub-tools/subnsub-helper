#!/bin/sh
# Cloudflare Workers Paid as an agent on the Monitor board: this billing
# period's projected bill against a budget of your own, then the free
# allowances that are past their limit or closest to it (helper README,
# "A quota of your own"; cloudflare.json beside this file runs it).
#
#   cp cloudflare-bill.sh cloudflare.json ~/.config/subnsub-helper/metrics.d/
#
# Needs curl and jq, and an API token with two read-only permissions,
# Account Analytics: Read and Billing: Read, for one account
# (dash.cloudflare.com → My Profile → API Tokens → Create Custom Token).
# The token stays in a file on this machine that only the helper's user can
# read; it never leaves the machine, and neither the relay nor the dashboard
# sees anything but the figures below.
#
#   install -m 600 /dev/null ~/.config/subnsub-helper/cloudflare.env
#   cat >> ~/.config/subnsub-helper/cloudflare.env <<'EOF'
#   CF_API_TOKEN=…
#   CF_ACCOUNT_ID=…
#   CF_BUDGET=10     # US dollars a billing period: the bill row's total
#   CF_ROWS=4        # rows on the card, the bill's included (2…8)
#   EOF
#
# Counted, at Cloudflare's published Workers Paid rates (checked 2026-10-11):
# the $5 base, Workers and Pages Functions requests, Workers CPU time,
# Workers KV, D1, Durable Objects (requests — incoming WebSocket messages at
# 20:1 — duration, SQLite and key-value storage) and R2 Standard storage and
# operations; Durable Objects and R2 are rounded up to their next billing
# unit (a million requests or GB-s, a GB-month), as Cloudflare bills them. Not counted: Queues, Workers Logs, Containers, Workers AI,
# Browser Rendering, Images, Stream, Vectorize, Hyperdrive and anything
# outside Workers Paid. Storage is billed per GB-month, each day's peak
# summed over the period and divided by thirty: days so far as recorded (a
# day before something existed adds nothing), the newest day's level carried
# on to the period's end, in GB of 10^9 bytes. The other figures are this
# period's usage so far; their money is a projection, that usage run on to
# the end of the period at the same pace. The invoice is the authority.
set -u

conf=${CF_ENV_FILE:-$HOME/.config/subnsub-helper/cloudflare.env}
# The file holds the settings; one already in the environment wins, so a
# setting can be tried from a shell without editing it.
_tok=${CF_API_TOKEN-} _acct=${CF_ACCOUNT_ID-} _budget=${CF_BUDGET-} _rows=${CF_ROWS-}
# shellcheck disable=SC1090
[ -r "$conf" ] && . "$conf"
CF_API_TOKEN=${_tok:-${CF_API_TOKEN-}} CF_ACCOUNT_ID=${_acct:-${CF_ACCOUNT_ID-}}
CF_BUDGET=${_budget:-${CF_BUDGET-}} CF_ROWS=${_rows:-${CF_ROWS-}}

# A reading this command cannot make is said as one: the agent shows as
# failed, with these words (customquota.go `error`), and the exit stays 0 so
# the helper reads them rather than "command failed".
fail() {
    printf '{"error":"%s"}\n' "$(printf '%s' "$1" | tr -d '"\\\n' | cut -c1-110)"
    exit 0
}
command -v curl >/dev/null 2>&1 || fail "curl is not installed"
command -v jq >/dev/null 2>&1 || fail "jq is not installed"
[ -n "${CF_API_TOKEN:-}" ] || fail "no CF_API_TOKEN in $conf"
[ -n "${CF_ACCOUNT_ID:-}" ] || fail "no CF_ACCOUNT_ID in $conf"
case "${CF_BUDGET:-10}" in ''|*[!0-9.]*) fail "CF_BUDGET is US dollars, a number above zero" ;; esac
jq -en --argjson b "${CF_BUDGET:-10}" '$b > 0' >/dev/null 2>&1 || fail "CF_BUDGET is US dollars, a number above zero"
case "${CF_ROWS:-4}" in [2-8]) ;; *) fail "CF_ROWS is 2…8" ;; esac

api=https://api.cloudflare.com/client/v4
# One request. The token goes to curl through its config on stdin, never on
# its command line, where every user of the machine could read it in ps.
cf() {
    {
        printf 'header = "Authorization: Bearer %s"\n' "$CF_API_TOKEN"
        printf 'url = "%s/%s"\n' "$api" "$1"
        if [ -n "${2:-}" ]; then
            printf 'header = "Content-Type: application/json"\n'
            printf 'data-binary = "%s"\n' "$(printf '%s' "$2" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        fi
    } | curl -sS --max-time 25 --config -
}
# The API's own words when it refused, or nothing.
refusal() {
    jq -r 'if type == "object" and (.success == true or (.data != null and .errors == null)) then empty
           else ((.errors // [])[0].message // "an answer it could not read") end' 2>/dev/null ||
        echo "an answer it could not read"
}

# The period the bill covers is Workers Paid's own, from the subscription.
subs=$(cf "accounts/$CF_ACCOUNT_ID/subscriptions") || fail "Cloudflare's API did not answer"
why=$(printf '%s' "$subs" | refusal)
[ -z "$why" ] || fail "subscriptions: $why"
period=$(printf '%s' "$subs" | jq -r '[.result[]? | select(.rate_plan.id == "workers_paid")][0]
    | if . == null then empty else "\(.current_period_start) \(.current_period_end)" end')
[ -n "$period" ] || fail "no Workers Paid subscription on this account"
start=${period% *}
end=${period#* }

# Counts from the period's own first second ($st…$et); storage by the day
# ($s…$e), each day's peak being what it is billed on.
q='query($a:String!,$s:Date!,$e:Date!,$st:Time!,$et:Time!){viewer{accounts(filter:{accountTag:$a}){
w:workersInvocationsAdaptive(limit:10000,filter:{datetime_geq:$st,datetime_leq:$et}){sum{requests cpuTimeUs}}
pf:pagesFunctionsInvocationsAdaptiveGroups(limit:10000,filter:{datetime_geq:$st,datetime_leq:$et}){sum{requests}}
kv:kvOperationsAdaptiveGroups(limit:10000,filter:{datetime_geq:$st,datetime_leq:$et}){sum{requests} dimensions{actionType}}
kvs:kvStorageAdaptiveGroups(limit:10000,filter:{date_geq:$s,date_leq:$e}){max{byteCount} dimensions{date namespaceId}}
d1:d1AnalyticsAdaptiveGroups(limit:10000,filter:{datetime_geq:$st,datetime_leq:$et}){sum{rowsRead rowsWritten}}
d1s:d1StorageAdaptiveGroups(limit:10000,filter:{date_geq:$s,date_leq:$e}){max{databaseSizeBytes} dimensions{date databaseId}}
dor:durableObjectsInvocationsAdaptiveGroups(limit:10000,filter:{datetime_geq:$st,datetime_leq:$et}){sum{requests} dimensions{type}}
dop:durableObjectsPeriodicGroups(limit:10000,filter:{datetime_geq:$st,datetime_leq:$et}){sum{activeTime inboundWebsocketMsgCount rowsRead rowsWritten storageReadUnits storageWriteUnits storageDeletes}}
dosql:durableObjectsSqlStorageGroups(limit:10000,filter:{date_geq:$s,date_leq:$e}){max{storedBytes} dimensions{date namespaceId}}
dokv:durableObjectsStorageGroups(limit:10000,filter:{date_geq:$s,date_leq:$e}){max{storedBytes} dimensions{date}}
r2o:r2OperationsAdaptiveGroups(limit:10000,filter:{datetime_geq:$st,datetime_leq:$et}){sum{requests} dimensions{actionType storageClass}}
r2s:r2StorageAdaptiveGroups(limit:10000,filter:{date_geq:$s,date_leq:$e}){max{payloadSize metadataSize} dimensions{date bucketName storageClass}}
}}}'
body=$(jq -cn --arg q "$q" --arg a "$CF_ACCOUNT_ID" --arg s "${start%%T*}" --arg e "$(date -u +%Y-%m-%d)" \
    --arg st "$start" --arg et "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{query: $q, variables: {a: $a, s: $s, e: $e, st: $st, et: $et}}')
usage=$(cf graphql "$body") || fail "Cloudflare's analytics did not answer"
why=$(printf '%s' "$usage" | refusal)
[ -z "$why" ] || fail "analytics: $why"

printf '%s' "$usage" | jq -c \
    --arg start "$start" --arg stop "$end" --argjson now "$(date -u +%s)" \
    --argjson budget "${CF_BUDGET:-10}" --argjson rows "${CF_ROWS:-4}" '
def n: if type == "number" then . else 0 end;
def total(f): map(f | n) | add // 0;
def cents: . * 100 | round / 100;
.data.viewer.accounts[0] as $x
| ($start | fromdateiso8601) as $t0 | ($stop | fromdateiso8601) as $t1
# Storage for the period, in byte-months, as Cloudflare bills it: each
# day'"'"'s peak (every database, bucket or namespace that day, added up),
# summed over the days recorded, plus the newest day'"'"'s level for each day
# after it until the period ends, over thirty.
| def monthly(f): (map(select(.dimensions.date)) | group_by(.dimensions.date)
      | map({d: .[0].dimensions.date, v: total(f)})) as $d
    | if ($d | length) == 0 then 0
      else (($d | map(.v) | add) + $d[-1].v * ([($t1 - (($d[-1].d + "T00:00:00Z" | fromdateiso8601) + 86400)) / 86400, 0] | max)) / 30
      end;
# Usage so far, run on to the end of the period: never from less than a
# day, or one busy first hour would be multiplied by seven hundred. Storage
# is the whole period'"'"'s byte-months already (monthly).
(($t1 - $t0) / ([$now - $t0, 86400] | max)) as $run
| ($x.kv | map({(.dimensions.actionType): .sum.requests}) | add // {}) as $kv
| ($x.r2o | map(select((.dimensions.storageClass // "Standard") == "Standard"))) as $r2o
| def a_class: test("^(ListBuckets|PutBucket|ListObjects|PutObject|CopyObject|CompleteMultipartUpload|CreateMultipartUpload|LifecycleStorageTierTransition|ListMultipartUploads|UploadPart|UploadPartCopy|ListParts|PutBucketEncryption|PutBucketCors|PutBucketLifecycleConfiguration)$");
  def b_class: test("^(HeadBucket|HeadObject|GetObject|UsageSummary|GetBucketEncryption|GetBucketLocation|GetBucketCors|GetBucketLifecycleConfiguration)$");
[
  # key, row names, used so far (or the storage average), the allowance,
  # dollars per unit past it, unit, and whether it is a flow (counted up
  # through the period) or a level (storage).
  {k: "requests", en: "Requests", u: (($x.w | total(.sum.requests)) + ($x.pf | total(.sum.requests))), free: 1e7, p: 0.30e-6, unit: "count", flow: true},
  {k: "cpu_ms", en: "CPU ms", u: (($x.w | total(.sum.cpuTimeUs)) / 1000), free: 3e7, p: 0.02e-6, unit: "count", flow: true},
  {k: "kv_reads", en: "KV reads", u: ($kv.read | n), free: 1e7, p: 0.50e-6, unit: "count", flow: true},
  {k: "kv_writes", en: "KV writes", u: ($kv.write | n), free: 1e6, p: 5e-6, unit: "count", flow: true},
  {k: "kv_deletes", en: "KV deletes", u: ($kv.delete | n), free: 1e6, p: 5e-6, unit: "count", flow: true},
  {k: "kv_lists", en: "KV lists", u: ($kv.list | n), free: 1e6, p: 5e-6, unit: "count", flow: true},
  {k: "kv_storage", en: "KV storage", u: ($x.kvs | monthly(.max.byteCount)), free: 1e9, p: 0.50e-9, unit: "bytes", flow: false},
  {k: "d1_reads", en: "D1 reads", u: ($x.d1 | total(.sum.rowsRead)), free: 25e9, p: 0.001e-6, unit: "count", flow: true},
  {k: "d1_writes", en: "D1 writes", u: ($x.d1 | total(.sum.rowsWritten)), free: 5e7, p: 1e-6, unit: "count", flow: true},
  {k: "d1_storage", en: "D1 storage", u: ($x.d1s | monthly(.max.databaseSizeBytes)), free: 5e9, p: 0.75e-9, unit: "bytes", flow: false},
  # Incoming WebSocket messages count one request in twenty: those a
  # hibernating object wakes for are invocations of their own type, the
  # rest are counted on the object (inboundWebsocketMsgCount).
  {k: "do_requests", en: "DO requests", u: ((($x.dor | total(if (.dimensions.type // "") | test("websocket|hibernation") then .sum.requests / 20 else .sum.requests end)) + (($x.dop | total(.sum.inboundWebsocketMsgCount)) / 20)) | round), free: 1e6, p: 0.15e-6, step: 1e6, unit: "count", flow: true},
  # Wall time while active, at 128 MB: Cloudflare'"'"'s own examples count
  # 1,000,000 s as 128,000 GB-s.
  {k: "do_duration", en: "DO GB-s", u: (($x.dop | total(.sum.activeTime)) / 1e6 * 0.128 | round), free: 4e5, p: 12.5e-6, step: 1e6, unit: "count", flow: true},
  {k: "do_reads", en: "DO reads", u: ($x.dop | total(.sum.rowsRead)), free: 25e9, p: 0.001e-6, unit: "count", flow: true},
  {k: "do_writes", en: "DO writes", u: ($x.dop | total(.sum.rowsWritten)), free: 5e7, p: 1e-6, unit: "count", flow: true},
  {k: "do_storage", en: "DO storage", u: ($x.dosql | monthly(.max.storedBytes)), free: 5e9, p: 0.20e-9, unit: "bytes", flow: false},
  {k: "do_kv_reads", en: "DO KV reads", u: ($x.dop | total(.sum.storageReadUnits)), free: 1e6, p: 0.20e-6, unit: "count", flow: true},
  {k: "do_kv_writes", en: "DO KV writes", u: ($x.dop | total(.sum.storageWriteUnits)), free: 1e6, p: 1e-6, unit: "count", flow: true},
  {k: "do_deletes", en: "DO deletes", u: ($x.dop | total(.sum.storageDeletes)), free: 1e6, p: 1e-6, unit: "count", flow: true},
  {k: "do_kv_store", en: "DO KV store", u: ($x.dokv | monthly(.max.storedBytes)), free: 1e9, p: 0.20e-9, unit: "bytes", flow: false},
  {k: "r2_storage", en: "R2 storage", u: ($x.r2s | map(select((.dimensions.storageClass // "Standard") == "Standard")) | monthly(.max.payloadSize + .max.metadataSize)), free: 10e9, p: 0.015e-9, step: 1e9, unit: "bytes", flow: false},
  {k: "r2_class_a", en: "R2 class A", u: ($r2o | map(select(.dimensions.actionType | a_class)) | total(.sum.requests)), free: 1e6, p: 4.5e-6, step: 1e6, unit: "count", flow: true},
  {k: "r2_class_b", en: "R2 class B", u: ($r2o | map(select(.dimensions.actionType | b_class)) | total(.sum.requests)), free: 1e7, p: 0.36e-6, step: 1e6, unit: "count", flow: true}
]
# What runs past the allowance by the period'"'"'s end, rounded up to the
# billing unit where Cloudflare rounds (step), times the rate.
| map(. + {cost: (([(.u * (if .flow then $run else 1 end)) - .free, 0] | max) as $past
                  | (if .step then (($past / .step) | ceil) * .step else $past end) * .p),
           share: (.u / .free * 100)})
| (map(.cost) | add + 5) as $bill
| ((($t1 - $t0) / 60) | floor) as $minutes
| map(select(.u > 0)) | sort_by(-.share) as $used
| ($used | map(select(.share > 100))) as $over
| ($used[0:([$rows - 1, ($over | length)] | max | [., 7] | min)]) as $shown
| {
    plan: "Workers Paid",
    windows: (
      # Its share is capped where the helper stops (1000%); the figures
      # behind it are not, and the board works the overage out from them.
      [{key: "bill", label: "Projected",
        used_percent: ([($bill / $budget * 10000 | round) / 100, 1000] | min),
        used: ($bill | cents), total: $budget, unit: "usd", resets_at: $t1}]
      + ($shown | map(
          {key: .k, label: .en,
           used_percent: ([(.share * 100 | round) / 100, 1000] | min),
           used: (if .unit == "count" then (.u | round) else (.u | floor) end), total: .free, unit,
           resets_at: $t1}
          + (if (.cost | cents) > 0 then {cost: (.cost | cents)} else {} end)
          + (if .flow then {minutes: $minutes} else {} end)))
    )
  }
' || fail "could not read Cloudflare's answer"
