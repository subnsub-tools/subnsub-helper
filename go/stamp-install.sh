#!/bin/sh
# Stamp install.sh for a release, in place:
#
#   sh go/stamp-install.sh DIST INSTALL.SH VERSION
#
# Every SUM_<os>_<arch> line takes the SHA-256 DIST/SHA256SUMS gives
# subnsub-helper-<os>-<arch>, and RELEASE the version, which install.sh
# fetches from GitHub first. A target the installer names and SHA256SUMS
# does not list, or the reverse, is an error: a machine that would download
# a binary it cannot verify, or one it is never offered.
#
# Run by the release workflow (.github/workflows/release.yml) on the build it
# publishes, and by the maintainers' release script, which checks the two
# agree.
set -eu

dist=$1
installer=$2
version=$3
case "$version" in
  [0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].[0-9]*) ;;
  *) echo "not a release version: '$version'" >&2; exit 1 ;;
esac
sums="$dist/SHA256SUMS"
[ -f "$sums" ] || { echo "no $sums" >&2; exit 1; }

tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.n"' EXIT INT TERM
cp "$installer" "$tmp"
targets=$(sed -n 's/^SUM_\([a-z0-9_]*\)=.*/\1/p' "$tmp")
[ -n "$targets" ] || { echo "no SUM_ lines in $installer" >&2; exit 1; }
n=0
for t in $targets; do
    name="subnsub-helper-$(echo "$t" | tr '_' '-')"
    s=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$sums")
    case "$s" in
      *[!0-9a-f]*|'') echo "$sums lists no $name" >&2; exit 1 ;;
    esac
    [ "${#s}" -eq 64 ] || { echo "$sums: '$s' is not a SHA-256" >&2; exit 1; }
    sed "s|^SUM_$t=.*|SUM_$t=$s|" "$tmp" > "$tmp.n" && mv "$tmp.n" "$tmp"
    printf '  %-16s %s\n' "$t" "$s"
    n=$((n + 1))
done
listed=$(awk 'NF >= 2' "$sums" | wc -l | tr -d ' ')
[ "$listed" -eq "$n" ] || { echo "$sums lists $listed files; $installer carries $n checksums" >&2; exit 1; }
sed "s|^RELEASE=[^ ]*|RELEASE=$version|" "$tmp" > "$tmp.n" && mv "$tmp.n" "$tmp"
grep -q "^RELEASE=$version " "$tmp" || { echo "$installer has no RELEASE line to stamp" >&2; exit 1; }
cat "$tmp" > "$installer"
echo "stamped $installer for $version"
