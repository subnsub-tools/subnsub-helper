#!/bin/sh
# Sign the macOS binaries of a build, in place, and rewrite SHA256SUMS:
#
#   MACOS_SIGNING_KEY="$(cat key.pem)" sh go/sign-darwin.sh DIST
#
# macOS keeps what a person allowed a program — reading Downloads, Documents,
# another disk — against the program's signing identity. As the Go linker
# leaves them, the arm64 binary is ad-hoc signed, so its identity is the hash
# of its own bytes, and the amd64 one is not signed at all. Every release was
# therefore a program the system had never seen, and it asked again. Signed
# with one certificate under one identifier, the identity is
#
#   identifier "com.subnsub.helper" and certificate root = H"<the certificate>"
#
# for every release, and an answer given once carries over to the next.
#
# The certificate (go/macos-signing-cert.pem) is self-signed. Apple did not
# issue it and it says nothing about who built a binary: the build provenance
# attestation and the checksums do that. All it has to be is the same one
# each time — a release signed with another would be asked about again on
# every Mac — so the result is checked against the certificate in the source
# before anything is published.
#
# Environment:
#   MACOS_SIGNING_KEY  the certificate's private key, PEM ("BEGIN PRIVATE
#                      KEY"). The release workflow's secret of that name.
#   SIGN_REQUIRED=1    no key is an error. Without it, no key leaves the
#                      binaries as built and says so (a fork's own build).
#   SIGNING_TIME       RFC 3339 time written into the signature (default:
#                      now). The workflow gives the commit's, so building a
#                      tag twice gives the same bytes.
#   RCODESIGN          an rcodesign to use instead of fetching the pinned one.
#
# rcodesign (https://github.com/indygreg/apple-platform-rs) is what signs a
# Mach-O binary on Linux. No timestamp server is asked: a self-signed
# signature gains nothing from one, and the build stays offline apart from
# fetching the tool.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dist=${1:?usage: sign-darwin.sh DIST}
cert="$here/macos-signing-cert.pem"
identifier=com.subnsub.helper
targets="subnsub-helper-darwin-amd64 subnsub-helper-darwin-arm64"

rc_version=0.29.0
rc_sum_x86_64=dbe85cedd8ee4217b64e9a0e4c2aef92ab8bcaaa41f20bde99781ff02e600002
rc_sum_aarch64=4af92c87ddf52f5f2d1258a3b4e56c7dcb8f1b2468df744976c5f139e031961f

for t in $targets; do
    [ -f "$dist/$t" ] || { echo "no $dist/$t" >&2; exit 1; }
done
[ -f "$cert" ] || { echo "no $cert" >&2; exit 1; }

if [ -z "${MACOS_SIGNING_KEY:-}" ]; then
    if [ "${SIGN_REQUIRED:-}" = 1 ]; then
        echo "MACOS_SIGNING_KEY is not set: a release has to be signed" >&2
        exit 1
    fi
    echo "MACOS_SIGNING_KEY is not set: the macOS binaries are left as built"
    exit 0
fi

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# The key is written where nobody else can read it, and removed on the way out.
work=$(umask 077 && mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
( umask 077 && printf '%s\n' "$MACOS_SIGNING_KEY" > "$work/key.pem" )

# The key has to be the certificate's. rcodesign pairs whatever key it is
# given with the first certificate it reads and does not compare them.
want=$(openssl x509 -in "$cert" -noout -pubkey | openssl pkey -pubin -outform DER | sha256 | cut -d' ' -f1)
have=$(openssl pkey -in "$work/key.pem" -pubout -outform DER 2>/dev/null | sha256 | cut -d' ' -f1)
[ -n "$have" ] && [ "$have" = "$want" ] || {
    echo "MACOS_SIGNING_KEY is not the key of $cert" >&2; exit 1; }
root=$(openssl x509 -in "$cert" -outform DER | openssl dgst -sha1 -r | cut -d' ' -f1)

rc=${RCODESIGN:-}
if [ -z "$rc" ]; then
    case "$(uname -s)/$(uname -m)" in
      Linux/x86_64)              rc_arch=x86_64;  rc_sum=$rc_sum_x86_64 ;;
      Linux/aarch64|Linux/arm64) rc_arch=aarch64; rc_sum=$rc_sum_aarch64 ;;
      *) echo "no pinned rcodesign for $(uname -s)/$(uname -m): set RCODESIGN" >&2; exit 1 ;;
    esac
    name="apple-codesign-$rc_version-$rc_arch-unknown-linux-musl"
    curl -fsSL --retry 3 -o "$work/rc.tgz" \
      "https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F$rc_version/$name.tar.gz"
    got=$(sha256 "$work/rc.tgz" | cut -d' ' -f1)
    [ "$got" = "$rc_sum" ] || { echo "rcodesign $rc_version: SHA-256 $got, expected $rc_sum" >&2; exit 1; }
    tar -C "$work" -xzf "$work/rc.tgz" "$name/rcodesign"
    rc="$work/$name/rcodesign"
fi

for t in $targets; do
    if [ -n "${SIGNING_TIME:-}" ]; then
        "$rc" sign --pem-file "$work/key.pem" --pem-file "$cert" \
          --binary-identifier "$identifier" --timestamp-url none \
          --signing-time "$SIGNING_TIME" "$dist/$t" "$work/$t" >/dev/null 2>"$work/log" \
          || { cat "$work/log" >&2; exit 1; }
    else
        "$rc" sign --pem-file "$work/key.pem" --pem-file "$cert" \
          --binary-identifier "$identifier" --timestamp-url none \
          "$dist/$t" "$work/$t" >/dev/null 2>"$work/log" \
          || { cat "$work/log" >&2; exit 1; }
    fi
    # What macOS will hold the next release to.
    "$rc" print-signature-info "$work/$t" > "$work/info"
    grep -qF "(identifier \"$identifier\") and (certificate root = H\"$root\")" "$work/info" || {
        echo "$t: signed, but not as $identifier under $cert" >&2
        grep -F 'designated' "$work/info" >&2 || true
        exit 1
    }
    chmod 0755 "$work/$t"
    cat "$work/$t" > "$dist/$t"
    echo "signed $t: identifier \"$identifier\" and certificate root = H\"$root\""
done
rm -f "$work/key.pem"

( cd "$dist" && sha256 subnsub-helper-* > SHA256SUMS )
echo "rewrote $dist/SHA256SUMS"
