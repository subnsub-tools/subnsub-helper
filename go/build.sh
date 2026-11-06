#!/bin/sh
# Cross-compile subnsub-helper for every target install.sh knows how to fetch.
#
#   sh go/build.sh [OUTDIR]     (default: go/dist)
#
# Binaries are not committed — this is what regenerates them.
#
# -trimpath keeps absolute build paths out of the binary and -buildvcs=false
# keeps the git state out of it. Both are needed for reproducibility: two
# people building the same source should get the same bytes, whether from a
# git checkout or a release archive.
set -eu

cd "$(dirname "$0")"
out="${1:-dist}"
mkdir -p "$out"
# Clear what a previous run left so removed targets do not linger in dist/.
rm -f "$out"/subnsub-helper-* "$out"/subnsub-monitor-* "$out/SHA256SUMS"

# The helper links tailcat (direct mode, see direct.go), which uses Go 1.27.
# A driver as old as 1.21 can still build it — go.mod
# names the version and GOTOOLCHAIN=auto fetches the matching toolchain into
# the module cache — so prefer an explicit $GO, then ~/.local/go/bin/go,
# then whatever is on PATH.
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
go=""
for cand in "${GO:-}" "$HOME/.local/go/bin/go" go; do
    [ -n "$cand" ] || continue
    command -v "$cand" >/dev/null 2>&1 || continue
    v=$("$cand" version 2>/dev/null | sed -n 's/^go version go\([0-9]*\)\.\([0-9]*\).*/\1 \2/p')
    set -- $v
    if [ "${1:-0}" -gt 1 ] || { [ "${1:-0}" -eq 1 ] && [ "${2:-0}" -ge 21 ]; }; then
        go=$cand; break
    fi
done
[ -n "$go" ] || { echo "no go toolchain >= 1.21 found (1.27 is fetched automatically from it)" >&2; exit 1; }

# Every target install.sh knows how to fetch.
#
# The NAMES matter as much as the list: a helper asked to update itself builds
# the asset name from its own runtime.GOOS and runtime.GOARCH, so
# `subnsub-helper-<goos>-<goarch>` is not a convention here, it is the protocol.
# (A helper from before the rename asks for subnsub-monitor-<goos>-<goarch>;
# release.sh publishes the same bytes under that name too.)
#
# linux/arm is built for ARMv7 explicitly. Left to the default the toolchain
# targets ARMv6, which runs on a Pi 1 and gives up the atomics and the barrier
# instructions every later board has. Naming the version is also the only way to
# be sure two people building this source get the same bytes.
#
# Windows source files remain behind `//go:build windows` tags (`GOOS=windows
# go vet ./...`), though prebuilt Windows binaries are not currently published.
#
# android/arm64 is a Linux kernel with a different userland, and GOOS=android
# is what makes the difference land: runtime.GOOS says "android" (so the
# asset name below is the one the helper asks for when it updates), Go's
# root-CA loader looks in Android's certificate store, and the linker emits
# what Android will execute — a PIE that names /system/bin/linker64 as its
# interpreter and needs no shared library, which the kernel runs directly
# under the F-Droid Termux and the Play build's linker-exec mode both accept.
# The static GOOS=linux arm64 binary ran there too, but found no CA roots and
# no resolver (helper/go/android_linux.go). 64-bit only: Android 15+ phones
# are commonly 64-bit-only, and the 32-bit ones left are the ones nobody
# monitors. CGO stays off — the Linux collectors compile as they are, and the
# tailscale androidbin feature does the rest with no NDK in the release chain.
for target in linux/amd64 linux/arm64 linux/arm \
              darwin/amd64 darwin/arm64 \
              freebsd/amd64 freebsd/arm64 \
              android/arm64; do
    os=${target%/*}
    arch=${target#*/}
    ext=""
    [ "$os" = windows ] && ext=".exe"
    bin="$out/subnsub-helper-$os-$arch$ext"
    goarm=""
    [ "$arch" = arm ] && goarm=7
    # CGO off so the Linux builds are genuinely static — a helper that needs a
    # matching glibc is a helper that fails on someone's older VPS. It is also
    # what keeps the Windows build free of a toolchain nobody cross-compiling
    # from Linux has.
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$goarm" \
      "$go" build -trimpath -buildvcs=false -ldflags="-s -w" -o "$bin" .
    printf '%-24s %6s KiB\n' "$target" "$(( $(wc -c < "$bin") / 1024 ))"
done

# Checksums, so install.sh can grow a verification step and so a published
# release has something to compare against.
( cd "$out" && sha256sum subnsub-helper-* > SHA256SUMS 2>/dev/null \
  || shasum -a 256 subnsub-helper-* > SHA256SUMS )
echo "wrote $out/SHA256SUMS"
