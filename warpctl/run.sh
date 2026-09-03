#!/bin/sh

# Select the host-native artifact produced by this directory's Makefile. The
# ignored ./warpctl development binary and PATH are deliberately not fallbacks.
set -eu

launcher_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)

case "$(uname -s)" in
Darwin)
    goos=darwin
    ;;
Linux)
    goos=linux
    ;;
*)
    echo "unsupported Warpctl host OS: $(uname -s)" >&2
    exit 127
    ;;
esac

case "$(uname -m)" in
arm64 | aarch64)
    goarch=arm64
    ;;
amd64 | x86_64)
    goarch=amd64
    ;;
*)
    echo "unsupported Warpctl host architecture: $(uname -m)" >&2
    exit 127
    ;;
esac

warpctl_executable="$launcher_dir/build/$goos/$goarch/warpctl"
if [ ! -f "$warpctl_executable" ] || [ ! -x "$warpctl_executable" ]; then
    echo "canonical Warpctl is missing or not executable: $warpctl_executable" >&2
    exit 127
fi

if [ "${1:-}" = "--print-executable" ]; then
    printf '%s\n' "$warpctl_executable"
    exit 0
fi

exec "$warpctl_executable" "$@"
