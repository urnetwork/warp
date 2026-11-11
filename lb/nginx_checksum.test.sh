#!/bin/bash
# Exercise the actual Makefile verification boundary offline. Only checksum
# tools are real; download, extraction, configure and build are local stubs.
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
makefile=${NGINX_CHECKSUM_TEST_MAKEFILE:-"$here/Makefile"}
workspace=$(mktemp -d "${TMPDIR:-/tmp}/nginx-checksum.XXXXXXXX")
if [[ ${NGINX_CHECKSUM_TEST_KEEP:-0} != 1 ]]; then
    trap 'rm -rf "$workspace"' EXIT
fi
printf '[nginx-checksum-workspace] %s\n' "$workspace"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

make_tool=$(command -v make) || fail 'make is required'
primary_tool=$(command -v sha256sum || true)
fallback_tool=$(command -v shasum || true)
[[ -n "$primary_tool" || -n "$fallback_tool" ]] || fail 'a real checksum tool is required for the test'
[[ -r "$makefile" ]] || fail "Makefile is missing: $makefile"

# These production pins never change for an offline synthetic payload.
grep -Fx 'NGINX_COMMIT := 11d11b5f0d3d8ace5215e1a77918e9dc219ce7db' "$makefile" >/dev/null || fail 'NGINX commit pin changed'
grep -Fx 'NGINX_SOURCE_SHA256 := dbc96585a7ddc6f3c3a8faae9487ecdf5ad4e1e2eeb77a8b26e69d935434c9de' "$makefile" >/dev/null || fail 'NGINX archive checksum pin changed'
archive_digest=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
printf abc >"$workspace/valid.tar.gz"
printf tampered >"$workspace/tampered.tar.gz"
mkdir -p "$workspace/stubs" "$workspace/cases"

cat >"$workspace/stubs/curl" <<'STUB'
#!/bin/sh
printf 'download\n' >>"$NGINX_CHECKSUM_FIXTURE_EVENTS"
while [ "$#" -gt 0 ]; do
    if [ "$1" = --output ]; then
        shift
        output=$1
    fi
    shift
done
if [ "$NGINX_CHECKSUM_FIXTURE_MODE" != missing ]; then
    /bin/cp "$NGINX_CHECKSUM_FIXTURE_ARCHIVE" "$output"
fi
STUB
cat >"$workspace/stubs/tar" <<'STUB'
#!/bin/sh
printf 'extract\n' >>"$NGINX_CHECKSUM_FIXTURE_EVENTS"
while [ "$#" -gt 0 ]; do
    if [ "$1" = --directory ]; then
        shift
        directory=$1
    fi
    shift
done
/bin/mkdir -p "$directory/auto"
/bin/cp "$NGINX_CHECKSUM_FIXTURE_STUBS/configure" "$directory/auto/configure"
/bin/cp "$NGINX_CHECKSUM_FIXTURE_STUBS/Makefile" "$directory/Makefile"
STUB
cat >"$workspace/stubs/configure" <<'STUB'
#!/bin/sh
printf 'configure\n' >>"$NGINX_CHECKSUM_FIXTURE_EVENTS"
STUB
cat >"$workspace/stubs/Makefile" <<'STUB'
.PHONY: all install
all:
	@printf 'build\n' >>"$(NGINX_CHECKSUM_FIXTURE_EVENTS)"
install:
	@printf 'install\n' >>"$(NGINX_CHECKSUM_FIXTURE_EVENTS)"
	@/bin/mkdir -p "$(NGINX_CHECKSUM_FIXTURE_PREFIX)/sbin"
	@/bin/cp "$(NGINX_CHECKSUM_FIXTURE_STUBS)/nginx" "$(NGINX_CHECKSUM_FIXTURE_PREFIX)/sbin/nginx"
STUB
cat >"$workspace/stubs/nginx" <<'STUB'
#!/bin/sh
printf 'version\n' >>"$NGINX_CHECKSUM_FIXTURE_EVENTS"
STUB

# The shared short-option interface is the portability regression on every
# platform, including hosts where the first installed tool accepts long flags.
cat >"$workspace/stubs/short-options-only" <<'STUB'
#!/bin/sh
if [ "$#" -ne 2 ] || [ "$1" != -c ] || [ "$2" != - ]; then
    printf 'usage: sha256sum [-bctwz] [files ...]\n' >&2
    exit 64
fi
if [ -n "$NGINX_CHECKSUM_REAL_PRIMARY" ]; then
    exec "$NGINX_CHECKSUM_REAL_PRIMARY" "$@"
fi
exec "$NGINX_CHECKSUM_REAL_FALLBACK" -a 256 "$@"
STUB
cat >"$workspace/stubs/broken-checksum" <<'STUB'
#!/bin/sh
printf 'checksum tool failed deliberately\n' >&2
exit 73
STUB
chmod +x "$workspace/stubs/curl" "$workspace/stubs/tar" "$workspace/stubs/configure" "$workspace/stubs/nginx" "$workspace/stubs/short-options-only" "$workspace/stubs/broken-checksum"
case_count=0

# A fresh build prefix forces the same prerequisite recipe used by test.sh.
# A refusal must stop before extraction; successful verification must complete
# every downstream stub exactly once, without a real compiler or network call.
run_case() {
    local label=$1 primary=$2 fallback=$3 mode=$4 expected=$5
    if [[ -n ${NGINX_CHECKSUM_TEST_ONLY:-} && $label != "$NGINX_CHECKSUM_TEST_ONLY" ]]; then return; fi
    local directory="$workspace/cases/$label" result
    mkdir -p "$directory/tools"
    cp "$makefile" "$directory/Makefile"
    ln -s "$(command -v mkdir)" "$directory/tools/mkdir"
    ln -s "$(command -v rm)" "$directory/tools/rm"
    ln -s "$workspace/stubs/curl" "$directory/tools/curl"
    ln -s "$workspace/stubs/tar" "$directory/tools/tar"
    if [[ -n "$primary" ]]; then ln -s "$primary" "$directory/tools/sha256sum"; fi
    if [[ -n "$fallback" ]]; then ln -s "$fallback" "$directory/tools/shasum"; fi
    : >"$directory/events"
    set +e
    PATH="$directory/tools" \
        MAKEFLAGS= MFLAGS= GNUMAKEFLAGS= \
        NGINX_CHECKSUM_FIXTURE_EVENTS="$directory/events" \
        NGINX_CHECKSUM_FIXTURE_ARCHIVE="$workspace/$mode.tar.gz" \
        NGINX_CHECKSUM_FIXTURE_MODE="$mode" \
        NGINX_CHECKSUM_FIXTURE_STUBS="$workspace/stubs" \
        NGINX_CHECKSUM_FIXTURE_PREFIX="$directory/build/nginx-local" \
        NGINX_CHECKSUM_REAL_PRIMARY="$primary_tool" \
        NGINX_CHECKSUM_REAL_FALLBACK="$fallback_tool" \
        "$make_tool" --no-print-directory -C "$directory" -f "$directory/Makefile" \
        "NGINX_SOURCE_SHA256=$archive_digest" nginx_local >"$directory/stdout" 2>"$directory/stderr"
    result=$?
    set -e
    if [[ "$expected" == pass ]]; then
        [[ $result == 0 ]] || fail "$label: valid archive did not complete the actual Makefile recipe (exit $result; $directory/stderr)"
        printf 'download\nextract\nconfigure\nbuild\ninstall\nversion\n' >"$directory/expected-events"
    else
        [[ $result != 0 ]] || fail "$label: rejected archive or missing tool completed the build"
        printf 'download\n' >"$directory/expected-events"
    fi
    cmp -s "$directory/events" "$directory/expected-events" || fail "$label: verification crossed the wrong extraction/build boundary"
    if [[ "$label" == missing-tools ]]; then
        grep -F 'NGINX source verification requires sha256sum or shasum' "$directory/stderr" >/dev/null || fail 'missing-tools: explicit prerequisite error is absent'
    fi
    printf '[nginx-checksum-case] %s expected=%s exit=%s downstream=%s\n' "$label" "$expected" "$result" "$(tr '\n' ',' <"$directory/events")"
    case_count=$((case_count + 1))
}

run_case short-options-valid "$workspace/stubs/short-options-only" '' valid pass
run_case short-options-tampered "$workspace/stubs/short-options-only" '' tampered fail
run_case short-options-missing-archive "$workspace/stubs/short-options-only" '' missing fail
if [[ -n "$primary_tool" ]]; then
    run_case host-primary-valid "$primary_tool" '' valid pass
    run_case host-primary-tampered "$primary_tool" '' tampered fail
fi
if [[ -x /sbin/sha256sum && /sbin/sha256sum != "$primary_tool" ]]; then
    run_case darwin-native-valid /sbin/sha256sum '' valid pass
    run_case darwin-native-tampered /sbin/sha256sum '' tampered fail
fi
if [[ -n "$fallback_tool" ]]; then
    run_case shasum-fallback-valid '' "$fallback_tool" valid pass
    run_case shasum-fallback-tampered '' "$fallback_tool" tampered fail
    run_case failing-primary-no-fallback "$workspace/stubs/broken-checksum" "$fallback_tool" valid fail
fi
run_case missing-tools '' '' valid fail
[[ $case_count -gt 0 ]] || fail 'no checksum control was selected'
printf 'PASS: NGINX archive verification portability and fail-closed controls (%s cases)\n' "$case_count"
