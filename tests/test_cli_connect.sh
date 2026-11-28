#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors

# All cases fail before opening sockets or creating a TUN.
set -euo pipefail
MQVPN="$1"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
PIN=I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzvM
LINK='mqvpn://h?key=SECRETKEY'

expect_error() {
    local message="$1"
    shift
    if "$MQVPN" "$@" >"$tmp/out" 2>&1; then
        echo "FAIL: invalid input was accepted" >&2
        exit 1
    fi
    if ! grep -Fq "$message" "$tmp/out"; then
        cat "$tmp/out" >&2
        echo "FAIL: expected $message" >&2
        exit 1
    fi
    # The key must never be echoed, and the option must exist.
    if grep -Fq SECRETKEY "$tmp/out"; then
        echo "FAIL: output contains the auth key" >&2
        exit 1
    fi
    if grep -Fq 'unrecognized option' "$tmp/out"; then
        cat "$tmp/out" >&2
        echo "FAIL: option not recognized" >&2
        exit 1
    fi
}

# Every conflict is rejected, whatever the option order.
expect_error 'error: --connect cannot be used with --insecure' --connect "$LINK" --insecure
expect_error 'error: --connect cannot be used with --insecure' --insecure --connect "$LINK"
expect_error 'error: --connect cannot be used with --server' --connect "$LINK" --server h:443
expect_error 'error: --connect cannot be used with --server' --server h:443 --connect "$LINK"
expect_error 'error: --connect cannot be used with --auth-key' --connect "$LINK" --auth-key k
expect_error 'error: --connect cannot be used with --pin' --connect "$LINK" --pin "$PIN"
expect_error 'error: --connect cannot be used with --pin' --pin "$PIN" --connect "$LINK"
expect_error 'error: --connect cannot be used with --mode server' --connect "$LINK" --mode server
expect_error 'error: --connect cannot be used with --mode server' --mode server --connect "$LINK"

expect_error 'error: invalid connection link' --connect 'mqvpn://h/x?key=SECRETKEY'
expect_error 'error: invalid pin: expected 43 base64url characters' \
    --mode client --server h:443 --auth-key k --pin abc

# A malformed Pin in the config file stops startup, in either format.
printf '[Server]\nAddress=h:443\nPin=abc\n' >"$tmp/pin.ini"
expect_error 'invalid [Server] Pin' --config "$tmp/pin.ini"
printf '{"server":"h:443","pin":123}' >"$tmp/pin.json"
expect_error 'invalid pin' --config "$tmp/pin.json"
printf '{"server":"h:443","pin":"%s\\u0000x"}' "$PIN" >"$tmp/pin_nul.json"
expect_error 'invalid pin' --config "$tmp/pin_nul.json"
# A pin under a near-miss key or section must not be dropped.
printf '{"server":"h:443","auth_key":"k","Pin":"%s"}' "$PIN" >"$tmp/pin_case.json"
expect_error 'invalid pin key' --config "$tmp/pin_case.json"
printf '[Server]\nAddress=h:443\n[Auth]\nKey=k\nPin=%s\n' "$PIN" >"$tmp/pin_sec.ini"
expect_error 'invalid Pin: it belongs in [Server]' --config "$tmp/pin_sec.ini"
printf 'Pin=%s\n[Server]\nAddress=h:443\n[Auth]\nKey=k\n' "$PIN" >"$tmp/pin_nosec.ini"
expect_error 'invalid Pin: it belongs in [Server]' --config "$tmp/pin_nosec.ini"
# --host is only for --show-link; --show-link is a server command.
expect_error 'error: --host requires --show-link' --host 192.0.2.7
expect_error 'error: --show-link cannot be used with --connect' --show-link --connect "$LINK"
expect_error 'error: --show-link cannot be used with --mode client' --show-link --mode client
expect_error 'error: --show-link needs an auth key' --show-link --host 192.0.2.7
# --link-user picks one user's key for the link.
CERT="$(dirname "$0")/certs/show_no_san.pem"
expect_error 'error: --link-user requires --show-link' --link-user alice
expect_error 'error: --link-user: no user with that name' \
    --show-link --host 192.0.2.7 --cert "$CERT" --user alice:SECRETKEY --link-user bob
expect_error 'error: --show-link needs an auth key' \
    --show-link --host 192.0.2.7 --cert "$CERT" --user alice:SECRETKEY
"$MQVPN" --show-link --host 192.0.2.7 --cert "$CERT" --auth-key GLOBALKEY \
    --user alice:ALICEKEY --user carol:OLDKEY --user carol:CAROLKEY --link-user carol >"$tmp/out"
if ! grep -q '^mqvpn://192\.0\.2\.7:443?key=CAROLKEY\(&pin=.*\)\?$' "$tmp/out"; then
    cat "$tmp/out" >&2
    echo "FAIL: --link-user did not put the user's key in the link" >&2
    exit 1
fi
# A pin together with insecure mode (either from the command line or the file) is refused.
PIN_INSECURE='error: a server pin cannot be used with insecure mode: remove --insecure / Insecure, or remove the pin'
printf '[Server]\nAddress=h:443\nInsecure=true\nPin=%s\n[Auth]\nKey=k\n' "$PIN" >"$tmp/both.ini"
printf '[Server]\nAddress=h:443\nInsecure=true\n[Auth]\nKey=k\n' >"$tmp/insecure.ini"
printf '[Server]\nAddress=h:443\nPin=%s\n[Auth]\nKey=k\n' "$PIN" >"$tmp/pin_only.ini"
expect_error "$PIN_INSECURE" --mode client --server h:443 --auth-key k --pin "$PIN" --insecure
expect_error "$PIN_INSECURE" --config "$tmp/both.ini"
expect_error "$PIN_INSECURE" --config "$tmp/insecure.ini" --pin "$PIN"
expect_error "$PIN_INSECURE" --config "$tmp/pin_only.ini" --insecure
# A failed write is not a success.
if [ -e /dev/full ] && "$MQVPN" --show-link --host 192.0.2.7 --cert "$CERT" \
    --auth-key GLOBALKEY >/dev/full 2>"$tmp/out"; then
    echo "FAIL: --show-link reported success on a write error" >&2
    exit 1
fi
echo 'PASS: --connect and --pin diagnostics'
