#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# mqvpn-server-info — print the mqvpn-server summary: status, auth key, port
# and subnets, then the connection link and QR code.
#
# Usage:
#   sudo mqvpn-server-info [--host ADDR[:PORT]] [--user NAME]
#
# --host sets the public address in the link. Without it the address is looked
# up once, only when the server's own address is not public.
# --user puts that user's key in the link instead of the global auth key.

set -euo pipefail

CONF=/etc/mqvpn/server.conf

err() { echo "mqvpn-server-info: $*" >&2; exit 1; }

usage() { echo "usage: mqvpn-server-info [--host ADDR[:PORT]] [--user NAME]" >&2; exit 2; }

HOST=""
LINK_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --host)   [ $# -ge 2 ] && [ -n "$2" ] || usage; HOST=$2; shift 2 ;;
        --host=*) HOST=${1#--host=}; [ -n "$HOST" ] || usage; shift ;;
        --user)   [ $# -ge 2 ] && [ -n "$2" ] || usage; LINK_ARGS=(--link-user "$2"); shift 2 ;;
        --user=*) [ -n "${1#--user=}" ] || usage; LINK_ARGS=(--link-user "${1#--user=}"); shift ;;
        *)        usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || err "run as root (use sudo): $CONF is readable only by root"
[ -f "$CONF" ] || err "$CONF not found. Run: sudo dpkg-reconfigure mqvpn-server"

conf_value() { # $1 = section, $2 = key
    sed -n "/^\\[$1\\]/,/^\\[/ s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*\\([^[:space:]#]*\\).*/\\1/p" "$CONF" | head -n 1
}

# [TLS] also has a Key line, so the section matters.
AUTH_KEY=$(conf_value Auth Key)
LISTEN=$(conf_value Interface Listen)
PORT=${LISTEN##*:}
SUBNET=$(conf_value Interface Subnet)
SUBNET6=$(conf_value Interface Subnet6)
PORT=${PORT:-443}
SUBNET=${SUBNET:-10.0.0.0/24}

STATUS=$(systemctl is-active mqvpn-server 2>/dev/null) || true

echo ""
echo "  mqvpn-server: ${STATUS:-unknown}"
echo ""
echo "  Config:    $CONF"
echo "  Auth key:  $AUTH_KEY"
echo "  Port:      ${PORT}/udp"
echo "  Subnet:    $SUBNET"
if [ -n "$SUBNET6" ]; then echo "  Subnet6:   $SUBNET6"; fi
echo ""
echo "  Show this again: sudo mqvpn-server-info"
echo ""

# --- Connection link and QR code ---
# mqvpn must inherit stdout: captured output is no terminal and draws no QR.
tmp_err=$(mktemp 2>/dev/null) || tmp_err=""
if [ -n "$tmp_err" ]; then trap 'rm -f "$tmp_err"' EXIT; fi

show_link() { # $1 = public address (optional); stderr goes to $tmp_err
    local rc=0
    if [ -n "${1:-}" ]; then
        mqvpn --show-link --config "$CONF" "${LINK_ARGS[@]}" --host "$1" \
            2>"${tmp_err:-/dev/null}" || rc=$?
    else
        mqvpn --show-link --config "$CONF" "${LINK_ARGS[@]}" 2>"${tmp_err:-/dev/null}" || rc=$?
    fi
    return "$rc"
}

# One lookup, only when the address is unknown. Prints the address to use
# (IPv6 bracketed) or nothing.
lookup_host() {
    local fam=-4 re='^[0-9]{1,3}(\.[0-9]{1,3}){3}$' ip=""
    if [[ "$LISTEN" == *"["* ]]; then fam=-6; re='^[0-9A-Fa-f:]+$'; fi
    command -v curl >/dev/null 2>&1 || return 0
    ip=$(curl -fsS "$fam" --max-time 5 ifconfig.me 2>/dev/null) || return 0
    [[ "$ip" =~ $re ]] || return 0
    if [ "$fam" = -6 ]; then
        [[ "$ip" == *:* ]] || return 0
        ip="[$ip]"
    fi
    echo "$ip"
}

link_rc=0
if ! command -v mqvpn >/dev/null 2>&1; then
    link_rc=127
else
    show_link "$HOST" || link_rc=$?
    if [ "$link_rc" -eq 3 ] && [ -z "$HOST" ]; then
        found=$(lookup_host)
        if [ -n "$found" ]; then
            link_rc=0
            show_link "$found" || link_rc=$?
        fi
    fi
fi

if [ "$link_rc" -ne 0 ]; then
    if [ "$link_rc" -ne 3 ] && [ -n "$tmp_err" ] && [ -s "$tmp_err" ]; then
        cat "$tmp_err" >&2
    fi
    if [ -z "$AUTH_KEY" ] && [ ${#LINK_ARGS[@]} -eq 0 ]; then
        echo "  Connection link: not shown. There is no shared auth key; run: sudo mqvpn-server-info --user NAME"
    elif [ ${#LINK_ARGS[@]} -gt 0 ]; then
        # the name is not echoed back: NAME:KEY typed by mistake would show the key
        echo "  Connection link: not shown. Check the name given to --user against the User lines in"
        echo "  $CONF, then run: sudo mqvpn-server-info --user NAME --host <public address>"
    else
        echo "  Connection link: not shown. Run: sudo mqvpn-server-info --host <public address>"
    fi
    echo ""
fi
