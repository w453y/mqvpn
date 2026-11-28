#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_connect_link_test.sh — connect link and server public-key pin E2E test
#
# Topology (same as run_reconnect_test.sh):
#   vpn-client  veth-c 192.168.100.1 ── 192.168.100.2 veth-s  vpn-server
#   vpn-server  veth-wan-s 172.16.0.1 ── 172.16.0.2 veth-wan-e  vpn-external
#
# Cases (the client never uses --insecure except where noted):
#   1. --connect link with the right pin: tunnel ping works
#   2. --connect link with the pin of another key: rejected
#   3. server certificate re-issued with the SAME key: the case 1 link works
#   4. --config with Pin(other) / Insecure=true / ServerName=wrong.example:
#      wrong-pin link rejected; right-pin link works
#   5. --server/--auth-key/--pin without a link: right pin works, the CLI pin
#      beats a stale file Pin, wrong pin is rejected, and a wrong file Pin
#      alone is rejected (so the file's Pin is really applied)
#   6. --show-link without --host: the address found is private -> exit code 3
#   7. --show-link on a pseudo-terminal: link, QR code and the secret notice
#
# The case 1 link comes from "mqvpn --show-link", not from a hand-built string;
# it is compared with the hand-built one as an independent check.
#
# "Rejected" = ping fails AND the client logs "TLS certificate verification
# failed" AND the client process has exited (exit code 1 alone is not proof).
#
# Usage: sudo ./scripts/ci_e2e/run_connect_link_test.sh [path-to-mqvpn-binary]

set -e

source "$(dirname "$0")/sanitizer_check.sh"
source "$(dirname "$0")/e2e_lib.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    exit 1
fi

MQVPN="$(realpath "$MQVPN")"
SUBNET="10.0.0.0/24"
IPTABLES_COMMENT="mqvpn-connlink-test:$$"
NS_SVR="vpn-server-cl"
NS_CLI="vpn-client-cl"
NS_EXT="vpn-external-cl"
SERVER_ADDR="192.168.100.2:4433"
TLS_MARK="TLS certificate verification failed"
WAIT_SEC=15 # budget for a tunnel to come up; rejected cases get the same

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0
FAILED=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns exec "$NS_SVR" iptables -t nat -D POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_SVR" iptables -D FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns exec "$NS_SVR" iptables -D FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null || true
    ip netns del "$NS_SVR" 2>/dev/null || true
    ip netns del "$NS_CLI" 2>/dev/null || true
    ip netns del "$NS_EXT" 2>/dev/null || true
    ip link del veth-c 2>/dev/null || true
    ip link del veth-wan-s 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}

WORK_DIR="$(mktemp -d)"
trap cleanup EXIT

PSK=$("$MQVPN" --genkey 2>/dev/null)
# In a link, + / = in the key must be percent-encoded (+ is not a space).
PSK_ENC=$(printf '%s' "$PSK" | sed 's/+/%2B/g; s/\//%2F/g; s/=/%3D/g')

# Two self-signed EC P-256 certs with different keys; the pin is the SHA-256
# of the SubjectPublicKeyInfo as base64url without padding.
for n in a b; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${WORK_DIR}/$n.key" -out "${WORK_DIR}/$n.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-connlink-$n" 2>/dev/null
done
pin_of() {
    openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | basenc --base64url | tr -d '='
}
PIN_A=$(pin_of "${WORK_DIR}/a.crt")
PIN_B=$(pin_of "${WORK_DIR}/b.crt")
if [ "${#PIN_A}" -ne 43 ] || [ "${#PIN_B}" -ne 43 ] || [ "$PIN_A" = "$PIN_B" ]; then
    echo "FAIL: pin computation: A=${PIN_A} B=${PIN_B}"
    exit 1
fi
LINK_HAND="mqvpn://${SERVER_ADDR}?key=${PSK_ENC}&pin=${PIN_A}"
LINK_BAD="mqvpn://${SERVER_ADDR}?key=${PSK_ENC}&pin=${PIN_B}"

ip netns del "$NS_SVR" 2>/dev/null || true
ip netns del "$NS_CLI" 2>/dev/null || true
ip netns del "$NS_EXT" 2>/dev/null || true
ip link del veth-c 2>/dev/null || true
ip link del veth-wan-s 2>/dev/null || true

echo "=== Setting up network namespaces ==="
ip netns add "$NS_SVR"
ip netns add "$NS_CLI"
ip netns add "$NS_EXT"

ip link add veth-c type veth peer name veth-s
ip link set veth-c netns "$NS_CLI"
ip link set veth-s netns "$NS_SVR"
ip netns exec "$NS_CLI" ip addr add 192.168.100.1/24 dev veth-c
ip netns exec "$NS_SVR" ip addr add 192.168.100.2/24 dev veth-s
ip netns exec "$NS_CLI" ip link set veth-c up
ip netns exec "$NS_SVR" ip link set veth-s up
ip netns exec "$NS_CLI" ip link set lo up
ip netns exec "$NS_SVR" ip link set lo up

ip link add veth-wan-s type veth peer name veth-wan-e
ip link set veth-wan-s netns "$NS_SVR"
ip link set veth-wan-e netns "$NS_EXT"
ip netns exec "$NS_SVR" ip addr add 172.16.0.1/24 dev veth-wan-s
ip netns exec "$NS_EXT" ip addr add 172.16.0.2/24 dev veth-wan-e
ip netns exec "$NS_SVR" ip link set veth-wan-s up
ip netns exec "$NS_EXT" ip link set veth-wan-e up
ip netns exec "$NS_EXT" ip link set lo up

ip netns exec "$NS_SVR" ip route add default via 172.16.0.2 dev veth-wan-s
ip netns exec "$NS_CLI" ip route add default via 192.168.100.2 dev veth-c
ip netns exec "$NS_SVR" sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec "$NS_SVR" iptables -t nat -A POSTROUTING -s "$SUBNET" -o veth-wan-s -j MASQUERADE \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec "$NS_SVR" iptables -I FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"
ip netns exec "$NS_SVR" iptables -I FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT \
    -m comment --comment "$IPTABLES_COMMENT"

ip netns exec "$NS_CLI" ping -c 1 -W 1 192.168.100.2 >/dev/null
echo "OK: client -> server underlay"

# start_server <cert> <key>
start_server() {
    ip netns exec "$NS_SVR" "$MQVPN" \
        --mode server \
        --listen "$SERVER_ADDR" \
        --subnet "$SUBNET" \
        --cert "$1" --key "$2" \
        --auth-key "$PSK" \
        --log-level debug >> "${WORK_DIR}/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: server process died"
        cat "${WORK_DIR}/server.log"
        exit 1
    fi
    echo "Server running (PID $SERVER_PID)"
}

stop_server() {
    stop_and_check_sanitizer "$SERVER_PID" "server" "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    SERVER_PID=""
}

# start_client <args...>: fresh log in ${WORK_DIR}/client.log
start_client() {
    : > "${WORK_DIR}/client.log"
    ip netns exec "$NS_CLI" "$MQVPN" "$@" --log-level debug \
        > "${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
}

# Ping through the tunnel for up to WAIT_SEC seconds; 0 as soon as one works.
tunnel_ping() {
    local i
    for i in $(seq 1 "$WAIT_SEC"); do
        if ip netns exec "$NS_CLI" ping -c 1 -W 1 172.16.0.2 >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# No TUN device may be left in the client namespace between cases.
check_no_tun() {
    local links
    links=$(ip netns exec "$NS_CLI" ip -o link show)
    if grep -q "mqvpn" <<< "$links"; then
        echo "  leftover TUN in client ns: $(grep mqvpn <<< "$links")"
        return 1
    fi
    return 0
}

dump_logs() {
    echo "--- client log ---"
    cat "${WORK_DIR}/client.log"
    echo "--- server log (tail) ---"
    tail -40 "${WORK_DIR}/server.log"
}

# expect_connect <name> <client args...>: the tunnel must come up.
expect_connect() {
    local name="$1"
    shift
    local ok=1
    start_client "$@"
    if ! tunnel_ping; then
        echo "  ping through the tunnel failed after ${WAIT_SEC}s"
        ok=0
    fi
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "  client exited early"
        ok=0
    fi
    if grep -q "$TLS_MARK" "${WORK_DIR}/client.log"; then
        echo "  unexpected '${TLS_MARK}' in client log"
        ok=0
    fi
    stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || ok=0
    CLIENT_PID=""
    check_no_tun || ok=0
    verdict "$name" "$ok"
}

# expect_reject <name> <client args...>: ping fails, TLS marker logged, client gone.
expect_reject() {
    local name="$1"
    shift
    local ok=1 n rc=0 i ping_res=failed
    start_client "$@"
    wait_for_log "${WORK_DIR}/client.log" "$TLS_MARK" "$WAIT_SEC" || true
    for i in $(seq 1 "$WAIT_SEC"); do
        kill -0 "$CLIENT_PID" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "  client still running after ${WAIT_SEC}s"
        ok=0
        kill "$CLIENT_PID" 2>/dev/null || true
    fi
    wait "$CLIENT_PID" 2>/dev/null || rc=$?
    CLIENT_PID=""
    n=$(grep -c "$TLS_MARK" "${WORK_DIR}/client.log" || true)
    n=${n:-0}
    if [ "$n" -lt 1 ]; then
        echo "  '${TLS_MARK}' not in client log (count=$n, exit code=$rc)"
        ok=0
    fi
    if grep -qE "$_SANITIZER_RE" "${WORK_DIR}/client.log"; then
        echo "  sanitizer report in client log"
        ok=0
    fi
    if ip netns exec "$NS_CLI" ping -c 3 -W 1 172.16.0.2 >/dev/null 2>&1; then
        echo "  ping through the tunnel SUCCEEDED but must fail"
        ping_res=succeeded
        ok=0
    fi
    check_no_tun || ok=0
    echo "  rejected: ping=${ping_res} tls_log_count=$n exit_code=$rc"
    verdict "$name" "$ok"
}

verdict() {
    if [ "$2" -eq 1 ]; then
        echo "=== $1: PASS ==="
    else
        echo "=== $1: FAIL ==="
        dump_logs
        FAILED=$((FAILED + 1))
    fi
}

echo "=== Starting VPN server (cert A) ==="
start_server "${WORK_DIR}/a.crt" "${WORK_DIR}/a.key"

CONF_STALE="${WORK_DIR}/client_stale.conf"
cat > "$CONF_STALE" <<CONF
[Server]
Address = ${SERVER_ADDR}
Insecure = true
ServerName = wrong.example
Pin = ${PIN_B}
CONF

# The server's config, as --show-link reads it (the running server uses the
# same values on its command line).
cat > "${WORK_DIR}/server_a.conf" <<CONF
[Interface]
Listen = ${SERVER_ADDR}

[TLS]
Cert = ${WORK_DIR}/a.crt
Key = ${WORK_DIR}/a.key

[Auth]
Key = ${PSK}
CONF
# Piped, so stdout is not a terminal and the output is the single link line.
LINK_OK=$(ip netns exec "$NS_SVR" "$MQVPN" --show-link --config "${WORK_DIR}/server_a.conf" \
    --host "${SERVER_ADDR%:*}")
if [ "$LINK_OK" != "$LINK_HAND" ]; then
    echo "FAIL: --show-link printed a link that differs from the hand-built one"
    echo "  lines: $(printf '%s\n' "$LINK_OK" | wc -l) pin_in_link: $([[ $LINK_OK == *"pin=${PIN_A}" ]] && echo yes || echo no)"
    exit 1
fi

echo ""
echo "=== Case 1: link with the right pin ==="
expect_connect "Case 1 (right-pin link)" --connect "$LINK_OK"

echo ""
echo "=== Case 2: link with another key's pin ==="
expect_reject "Case 2 (wrong-pin link)" --connect "$LINK_BAD"

echo ""
echo "=== Case 3: certificate re-issued with the same key ==="
stop_server
openssl req -x509 -new -key "${WORK_DIR}/a.key" -out "${WORK_DIR}/a2.crt" \
    -days 365 -subj "/CN=mqvpn-connlink-a-reissued" 2>/dev/null
if [ "$(pin_of "${WORK_DIR}/a2.crt")" != "$PIN_A" ] \
    || cmp -s "${WORK_DIR}/a.crt" "${WORK_DIR}/a2.crt"; then
    echo "FAIL: re-issued cert must differ but keep the pin"
    exit 1
fi
start_server "${WORK_DIR}/a2.crt" "${WORK_DIR}/a.key"
expect_connect "Case 3 (re-issued cert, same link)" --connect "$LINK_OK"

echo ""
echo "=== Case 4: config with stale Pin / Insecure / ServerName ==="
expect_reject "Case 4a (config + wrong-pin link)" --config "$CONF_STALE" --connect "$LINK_BAD"
expect_connect "Case 4b (config + right-pin link)" --config "$CONF_STALE" --connect "$LINK_OK"

echo ""
echo "=== Case 5: pin without a link ==="
expect_connect "Case 5a (--pin right)" --mode client --server "$SERVER_ADDR" \
    --auth-key "$PSK" --pin "$PIN_A"
CONF_PIN="${WORK_DIR}/client_pin.conf"
printf '[Server]\nPin = %s\n' "$PIN_B" > "$CONF_PIN"
expect_connect "Case 5b (--pin right beats file Pin)" --mode client --config "$CONF_PIN" \
    --server "$SERVER_ADDR" --auth-key "$PSK" --pin "$PIN_A"
expect_reject "Case 5c (--pin wrong)" --mode client --server "$SERVER_ADDR" \
    --auth-key "$PSK" --pin "$PIN_B"
expect_reject "Case 5d (wrong file Pin, no --pin)" --mode client --config "$CONF_PIN" \
    --server "$SERVER_ADDR" --auth-key "$PSK"

echo ""
echo "=== Case 6: --show-link without --host, private address ==="
printf '[Interface]\nListen = 0.0.0.0:4433\n\n[TLS]\nCert = %s\nKey = %s\n\n[Auth]\nKey = %s\n' \
    "${WORK_DIR}/a.crt" "${WORK_DIR}/a.key" "$PSK" > "${WORK_DIR}/server_any.conf"
ok=1
rc=0
ip netns exec "$NS_SVR" "$MQVPN" --show-link --config "${WORK_DIR}/server_any.conf" \
    > "${WORK_DIR}/show6.out" 2> "${WORK_DIR}/show6.err" || rc=$?
if [ "$rc" -ne 3 ]; then
    echo "  exit code $rc, expected 3"
    ok=0
fi
if [ -s "${WORK_DIR}/show6.out" ]; then
    echo "  a link was printed"
    ok=0
fi
if ! grep -q -- "--host" "${WORK_DIR}/show6.err"; then
    echo "  stderr does not tell the user to pass --host: $(cat "${WORK_DIR}/show6.err")"
    ok=0
fi
if grep -qF "$PSK" "${WORK_DIR}/show6.err"; then
    echo "  stderr contains the auth key"
    ok=0
fi
verdict "Case 6 (private address, exit code 3)" "$ok"

echo ""
echo "=== Case 7: --show-link on a pseudo-terminal ==="
ok=1
script -qec "ip netns exec $NS_SVR $MQVPN --show-link --config ${WORK_DIR}/server_a.conf --host ${SERVER_ADDR%:*}" \
    /dev/null > "${WORK_DIR}/show7.out" || {
    echo "  --show-link exited with a non-zero status"
    ok=0
}
if grep -qE "$_SANITIZER_RE" "${WORK_DIR}/show7.out"; then
    echo "  sanitizer report in the --show-link output"
    ok=0
fi
if ! grep -q "mqvpn://${SERVER_ADDR}?key=" "${WORK_DIR}/show7.out"; then
    echo "  no mqvpn:// line"
    ok=0
fi
if ! grep -q "█\|▀\|▄" "${WORK_DIR}/show7.out"; then
    echo "  no QR block characters"
    ok=0
fi
if ! grep -q "contain the auth key" "${WORK_DIR}/show7.out"; then
    echo "  no secret notice line"
    ok=0
fi
# the client command repeats the link of the first line (the pty adds CRs)
tr -d '\r' < "${WORK_DIR}/show7.out" > "${WORK_DIR}/show7.clean"
link7=$(grep -m1 '^mqvpn://' "${WORK_DIR}/show7.clean" || true)
if [ -z "$link7" ] || ! grep -qxF "    sudo mqvpn --connect '${link7}'" "${WORK_DIR}/show7.clean"; then
    echo "  no client command line; link line was: '${link7}'"
    grep -n 'mqvpn --connect' "${WORK_DIR}/show7.clean" || true
    ok=0
fi
verdict "Case 7 (terminal output)" "$ok"

echo ""
echo "=== Case 8: server with a CA-issued certificate ==="
stop_server
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/ca.key" -out "${WORK_DIR}/ca.crt" -days 30 -nodes \
    -subj "/CN=mqvpn-connlink-ca" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/c.key" -out "${WORK_DIR}/c.csr" -nodes \
    -subj "/CN=vpn.test" 2>/dev/null
printf 'subjectAltName=DNS:vpn.test\n' > "${WORK_DIR}/c.ext"
openssl x509 -req -in "${WORK_DIR}/c.csr" -CA "${WORK_DIR}/ca.crt" \
    -CAkey "${WORK_DIR}/ca.key" -CAcreateserial -days 30 \
    -extfile "${WORK_DIR}/c.ext" -out "${WORK_DIR}/c.crt" 2>/dev/null
start_server "${WORK_DIR}/c.crt" "${WORK_DIR}/c.key"
cat > "${WORK_DIR}/server_c.conf" <<CONF
[Interface]
Listen = ${SERVER_ADDR}

[TLS]
Cert = ${WORK_DIR}/c.crt
Key = ${WORK_DIR}/c.key

[Auth]
Key = ${PSK}
CONF
# A CA certificate gives a link without a pin. The namespaces have no DNS, so
# the link carries the address and the name goes in --tls-server-name.
LINK_CA=$(ip netns exec "$NS_SVR" "$MQVPN" --show-link --config "${WORK_DIR}/server_c.conf" \
    --host "${SERVER_ADDR%:*}")
if [ "$LINK_CA" != "mqvpn://${SERVER_ADDR}?key=${PSK_ENC}" ]; then
    echo "FAIL: the link for a CA certificate must carry no pin"
    echo "  lines: $(printf '%s\n' "$LINK_CA" | wc -l) has_pin: $([[ $LINK_CA == *pin=* ]] && echo yes || echo no)"
    exit 1
fi
expect_reject "Case 8a (CA link, CA not trusted)" --connect "$LINK_CA" \
    --tls-server-name vpn.test
export SSL_CERT_FILE="${WORK_DIR}/ca.crt"
expect_connect "Case 8b (CA link, CA trusted)" --connect "$LINK_CA" \
    --tls-server-name vpn.test
expect_reject "Case 8c (CA link, wrong server name)" --connect "$LINK_CA" \
    --tls-server-name other.test
# The certificate passes the CA check, but the pin names another key.
expect_reject "Case 8d (CA-valid certificate, wrong pin)" --mode client \
    --server "$SERVER_ADDR" --auth-key "$PSK" --tls-server-name vpn.test --pin "$PIN_B"
unset SSL_CERT_FILE

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "=== connect link tests: ${FAILED} case(s) FAILED ==="
    exit 1
fi
echo "=== All connect link tests PASSED ==="
