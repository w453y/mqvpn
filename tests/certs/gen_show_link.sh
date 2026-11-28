#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and contributors
#
# Regenerates the PEM fixtures used by tests/test_show_link.c. Run from this
# directory. The CA and every key stay in a temporary directory; only the
# certificates are kept. The self-signed fixture is pin_selfsigned.pem.
#
#   throwaway CA "mqvpn show-link CA"
#     ├─ show_ca_leaf.pem      SAN DNS:vpn.example.com
#     ├─ show_wild_first.pem   SAN DNS:*.example.com, DNS:vpn.example.com
#     ├─ show_no_san.pem       no SAN
#     └─ show_chain.pem        show_ca_leaf + the CA (leaf first)
#   same-name CA "same-name"
#     └─ show_same_name.pem    issuer == subject == "same-name", signed by the
#                              CA's key, not its own (the CA certificate is
#                              self-signed, the leaf is not)
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
days=3650
ec="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"

# mkca PREFIX CN
mkca() {
    # shellcheck disable=SC2086
    openssl req -x509 $ec -keyout "$tmp/$1.key" -out "$tmp/$1.crt" -days "$days" \
        -subj "/CN=$2" -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
# mkleaf PREFIX CAPREFIX CN SAN("" = none) OUT
mkleaf() {
    # shellcheck disable=SC2086
    openssl req $ec -keyout "$tmp/$1.key" -out "$tmp/$1.csr" -subj "/CN=$3" 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$tmp/$1.ext"
    if [ -n "$4" ]; then printf 'subjectAltName=%s\n' "$4" >> "$tmp/$1.ext"; fi
    openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/$2.crt" -CAkey "$tmp/$2.key" \
        -CAcreateserial -out "$5" -days "$days" -extfile "$tmp/$1.ext" 2>/dev/null
}

mkca ca "mqvpn show-link CA"
mkleaf l1 ca "leaf" "DNS:vpn.example.com" show_ca_leaf.pem
mkleaf l2 ca "wild" "DNS:*.example.com,DNS:vpn.example.com" show_wild_first.pem
mkleaf l3 ca "nosan" "" show_no_san.pem
cat show_ca_leaf.pem "$tmp/ca.crt" > show_chain.pem

mkca same "same-name"
mkleaf l4 same "same-name" "DNS:vpn.example.com" show_same_name.pem

# self-check: the same-name leaf is not self-signed, the others verify under their CA
openssl verify -CAfile "$tmp/ca.crt" show_ca_leaf.pem show_wild_first.pem show_no_san.pem > /dev/null
openssl verify -CAfile "$tmp/same.crt" show_same_name.pem > /dev/null
echo "fixtures regenerated"
