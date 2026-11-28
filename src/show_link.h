// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * show_link.h — `mqvpn --show-link`: print an mqvpn:// connection link (and a
 * QR code on a terminal) for the server described by its config. CLI only;
 * the core library never touches a socket.
 */
#ifndef MQVPN_SHOW_LINK_H
#define MQVPN_SHOW_LINK_H

#include <stdio.h>

/* The public address is unknown: the caller must pass --host. */
#define MQVPN_EXIT_NO_PUBLIC_ADDR 3

struct sockaddr; /* the header includes no socket headers */

typedef enum {
    SHOW_LINK_CERT_SELF_SIGNED,
    SHOW_LINK_CERT_CA,
    SHOW_LINK_CERT_ERROR
} show_link_cert_kind_t;

/* Reads the first PEM certificate of cert_path (the leaf). Self-signed = its
 * own public key verifies its signature. Fills pin (always, on non-ERROR).
 * san = the FIRST DNS SAN, or "" when there is none or the first one is a
 * wildcard. */
show_link_cert_kind_t show_link_classify_cert(const char *cert_path, char pin[44],
                                              char san[256]);

/* 1 = usable in a link without --host; 0 = private, CGNAT, link-local, ULA,
 * loopback, unspecified or multicast. */
int show_link_addr_is_public(const struct sockaddr *sa);

/* listen_host / listen_port / cert_path / auth_key come from the server
 * config. host_override is "ADDR", "ADDR:PORT", "[V6]:PORT" or NULL.
 * out is a terminal: link, QR, the client command, then the one-line secret notice.
 * out is not a terminal: the link only, one line.
 * Errors go to stderr and never include the link or the key.
 * Returns the process exit code: 0, 1, or MQVPN_EXIT_NO_PUBLIC_ADDR. */
int show_link_run(const char *listen_host, int listen_port, const char *cert_path,
                  const char *auth_key, const char *host_override, FILE *out);

#endif /* MQVPN_SHOW_LINK_H */
