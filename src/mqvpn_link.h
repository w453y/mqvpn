// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_link.h — internal side of mqvpn:// connection links. Parsing is the
 * public mqvpn_link_parse() in libmqvpn.h; formatting is internal.
 */
#ifndef MQVPN_LINK_H
#define MQVPN_LINK_H

#include <stddef.h>

/* pin may be NULL or "" for no pin. Brackets an IPv6 host and percent-encodes
 * every byte of auth_key outside A-Z a-z 0-9 - . _ ~ . Returns the length
 * written (excluding the NUL), or -1 if out is too small or an argument is
 * invalid. */
int mqvpn_link_format(const char *host, int port, const char *auth_key, const char *pin,
                      char *out, size_t out_len);

#endif /* MQVPN_LINK_H */
