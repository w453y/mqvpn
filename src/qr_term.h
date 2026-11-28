// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_QR_TERM_H
#define MQVPN_QR_TERM_H

#include <stdio.h>

/* Draw text as a QR code with UTF-8 half blocks (two module rows per
 * line), 4-module quiet zone, explicit black-on-white ANSI colours.
 * 0 on success, -1 (nothing written) if text does not fit a QR code. */
int qr_term_print(FILE *out, const char *text);

#endif /* MQVPN_QR_TERM_H */
