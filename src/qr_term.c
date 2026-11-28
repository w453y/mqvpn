// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "qr_term.h"

#include "qrcodegen.h"

#define QUIET 4

static int
dark(const uint8_t *qr, int size, int x, int y)
{
    return x >= 0 && x < size && y >= 0 && y < size && qrcodegen_getModule(qr, x, y);
}

int
qr_term_print(FILE *out, const char *text)
{
    uint8_t qr[qrcodegen_BUFFER_LEN_MAX], tmp[qrcodegen_BUFFER_LEN_MAX];
    if (!qrcodegen_encodeText(text, tmp, qr, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN,
                              qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true))
        return -1;

    int size = qrcodegen_getSize(qr);
    /* Black on white on every line, so a dark terminal theme cannot invert it. */
    for (int y = -QUIET; y < size + QUIET; y += 2) {
        fputs("\x1b[30;47m", out);
        for (int x = -QUIET; x < size + QUIET; x++) {
            int top = dark(qr, size, x, y), bot = dark(qr, size, x, y + 1);
            fputs(top ? (bot ? "\xe2\x96\x88" : "\xe2\x96\x80")
                      : (bot ? "\xe2\x96\x84" : " "),
                  out);
        }
        fputs("\x1b[0m\n", out);
    }
    return 0;
}
