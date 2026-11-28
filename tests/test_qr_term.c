// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qr_term.h"
#include "qrcodegen.h"

#define QUIET 4

static char *
slurp(FILE *f, size_t *len)
{
    fflush(f);
    rewind(f);
    char *buf = malloc(65536);
    assert(buf);
    *len = fread(buf, 1, 65535, f);
    buf[*len] = '\0';
    return buf;
}

/* Remove ESC [ ... m sequences in place. */
static void
strip_ansi(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        if (r[0] == '\x1b' && r[1] == '[') {
            r += 2;
            while (*r && *r != 'm')
                r++;
            if (!*r) break;
            continue;
        }
        *w++ = *r;
    }
    *w = '\0';
}

/* Decode one glyph into (top, bottom) darkness; return its byte length. */
static int
glyph(const char *p, int *top, int *bot)
{
    if (*p == ' ') {
        *top = 0;
        *bot = 0;
        return 1;
    }
    if (!strncmp(p, "\xe2\x96\x80", 3)) {
        *top = 1;
        *bot = 0;
        return 3;
    } /* U+2580 */
    if (!strncmp(p, "\xe2\x96\x84", 3)) {
        *top = 0;
        *bot = 1;
        return 3;
    } /* U+2584 */
    if (!strncmp(p, "\xe2\x96\x88", 3)) {
        *top = 1;
        *bot = 1;
        return 3;
    } /* U+2588 */
    assert(!"unexpected glyph");
    return 0;
}

static void
test_roundtrip(void)
{
    char text[131];
    memcpy(text, "mqvpn://example.test:443?pin=sha256:", 36);
    for (int i = 36; i < 130; i++)
        text[i] = (char)('A' + (i * 7) % 26);
    text[130] = '\0';
    assert(strlen(text) == 130);

    uint8_t qr[qrcodegen_BUFFER_LEN_MAX], tmp[qrcodegen_BUFFER_LEN_MAX];
    assert(qrcodegen_encodeText(text, tmp, qr, qrcodegen_Ecc_LOW, qrcodegen_VERSION_MIN,
                                qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true));
    int size = qrcodegen_getSize(qr);
    int total = size + 2 * QUIET;

    FILE *f = tmpfile();
    assert(f);
    assert(qr_term_print(f, text) == 0);
    size_t len;
    char *out = slurp(f, &len);
    fclose(f);
    assert(len > 0);
    strip_ansi(out);

    int row = 0, nlines = 0;
    for (char *line = out; *line;) {
        char *nl = strchr(line, '\n');
        assert(nl);
        *nl = '\0';
        int col = 0;
        for (const char *p = line; *p; col++) {
            int top, bot;
            p += glyph(p, &top, &bot);
            int y0 = row * 2 - QUIET, y1 = y0 + 1, x = col - QUIET;
            int e_top = x >= 0 && x < size && y0 >= 0 && y0 < size &&
                        qrcodegen_getModule(qr, x, y0);
            int e_bot = x >= 0 && x < size && y1 >= 0 && y1 < size &&
                        qrcodegen_getModule(qr, x, y1);
            assert(top == e_top);
            assert(bot == e_bot);
        }
        assert(col == total);
        row++;
        nlines++;
        line = nl + 1;
    }
    assert(nlines == (total + 1) / 2);
    free(out);
}

static void
test_too_long(void)
{
    char *text = malloc(4001);
    assert(text);
    memset(text, 'x', 4000);
    text[4000] = '\0';
    FILE *f = tmpfile();
    assert(f);
    assert(qr_term_print(f, text) == -1);
    size_t len;
    char *out = slurp(f, &len);
    assert(len == 0);
    free(out);
    fclose(f);
    free(text);
}

int
main(void)
{
    test_roundtrip();
    test_too_long();
    printf("test_qr_term: OK\n");
    return 0;
}
