// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libmqvpn.h"
#include "mqvpn_link.h"
#include "mqvpn_pin.h"

#define LINK_SCHEME "mqvpn://"

static int
hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Percent-decode s[0..n) once into dst (capacity cap, NUL added). '+' stays
 * '+'. Returns the decoded length, or -1 on a broken escape, a NUL or control
 * character, or overflow. */
static int
pct_decode(const char *s, size_t n, char *dst, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '%') {
            if (i + 2 >= n) return -1;
            int h = hexval(s[i + 1]), l = hexval(s[i + 2]);
            if (h < 0 || l < 0) return -1;
            c = (unsigned char)(h * 16 + l);
            i += 2;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                     (c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == '_' ||
                     c == '~')) {
            /* A raw '=', ';' or '?' would let "key=k;pin=..." swallow the
             * pin into the key: anything else must be percent-encoded. */
            return -1;
        }
        if (c < 0x20 || c == 0x7f) return -1;
        if (o + 1 >= cap) return -1;
        dst[o++] = (char)c;
    }
    dst[o] = '\0';
    return (int)o;
}

static int
name_is(const char *p, size_t n, const char *name)
{
    return strlen(name) == n && memcmp(p, name, n) == 0;
}

/* Case-insensitive (ASCII) name_is(). */
int
mqvpn_link_parse(const char *link, mqvpn_link_t *out)
{
    if (!link || !out || out->struct_size < sizeof(*out)) return MQVPN_ERR_INVALID_ARG;
    if (strncmp(link, LINK_SCHEME, sizeof(LINK_SCHEME) - 1) != 0)
        return MQVPN_ERR_INVALID_ARG;
    const char *rest = link + sizeof(LINK_SCHEME) - 1;
    if (strchr(rest, '#')) return MQVPN_ERR_INVALID_ARG;

    const char *q = strchr(rest, '?');
    size_t alen = q ? (size_t)(q - rest) : strlen(rest);
    const char *query = q ? q + 1 : "";
    if (memchr(rest, '/', alen) || memchr(rest, '@', alen)) return MQVPN_ERR_INVALID_ARG;

    /* authority: host [":" port] */
    const char *host, *portp = NULL;
    size_t hlen, plen = 0;
    if (alen > 0 && rest[0] == '[') {
        const char *rb = memchr(rest, ']', alen);
        if (!rb) return MQVPN_ERR_INVALID_ARG;
        host = rest + 1;
        hlen = (size_t)(rb - host);
        const char *after = rb + 1;
        size_t alen2 = (size_t)(rest + alen - after);
        if (alen2 > 0) {
            if (after[0] != ':') return MQVPN_ERR_INVALID_ARG;
            portp = after + 1;
            plen = alen2 - 1;
        }
        if (!memchr(host, ':', hlen)) return MQVPN_ERR_INVALID_ARG;
        for (size_t i = 0; i < hlen; i++)
            if (hexval(host[i]) < 0 && host[i] != ':' && host[i] != '.')
                return MQVPN_ERR_INVALID_ARG;
    } else {
        const char *colon = memchr(rest, ':', alen);
        host = rest;
        hlen = colon ? (size_t)(colon - rest) : alen;
        if (colon) {
            portp = colon + 1;
            plen = alen - hlen - 1;
            if (memchr(portp, ':', plen)) return MQVPN_ERR_INVALID_ARG; /* bare IPv6 */
        }
        for (size_t i = 0; i < hlen; i++) {
            char c = host[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '_'))
                return MQVPN_ERR_INVALID_ARG;
        }
    }
    if (hlen == 0 || hlen >= sizeof(out->host)) return MQVPN_ERR_INVALID_ARG;

    int port = 443;
    if (portp) {
        if (plen == 0 || plen > 5) return MQVPN_ERR_INVALID_ARG;
        port = 0;
        for (size_t i = 0; i < plen; i++) {
            if (portp[i] < '0' || portp[i] > '9') return MQVPN_ERR_INVALID_ARG;
            port = port * 10 + (portp[i] - '0');
        }
        if (port < 1 || port > 65535) return MQVPN_ERR_INVALID_ARG;
    }

    /* query: split on '&' and the first '=', then decode each value once */
    char key[sizeof(out->auth_key)], pin[sizeof(out->pin)];
    int have_key = 0, have_pin = 0;
    for (const char *p = query; *p;) {
        size_t plen2 = strcspn(p, "&");
        const char *eq = memchr(p, '=', plen2);
        size_t nlen = eq ? (size_t)(eq - p) : plen2;
        const char *val = eq ? eq + 1 : p + plen2;
        size_t vlen = eq ? plen2 - nlen - 1 : 0;
        if (name_is(p, nlen, "key")) {
            if (have_key) return MQVPN_ERR_INVALID_ARG;
            int n = pct_decode(val, vlen, key, sizeof(key));
            if (n <= 0) return MQVPN_ERR_INVALID_ARG;
            have_key = 1;
        } else if (name_is(p, nlen, "pin")) {
            if (have_pin) return MQVPN_ERR_INVALID_ARG;
            uint8_t raw[MQVPN_PIN_LEN];
            if (pct_decode(val, vlen, pin, sizeof(pin)) < 0 ||
                mqvpn_pin_decode(pin, raw) != 0)
                return MQVPN_ERR_INVALID_ARG;
            have_pin = 1;
        } else {
            /* Only key and pin exist. An unknown, empty or look-alike name
             * ("PIN", "xpin", "") is an error, never ignored: a dropped pin
             * would silently weaken the link. */
            return MQVPN_ERR_INVALID_ARG;
        }
        p += plen2;
        if (*p == '&' && *++p == '\0') return MQVPN_ERR_INVALID_ARG; /* trailing '&' */
    }
    if (!have_key) return MQVPN_ERR_INVALID_ARG;

    /* everything validated: write *out in one go */
    memcpy(out->host, host, hlen);
    out->host[hlen] = '\0';
    out->port = port;
    memcpy(out->auth_key, key, strlen(key) + 1);
    if (have_pin)
        memcpy(out->pin, pin, strlen(pin) + 1);
    else
        out->pin[0] = '\0';
    return MQVPN_OK;
}

/* Append s (percent-encoded when enc) to out at *o; 0 on success, -1 if full. */
static int
put(char *out, size_t cap, size_t *o, const char *s, int enc)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        int plain = !enc || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                    c == '~';
        size_t need = plain ? 1 : 3;
        if (*o + need >= cap) return -1;
        if (plain)
            out[(*o)++] = (char)c;
        else
            *o += (size_t)snprintf(out + *o, cap - *o, "%%%02X", c);
    }
    return 0;
}

int
mqvpn_link_format(const char *host, int port, const char *auth_key, const char *pin,
                  char *out, size_t out_len)
{
    if (!host || !auth_key || !out || out_len == 0 || port < 1 || port > 65535) return -1;
    /* Refuse what mqvpn_link_parse() would reject: an empty or bracketed host
     * (the brackets are added here), a key of 0 or more than 255 bytes, and
     * a control byte in the key. */
    if (host[0] == '\0' || host[0] == '[' || auth_key[0] == '\0' ||
        strlen(auth_key) > 255)
        return -1;
    for (const char *k = auth_key; *k; k++)
        if ((unsigned char)*k < 0x20 || *k == 0x7f) return -1;
    int v6 = strchr(host, ':') != NULL;
    char num[8];
    size_t o = 0;
    snprintf(num, sizeof(num), "%d", port);
    if (put(out, out_len, &o, LINK_SCHEME, 0) || (v6 && put(out, out_len, &o, "[", 0)) ||
        put(out, out_len, &o, host, 0) || (v6 && put(out, out_len, &o, "]", 0)) ||
        put(out, out_len, &o, ":", 0) || put(out, out_len, &o, num, 0) ||
        put(out, out_len, &o, "?key=", 0) || put(out, out_len, &o, auth_key, 1) ||
        (pin && *pin &&
         (put(out, out_len, &o, "&pin=", 0) || put(out, out_len, &o, pin, 1)))) {
        out[0] = '\0';
        return -1;
    }
    out[o] = '\0';
    return (int)o;
}
