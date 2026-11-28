// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_pin.h — server public-key pin: SHA-256 of the certificate's
 * SubjectPublicKeyInfo, written as 43 characters of unpadded base64url.
 * The encode/decode helpers are header-only because config.c and
 * mqvpn_config.c are compiled directly into targets that do not link
 * mqvpn_lib.
 */
#ifndef MQVPN_PIN_H
#define MQVPN_PIN_H

#include <stddef.h>
#include <stdint.h>

#define MQVPN_PIN_LEN     32 /* SHA-256 */
#define MQVPN_PIN_STR_LEN 43 /* base64url, no padding */

static const char mqvpn_pin_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static inline void
mqvpn_pin_encode(const uint8_t in[MQVPN_PIN_LEN], char out[MQVPN_PIN_STR_LEN + 1])
{
    size_t o = 0;
    for (size_t i = 0; i < MQVPN_PIN_LEN; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        size_t n = MQVPN_PIN_LEN - i < 3 ? MQVPN_PIN_LEN - i : 3;
        if (n > 1) v |= (uint32_t)in[i + 1] << 8;
        if (n > 2) v |= in[i + 2];
        for (size_t k = 0; k <= n; k++)
            out[o++] = mqvpn_pin_alphabet[(v >> (18 - 6 * k)) & 63];
    }
    out[o] = '\0';
}

/* 1 when a JSON key is "pin" in the wrong letter case ("Pin", "PIN"): JSON
 * keys are case-sensitive, so it would be ignored and the pin silently lost. */
static inline int
mqvpn_pin_key_is_miscased(const char *k)
{
    if (!k || k[0] == '\0' || k[1] == '\0' || k[2] == '\0' || k[3] != '\0') return 0;
    if (k[0] == 'p' && k[1] == 'i' && k[2] == 'n') return 0;
    return (k[0] | 0x20) == 'p' && (k[1] | 0x20) == 'i' && (k[2] | 0x20) == 'n';
}

/* 0 on success; -1 unless s is exactly 43 chars of canonical base64url
 * (alphabet A-Z a-z 0-9 - _, no '=', unused trailing bits zero). */
static inline int
mqvpn_pin_decode(const char *s, uint8_t out[MQVPN_PIN_LEN])
{
    uint8_t v[MQVPN_PIN_STR_LEN];
    if (!s) return -1;
    for (size_t i = 0; i < MQVPN_PIN_STR_LEN; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z')
            v[i] = (uint8_t)(c - 'A');
        else if (c >= 'a' && c <= 'z')
            v[i] = (uint8_t)(c - 'a' + 26);
        else if (c >= '0' && c <= '9')
            v[i] = (uint8_t)(c - '0' + 52);
        else if (c == '-')
            v[i] = 62;
        else if (c == '_')
            v[i] = 63;
        else
            return -1; /* includes the NUL of a short string */
    }
    if (s[MQVPN_PIN_STR_LEN] != '\0') return -1;
    if (v[MQVPN_PIN_STR_LEN - 1] & 3) return -1; /* 258 bits carry 256 */
    size_t o = 0;
    for (size_t i = 0; i < MQVPN_PIN_STR_LEN; i += 4) {
        size_t n = MQVPN_PIN_STR_LEN - i < 4 ? MQVPN_PIN_STR_LEN - i : 4;
        uint32_t x = 0;
        for (size_t k = 0; k < 4; k++)
            x = (x << 6) | (k < n ? v[i + k] : 0);
        for (size_t k = 0; k + 1 < n; k++)
            out[o++] = (uint8_t)(x >> (16 - 8 * k));
    }
    return 0;
}

/* SHA-256 of the certificate's SubjectPublicKeyInfo DER. 0 / -1. */
int mqvpn_pin_from_cert_der(const uint8_t *der, size_t der_len,
                            uint8_t out[MQVPN_PIN_LEN]);

#endif /* MQVPN_PIN_H */
