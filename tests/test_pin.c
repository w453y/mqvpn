// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_pin.c — pin value encoding and the SPKI fingerprint of a certificate.
 * Expected pins come from:
 *   openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
 *     | openssl dgst -sha256 -binary | basenc --base64url | tr -d '='
 */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "libmqvpn.h"
#include "mqvpn_internal.h"
#include "mqvpn_pin.h"

#define SELFSIGNED_PIN "I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzvM"
#define OTHER_PIN      "wdqeGrm_TvYhJTu9l1QFqGj50A49U3nEKuP3dS6Zw74"

static size_t
read_fixture(const char *name, uint8_t *buf, size_t cap)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", TEST_CERT_DIR, name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        assert(0);
    }
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    assert(n > 0);
    return n;
}

static void
expect_pin(const char *der_name, const char *want)
{
    uint8_t der[2048], pin[MQVPN_PIN_LEN];
    char str[MQVPN_PIN_STR_LEN + 1];
    size_t n = read_fixture(der_name, der, sizeof(der));
    assert(mqvpn_pin_from_cert_der(der, n, pin) == 0);
    mqvpn_pin_encode(pin, str);
    assert(strcmp(str, want) == 0);
}

static void
test_pin_from_cert_matches_openssl(void)
{
    expect_pin("pin_selfsigned.der", SELFSIGNED_PIN);
    expect_pin("pin_other.der", OTHER_PIN);
}

static void
test_pin_roundtrip(void)
{
    uint8_t in[MQVPN_PIN_LEN], out[MQVPN_PIN_LEN];
    char str[MQVPN_PIN_STR_LEN + 1];
    for (int i = 0; i < MQVPN_PIN_LEN; i++)
        in[i] = (uint8_t)(i * 37 + 250);
    mqvpn_pin_encode(in, str);
    assert(strlen(str) == MQVPN_PIN_STR_LEN);
    assert(mqvpn_pin_decode(str, out) == 0);
    assert(memcmp(in, out, MQVPN_PIN_LEN) == 0);

    memset(in, 0xff, sizeof(in)); /* exercises '-' and '_' */
    mqvpn_pin_encode(in, str);
    assert(strcmp(str, "__________________________________________8") == 0);
    assert(mqvpn_pin_decode(str, out) == 0);
    assert(memcmp(in, out, MQVPN_PIN_LEN) == 0);
}

static void
test_pin_decode_rejects(void)
{
    uint8_t out[MQVPN_PIN_LEN];
    char s[MQVPN_PIN_STR_LEN + 2];

    assert(mqvpn_pin_decode(NULL, out) == -1);
    assert(mqvpn_pin_decode("", out) == -1);

    memset(s, 'A', sizeof(s));
    s[MQVPN_PIN_STR_LEN - 1] = '\0';
    assert(mqvpn_pin_decode(s, out) == -1); /* 42 */
    s[MQVPN_PIN_STR_LEN - 1] = 'A';
    s[MQVPN_PIN_STR_LEN] = '\0';
    assert(mqvpn_pin_decode(s, out) == 0); /* 43, the control */
    s[MQVPN_PIN_STR_LEN] = 'A';
    s[MQVPN_PIN_STR_LEN + 1] = '\0';
    assert(mqvpn_pin_decode(s, out) == -1); /* 44 */

    const char bad[] = "+/=";
    for (size_t k = 0; k < sizeof(bad) - 1; k++) {
        memset(s, 'A', MQVPN_PIN_STR_LEN);
        s[MQVPN_PIN_STR_LEN] = '\0';
        s[10] = bad[k];
        assert(mqvpn_pin_decode(s, out) == -1);
    }

    /* the last char holds 4 bits, only 2 of them data: low 2 must be zero */
    const char ok_last[] = "AEIMQUYcgkosw048";
    for (int c = 0; c < 256; c++) {
        memset(s, 'A', MQVPN_PIN_STR_LEN);
        s[MQVPN_PIN_STR_LEN] = '\0';
        s[MQVPN_PIN_STR_LEN - 1] = (char)c;
        int allowed = c != 0 && strchr(ok_last, c) != NULL;
        assert((mqvpn_pin_decode(s, out) == 0) == allowed);
    }
}

static void
test_pin_from_cert_rejects_garbage(void)
{
    uint8_t junk[64], pin[MQVPN_PIN_LEN];
    for (int i = 0; i < 64; i++)
        junk[i] = (uint8_t)(i * 151 + 7);
    assert(mqvpn_pin_from_cert_der(junk, sizeof(junk), pin) == -1);
    assert(mqvpn_pin_from_cert_der(junk, 0, pin) == -1);
    assert(mqvpn_pin_from_cert_der(NULL, 10, pin) == -1);
}

static void
test_set_server_pin(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    assert(cfg && !cfg->has_server_pin);
    assert(mqvpn_config_set_server_pin(NULL, SELFSIGNED_PIN) == MQVPN_ERR_INVALID_ARG);

    assert(mqvpn_config_set_server_pin(cfg, SELFSIGNED_PIN) == MQVPN_OK);
    assert(cfg->has_server_pin == 1);
    uint8_t want[MQVPN_PIN_LEN];
    assert(mqvpn_pin_decode(SELFSIGNED_PIN, want) == 0);
    assert(memcmp(cfg->server_pin, want, MQVPN_PIN_LEN) == 0);

    /* a malformed pin changes nothing: the earlier good pin stays */
    assert(mqvpn_config_set_server_pin(cfg, "short") == MQVPN_ERR_INVALID_ARG);
    assert(mqvpn_config_set_server_pin(cfg, SELFSIGNED_PIN "A") == MQVPN_ERR_INVALID_ARG);
    assert(cfg->has_server_pin == 1);
    assert(memcmp(cfg->server_pin, want, MQVPN_PIN_LEN) == 0);

    assert(mqvpn_config_set_server_pin(cfg, NULL) == MQVPN_OK);
    assert(cfg->has_server_pin == 0);
    assert(mqvpn_config_set_server_pin(cfg, OTHER_PIN) == MQVPN_OK);
    assert(cfg->has_server_pin == 1);
    assert(mqvpn_config_set_server_pin(cfg, "") == MQVPN_OK);
    assert(cfg->has_server_pin == 0);
    mqvpn_config_free(cfg);
}

int
main(void)
{
    test_set_server_pin();
    test_pin_from_cert_matches_openssl();
    test_pin_roundtrip();
    test_pin_decode_rejects();
    test_pin_from_cert_rejects_garbage();
    printf("test_pin: all passed\n");
    return 0;
}
