// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_cert_decision.c — the client's certificate decision, without a
 * handshake: which xquic verification flags a config selects, and whether a
 * presented chain is trusted. Precedence: insecure > pin > verifier > library.
 */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <xquic/xquic.h>

#include "libmqvpn.h"
#include "mqvpn_internal.h"

#define SELFSIGNED_PIN "I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzvM"

static uint8_t g_a[2048], g_b[2048];
static size_t g_a_len, g_b_len;
static int g_calls;

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

static int
accept_verifier(const uint8_t *const certs[], const size_t lens[], size_t n,
                const char *host, void *ctx)
{
    (void)certs, (void)lens, (void)n, (void)host, (void)ctx;
    g_calls++;
    return 0;
}

static int
reject_verifier(const uint8_t *const certs[], const size_t lens[], size_t n,
                const char *host, void *ctx)
{
    (void)certs, (void)lens, (void)n, (void)host, (void)ctx;
    g_calls++;
    return -1;
}

static mqvpn_config_t *
make_cfg(int pin, mqvpn_cert_verify_fn fn)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    assert(cfg);
    if (pin) assert(mqvpn_config_set_server_pin(cfg, SELFSIGNED_PIN) == MQVPN_OK);
    if (fn) assert(mqvpn_config_set_cert_verifier(cfg, fn, NULL) == MQVPN_OK);
    g_calls = 0;
    return cfg;
}

static int
check(const mqvpn_config_t *cfg, const uint8_t *der, size_t len)
{
    const unsigned char *certs[1] = {der};
    size_t lens[1] = {len};
    return mqvpn_client_cert_check(cfg, certs, lens, der ? 1 : 0, "example.test");
}

static void
test_pin_ignores_accepting_verifier(void)
{
    mqvpn_config_t *cfg = make_cfg(1, accept_verifier);
    assert(check(cfg, g_b, g_b_len) == -1);
    assert(g_calls == 0);
    mqvpn_config_free(cfg);
}

static void
test_pin_ignores_rejecting_verifier(void)
{
    mqvpn_config_t *cfg = make_cfg(1, reject_verifier);
    assert(check(cfg, g_a, g_a_len) == 0);
    assert(g_calls == 0);
    mqvpn_config_free(cfg);
}

static void
test_no_pin_uses_verifier(void)
{
    mqvpn_config_t *cfg = make_cfg(0, accept_verifier);
    assert(check(cfg, g_b, g_b_len) == 0);
    assert(g_calls == 1);
    mqvpn_config_free(cfg);
}

static void
test_pin_error_paths_reject(void)
{
    mqvpn_config_t *cfg = make_cfg(1, accept_verifier);
    uint8_t junk[64];
    memset(junk, 0x5a, sizeof(junk));
    assert(check(cfg, junk, sizeof(junk)) == -1);
    assert(check(cfg, g_a, 0) == -1);
    const unsigned char *certs[1] = {g_a};
    size_t lens[1] = {g_a_len};
    assert(mqvpn_client_cert_check(cfg, certs, lens, 0, "x") == -1);
    assert(g_calls == 0);
    mqvpn_config_free(cfg);
}

static void
test_no_pin_no_verifier_rejects(void)
{
    mqvpn_config_t *cfg = make_cfg(0, NULL);
    assert(check(cfg, g_a, g_a_len) == -1);
    mqvpn_config_free(cfg);
}

static void
test_flags(void)
{
    mqvpn_config_t *cfg = make_cfg(1, NULL);
    assert(mqvpn_config_set_insecure(cfg, 1) == MQVPN_OK);
    assert(mqvpn_client_cert_verify_flags(cfg) == XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED);
    mqvpn_config_free(cfg);

    cfg = make_cfg(1, NULL);
    assert(mqvpn_client_cert_verify_flags(cfg) ==
           (XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_APP_VERIFY));
    mqvpn_config_free(cfg);

    cfg = make_cfg(0, accept_verifier);
    assert(mqvpn_client_cert_verify_flags(cfg) ==
           (XQC_TLS_CERT_FLAG_NEED_VERIFY | XQC_TLS_CERT_FLAG_APP_VERIFY));
    mqvpn_config_free(cfg);

    cfg = make_cfg(0, NULL);
    assert(mqvpn_client_cert_verify_flags(cfg) == XQC_TLS_CERT_FLAG_NEED_VERIFY);
    mqvpn_config_free(cfg);
}

int
main(void)
{
    g_a_len = read_fixture("pin_selfsigned.der", g_a, sizeof(g_a));
    g_b_len = read_fixture("pin_other.der", g_b, sizeof(g_b));
    test_pin_ignores_accepting_verifier();
    test_pin_ignores_rejecting_verifier();
    test_no_pin_uses_verifier();
    test_pin_error_paths_reject();
    test_no_pin_no_verifier_rejects();
    test_flags();
    printf("test_cert_decision: all passed\n");
    return 0;
}
