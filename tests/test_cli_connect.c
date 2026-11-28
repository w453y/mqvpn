// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* test_cli_connect.c — a link alone decides how the server is verified. */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "cli_connect.h"

#define PIN_X "I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzvM"
#define PIN_Y "wdqeGrm_TvYhJTu9l1QFqGj50A49U3nEKuP3dS6Zw74"

static mqvpn_client_cfg_t
stale_cfg(void)
{
    mqvpn_client_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.insecure = 1;
    cfg.tls_server_name = "old.example";
    cfg.server_pin = PIN_X;
    cfg.server_addr = "old";
    cfg.server_port = 1;
    cfg.auth_key = "oldkey";
    return cfg;
}

static mqvpn_link_t
make_link(const char *pin)
{
    mqvpn_link_t l;
    memset(&l, 0, sizeof(l));
    l.struct_size = sizeof(l);
    snprintf(l.host, sizeof(l.host), "vpn.example");
    l.port = 4433;
    snprintf(l.auth_key, sizeof(l.auth_key), "linkkey");
    snprintf(l.pin, sizeof(l.pin), "%s", pin);
    return l;
}

int
main(void)
{
    mqvpn_link_t pinned = make_link(PIN_Y), bare = make_link("");

    mqvpn_client_cfg_t c = stale_cfg();
    cli_connect_apply(&c, &pinned, NULL);
    assert(c.insecure == 0 && c.tls_server_name == NULL);
    assert(c.server_pin && strcmp(c.server_pin, PIN_Y) == 0);
    assert(strcmp(c.server_addr, "vpn.example") == 0 && c.server_port == 4433);
    assert(strcmp(c.auth_key, "linkkey") == 0);

    c = stale_cfg();
    cli_connect_apply(&c, &pinned, "x.example");
    assert(c.tls_server_name == NULL);

    c = stale_cfg();
    cli_connect_apply(&c, &bare, NULL);
    assert(c.server_pin == NULL && c.tls_server_name == NULL && c.insecure == 0);

    c = stale_cfg();
    cli_connect_apply(&c, &bare, "x.example");
    assert(c.server_pin == NULL && c.insecure == 0);
    assert(c.tls_server_name && strcmp(c.tls_server_name, "x.example") == 0);

    puts("PASS: test_cli_connect");
    return 0;
}
