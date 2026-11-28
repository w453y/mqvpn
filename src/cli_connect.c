// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "cli_connect.h"

void
cli_connect_apply(mqvpn_client_cfg_t *cfg, const mqvpn_link_t *link, const char *cli_sni)
{
    cfg->server_addr = link->host;
    cfg->server_port = link->port;
    cfg->auth_key = link->auth_key;
    cfg->server_pin = link->pin[0] ? link->pin : NULL;
    cfg->insecure = 0;
    cfg->tls_server_name = link->pin[0] ? NULL : cli_sni;
}
