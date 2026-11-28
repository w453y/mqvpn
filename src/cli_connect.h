// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_CLI_CONNECT_H
#define MQVPN_CLI_CONNECT_H

#include "libmqvpn.h"
#include "vpn_client.h"

/* The one place that enforces "the link alone decides how the server is
 * verified". Overwrites server_addr, server_port, auth_key and server_pin
 * from *link (server_pin = NULL when the link has no pin); sets insecure = 0;
 * sets tls_server_name = cli_sni only when the link has no pin, otherwise
 * NULL. cli_sni is the --tls-server-name value from the command line (NULL
 * if absent), never the config file's ServerName. cfg's pointers point into
 * *link, which must outlive cfg. */
void cli_connect_apply(mqvpn_client_cfg_t *cfg, const mqvpn_link_t *link,
                       const char *cli_sni);

#endif /* MQVPN_CLI_CONNECT_H */
