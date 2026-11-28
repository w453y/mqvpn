// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include <limits.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "mqvpn_pin.h"

int
mqvpn_pin_from_cert_der(const uint8_t *der, size_t der_len, uint8_t out[MQVPN_PIN_LEN])
{
    if (!der || der_len == 0 || der_len > (size_t)INT_MAX) return -1;

    const uint8_t *p = der;
    X509 *x = d2i_X509(NULL, &p, (long)der_len);
    if (!x) return -1;

    int rc = -1;
    uint8_t *spki = NULL;
    int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &spki);
    if (n > 0 && spki) {
        SHA256(spki, (size_t)n, out);
        rc = 0;
    }
    OPENSSL_free(spki);
    X509_free(x);
    return rc;
}
