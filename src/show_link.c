// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * show_link.c — `mqvpn --show-link`. Nothing here logs: the link and the auth
 * key go to the one output stream the caller passes, never to the log, and no
 * error message contains them.
 */
/* BoringSSL first: on Windows, wincrypt.h (pulled in by winsock2.h through
 * libmqvpn.h) defines macros such as X509_NAME that collide with its types. */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "show_link.h"

#include "libmqvpn.h"
#include "mqvpn_link.h"
#include "mqvpn_pin.h"
#include "qr_term.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <io.h>
#  define SL_SOCKET           SOCKET
#  define SL_BAD_SOCKET       INVALID_SOCKET
#  define sl_close_socket     closesocket
#  define sl_stream_is_tty(f) _isatty(_fileno(f))
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  define SL_SOCKET           int
#  define SL_BAD_SOCKET       (-1)
#  define sl_close_socket     close
#  define sl_stream_is_tty(f) isatty(fileno(f))
#endif

#define SL_LINK_MAX 2048

/* ---- console (Windows needs UTF-8 and ANSI escapes switched on for the QR) ---- */

#ifdef _WIN32
#  ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#    define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#  endif
typedef struct {
    HANDLE h;
    DWORD mode;
    UINT cp;
} sl_console_t;

/* Returns 1 when the QR can be drawn. On failure nothing is left changed. */
static int
sl_console_begin(sl_console_t *c)
{
    c->h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (c->h == INVALID_HANDLE_VALUE || c->h == NULL) return 0;
    if (!GetConsoleMode(c->h, &c->mode)) return 0;
    if (!SetConsoleMode(c->h, c->mode | ENABLE_PROCESSED_OUTPUT |
                                  ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        return 0;
    c->cp = GetConsoleOutputCP();
    if (!SetConsoleOutputCP(CP_UTF8)) {
        SetConsoleMode(c->h, c->mode);
        return 0;
    }
    return 1;
}

static void
sl_console_end(const sl_console_t *c)
{
    SetConsoleOutputCP(c->cp);
    SetConsoleMode(c->h, c->mode);
}
#else
typedef struct {
    int unused;
} sl_console_t;

static int
sl_console_begin(sl_console_t *c)
{
    (void)c;
    return 1;
}

static void
sl_console_end(const sl_console_t *c)
{
    (void)c;
}
#endif

/* ---- certificate ---- */

show_link_cert_kind_t
show_link_classify_cert(const char *cert_path, char pin[44], char san[256])
{
    show_link_cert_kind_t kind = SHOW_LINK_CERT_ERROR;
    BIO *bio = BIO_new_file(cert_path, "rb");
    X509 *x = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    if (!x) return SHOW_LINK_CERT_ERROR;

    uint8_t *der = NULL;
    int der_len = i2d_X509(x, &der);
    uint8_t raw[MQVPN_PIN_LEN];
    if (der_len <= 0 || mqvpn_pin_from_cert_der(der, (size_t)der_len, raw) != 0) goto out;
    mqvpn_pin_encode(raw, pin);

    san[0] = '\0';
    GENERAL_NAMES *gens =
        (GENERAL_NAMES *)X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    for (size_t i = 0; gens && i < sk_GENERAL_NAME_num(gens); i++) {
        const GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        if (g->type != GEN_DNS) continue;
        const uint8_t *d = ASN1_STRING_get0_data(g->d.dNSName);
        int n = ASN1_STRING_length(g->d.dNSName);
        /* A wildcard name cannot be dialled; an embedded NUL is never a host. */
        if (n > 0 && n < 256 && !memchr(d, '*', (size_t)n) && !memchr(d, 0, (size_t)n)) {
            memcpy(san, d, (size_t)n);
            san[n] = '\0';
        }
        break; /* only the first DNS SAN counts */
    }
    GENERAL_NAMES_free(gens);

    /* Self-signed = the certificate's own key verifies its signature; names are
     * not compared (a CA may issue a certificate with an identical name). */
    kind = X509_verify(x, X509_get0_pubkey(x)) == 1 ? SHOW_LINK_CERT_SELF_SIGNED
                                                    : SHOW_LINK_CERT_CA;
    ERR_clear_error();
out:
    OPENSSL_free(der);
    X509_free(x);
    return kind;
}

/* ---- address classification ---- */

static int
v4_is_public(uint32_t a) /* host order */
{
    uint32_t b0 = a >> 24, b1 = (a >> 16) & 0xff;
    if (b0 == 0 || b0 == 10 || b0 == 127) return 0;   /* this net, RFC 1918, loopback */
    if (b0 == 100 && b1 >= 64 && b1 <= 127) return 0; /* 100.64.0.0/10 */
    if (b0 == 169 && b1 == 254) return 0;             /* link-local */
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return 0;  /* RFC 1918 */
    if (b0 == 192 && b1 == 168) return 0;             /* RFC 1918 */
    if (b0 >= 224) return 0;                          /* multicast, reserved, broadcast */
    return 1;
}

int
show_link_addr_is_public(const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return v4_is_public(ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr));
    if (sa->sa_family != AF_INET6) return 0;

    const uint8_t *b = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
    static const uint8_t zero[16];
    if (memcmp(b, zero, 15) == 0 && b[15] <= 1) return 0;           /* :: and ::1 */
    if (memcmp(b, zero, 10) == 0 && b[10] == 0xff && b[11] == 0xff) /* ::ffff:a.b.c.d */
        return v4_is_public(((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) |
                            ((uint32_t)b[14] << 8) | b[15]);
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 0; /* fe80::/10 */
    if ((b[0] & 0xfe) == 0xfc) return 0;                 /* fc00::/7 */
    if (b[0] == 0xff) return 0;                          /* ff00::/8 */
    return 1;
}

/* Fill ss from an IP literal; returns its family, or -1. */
static int
parse_ip(const char *s, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof(*ss));
    struct sockaddr_in *a4 = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ss;
    if (inet_pton(AF_INET, s, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        return AF_INET;
    }
    memset(ss, 0, sizeof(*ss));
    if (inet_pton(AF_INET6, s, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        return AF_INET6;
    }
    return -1;
}

static int
is_unspecified(const struct sockaddr_storage *ss)
{
    static const uint8_t zero[16];
    if (ss->ss_family == AF_INET)
        return ((const struct sockaddr_in *)ss)->sin_addr.s_addr == 0;
    return memcmp(((const struct sockaddr_in6 *)ss)->sin6_addr.s6_addr, zero, 16) == 0;
}

static int
addr_to_string(const struct sockaddr_storage *ss, char *host, size_t len)
{
    const void *a = ss->ss_family == AF_INET
                        ? (const void *)&((const struct sockaddr_in *)ss)->sin_addr
                        : (const void *)&((const struct sockaddr_in6 *)ss)->sin6_addr;
    return inet_ntop(ss->ss_family, a, host, (socklen_t)len) ? 0 : -1;
}

/* The source address of the default route in this family. connect() on a UDP
 * socket only selects a route; no packet is sent. Never tries another family. */
static int
route_probe(int family, struct sockaddr_storage *out)
{
    struct sockaddr_storage dst;
    socklen_t dl;
    memset(&dst, 0, sizeof(dst));
    if (family == AF_INET) {
        struct sockaddr_in *d = (struct sockaddr_in *)&dst;
        d->sin_family = AF_INET;
        d->sin_port = htons(443);
        if (inet_pton(AF_INET, "1.1.1.1", &d->sin_addr) != 1) return -1;
        dl = sizeof(*d);
    } else {
        struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dst;
        d->sin6_family = AF_INET6;
        d->sin6_port = htons(443);
        if (inet_pton(AF_INET6, "2606:4700:4700::1111", &d->sin6_addr) != 1) return -1;
        dl = sizeof(*d);
    }
    SL_SOCKET s = socket(family, SOCK_DGRAM, 0);
    if (s == SL_BAD_SOCKET) return -1;
    int rc = -1;
    socklen_t ol = sizeof(*out);
    memset(out, 0, sizeof(*out));
    if (connect(s, (struct sockaddr *)&dst, dl) == 0 &&
        getsockname(s, (struct sockaddr *)out, &ol) == 0)
        rc = 0;
    sl_close_socket(s);
    return rc;
}

/* Replaced by the unit test to count calls and fake an address. */
static int (*show_link_probe)(int family, struct sockaddr_storage *out) = route_probe;

/* ---- --host ---- */

static int
parse_port(const char *s, int *port)
{
    if (!*s || strlen(s) > 5) return -1;
    int v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s - '0');
    }
    if (v < 1 || v > 65535) return -1;
    *port = v;
    return 0;
}

static int
is_v6_literal(const char *s)
{
    struct sockaddr_storage ss;
    return parse_ip(s, &ss) == AF_INET6;
}

/* "ADDR", "ADDR:PORT", "[V6]:PORT" or a bare IPv6 literal. *port stays 0
 * when the value has none. */
static int
parse_host_override(const char *s, char host[256], int *port)
{
    size_t n;
    *port = 0;
    if (s[0] == '[') {
        const char *close = strchr(s, ']');
        if (!close) return -1;
        n = (size_t)(close - s - 1);
        if (n == 0 || n >= 256) return -1;
        memcpy(host, s + 1, n);
        host[n] = '\0';
        if (!is_v6_literal(host)) return -1;
        if (close[1] == '\0') return 0;
        return close[1] == ':' ? parse_port(close + 2, port) : -1;
    }
    const char *colon = strchr(s, ':');
    if (colon &&
        strchr(colon + 1, ':')) { /* several colons, no brackets: IPv6, no port */
        if (strlen(s) >= 256 || !is_v6_literal(s)) return -1;
        memcpy(host, s, strlen(s) + 1);
        return 0;
    }
    n = colon ? (size_t)(colon - s) : strlen(s);
    if (n == 0 || n >= 256) return -1;
    for (size_t i = 0; i < n; i++) { /* the characters mqvpn_link_parse() accepts */
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '_'))
            return -1;
    }
    memcpy(host, s, n);
    host[n] = '\0';
    return colon ? parse_port(colon + 1, port) : 0;
}

/* ---- run ---- */

int
show_link_run(const char *listen_host, int listen_port, const char *cert_path,
              const char *auth_key, const char *host_override, FILE *out)
{
    char host[256], pin[44], san[256];
    int port = listen_port;

    if (host_override) {
        int p;
        if (parse_host_override(host_override, host, &p) < 0) {
            fprintf(stderr, "error: invalid --host: use ADDR, ADDR:PORT or "
                            "[IPv6]:PORT, port 1-65535\n");
            return 1;
        }
        if (p) port = p;
    }

    show_link_cert_kind_t kind = show_link_classify_cert(cert_path, pin, san);
    if (kind == SHOW_LINK_CERT_ERROR) {
        fprintf(stderr, "error: cannot read a PEM certificate from '%s'\n", cert_path);
        return 1;
    }

    if (!host_override) {
        if (kind == SHOW_LINK_CERT_CA) {
            if (!san[0]) {
                fprintf(stderr, "error: the certificate has no usable DNS name "
                                "(none, or a wildcard); use --host\n");
                return 1;
            }
            snprintf(host, sizeof(host), "%s", san);
        } else {
            struct sockaddr_storage ss;
            int family = parse_ip(listen_host, &ss);
            if (family < 0) {
                fprintf(stderr, "error: Listen is not an IP address; use --host\n");
                return 1;
            }
            /* 0.0.0.0 / :: = every address: ask the routing table, same family only */
            if (is_unspecified(&ss) && show_link_probe(family, &ss) < 0) {
                fprintf(stderr, "error: cannot find this server's address; use --host\n");
                return MQVPN_EXIT_NO_PUBLIC_ADDR;
            }
            if (!show_link_addr_is_public((const struct sockaddr *)&ss) ||
                addr_to_string(&ss, host, sizeof(host)) < 0) {
                fprintf(stderr, "error: the public address of this server is unknown "
                                "(the address found is not a public one); "
                                "use --host ADDR[:PORT]\n");
                return MQVPN_EXIT_NO_PUBLIC_ADDR;
            }
        }
    }

    char link[SL_LINK_MAX];
    const char *link_pin = kind == SHOW_LINK_CERT_SELF_SIGNED ? pin : NULL;
    if (mqvpn_link_format(host, port, auth_key, link_pin, link, sizeof(link)) < 0) {
        fprintf(stderr,
                "error: cannot build a link (the auth key must be 1-255 bytes)\n");
        return 1;
    }
    /* Never print a link a client would refuse. */
    mqvpn_link_t chk;
    memset(&chk, 0, sizeof(chk));
    chk.struct_size = sizeof(chk);
    if (mqvpn_link_parse(link, &chk) != MQVPN_OK || strcmp(chk.host, host) != 0 ||
        chk.port != port || strcmp(chk.auth_key, auth_key) != 0 ||
        strcmp(chk.pin, link_pin ? link_pin : "") != 0) {
        fprintf(stderr, "error: cannot build a valid link from this configuration\n");
        return 1;
    }

    fprintf(out, "%s\n", link);
    if (sl_stream_is_tty(out)) {
        sl_console_t con;
        if (sl_console_begin(&con)) {
            fflush(out);
            if (qr_term_print(out, link) < 0)
                fprintf(stderr, "warning: the link is too long for a QR code\n");
            fflush(out);
            sl_console_end(&con);
        }
        /* A link with a quote would break the shell line: skip the command then. */
        if (!strchr(link, '\'') && !strchr(link, '"')) {
#ifdef _WIN32 /* cmd.exe does not treat single quotes as quotes */
            fprintf(out, "\n  Connect a client with:\n    mqvpn --connect \"%s\"\n\n",
                    link);
#else
            fprintf(out, "\n  Connect a client with:\n    sudo mqvpn --connect '%s'\n\n",
                    link);
#endif
        }
        fprintf(out, "This link and QR code contain the auth key: treat them like a "
                     "password.\n");
    }
    if (fflush(out) != 0 || ferror(out)) {
        fprintf(stderr, "error: cannot write the link\n");
        return 1;
    }
    return 0;
}
