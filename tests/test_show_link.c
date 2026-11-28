// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_show_link.c — `mqvpn --show-link`: certificate classification, address
 * classification, host choice and the printed link. The unit under test is
 * included so the test can replace its file-local route probe.
 */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/show_link.c"

#define SELFSIGNED_PIN "I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzvM"
#define KEY            "s3cr3t+key/=1"

static char *
cert(const char *name)
{
    static char path[4][512];
    static int i;
    i = (i + 1) % 4;
    snprintf(path[i], sizeof(path[i]), "%s/%s", TEST_CERT_DIR, name);
    return path[i];
}

/* ---- address classification ---- */

static int
pub(const char *s)
{
    struct sockaddr_storage ss;
    assert(parse_ip(s, &ss) > 0);
    return show_link_addr_is_public((const struct sockaddr *)&ss);
}

static void
test_addr(void)
{
    const char *yes[] = {"8.8.8.8",        "203.0.113.5",         "2001:4860::1",
                         "172.15.255.255", "172.32.0.0",          "100.63.255.255",
                         "100.128.0.0",    "2606:4700:4700::1111"};
    const char *no[] = {"10.1.2.3",
                        "172.16.0.1",
                        "172.31.255.255",
                        "192.168.1.1",
                        "100.64.0.1",
                        "100.127.255.255",
                        "169.254.1.1",
                        "127.0.0.1",
                        "0.0.0.0",
                        "224.0.0.1",
                        "fe80::1",
                        "fc00::1",
                        "fd12::1",
                        "::1",
                        "::",
                        "ff02::1",
                        "::ffff:10.0.0.1"};
    for (size_t i = 0; i < sizeof(yes) / sizeof(*yes); i++)
        assert(pub(yes[i]) == 1);
    for (size_t i = 0; i < sizeof(no) / sizeof(*no); i++)
        assert(pub(no[i]) == 0);
    assert(pub("::ffff:8.8.8.8") == 1);
}

/* ---- certificate classification ---- */

static void
test_classify(void)
{
    char pin[44], san[256];

    assert(show_link_classify_cert(cert("pin_selfsigned.pem"), pin, san) ==
           SHOW_LINK_CERT_SELF_SIGNED);
    assert(strcmp(pin, SELFSIGNED_PIN) == 0);

    assert(show_link_classify_cert(cert("show_ca_leaf.pem"), pin, san) ==
           SHOW_LINK_CERT_CA);
    assert(strcmp(san, "vpn.example.com") == 0 && strlen(pin) == 43);

    /* issuer and subject names are equal, but another key signed it */
    assert(show_link_classify_cert(cert("show_same_name.pem"), pin, san) ==
           SHOW_LINK_CERT_CA);

    /* first DNS SAN is a wildcard: no SAN, even though a second one is concrete */
    assert(show_link_classify_cert(cert("show_wild_first.pem"), pin, san) ==
           SHOW_LINK_CERT_CA);
    assert(san[0] == '\0');

    assert(show_link_classify_cert(cert("show_no_san.pem"), pin, san) ==
           SHOW_LINK_CERT_CA);
    assert(san[0] == '\0');

    /* leaf + intermediate: the leaf decides */
    assert(show_link_classify_cert(cert("show_chain.pem"), pin, san) ==
           SHOW_LINK_CERT_CA);
    assert(strcmp(san, "vpn.example.com") == 0);

    assert(show_link_classify_cert(cert("does-not-exist.pem"), pin, san) ==
           SHOW_LINK_CERT_ERROR);
    assert(show_link_classify_cert(cert("pin_selfsigned.der"), pin, san) ==
           SHOW_LINK_CERT_ERROR); /* PEM only */
}

/* ---- run ---- */

static int probe_v4, probe_v6;
static int probe_fail;

static int
fake_probe(int family, struct sockaddr_storage *out)
{
    memset(out, 0, sizeof(*out));
    if (family == AF_INET) {
        probe_v4++;
        ((struct sockaddr_in *)out)->sin_family = AF_INET;
        inet_pton(AF_INET, "203.0.113.9", &((struct sockaddr_in *)out)->sin_addr);
    } else {
        probe_v6++;
        ((struct sockaddr_in6 *)out)->sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2001:4860::9", &((struct sockaddr_in6 *)out)->sin6_addr);
    }
    return probe_fail ? -1 : 0;
}

/* Runs show_link_run into a non-terminal stream; returns the exit code and
 * leaves the text written in buf. */
static int
run(const char *listen, int port, const char *cert_name, const char *key,
    const char *host, char *buf, size_t cap)
{
    FILE *f = tmpfile();
    assert(f);
    int rc = show_link_run(listen, port, cert(cert_name), key, host, f);
    rewind(f);
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return rc;
}

/* The output is exactly one line that parses back to the expected values. */
static void
expect_link(const char *buf, const char *host, int port, const char *key, const char *pin)
{
    size_t n = strlen(buf);
    assert(n > 0 && buf[n - 1] == '\n' && !memchr(buf, '\n', n - 1));
    char line[2048];
    snprintf(line, sizeof(line), "%.*s", (int)(n - 1), buf);
    mqvpn_link_t l;
    memset(&l, 0, sizeof(l));
    l.struct_size = sizeof(l);
    assert(mqvpn_link_parse(line, &l) == MQVPN_OK);
    assert(strcmp(l.host, host) == 0 && l.port == port);
    assert(strcmp(l.auth_key, key) == 0 && strcmp(l.pin, pin) == 0);
}

static void
test_run(void)
{
    char buf[4096];
    show_link_probe = fake_probe;

    /* explicit host, self-signed: pin, listen port */
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, "192.0.2.7", buf,
               sizeof(buf)) == 0);
    assert(strncmp(buf, "mqvpn://192.0.2.7:443?key=", 26) == 0);
    expect_link(buf, "192.0.2.7", 443, KEY, SELFSIGNED_PIN);
    assert(probe_v4 == 0 && probe_v6 == 0);

    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, "192.0.2.7:8443", buf,
               sizeof(buf)) == 0);
    expect_link(buf, "192.0.2.7", 8443, KEY, SELFSIGNED_PIN);
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, "[2001:db8::1]:8444", buf,
               sizeof(buf)) == 0);
    expect_link(buf, "2001:db8::1", 8444, KEY, SELFSIGNED_PIN);
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, "2001:db8::1", buf,
               sizeof(buf)) == 0);
    expect_link(buf, "2001:db8::1", 443, KEY, SELFSIGNED_PIN);
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, "vpn.example.org", buf,
               sizeof(buf)) == 0);
    expect_link(buf, "vpn.example.org", 443, KEY, SELFSIGNED_PIN);

    /* a host the link parser would not accept is refused up front */
    {
        static const char *const badh[] = {"bad host", "h?x", "a/b"};
        for (size_t i = 0; i < sizeof(badh) / sizeof(badh[0]); i++) {
            assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, badh[i], buf,
                       sizeof(buf)) == 1);
            assert(buf[0] == '\0');
        }
    }

    /* an explicit private address is used as given */
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, "10.0.0.5", buf, sizeof(buf)) ==
           0);
    expect_link(buf, "10.0.0.5", 443, KEY, SELFSIGNED_PIN);

    /* malformed --host: error, nothing printed */
    const char *bad[] = {"",       ":443",  "h:0",     "h:65536", "h:x",
                         "h:",     "[::1",  "[::1]x",  "[::1]:",  "[1.2.3.4]:443",
                         "[]:443", "1:2:3", "[h]:443", "a/b?c",   "h:1:2"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, bad[i], buf, sizeof(buf)) ==
               1);
        assert(buf[0] == '\0');
    }

    /* CA certificate: first DNS SAN, no pin */
    assert(run("0.0.0.0", 443, "show_ca_leaf.pem", KEY, NULL, buf, sizeof(buf)) == 0);
    expect_link(buf, "vpn.example.com", 443, KEY, "");
    assert(run("0.0.0.0", 443, "show_ca_leaf.pem", KEY, "192.0.2.7", buf, sizeof(buf)) ==
           0);
    expect_link(buf, "192.0.2.7", 443, KEY, "");
    assert(run("0.0.0.0", 443, "show_wild_first.pem", KEY, NULL, buf, sizeof(buf)) == 1);
    assert(buf[0] == '\0');
    assert(run("0.0.0.0", 443, "show_no_san.pem", KEY, NULL, buf, sizeof(buf)) == 1);
    assert(buf[0] == '\0');
    assert(run("0.0.0.0", 443, "show_same_name.pem", KEY, "192.0.2.7", buf,
               sizeof(buf)) == 0);
    expect_link(buf, "192.0.2.7", 443, KEY,
                ""); /* same name does not make it self-signed */

    /* a specific public Listen address is used as is */
    assert(run("198.51.100.4", 4433, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) ==
           0);
    expect_link(buf, "198.51.100.4", 4433, KEY, SELFSIGNED_PIN);
    assert(run("2001:4860::5", 443, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) ==
           0);
    expect_link(buf, "2001:4860::5", 443, KEY, SELFSIGNED_PIN);
    assert(probe_v4 == 0 && probe_v6 == 0);

    /* a specific private / loopback Listen address and no --host */
    assert(run("127.0.0.1", 443, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) ==
           MQVPN_EXIT_NO_PUBLIC_ADDR);
    assert(buf[0] == '\0');
    assert(run("192.168.1.2", 443, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) ==
           MQVPN_EXIT_NO_PUBLIC_ADDR);
    assert(run("not-an-ip", 443, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) == 1);

    /* family follows Listen, never the other one */
    probe_v4 = probe_v6 = 0;
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) == 0);
    assert(probe_v4 == 1 && probe_v6 == 0);
    expect_link(buf, "203.0.113.9", 443, KEY, SELFSIGNED_PIN);
    probe_v4 = probe_v6 = 0;
    assert(run("::", 443, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) == 0);
    assert(probe_v4 == 0 && probe_v6 == 1);
    expect_link(buf, "2001:4860::9", 443, KEY, SELFSIGNED_PIN);
    assert(strncmp(buf, "mqvpn://[2001:4860::9]:443?key=", 31) == 0);

    /* the probe fails for the family: exit code 3, no switch to the other one */
    probe_v4 = probe_v6 = 0;
    probe_fail = 1;
    assert(run("::", 443, "pin_selfsigned.pem", KEY, NULL, buf, sizeof(buf)) ==
           MQVPN_EXIT_NO_PUBLIC_ADDR);
    assert(probe_v4 == 0 && probe_v6 == 1 && buf[0] == '\0');
    probe_fail = 0;

    /* a probe that finds a private address is "unknown", not an error */
    show_link_probe = route_probe;

    /* errors: missing certificate is 1, not 3; unusable keys */
    assert(run("0.0.0.0", 443, "does-not-exist.pem", KEY, NULL, buf, sizeof(buf)) == 1);
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", "", "192.0.2.7", buf, sizeof(buf)) ==
           1);
    char longkey[300];
    memset(longkey, 'k', sizeof(longkey));
    longkey[256] = '\0';
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", longkey, "192.0.2.7", buf,
               sizeof(buf)) == 1);
    assert(buf[0] == '\0');
    longkey[255] = '\0';
    assert(run("0.0.0.0", 443, "pin_selfsigned.pem", longkey, "192.0.2.7", buf,
               sizeof(buf)) == 0);
    expect_link(buf, "192.0.2.7", 443, longkey, SELFSIGNED_PIN);
}

int
main(void)
{
    test_addr();
    test_classify();
    test_run();
    printf("PASS: test_show_link\n");
    return 0;
}
