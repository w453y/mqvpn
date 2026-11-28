// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* test_link.c — mqvpn:// connection link parsing and formatting. */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "libmqvpn.h"
#include "mqvpn_link.h"

#define PIN "I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzvM"

static mqvpn_link_t
fresh(void)
{
    mqvpn_link_t l;
    memset(&l, 0x5a, sizeof(l));
    l.struct_size = sizeof(l);
    return l;
}

static void
ok(const char *link, const char *host, int port, const char *key, const char *pin)
{
    mqvpn_link_t l = fresh();
    assert(mqvpn_link_parse(link, &l) == MQVPN_OK);
    assert(strcmp(l.host, host) == 0);
    assert(l.port == port);
    assert(strcmp(l.auth_key, key) == 0);
    assert(strcmp(l.pin, pin) == 0);
}

static void
bad(const char *link)
{
    mqvpn_link_t l = fresh(), ref = fresh();
    assert(mqvpn_link_parse(link, &l) == MQVPN_ERR_INVALID_ARG);
    assert(memcmp(&l, &ref, sizeof(l)) == 0);
}

int
main(void)
{
    ok("mqvpn://203.0.113.5:443?key=abc&pin=" PIN, "203.0.113.5", 443, "abc", PIN);
    ok("mqvpn://203.0.113.5?key=abc", "203.0.113.5", 443, "abc", "");
    ok("mqvpn://[2001:db8::1]:8443?key=k", "2001:db8::1", 8443, "k", "");
    ok("mqvpn://[2001:db8::1]?key=k", "2001:db8::1", 443, "k", "");
    ok("mqvpn://vpn.example.com:65535?key=k", "vpn.example.com", 65535, "k", "");
    bad("mqvpn://h?x=1&key=k");
    ok("mqvpn://h?key=a%2Bb%2Fc%3D%3d", "h", 443, "a+b/c==", ""); /* decoded once */
    ok("mqvpn://h?key=%2541", "h", 443, "%41", "");               /* decoded once */

    /* format / parse round trip */
    {
        char buf[512];
        int n =
            mqvpn_link_format("vpn.example.com", 443, "a+b/c==", PIN, buf, sizeof(buf));
        assert(n > 0 && (size_t)n == strlen(buf));
        assert(strstr(buf, "key=a%2Bb%2Fc%3D%3D&pin=" PIN));
        assert(!strchr(buf + strlen("mqvpn://"), '+') && !strchr(buf + 8, '/'));
        assert(strchr(strchr(buf, '=') + 1, '=') == strstr(buf, "&pin=") + 4);
        ok(buf, "vpn.example.com", 443, "a+b/c==", PIN);

        n = mqvpn_link_format("2001:db8::1", 8443, "k~._-", NULL, buf, sizeof(buf));
        assert(strcmp(buf, "mqvpn://[2001:db8::1]:8443?key=k~._-") == 0);
        ok(buf, "2001:db8::1", 8443, "k~._-", "");
        n = mqvpn_link_format("h", 1, "k", "", buf, sizeof(buf));
        assert(n > 0 && !strstr(buf, "pin"));

        char small[8];
        assert(mqvpn_link_format("h", 1, "k", NULL, small, sizeof(small)) == -1);
        assert(mqvpn_link_format("h", 0, "k", NULL, buf, sizeof(buf)) == -1);

        /* never produce a link that mqvpn_link_parse() rejects */
        assert(mqvpn_link_format("[::1]", 443, "k", NULL, buf, sizeof(buf)) == -1);
        assert(mqvpn_link_format("h", 443, "", NULL, buf, sizeof(buf)) == -1);
        assert(mqvpn_link_format("h", 443, "a\nb", NULL, buf, sizeof(buf)) == -1);
        assert(mqvpn_link_format("h", 443, "a\x7f", NULL, buf, sizeof(buf)) == -1);
        char longkey[257];
        memset(longkey, 'a', 256);
        longkey[256] = '\0';
        char big[2048];
        assert(mqvpn_link_format("h", 443, longkey, NULL, big, sizeof(big)) == -1);
        longkey[255] = '\0';
        assert(mqvpn_link_format("h", 443, longkey, NULL, big, sizeof(big)) > 0);
    }

    bad("https://h?key=k");
    bad("mqvpn:h?key=k");
    bad("");
    bad("mqvpn://user@h?key=k");
    bad("mqvpn://h/x?key=k");
    bad("mqvpn://h?key=k#frag");
    bad("mqvpn://h#?key=k");
    bad("mqvpn://h");
    bad("mqvpn://h?");
    bad("mqvpn://h?pin=" PIN);
    bad("mqvpn://h?key=");
    bad("mqvpn://h?key");
    bad("mqvpn://h?key=k&key=k");
    bad("mqvpn://h?key=k&pin=" PIN "&pin=" PIN);
    bad("mqvpn://h?key=%zz");
    bad("mqvpn://h?key=%0");
    bad("mqvpn://h?key=%");
    bad("mqvpn://h?key=ab%");
    bad("mqvpn://h?key=%00");
    bad("mqvpn://h?key=%0a");
    bad("mqvpn://h?key=a%7F");
    bad("mqvpn://h?key=k&pin=I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzv");
    bad("mqvpn://h?key=k&pin=I7FvtHlDziB1xdZGyn+LS3mEDKTQoCGvgGp4/4HRzvM");
    bad("mqvpn://h?key=k&pin=I7FvtHlDziB1xdZGyn_LS3mEDKTQoCGvgGp4_4HRzvN"); /* bits */
    bad("mqvpn://h?key=k&pin=");
    /* look-alike parameter names are rejected, not ignored */
    bad("mqvpn://h?key=k&PIN=" PIN);
    bad("mqvpn://h?key=k&pin =" PIN);
    bad("mqvpn://h?key=k&pin\t=" PIN);
    bad("mqvpn://h?key=k& pin=" PIN);
    bad("mqvpn://h?KEY=k");
    bad("mqvpn://h?Key=k&key=k");
    bad("mqvpn://h?key=k&%70in=" PIN);
    bad("mqvpn://h?key=k&p%69n=x");
    /* key and pin are the only parameters; a slipped separator is an error */
    bad("mqvpn://h?key=k&x=1");
    bad("mqvpn://h?key=k&pinx=1");
    bad("mqvpn://h?key=k&xpin=" PIN);
    bad("mqvpn://h?key=k&=pin=" PIN);
    bad("mqvpn://h?key=k;pin=" PIN);
    bad("mqvpn://h?key=k?pin=" PIN);
    bad("mqvpn://h?key=kpin=" PIN);
    bad("mqvpn://h?key=k&");
    bad("mqvpn://h?key=k&&pin=" PIN);
    bad("mqvpn://h?key=a+b");
    bad("mqvpn://h?key=a/b");
    bad("mqvpn://h?key=k&keys=1");

    bad("mqvpn://h:0?key=k");
    bad("mqvpn://h:65536?key=k");
    bad("mqvpn://h:44a?key=k");
    bad("mqvpn://h:?key=k");
    bad("mqvpn://h:-1?key=k");
    bad("mqvpn://[2001:db8::1]:?key=k");
    bad("mqvpn://[2001:db8::1?key=k");
    bad("mqvpn://[2001:db8::1]x?key=k");
    bad("mqvpn://[]:443?key=k");
    bad("mqvpn://[example.com]?key=k");
    bad("mqvpn://2001:db8::1?key=k");
    bad("mqvpn://2001:db8::1:443?key=k");
    bad("mqvpn://:443?key=k");
    bad("mqvpn://?key=k");

    /* size limits */
    {
        char link[1200];
        char big[400];
        char big255[256];
        memset(big, 'a', sizeof(big));
        memset(big255, 'a', 255);
        big255[255] = '\0';

        snprintf(link, sizeof(link), "mqvpn://h?key=%.255s", big);
        ok(link, "h", 443, big255, "");
        snprintf(link, sizeof(link), "mqvpn://h?key=%.256s", big);
        bad(link);
        snprintf(link, sizeof(link), "mqvpn://h?key=%.300s", big);
        bad(link);

        snprintf(link, sizeof(link), "mqvpn://%.255s?key=k", big);
        ok(link, big255, 443, "k", "");
        snprintf(link, sizeof(link), "mqvpn://%.256s?key=k", big);
        bad(link);
    }

    {
        mqvpn_link_t l = fresh();
        mqvpn_link_t ref = fresh();
        assert(mqvpn_link_parse(NULL, &l) == MQVPN_ERR_INVALID_ARG);
        assert(mqvpn_link_parse("mqvpn://h?key=k", NULL) == MQVPN_ERR_INVALID_ARG);
        l.struct_size = sizeof(l) - 1;
        ref.struct_size = sizeof(l) - 1;
        assert(mqvpn_link_parse("mqvpn://h?key=k", &l) == MQVPN_ERR_INVALID_ARG);
        assert(memcmp(&l, &ref, sizeof(l)) == 0);
    }

    printf("test_link: all passed\n");
    return 0;
}
