// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_dgram_fq.c — unit tests for the per-flow DATAGRAM fair queue.
 */

/* Keep assert() live even in Release builds (CI-checked). */
#undef NDEBUG
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dgram_fq.h"

static int g_run = 0;
#define RUN(fn)                  \
    do {                         \
        printf("  %-40s ", #fn); \
        fn();                    \
        g_run++;                 \
        printf("PASS\n");        \
    } while (0)

/* A packet is 100 bytes: [flow id][sequence in that flow][fill]. */
#define PKT 100

static void
mk(uint8_t *p, uint8_t flow, uint8_t seq)
{
    memset(p, 0xab, PKT);
    p[0] = flow;
    p[1] = seq;
}

static void
put(mqvpn_dgram_fq_t *q, uint8_t flow, uint8_t seq)
{
    uint8_t p[PKT];
    mk(p, flow, seq);
    mqvpn_dgram_fq_enqueue(q, flow, 1000u + flow, p, PKT);
}

/* Records what was sent; refuses (AGAIN) once `budget` sends were taken,
 * and fails for good every packet whose sequence is `fail_seq`. */
typedef struct {
    uint8_t flow[256], seq[256];
    uint32_t hash[256];
    int n;
    int budget;
    int fail_seq;
} sink_t;

static int
sink_send(void *ctx, uint32_t flow_hash, const uint8_t *frame, size_t len)
{
    sink_t *s = ctx;
    assert(len == PKT);
    if (s->budget >= 0 && s->n >= s->budget) return MQVPN_DGRAM_FQ_AGAIN;
    if (frame[1] == s->fail_seq) return -1;
    s->flow[s->n] = frame[0];
    s->seq[s->n] = frame[1];
    s->hash[s->n] = flow_hash;
    s->n++;
    return 0;
}

static void
sink_init(sink_t *s)
{
    memset(s, 0, sizeof(*s));
    s->budget = -1;
    s->fail_seq = -1;
}

static void
test_empty(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(10 * PKT, PKT);
    assert(q);
    sink_t s;
    sink_init(&s);
    assert(mqvpn_dgram_fq_empty(q));
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 0);
    assert(s.n == 0);
    mqvpn_dgram_fq_free(q);
}

static void
test_fifo_within_flow(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(10 * PKT, PKT);
    for (int i = 0; i < 5; i++)
        put(q, 7, (uint8_t)i);
    assert(mqvpn_dgram_fq_packets(q) == 5);
    assert(mqvpn_dgram_fq_bytes(q) == 5 * PKT);
    sink_t s;
    sink_init(&s);
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 5);
    for (int i = 0; i < 5; i++) {
        assert(s.flow[i] == 7 && s.seq[i] == i);
        assert(s.hash[i] == 1007); /* the hint, not the queue key */
    }
    assert(mqvpn_dgram_fq_empty(q));
    mqvpn_dgram_fq_free(q);
}

/* A big flow queued first does not make a later small flow wait for it:
 * with a one-packet quantum the two alternate. */
static void
test_round_robin(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(100 * PKT, PKT);
    for (int i = 0; i < 10; i++)
        put(q, 1, (uint8_t)i);
    put(q, 2, 0);
    put(q, 2, 1);
    sink_t s;
    sink_init(&s);
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 12);
    /* 1/0, 2/0, 1/1, 2/1, then the rest of flow 1 in order */
    assert(s.flow[0] == 1 && s.seq[0] == 0);
    assert(s.flow[1] == 2 && s.seq[1] == 0);
    assert(s.flow[2] == 1 && s.seq[2] == 1);
    assert(s.flow[3] == 2 && s.seq[3] == 1);
    for (int i = 4; i < 12; i++)
        assert(s.flow[i] == 1 && s.seq[i] == i - 2);
    mqvpn_dgram_fq_free(q);
}

/* Over the limit, the flow holding the most bytes loses its oldest packets;
 * the small flow keeps its packet. */
static void
test_drop_from_fattest(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(10 * PKT, PKT);
    put(q, 2, 0);
    int dropped = 0;
    for (int i = 0; i < 20; i++) {
        uint8_t p[PKT];
        mk(p, 1, (uint8_t)i);
        dropped += mqvpn_dgram_fq_enqueue(q, 1, 1001, p, PKT);
    }
    assert(dropped == 11);
    assert(mqvpn_dgram_fq_dropped(q) == 11);
    assert(mqvpn_dgram_fq_bytes(q) == 10 * PKT);
    sink_t s;
    sink_init(&s);
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 10);
    int small = 0;
    for (int i = 0; i < s.n; i++) {
        if (s.flow[i] == 2) small++;
        /* flow 1 lost its oldest: what is left is the newest nine, in order */
        if (s.flow[i] == 1) assert(s.seq[i] >= 11);
    }
    assert(small == 1);
    mqvpn_dgram_fq_free(q);
}

/* AGAIN stops the drain and keeps the packet; the next drain resumes with it. */
static void
test_again_keeps_packet(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(10 * PKT, PKT);
    for (int i = 0; i < 4; i++)
        put(q, 3, (uint8_t)i);
    sink_t s;
    sink_init(&s);
    s.budget = 2;
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 2);
    assert(mqvpn_dgram_fq_packets(q) == 2);
    s.budget = -1;
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 2);
    for (int i = 0; i < 4; i++)
        assert(s.seq[i] == i);
    assert(mqvpn_dgram_fq_dropped(q) == 0);
    mqvpn_dgram_fq_free(q);
}

/* A send that fails for good drops that packet and goes on. */
static void
test_failed_send_drops(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(10 * PKT, PKT);
    for (int i = 0; i < 3; i++)
        put(q, 4, (uint8_t)i);
    sink_t s;
    sink_init(&s);
    s.fail_seq = 1;
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 2);
    assert(s.seq[0] == 0 && s.seq[1] == 2);
    assert(mqvpn_dgram_fq_dropped(q) == 1);
    assert(mqvpn_dgram_fq_empty(q));
    mqvpn_dgram_fq_free(q);
}

/* A flow that empties and comes back is served again. */
static void
test_flow_returns(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(10 * PKT, PKT);
    sink_t s;
    sink_init(&s);
    put(q, 5, 0);
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 1);
    put(q, 5, 1);
    put(q, 6, 0);
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 2);
    assert(s.flow[1] == 5 && s.seq[1] == 1);
    assert(s.flow[2] == 6);
    mqvpn_dgram_fq_free(q);
}

/* Flows with one xquic hint (UDP and ICMP without wlb_udp_pin) still get a
 * queue each when their keys differ. */
static void
test_key_not_hint(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(100 * PKT, PKT);
    uint8_t p[PKT];
    for (int i = 0; i < 6; i++) {
        mk(p, 1, (uint8_t)i);
        mqvpn_dgram_fq_enqueue(q, 11, 99, p, PKT);
    }
    mk(p, 2, 0);
    mqvpn_dgram_fq_enqueue(q, 12, 99, p, PKT);
    sink_t s;
    sink_init(&s);
    assert(mqvpn_dgram_fq_drain(q, sink_send, &s) == 7);
    assert(s.flow[1] == 2); /* second out, not last */
    assert(s.hash[1] == 99);
    mqvpn_dgram_fq_free(q);
}

/* Freeing a queue that still holds packets releases them (ASan checks). */
static void
test_free_nonempty(void)
{
    mqvpn_dgram_fq_t *q = mqvpn_dgram_fq_new(100 * PKT, PKT);
    for (int i = 0; i < 30; i++)
        put(q, (uint8_t)(i % 3), (uint8_t)i);
    mqvpn_dgram_fq_free(q);
    mqvpn_dgram_fq_free(NULL);
}

int
main(void)
{
    printf("test_dgram_fq:\n");
    RUN(test_empty);
    RUN(test_fifo_within_flow);
    RUN(test_round_robin);
    RUN(test_drop_from_fattest);
    RUN(test_again_keeps_packet);
    RUN(test_failed_send_drops);
    RUN(test_flow_returns);
    RUN(test_key_not_hint);
    RUN(test_free_nonempty);
    printf("%d tests passed\n", g_run);
    return 0;
}
