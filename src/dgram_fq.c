// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
/*
 * dgram_fq.c — per-flow fair queue for DATAGRAMs xquic cannot take yet.
 * See dgram_fq.h.
 */
#include "dgram_fq.h"

#include <stdlib.h>
#include <string.h>

/* Flows hash into this many FIFOs; flows sharing one share its turn. */
#define DGRAM_FQ_BUCKETS 1024

typedef struct fq_pkt_s {
    struct fq_pkt_s *next;
    uint32_t flow_hash;
    size_t len;
    uint8_t data[];
} fq_pkt_t;

typedef struct {
    fq_pkt_t *head, *tail;
    size_t bytes;
    size_t packets;
    long deficit;
    int active; /* on the round-robin list */
    int next;   /* next active bucket, -1 at the end */
} fq_bucket_t;

struct mqvpn_dgram_fq_s {
    fq_bucket_t buckets[DGRAM_FQ_BUCKETS];
    int rr_head, rr_tail; /* round-robin list of active buckets */
    size_t max_bytes;
    size_t quantum;
    size_t bytes;
    size_t packets;
    uint64_t dropped;
};

mqvpn_dgram_fq_t *
mqvpn_dgram_fq_new(size_t max_bytes, size_t quantum)
{
    mqvpn_dgram_fq_t *q = calloc(1, sizeof(*q));
    if (!q) return NULL;
    q->rr_head = q->rr_tail = -1;
    q->max_bytes = max_bytes;
    q->quantum = quantum ? quantum : 1;
    return q;
}

void
mqvpn_dgram_fq_free(mqvpn_dgram_fq_t *q)
{
    if (!q) return;
    for (int i = 0; i < DGRAM_FQ_BUCKETS; i++) {
        fq_pkt_t *p = q->buckets[i].head;
        while (p) {
            fq_pkt_t *n = p->next;
            free(p);
            p = n;
        }
    }
    free(q);
}

int
mqvpn_dgram_fq_empty(const mqvpn_dgram_fq_t *q)
{
    return !q || q->packets == 0;
}

size_t
mqvpn_dgram_fq_bytes(const mqvpn_dgram_fq_t *q)
{
    return q ? q->bytes : 0;
}

size_t
mqvpn_dgram_fq_packets(const mqvpn_dgram_fq_t *q)
{
    return q ? q->packets : 0;
}

uint64_t
mqvpn_dgram_fq_dropped(const mqvpn_dgram_fq_t *q)
{
    return q ? q->dropped : 0;
}

static void
rr_append(mqvpn_dgram_fq_t *q, int i)
{
    fq_bucket_t *b = &q->buckets[i];
    b->active = 1;
    b->next = -1;
    if (q->rr_tail < 0) {
        q->rr_head = i;
    } else {
        q->buckets[q->rr_tail].next = i;
    }
    q->rr_tail = i;
}

/* Take the head bucket off the round-robin list. */
static int
rr_pop(mqvpn_dgram_fq_t *q)
{
    int i = q->rr_head;
    if (i < 0) return -1;
    q->rr_head = q->buckets[i].next;
    if (q->rr_head < 0) q->rr_tail = -1;
    q->buckets[i].active = 0;
    q->buckets[i].next = -1;
    return i;
}

/* Unlink and return a bucket's head packet (the caller frees it). An emptied
 * bucket stays on the round-robin list; the round robin skips and drops it. */
static fq_pkt_t *
bucket_pop(mqvpn_dgram_fq_t *q, fq_bucket_t *b)
{
    fq_pkt_t *p = b->head;
    if (!p) return NULL;
    b->head = p->next;
    if (!b->head) b->tail = NULL;
    b->bytes -= p->len;
    b->packets--;
    q->bytes -= p->len;
    q->packets--;
    return p;
}

/* Drop the head packet of the flow holding the most bytes. */
static void
drop_from_fattest(mqvpn_dgram_fq_t *q)
{
    int fattest = -1;
    for (int i = q->rr_head; i >= 0; i = q->buckets[i].next) {
        if (fattest < 0 || q->buckets[i].bytes > q->buckets[fattest].bytes) fattest = i;
    }
    if (fattest < 0) return;
    fq_pkt_t *p = bucket_pop(q, &q->buckets[fattest]);
    if (p) {
        free(p);
        q->dropped++;
    }
}

int
mqvpn_dgram_fq_enqueue(mqvpn_dgram_fq_t *q, uint32_t flow_key, uint32_t flow_hash,
                       const uint8_t *frame, size_t len)
{
    if (!q || !frame || len == 0) return 0;
    fq_pkt_t *p = malloc(sizeof(*p) + len);
    if (!p) {
        q->dropped++;
        return 1;
    }
    p->next = NULL;
    p->flow_hash = flow_hash;
    p->len = len;
    memcpy(p->data, frame, len);

    int i = (int)(flow_key % DGRAM_FQ_BUCKETS);
    fq_bucket_t *b = &q->buckets[i];
    if (b->tail) {
        b->tail->next = p;
    } else {
        b->head = p;
    }
    b->tail = p;
    b->bytes += len;
    b->packets++;
    q->bytes += len;
    q->packets++;
    if (!b->active) {
        /* a flow that was idle starts with a full quantum */
        b->deficit = (long)q->quantum;
        rr_append(q, i);
    }

    uint64_t before = q->dropped;
    while (q->bytes > q->max_bytes && q->packets > 0)
        drop_from_fattest(q);
    return (int)(q->dropped - before);
}

size_t
mqvpn_dgram_fq_drain(mqvpn_dgram_fq_t *q, mqvpn_dgram_fq_send_fn send, void *ctx)
{
    size_t sent = 0;
    if (!q || !send) return 0;
    while (q->rr_head >= 0) {
        int i = q->rr_head;
        fq_bucket_t *b = &q->buckets[i];
        if (!b->head) {
            /* emptied by drops or sends: leave the round robin */
            rr_pop(q);
            continue;
        }
        if (b->deficit < (long)b->head->len) {
            /* turn over: next round, one more quantum */
            b->deficit += (long)q->quantum;
            rr_pop(q);
            rr_append(q, i);
            continue;
        }
        int rc = send(ctx, b->head->flow_hash, b->head->data, b->head->len);
        if (rc == MQVPN_DGRAM_FQ_AGAIN) break;
        fq_pkt_t *p = bucket_pop(q, b);
        b->deficit -= (long)p->len;
        if (rc == 0) {
            sent++;
        } else {
            q->dropped++;
        }
        free(p);
    }
    return sent;
}
