// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
/*
 * dgram_fq.h — per-flow fair queue for DATAGRAMs xquic cannot take yet.
 * Pure logic (no xquic, no sockets): the caller frames the packet and sends it.
 *
 * While xquic accepts datagrams, nothing is queued. Once a send returns
 * -XQC_EAGAIN, packets wait here in one FIFO per flow, and are sent round
 * robin across flows (deficit round robin, one quantum of bytes per flow per
 * round) when xquic can take them again. Over the byte limit, packets are
 * dropped from the head of the flow holding the most bytes, so a flow sending
 * more than the paths carry loses its own packets, and a small flow only
 * waits for one round. mp0rta/mqvpn#447.
 */
#ifndef MQVPN_DGRAM_FQ_H
#define MQVPN_DGRAM_FQ_H

#include <stddef.h>
#include <stdint.h>

/* What the client and the server use: bytes queued at most (a few RTTs of a
 * slow path, a few ms of a fast one; past it the largest flow loses packets),
 * and the bytes a flow sends per round (one full packet). */
#define MQVPN_DGRAM_FQ_MAX_BYTES (256 * 1024)
#define MQVPN_DGRAM_FQ_QUANTUM   1500

typedef struct mqvpn_dgram_fq_s mqvpn_dgram_fq_t;

/* max_bytes: framed bytes the queue may hold; quantum: bytes a flow may send
 * per round (at least one full packet). NULL on allocation failure. */
mqvpn_dgram_fq_t *mqvpn_dgram_fq_new(size_t max_bytes, size_t quantum);
void mqvpn_dgram_fq_free(mqvpn_dgram_fq_t *q);

int mqvpn_dgram_fq_empty(const mqvpn_dgram_fq_t *q);
size_t mqvpn_dgram_fq_bytes(const mqvpn_dgram_fq_t *q);
size_t mqvpn_dgram_fq_packets(const mqvpn_dgram_fq_t *q);
/* Packets dropped to stay within max_bytes (or because a copy failed). */
uint64_t mqvpn_dgram_fq_dropped(const mqvpn_dgram_fq_t *q);

/* Copy one framed packet into the FIFO of flow_key. flow_hash is kept with
 * the packet and passed back on send (the hint xquic schedules by, which can
 * be the same for many flows). Over max_bytes, drop from the head of the flow
 * with the most bytes (possibly this one) until it fits. Returns the number of
 * packets dropped, 0 when none. */
int mqvpn_dgram_fq_enqueue(mqvpn_dgram_fq_t *q, uint32_t flow_key, uint32_t flow_hash,
                           const uint8_t *frame, size_t len);

/* Send one framed packet. Return 0 when it was taken, MQVPN_DGRAM_FQ_AGAIN
 * when xquic cannot take it now (it stays queued and draining stops), any
 * other value when it failed for good (it is dropped). */
#define MQVPN_DGRAM_FQ_AGAIN 1
typedef int (*mqvpn_dgram_fq_send_fn)(void *ctx, uint32_t flow_hash, const uint8_t *frame,
                                      size_t len);

/* Send queued packets in round-robin order until the queue is empty or send
 * returns MQVPN_DGRAM_FQ_AGAIN. Returns the number of packets taken. */
size_t mqvpn_dgram_fq_drain(mqvpn_dgram_fq_t *q, mqvpn_dgram_fq_send_fn send, void *ctx);

#endif /* MQVPN_DGRAM_FQ_H */
