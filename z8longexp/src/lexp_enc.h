/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Long exposure merge: Z 8 14-bit lossless NEF encoder, the exact inverse of nef.c's decoder (same prefix code,
   same predictors, MSB-first bits without byte stuffing). */
#ifndef Z8_LEXP_ENC_H
#define Z8_LEXP_ENC_H

#include <stdint.h>

typedef int (*lexp_sink_fn)(void *, const uint8_t *, uint32_t);

typedef struct {
    uint16_t code[16];          /* prefix code per difference category 0..14 */
    uint8_t length[16];
    int32_t vertical[2][2];     /* first two samples of the last row of each parity (seeded from the 0x96 block) */
    uint64_t bits;              /* pending bits, MSB first */
    uint32_t held;
    uint32_t width, next_row;
    uint32_t used, capacity;    /* bytes staged in out */
    uint8_t *out;
    uint64_t total;             /* bytes passed to sink */
    lexp_sink_fn sink;
    void *context;
} lexp_encoder;

/* out / capacity: staging buffer (capacity >= 64); sink receives it whenever it fills. seeds = nef.c's seeds. */
void lexp_enc_init(lexp_encoder *e, uint32_t width, const uint16_t seeds[4], uint8_t *out, uint32_t capacity,
                   lexp_sink_fn sink, void *context);
int lexp_enc_row(lexp_encoder *e, const uint16_t *row);
/* Flushes the last bits (zero-padded to a byte), then pad zero bytes up to a multiple of align, then the stage. */
int lexp_enc_finish(lexp_encoder *e, uint32_t align);

#endif
