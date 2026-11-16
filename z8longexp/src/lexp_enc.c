/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "lexp_enc.h"

/* nef.c's prefix_table, as codes: lengths 1..8 hold {0,1,4,2,2,3,1,2} codes for the categories in this order */
static void lexp_codes(lexp_encoder *e)
{
    static const uint8_t counts[8] = {0,1,4,2,2,3,1,2};
    static const uint8_t categories[15] = {7,6,8,5,9,4,10,3,11,12,2,0,1,13,14};
    uint32_t code = 0, symbol = 0;
    for (uint32_t length = 1; length <= 8; ++length) {
        for (uint32_t j = 0; j < counts[length - 1]; ++j) {
            e->code[categories[symbol]] = (uint16_t)code;
            e->length[categories[symbol]] = (uint8_t)length;
            ++code;
            ++symbol;
        }
        code <<= 1;
    }
}

void lexp_enc_init(lexp_encoder *e, uint32_t width, const uint16_t seeds[4], uint8_t *out, uint32_t capacity,
                   lexp_sink_fn sink, void *context)
{
    lexp_codes(e);
    for (uint32_t i = 0; i < 4; ++i)
        e->vertical[i / 2][i % 2] = seeds[i];
    e->bits = 0;
    e->held = 0;
    e->width = width;
    e->next_row = 0;
    e->used = 0;
    e->capacity = capacity;
    e->out = out;
    e->total = 0;
    e->sink = sink;
    e->context = context;
}

static int lexp_drain(lexp_encoder *e)
{
    while (e->held >= 8) {
        if (e->used == e->capacity) {
            if (e->sink(e->context, e->out, e->used))
                return 1;
            e->total += e->used;
            e->used = 0;
        }
        e->held -= 8;
        e->out[e->used++] = (uint8_t)(e->bits >> e->held);
    }
    return 0;
}

/* one difference: prefix code of its category, then the category's bits (negative: difference + 2^c - 1) */
static int lexp_put(lexp_encoder *e, int32_t difference)
{
    uint32_t magnitude = (uint32_t)(difference < 0 ? -difference : difference), category = 0;
    while (magnitude >> category)
        ++category;
    if (category > 14)
        return 1;
    uint32_t payload = difference < 0 ? (uint32_t)(difference + (1 << category) - 1) : (uint32_t)difference;
    e->bits = e->bits << e->length[category] | e->code[category];
    e->held += e->length[category];
    if (category) {
        e->bits = e->bits << category | (payload & ((1u << category) - 1u));
        e->held += category;
    }
    return e->held >= 32 ? lexp_drain(e) : 0;
}

int lexp_enc_row(lexp_encoder *e, const uint16_t *row)
{
    int32_t *vertical = e->vertical[e->next_row & 1u];
    int32_t even = 0, odd = 0;
    uint32_t x = 0, width = e->width;
    for (; x < 2 && x < width; ++x) {
        if (row[x] >> 14 || lexp_put(e, (int32_t)row[x] - vertical[x]))
            return 1;
        vertical[x] = row[x];
    }
    even = vertical[0];
    odd = vertical[1];
    for (; x + 1 < width; x += 2) {
        if ((row[x] | row[x + 1]) >> 14 || lexp_put(e, (int32_t)row[x] - even) || lexp_put(e, (int32_t)row[x + 1] - odd))
            return 1;
        even = row[x];
        odd = row[x + 1];
    }
    if (x < width && (row[x] >> 14 || lexp_put(e, (int32_t)row[x] - even)))
        return 1;
    ++e->next_row;
    return lexp_drain(e);
}

int lexp_enc_finish(lexp_encoder *e, uint32_t align)
{
    if (e->held % 8) {
        uint32_t pad = 8 - e->held % 8;
        e->bits <<= pad;
        e->held += pad;
    }
    if (lexp_drain(e))
        return 1;
    while (align > 1 && (e->total + e->used) % align) {
        e->bits = 0;
        e->held = 8;
        if (lexp_drain(e))
            return 1;
    }
    if (e->used) {
        if (e->sink(e->context, e->out, e->used))
            return 1;
        e->total += e->used;
        e->used = 0;
    }
    return 0;
}
