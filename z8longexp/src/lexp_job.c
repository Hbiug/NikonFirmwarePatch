/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Long exposure merge: the average of a sequence of ordinary Z 8 NEFs (FX, L, 14-bit lossless compressed), written
   as a new NEF: the first frame's file with its raw data replaced by the rounded mean of every frame.

   Memory and file handles do not grow with the number of frames: the image is processed in bands of rows. For each
   band every frame is opened, its decoder (kept between bands) continues through the band's rows into a 32-bit
   accumulator, and the file is closed again; then the band's mean is encoded and written. One read cache is shared
   by all decoders. Included by the unity build after job.c (uses its card_job, bridges and output helpers). */
#include "lexp_enc.h"

#define LEXP_BAND_ROWS 256u          /* first try; halved while the accumulator cannot be allocated */
#define LEXP_BAND_MIN 8u
#define LEXP_CACHE 0x40000u          /* shared decoder cache */
#define LEXP_COPY 0x10000u           /* header copy chunk */

/* The raw IFD's StripByteCounts entry: walks IFD0, its SubIFDs (0x014A) and next IFDs like nef.c. */
static int lexp_strip_count_at(psm_nef *n, uint32_t *count_pos)
{
    uint32_t queue[64], queued = 0, visits = 0, found = 0;
    uint8_t header[8], small[2], entry[12];
    int be = n->big_endian;
    if (read_data(n, 0, header, 8))
        return PSM_READ_ERROR;
    queue[queued++] = u32(header + 4, be);
    while (queued) {
        uint32_t at = queue[--queued], count, photo = 0, strip_count_at = 0, next;
        if (!at || ++visits > 64 || read_data(n, at, small, 2))
            return at ? PSM_BAD_NEF : PSM_OK;
        count = u16(small, be);
        if (count > 512 || (uint64_t)at + 2 + 12 * count + 4 > n->file.size)
            return PSM_BAD_NEF;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t tag, type, values, value;
            if (read_data(n, at + 2 + 12 * i, entry, 12))
                return PSM_BAD_NEF;
            tag = u16(entry, be);
            type = u16(entry + 2, be);
            values = u32(entry + 4, be);
            if (tag == 0x14A) {
                if (!values || values > 16 || queued + values > 64)
                    return PSM_BAD_NEF;
                for (uint32_t j = 0; j < values; ++j) {
                    if (value_at(n, entry, be, 0, j, &value))
                        return PSM_BAD_NEF;
                    queue[queued++] = value;
                }
            } else if (tag == 0x106 && values == 1 && !value_at(n, entry, be, 0, 0, &value)) {
                photo = value;
            } else if (tag == 0x117) {
                /* one LONG, stored in the entry */
                if (type != 4 || values != 1)
                    strip_count_at = 1;
                else
                    strip_count_at = at + 2 + 12 * i + 8;
            }
        }
        if (photo == 32803) {
            if (found++ || strip_count_at <= 1)
                return PSM_UNSUPPORTED_NEF;
            *count_pos = strip_count_at;
        }
        if (read_data(n, at + 2 + 12 * count, header, 4))
            return PSM_BAD_NEF;
        next = u32(header, be);
        if (next) {
            if (queued == 64)
                return PSM_BAD_NEF;
            queue[queued++] = next;
        }
    }
    return found == 1 ? PSM_OK : PSM_UNSUPPORTED_NEF;
}

typedef struct {
    output_handle *out;
    uint32_t offset;
} lexp_sink;

static int lexp_write(void *context, const uint8_t *data, uint32_t bytes)
{
    lexp_sink *k = context;
    if (out_bridge(k->out, k->offset, data, bytes))
        return 1;
    k->offset += bytes;
    return 0;
}

/* <folder>\<first frame's stem>_AVG.NEF, else _AVG_2 .. _AVG_99; the temporary name is <folder>\LEXP_TMP.TMP */
static int lexp_names(card_job *j, const psm_platform *p, char *temporary)
{
    const char *first = j->paths[0];
    uint32_t n = length(first), slash = 0, dot = n;
    for (uint32_t k = 0; k < n; ++k) {
        if (first[k] == '\\') slash = k + 1;
        if (first[k] == '.') dot = k;
    }
    if (dot < slash || n + 12 >= sizeof(j->final_path))
        return PSM_BAD_GROUP;
    for (uint32_t k = 0; k < slash; ++k)
        temporary[k] = first[k];
    {
        static const char tmp[] = "LEXP_TMP.TMP";
        for (uint32_t k = 0; k < sizeof(tmp); ++k)
            temporary[slash + k] = tmp[k];
    }
    for (uint32_t number = 1; number < 100; ++number) {
        uint32_t at = dot;
        static const char avg[] = "_AVG", ext[] = ".NEF";
        for (uint32_t k = 0; k < dot; ++k)
            j->final_path[k] = first[k];
        for (uint32_t k = 0; k < 4; ++k)
            j->final_path[at++] = avg[k];
        if (number > 1) {
            j->final_path[at++] = '_';
            if (number >= 10) j->final_path[at++] = (char)('0' + number / 10);
            j->final_path[at++] = (char)('0' + number % 10);
        }
        for (uint32_t k = 0; k < sizeof(ext); ++k)
            j->final_path[at++] = ext[k];
        if (!p->exists(p->context, j->final_path))
            return PSM_OK;
    }
    return PSM_OUTPUT_EXISTS;
}

/* Rounded mean of n frames: (sum + n/2) / n. */
static void lexp_mean(const uint32_t *sum, uint16_t *out, uint32_t width, uint32_t n)
{
    uint32_t half = n / 2;
    for (uint32_t x = 0; x < width; ++x)
        out[x] = (uint16_t)((sum[x] + half) / n);
}

static int lexp_merge_group(const psm_platform *p, const psm_scan *s, const psm_group *g, card_job *j,
                            uint32_t *rows_done)
{
    void *cache_memory = 0, *acc_memory = 0, *row_memory = 0;
    uint8_t *cache;
    uint32_t *acc = 0;
    uint16_t *row_in, *row_out;
    uint32_t n = g->count, opened = 0, band = LEXP_BAND_ROWS, width, height, count_at = 0, done = 0;
    int status = PSM_BAD_GROUP, created = 0;
    char temporary[128];
    output_handle out;
    lexp_sink sink;
    lexp_encoder enc;
    psm_times *t = &j->times;
    uint64_t t0 = now(p), t1;
    clear(t, sizeof(*t));
    j->clock.in_rows = 0;
    out.platform = p;
    out.clock = &j->clock;
    out.fd = -1;
    out.buffer = j->out_buffer;
    out.used = out.offset = 0;
    *rows_done = 0;
    for (uint32_t i = 0; i < PSM_MAX_FRAMES; ++i) {
        clear(&j->handles[i], sizeof(j->handles[i]));
        j->handles[i].fd = -1;
    }
    if (n < LEXP_MIN_FRAMES || n > PSM_MAX_FRAMES)
        return PSM_BAD_GROUP;
    if (p->progress) p->progress(p->context, 0, 0);
    cache_memory = p->allocate(p->context, LEXP_CACHE + 64u);
    if (!cache_memory) {
        t->memory_stage = 1;
        t->memory_bytes = LEXP_CACHE + 64u;
        status = PSM_NO_MEMORY;
        goto finished;
    }
    cache = align64(cache_memory);
    t->cache_bytes = LEXP_CACHE;
    /* every frame: the scanned file, its metadata unchanged since the scan, a decoder at row 0 */
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t bytes = 0;
        psm_file file;
        input_handle *h = &j->handles[i];
        psm_nef *nef = &j->nefs[i];
        if (p->cancelled && p->cancelled(p->context)) {
            status = PSM_CANCELLED;
            goto finished;
        }
        PSM_PHASE(p, PSM_PHASE_READ, (i + 1) | ((n > 255 ? 255 : n) << 8), 100u * i / n);
        status = PSM_BAD_GROUP;
        if (psm_frame_path(s, g, i, j->paths[i])) goto finished;
        h->platform = p;
        h->clock = &j->clock;
        h->path = j->paths[i];
        h->fd = p->open(p->context, h->path, &bytes);
        status = PSM_READ_ERROR;
        if (h->fd < 0) goto finished;
        h->bytes = j->sizes[i] = bytes;
        status = PSM_BAD_GROUP;
        if (bytes != s->frames[g->frames[i]].bytes || bytes >= 0x80000000u) {
            psm_group_reject(3, bytes, s->frames[g->frames[i]].bytes, h->path);
            goto finished;
        }
        status = psm_probe_metadata(p, h->fd, bytes, &j->selected[i], j->probe_cache);
        if (status) goto finished;
        if (psm_crc32(&j->selected[i], sizeof(psm_metadata), 0) != s->frames[g->frames[i]].metadata) {
            psm_group_reject(11, i, j->selected[i].index, h->path);
            status = PSM_BAD_GROUP;
            goto finished;
        }
        clear(nef, sizeof(*nef));
        nef->cache = cache;
        nef->cache_size = LEXP_CACHE;
        nef->fast = j->fast;
        file.read_at = read_bridge;
        file.context = h;
        file.size = bytes;
        status = psm_nef_open(nef, &file);
        if (!status && i == 0) {
            status = lexp_strip_count_at(nef, &count_at);
            /* the raw data must be the end of the file: nothing after it moves when its length changes */
            if (!status && (uint64_t)nef->strip_offset + nef->strip_bytes != bytes)
                status = PSM_UNSUPPORTED_NEF;
        }
        if (!status && i && (nef->width != j->nefs[0].width || nef->height != j->nefs[0].height ||
                             nef->cfa[0] != j->nefs[0].cfa[0] || nef->cfa[1] != j->nefs[0].cfa[1] ||
                             nef->cfa[2] != j->nefs[0].cfa[2] || nef->cfa[3] != j->nefs[0].cfa[3] ||
                             nef->seeds[0] != j->nefs[0].seeds[0] || nef->seeds[1] != j->nefs[0].seeds[1] ||
                             nef->seeds[2] != j->nefs[0].seeds[2] || nef->seeds[3] != j->nefs[0].seeds[3]))
            status = PSM_BAD_GROUP;
        nef->cache_bytes = 0;                 /* the shared cache now holds another frame's data */
        psm_frame_opened(i, bytes, LEXP_CACHE);
        if (p->close(p->context, h->fd)) {
            h->fd = -1;
            status = PSM_READ_ERROR;
        }
        h->fd = -1;
        if (status) goto finished;
        ++opened;
    }
    width = j->nefs[0].width;
    height = j->nefs[0].height;
    PSM_PHASE(p, PSM_PHASE_NAME, 0, 0);
    status = lexp_names(j, p, temporary);
    if (status) goto finished;
    if (p->exists(p->context, temporary)) {
        p->remove(p->context, temporary);
        if (p->exists(p->context, temporary)) {
            status = PSM_OUTPUT_EXISTS;
            goto finished;
        }
    }
    PSM_PHASE(p, PSM_PHASE_SETUP, 0, 0);
    row_memory = p->allocate(p->context, width * 4u + 64u);
    for (; band >= LEXP_BAND_MIN && !acc_memory; band /= 2)
        acc_memory = p->allocate(p->context, band * width * 4u + 64u);
    if (!row_memory || !acc_memory) {
        t->memory_stage = 2;
        t->memory_bytes = LEXP_BAND_MIN * width * 4u + 64u;
        status = PSM_NO_MEMORY;
        goto finished;
    }
    band *= 2;                                /* the loop halved once more after the successful allocation */
    acc = align64(acc_memory);
    row_in = align64(row_memory);
    row_out = row_in + width;
    PSM_PHASE(p, PSM_PHASE_CREATE, 0, 0);
    out.fd = p->create(p->context, temporary);
    if (out.fd < 0) {
        status = PSM_WRITE_ERROR;
        goto finished;
    }
    created = 1;
    PSM_PHASE(p, PSM_PHASE_HEADER, 0, 0);
    /* header: the first frame's bytes up to its raw data (tags, maker notes, previews), copied unchanged */
    {
        input_handle *h = &j->handles[0];
        uint32_t at = 0, end = j->nefs[0].strip_offset;
        status = PSM_READ_ERROR;
        h->fd = p->open(p->context, h->path, &h->bytes);
        if (h->fd < 0) goto finished;
        while (at < end) {
            uint32_t chunk = end - at > LEXP_COPY ? LEXP_COPY : end - at;
            if (read_bridge(h, at, cache, chunk) || out_bridge(&out, at, cache, chunk)) goto finished;
            at += chunk;
        }
        if (p->close(p->context, h->fd)) {
            h->fd = -1;
            goto finished;
        }
        h->fd = -1;
        j->nefs[0].cache_bytes = 0;
    }
    sink.out = &out;
    sink.offset = j->nefs[0].strip_offset;
    if (out_flush(&out)) {
        status = PSM_WRITE_ERROR;
        goto finished;
    }
    /* the encoder's stage: the pixel-shift configuration buffer, unused here (the shared cache belongs to the
       decoders while the bands are read) */
    lexp_enc_init(&enc, width, j->nefs[0].seeds, j->config, sizeof(j->config), lexp_write, &sink);
    t1 = now(p);
    t->open = t1 - t0;
    t0 = t1;
    j->clock.in_rows = 1;
    for (uint32_t first = 0; first < height; first += band) {
        uint32_t rows = height - first < band ? height - first : band;
        uint64_t m0 = now(p);
        clear(acc, rows * width * 4u);
        for (uint32_t i = 0; i < n; ++i) {
            input_handle *h = &j->handles[i];
            psm_nef *nef = &j->nefs[i];
            uint32_t bytes = 0;
            if (p->cancelled && p->cancelled(p->context)) {
                status = PSM_CANCELLED;
                goto finished;
            }
            status = PSM_READ_ERROR;
            h->fd = p->open(p->context, h->path, &bytes);
            if (h->fd < 0) goto finished;
            if (bytes != h->bytes) {
                status = PSM_BAD_GROUP;
                goto finished;
            }
            nef->cache_bytes = 0;
            for (uint32_t r = 0; r < rows; ++r) {
                uint64_t d0 = now(p);
                uint32_t *sum = acc + r * width;
                status = psm_nef_row(nef, first + r, row_in, width);
                t->decode += now(p) - d0;
                if (status) goto finished;
                for (uint32_t x = 0; x < width; ++x)
                    sum[x] += row_in[x];
            }
            status = PSM_READ_ERROR;
            if (p->close(p->context, h->fd)) {
                h->fd = -1;
                goto finished;
            }
            h->fd = -1;
            if (p->progress)
                p->progress(p->context, (uint32_t)(((uint64_t)first * n + (uint64_t)(i + 1) * rows) / n), height);
        }
        t->merge += now(p) - m0;
        m0 = now(p);
        for (uint32_t r = 0; r < rows; ++r) {
            lexp_mean(acc + r * width, row_out, width, n);
            if (lexp_enc_row(&enc, row_out)) {
                status = PSM_WRITE_ERROR;
                goto finished;
            }
        }
        t->pack += now(p) - m0;
        done = first + rows;
        *rows_done = done;
    }
    j->clock.in_rows = 0;
    if (lexp_enc_finish(&enc, 16u) || out_flush(&out)) {
        status = PSM_WRITE_ERROR;
        goto finished;
    }
    {
        uint8_t le[4];
        uint32_t total = (uint32_t)enc.total;
        for (uint32_t k = 0; k < 4; ++k)
            le[k] = (uint8_t)(total >> (j->nefs[0].big_endian ? 24 - 8 * k : 8 * k));
        if (p->write_at(p->context, out.fd, count_at, le, 4)) {
            status = PSM_WRITE_ERROR;
            goto finished;
        }
    }
    t1 = now(p);
    t->rows = t1 - t0;
    t0 = t1;
    if (p->close(p->context, out.fd)) {
        out.fd = -1;
        status = PSM_WRITE_ERROR;
        goto finished;
    }
    out.fd = -1;
    status = PSM_OUTPUT_EXISTS;
    if (p->exists(p->context, j->final_path))
        goto finished;
    created = 0;
    status = p->rename(p->context, temporary, j->final_path) ? PSM_WRITE_ERROR : PSM_OK;
    t->finish = now(p) - t0;
finished:
    j->clock.in_rows = 0;
    if (out.fd >= 0) p->close(p->context, out.fd);
    if (created && status != PSM_OK) p->remove(p->context, temporary);
    for (uint32_t i = 0; i < n && i < PSM_MAX_FRAMES; ++i) {
        if (j->handles[i].fd >= 0)
            p->close(p->context, j->handles[i].fd);
        j->handles[i].fd = -1;
    }
    (void)opened;
    if (acc_memory) p->release(p->context, acc_memory);
    if (row_memory) p->release(p->context, row_memory);
    if (cache_memory) p->release(p->context, cache_memory);
    return status;
}
