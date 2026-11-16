/* Host test of the long exposure merge job (z8longexp/src): the card scan, the sequence grouping and the average
   job run against a directory tree standing for the cards (<root>/A/DCIM/...), through a POSIX psm_platform.

   usage: host_job <root> make <source.nef> <folder> <first number> <count> <first shutter count> <seed> [seconds step]
          host_job <root> run               (scan both cards, average every unmerged sequence, print the summary)
          host_job <root> check <output> <input>...   (decode with nef.c, compare the output with the rounded mean) */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "job.c"
#include "group.c"
#include "nef.c"
#include "lexp_enc.c"
#include "lexp_job.c"

/* the firmware build has these in browser.c / thumbnail.c (not needed by the job) */
static const char *root;
static FILE *files[64];

static void host_path(const char *path, char *out)
{
    /* "A:\DCIM\100NCZ_8\X.NEF" -> <root>/A/DCIM/100NCZ_8/X.NEF */
    size_t n = (size_t)sprintf(out, "%s/%c", root, path[0]);
    for (const char *c = path + 2; *c; ++c)
        out[n++] = *c == '\\' ? '/' : *c;
    out[n] = 0;
    if (n && out[n - 1] == '/') out[n - 1] = 0;
}
static void *h_alloc(void *c, uint32_t n) { (void)c; const char *l = getenv("H_ALLOC_LIMIT"); if (l && n > (uint32_t)atoi(l)) return 0; return malloc(n); }
static void h_free(void *c, void *p) { (void)c; free(p); }
static int slot(FILE *f) { for (int i = 0; i < 64; ++i) if (!files[i]) { files[i] = f; return i; } fclose(f); return -1; }
static int h_open(void *c, const char *path, uint32_t *size)
{
    (void)c; char hp[512]; host_path(path, hp);
    FILE *f = fopen(hp, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); *size = (uint32_t)ftell(f); return slot(f);
}
static int h_read(void *c, int fd, uint32_t off, void *out, uint32_t n)
{ (void)c; return fseek(files[fd], off, SEEK_SET) || fread(out, 1, n, files[fd]) != n; }
static int h_create(void *c, const char *path)
{ (void)c; char hp[512]; host_path(path, hp); FILE *f = fopen(hp, "w+b"); return f ? slot(f) : -1; }
static int h_write(void *c, int fd, uint32_t off, const void *d, uint32_t n)
{ (void)c; return fseek(files[fd], off, SEEK_SET) || fwrite(d, 1, n, files[fd]) != n; }
static int h_close(void *c, int fd) { (void)c; int r = fclose(files[fd]); files[fd] = 0; return r; }
static int h_exists(void *c, const char *path) { (void)c; char hp[512]; host_path(path, hp); return access(hp, F_OK) == 0; }
static int h_rename(void *c, const char *a, const char *b)
{ (void)c; char x[512], y[512]; host_path(a, x); host_path(b, y); return rename(x, y); }
static int h_remove(void *c, const char *path) { (void)c; char hp[512]; host_path(path, hp); return unlink(hp); }
static int h_cancelled(void *c) { (void)c; return 0; }
static int h_list(void *c, const char *path, uint32_t attrs, psm_list_fn fn, void *ctx)
{
    (void)c; (void)attrs; char hp[512]; host_path(path, hp);
    DIR *d = opendir(hp); if (!d) return 1;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char full[1024]; struct stat st; snprintf(full, sizeof full, "%s/%s", hp, e->d_name);
        if (stat(full, &st)) continue;
        if (fn(ctx, e->d_name, (uint64_t)st.st_size, S_ISDIR(st.st_mode) ? 16u : 32u)) break;
    }
    closedir(d); return 0;
}
static uint32_t last_percent = 101;
static void h_progress(void *c, uint32_t done, uint32_t total)
{ (void)c; uint32_t p = total ? 100u * done / total : 0; if (p / 25 != last_percent / 25) { printf("  progress %u%%\n", p); last_percent = p; } }
static void h_group(void *c, uint32_t i, uint32_t n, const char *where, const char *frame)
{ (void)c; printf("group %u/%u %s %s\n", i, n, where, frame); last_percent = 101; }

/* ---- making test frames from a real NEF: noisy copies with consecutive shutter counts ---- */
static uint32_t hash(uint32_t x) { x ^= x >> 16; x *= 0x7feb352dU; x ^= x >> 15; x *= 0x846ca68bU; x ^= x >> 16; return x; }
static FILE *mk_out; static uint32_t mk_pos;
static int mk_sink(void *c, const uint8_t *d, uint32_t n) { (void)c; fwrite(d, 1, n, mk_out); mk_pos += n; return 0; }
static FILE *src_file;
static int src_read(void *c, uint32_t off, void *out, uint32_t n) { (void)c; return fseek(src_file, off, SEEK_SET) || fread(out, 1, n, src_file) != n; }

/* makernote tag position (value field) in the file, or 0 */
static uint32_t maker_tag(const uint8_t *f, uint32_t size, uint16_t want)
{
    uint32_t ifd = *(const uint32_t *)(f + 4), exif = 0;
    uint16_t n = *(const uint16_t *)(f + ifd);
    for (uint32_t i = 0; i < n; ++i) if (*(const uint16_t *)(f + ifd + 2 + 12 * i) == 0x8769) exif = *(const uint32_t *)(f + ifd + 2 + 12 * i + 8);
    n = *(const uint16_t *)(f + exif);
    for (uint32_t i = 0; i < n; ++i) {
        const uint8_t *e = f + exif + 2 + 12 * i;
        if (*(const uint16_t *)e != 0x927c) continue;
        uint32_t at = *(const uint32_t *)(e + 8), base = at + 10, mifd = base + *(const uint32_t *)(f + at + 14);
        uint16_t m = *(const uint16_t *)(f + mifd);
        for (uint32_t k = 0; k < m; ++k) {
            const uint8_t *me = f + mifd + 2 + 12 * k;
            if (*(const uint16_t *)me == want) {
                uint32_t type = *(const uint16_t *)(me + 2), count = *(const uint32_t *)(me + 4);
                uint32_t bytes = count * (type == 4 ? 4u : type == 3 ? 2u : 1u);
                return bytes <= 4 ? (uint32_t)(me + 8 - f) : base + *(const uint32_t *)(me + 8);
            }
        }
    }
    (void)size; return 0;
}
static uint32_t exif_tag(const uint8_t *f, uint16_t want)
{
    uint32_t ifd = *(const uint32_t *)(f + 4), exif = 0;
    uint16_t n = *(const uint16_t *)(f + ifd);
    for (uint32_t i = 0; i < n; ++i) if (*(const uint16_t *)(f + ifd + 2 + 12 * i) == 0x8769) exif = *(const uint32_t *)(f + ifd + 2 + 12 * i + 8);
    n = *(const uint16_t *)(f + exif);
    for (uint32_t i = 0; i < n; ++i) if (*(const uint16_t *)(f + exif + 2 + 12 * i) == want) return *(const uint32_t *)(f + exif + 2 + 12 * i + 8);
    return 0;
}

static int make(int argc, char **argv)
{
    if (argc < 9) return 2;
    const char *source = argv[3], *folder = argv[4];
    uint32_t number = (uint32_t)atoi(argv[5]), count = (uint32_t)atoi(argv[6]), shutter = (uint32_t)atoi(argv[7]);
    uint32_t seed = (uint32_t)atoi(argv[8]), step = argc > 9 ? (uint32_t)atoi(argv[9]) : 1;
    src_file = fopen(source, "rb"); fseek(src_file, 0, SEEK_END); uint32_t size = (uint32_t)ftell(src_file);
    uint8_t *whole = malloc(size); fseek(src_file, 0, SEEK_SET); fread(whole, 1, size, src_file);
    static int32_t fast[1u << PSM_FAST_BITS]; psm_nef_fast_table(fast);
    psm_nef n; uint32_t count_at = 0;
    uint32_t shutter_at = maker_tag(whole, size, 0xa7), time_at = exif_tag(whole, 0x9003);
    if (!shutter_at || !time_at) { printf("no shutter count / time tag\n"); return 1; }
    for (uint32_t k = 0; k < count; ++k) {
        memset(&n, 0, sizeof n); n.cache = aligned_alloc(64, 1 << 18); n.cache_size = 1 << 18; n.fast = fast;
        psm_file file = {src_read, 0, size};
        if (psm_nef_open(&n, &file) || lexp_strip_count_at(&n, &count_at)) { printf("source NEF refused\n"); return 1; }
        char path[1024]; snprintf(path, sizeof path, "%s/%s/DSC_%04u.NEF", root, folder, number + k);
        mk_out = fopen(path, "wb"); mk_pos = 0;
        uint8_t *head = malloc(n.strip_offset); memcpy(head, whole, n.strip_offset);
        *(uint32_t *)(head + shutter_at) = shutter + k;
        /* DateTimeOriginal: 2026:11:16, 10:00:00 + 10 s per file number + step seconds per frame */
        uint32_t t = 36000 + number * 10 + k * step;
        char when[20]; snprintf(when, sizeof when, "2026:11:16 %02u:%02u:%02u", t / 3600 % 24, t / 60 % 60, t % 60);
        memcpy(head + time_at, when, 20);
        fwrite(head, 1, n.strip_offset, mk_out);
        uint16_t *row = malloc(2 * n.width); static uint8_t stage[1 << 16]; lexp_encoder e;
        lexp_enc_init(&e, n.width, n.seeds, stage, sizeof stage, mk_sink, 0);
        for (uint32_t r = 0; r < n.height; ++r) {
            psm_nef_row(&n, r, row, n.width);
            for (uint32_t x = 0; x < n.width; ++x) {
                int32_t v = row[x] + (int32_t)(hash(seed * 7919u + k * 104729u + r * 8280u + x) % 801u) - 400;
                if (k == 0 && x < 16 && r < 16) v = 16383;    /* a clipped corner in one frame only */
                row[x] = (uint16_t)(v < 0 ? 0 : v > 16383 ? 16383 : v);
            }
            lexp_enc_row(&e, row);
        }
        lexp_enc_finish(&e, 16);
        fseek(mk_out, count_at, SEEK_SET); fwrite(&mk_pos, 4, 1, mk_out); fclose(mk_out);
        printf("wrote %s strip %u\n", path, mk_pos);
        free(head); free(row); free(n.cache);
    }
    return 0;
}

static int check(int argc, char **argv)
{
    uint32_t inputs = (uint32_t)(argc - 4);
    static int32_t fast[1u << PSM_FAST_BITS]; psm_nef_fast_table(fast);
    psm_nef *n = calloc(inputs + 1, sizeof *n);
    FILE **f = calloc(inputs + 1, sizeof *f);
    for (uint32_t i = 0; i <= inputs; ++i) {
        f[i] = fopen(argv[3 + i], "rb"); fseek(f[i], 0, SEEK_END);
        psm_file file = {0, f[i], (uint32_t)ftell(f[i])};
        file.read_at = (psm_read_at_fn)(void *)0;
        n[i].cache = aligned_alloc(64, 1 << 18); n[i].cache_size = 1 << 18; n[i].fast = fast;
        int fread_at(void *c, uint32_t off, void *out, uint32_t len);
        file.read_at = fread_at;
        if (psm_nef_open(&n[i], &file)) { printf("open %s refused\n", argv[3 + i]); return 1; }
    }
    uint16_t *row = malloc(2 * n[0].width), *mean = malloc(2 * n[0].width); uint32_t *sum = malloc(4 * n[0].width);
    uint64_t diff = 0, clipped_ok = 0;
    for (uint32_t r = 0; r < n[0].height; ++r) {
        memset(sum, 0, 4 * n[0].width);
        for (uint32_t i = 1; i <= inputs; ++i) { psm_nef_row(&n[i], r, row, n[i].width); for (uint32_t x = 0; x < n[i].width; ++x) sum[x] += row[x]; }
        psm_nef_row(&n[0], r, mean, n[0].width);
        for (uint32_t x = 0; x < n[0].width; ++x) {
            uint32_t want = (sum[x] + inputs / 2) / inputs;
            if (mean[x] != want) ++diff;
        }
        if (r == 0) clipped_ok = mean[0];
    }
    printf("output %ux%u, %llu samples differ from the rounded mean of %u inputs; corner sample %llu\n",
           n[0].width, n[0].height, (unsigned long long)diff, inputs, (unsigned long long)clipped_ok);
    return diff != 0;
}
int fread_at(void *c, uint32_t off, void *out, uint32_t len) { FILE *f = c; return fseek(f, off, SEEK_SET) || fread(out, 1, len, f) != len; }

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    root = argv[1];
    if (!strcmp(argv[2], "make")) return make(argc, argv);
    if (!strcmp(argv[2], "check")) return check(argc, argv);
    psm_platform p; memset(&p, 0, sizeof p);
    p.allocate = h_alloc; p.release = h_free; p.open = h_open; p.read_at = h_read; p.create = h_create;
    p.write_at = h_write; p.close = h_close; p.exists = h_exists; p.rename = h_rename; p.remove = h_remove;
    p.cancelled = h_cancelled; p.list = h_list; p.progress = h_progress; p.group = h_group;
    psm_summary s;
    int status = psm_camera_job(&p, PSM_MODE_ALL, &s);
    printf("job status %d groups %u targets %u merged %u first_error %d\n", status, s.groups, s.targets, s.merged, s.first_error);
    return status;
}
