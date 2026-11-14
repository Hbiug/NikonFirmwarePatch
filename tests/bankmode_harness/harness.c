/* Instruction-level test of the bank-mode / link-banks code.
 *
 * The code under test is the real patch block (hooks.bin, assembled by z8bankmode.patcher.code) loaded at its real
 * virtual address.  The stock routines it calls are replaced by stubs placed at their real 3.11 addresses (link.ld),
 * so the patch runs unmodified: GetDS, the data-store copy API (entry + body), SetItem, the two bank-switch routines
 * with their dispatcher thunks, and txn.Set.  The stubs model what the notes say about them:
 *   - GetDS returns the PRE-COMMIT value: a bank switch only becomes visible when the transaction is committed;
 *   - txn.Set appends {id, value} to {count; ids[] at +4; values at +0xA44};
 *   - the dispatcher records an item (txn.Set) before it runs the item's handler.
 * Output: one PASS/FAIL line per check on the UART, then the semihosting exit status (0 = all passed).
 */
#include "gen.h"
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;

#define UART (*(volatile u32 *)0x09000000UL)
#define SWITCH (*(volatile u8 *)SWITCH_ADDR)

static void putc_(char c) { UART = (u32)c; }
static void puts_(const char *s) { while (*s) putc_(*s++); }
static void puthex(u64 v) {
    puts_("0x");
    int started = 0;
    for (int i = 60; i >= 0; i -= 4) {
        int d = (v >> i) & 15;
        if (d || started || i == 0) { putc_("0123456789abcdef"[d]); started = 1; }
    }
}
static void halt(int code) {
    static u64 blk[2];
    blk[0] = 0x20026; blk[1] = (u64)code;
    register u64 x0 __asm__("x0") = 0x18;
    register u64 x1 __asm__("x1") = (u64)blk;
    __asm__ volatile("hlt #0xf000" :: "r"(x0), "r"(x1) : "memory");
    for (;;) {}
}

/* ---- fake data store and call log -------------------------------------------------------------------------- */
struct txn { u32 count; u32 ids[0x28F]; u32 pad; u32 values[0x28F]; u8 tail[0x100]; };
#define MARK(t) (*((volatile u8 *)(t) + 0x155C))        /* a bank switched in this transaction */
#define MARKTYPE(t) (*(volatile u32 *)((u8 *)(t) + 0x1560))   /* 0 menu bank, 1 extended, 2 Custom Settings bank */
_Static_assert(__builtin_offsetof(struct txn, values) == 0xA44, "transaction layout");

enum { K_SMENU = 1, K_SCUSTOM, K_COPY, K_SETITEM, K_DISP, K_POST, K_BKT };
struct rec { u32 kind; u64 a, b, c, d; };
static struct rec L[64];
static int nlog;
static u32 ds_menu, ds_custom, ds_ext, ds_relmode, ds_relsub, ds_bktshots, ds_bktdir, ds_fsshots, ds_fswidth;
#define BKTFLAG (*(volatile u8 *)(SWITCH_ADDR + 2))
#define REL(bank) ((volatile u8 *)(SWITCH_ADDR + 0x2D0UL * ((bank) + 1)))   /* data byte, then its complement */
static u32 s_menu_result = 1, s_custom_result = 1;
static int copy_calls, copy_fail_at;     /* fail (return -1) on the Nth copy call, 0 = never */

static void logrec(u32 k, u64 a, u64 b, u64 c, u64 d) {
    if (nlog < 64) { L[nlog].kind = k; L[nlog].a = a; L[nlog].b = b; L[nlog].c = c; L[nlog].d = d; nlog++; }
}

__attribute__((section(".s_getds"), noinline, used)) u32 st_getds(u32 id) {
    if (id == ID_BANK) return ds_menu;
    if (id == ID_CUSTOM) return ds_custom;
    if (id == ID_EXT) return ds_ext;
    if (id == ID_REL_MODE) return ds_relmode;
    if (id == ID_REL_SUB) return ds_relsub;
    if (id == ID_BKT_SHOTS) return ds_bktshots;
    if (id == ID_BKT_DIR) return ds_bktdir;
    if (id == ID_FS_SHOTS) return ds_fsshots;
    if (id == ID_FS_WIDTH) return ds_fswidth;
    return 0;
}
__attribute__((section(".s_txnset"), noinline, used)) void st_txnset(u32 id, u32 value, struct txn *t) {
    t->ids[t->count] = id;
    t->values[t->count] = value;
    t->count++;
}
/* the stock dispatcher, as far as the release-mode restore uses it: record the item (its handler adds nothing we model) */
__attribute__((section(".s_disp"), noinline, used)) u32 st_dispatcher(u32 id, u32 value, struct txn *t) {
    logrec(K_DISP, id, value, t->count, 0);
    st_txnset(id, value, t);
    return 1;
}
__attribute__((section(".s_smenu"), noinline, used)) u32 st_smenu(u32 bank, u32 flags, struct txn *t) {
    logrec(K_SMENU, bank, flags, t->count, 0);
    if (s_menu_result & 1) { MARK(t) = 1; MARKTYPE(t) = 0; }
    return s_menu_result;
}
__attribute__((section(".s_scustom"), noinline, used)) u32 st_scustom(u32 bank, u32 flags, struct txn *t) {
    logrec(K_SCUSTOM, bank, flags, t->count, 0);
    if (s_custom_result & 1) { MARK(t) = 1; MARKTYPE(t) = 2; }
    return s_custom_result;
}
/* the stock copy API body (the part after the first instruction, which the patch's `native` entry reproduces) */
__attribute__((noinline, used)) long c_copy(u32 src, u32 dst, u64 list, u32 count) {
    copy_calls++;
    logrec(K_COPY, src, dst, list, count);
    return (copy_fail_at && copy_calls == copy_fail_at) ? -1 : 0;
}
/* the stock Bracketing burst button handler (body after its first instruction) */
__attribute__((noinline, used)) u32 c_bkt(u32 button, u32 pressed, u32 a, u32 b) { logrec(K_BKT, button, pressed, a, ds_bktshots << 8 | b); return 0x55; }
__asm__(".section .s_bkt,\"ax\"\n"
        "    b hook_bkt_wrap\n"                                       /* the patched entry */
        "    str x30, [sp, #0x28]\n"                                  /* body: inside the frame of `str x22,[sp,#-0x30]!` */
        "    bl c_bkt\n"
        "    ldr x30, [sp, #0x28]\n"
        "    ldr x22, [sp], #0x30\n"
        "    ret\n");
/* the stock change-notice routine (body after its first instruction): which bank type is announced */
__attribute__((noinline, used)) void c_post(struct txn *t) { logrec(K_POST, MARK(t), MARKTYPE(t), t->count, 0); }
__asm__(".section .s_post,\"ax\"\n"
        "    b hook_post_wrap\n"                                      /* the patched entry */
        "    str x30, [sp, #0x28]\n"                                  /* body: inside the frame of `stp x23,x22,[sp,#-0x30]!` */
        "    bl c_post\n"
        "    ldr x30, [sp, #0x28]\n"
        "    ldp x23, x22, [sp], #0x30\n"
        "    ret\n");
__asm__(".section .s_copyentry,\"ax\"\n"
        ".global copy_entry\ncopy_entry:\n    b hook_gate\n"          /* the patched entry: b gate */
        ".section .s_copybody,\"ax\"\n"
        ".global copy_body\ncopy_body:\n"
        "    stp x29, x30, [sp, #-16]!\n"
        "    bl c_copy\n"
        "    ldp x29, x30, [sp], #16\n"
        "    ldr x20, [sp], #0x20\n"                                    /* undo the entry's `str x20,[sp,#-0x20]!` */
        "    ret\n"
        ".section .s_thunk_menu,\"ax\"\n"
        "    .word " THUNK_MENU "\n"
        ".section .s_thunk_custom,\"ax\"\n"
        "    .word " THUNK_CUSTOM "\n"
        ".text\n");

typedef u32 (*hookfn)(u32, u32, struct txn *);
extern char hook_gate[], hook_save[], hook_has_prev[], hook_hook_menu[], hook_hook_custom[], hook_link_sync[];
extern char hook_texts[];
extern long call_canary(void *fn, u64 a0, u64 a1, u64 a2, u64 a3, u64 *regs);

/* calls fn with canary values in x19..x29 and checks that they (and sp) come back unchanged */
static int canary_bad;
static long call(void *fn, u64 a0, u64 a1, u64 a2, u64 a3) {
    u64 regs[16];
    for (int i = 0; i < 16; i++) regs[i] = 0;
    long r = call_canary(fn, a0, a1, a2, a3, regs);
    for (int i = 0; i < 11; i++)
        if (regs[i] != (0xC0DE000000000000UL | (u64)(19 + i))) canary_bad |= 1 << i;
    if (regs[12] != regs[13]) canary_bad |= 1 << 12;
    return r;
}
#define GETDS_PTR ((u32 (*)(u32))st_getds)

/* ---- the dispatcher model: record the item, then run the item's handler (the patched call site) --------------- */
static u32 dispatch(struct txn *t, u32 id, u32 value) {
    st_txnset(id, value, t);
    if (id == ID_BANK) return (u32)call(hook_hook_menu, id, value, (u64)t, 0);
    if (id == ID_CUSTOM) return (u32)call(hook_hook_custom, id, value, (u64)t, 0);
    return 1;
}
static void commit(struct txn *t) {
    for (u32 i = 0; i < t->count; i++) {
        if (t->ids[i] == ID_BANK) ds_menu = t->values[i];
        if (t->ids[i] == ID_CUSTOM) ds_custom = t->values[i];
        if (t->ids[i] == ID_REL_MODE) ds_relmode = t->values[i];
        if (t->ids[i] == ID_REL_SUB) ds_relsub = t->values[i];
        if (t->ids[i] == ID_BKT_SHOTS) ds_bktshots = t->values[i];
        if (t->ids[i] == ID_BKT_DIR) ds_bktdir = t->values[i];
    }
}
/* stock set-item API: a one-item transaction through the dispatcher */
__attribute__((section(".s_setitem"), noinline, used)) u32 st_setitem(u32 id, u32 value) {
    static struct txn t;
    t.count = 0;
    logrec(K_SETITEM, id, value, 0, 0);
    u32 r = dispatch(&t, id, value);
    commit(&t);
    return r;
}

/* ---- checks --------------------------------------------------------------------------------------------------- */
static int failures, checks;
static void check(int ok, const char *name) {
    checks++;
    if (!ok) failures++;
    puts_(ok ? "PASS " : "FAIL "); puts_(name); putc_('\n');
}
static void reset(u32 sw, u32 menu, u32 custom) {
    SWITCH = (u8)sw; ds_menu = menu; ds_custom = custom; ds_ext = 0;
    nlog = 0; copy_calls = 0; copy_fail_at = 0; s_menu_result = s_custom_result = 1;
    ds_relmode = ds_relsub = 0; ds_bktshots = ds_bktdir = 0; BKTFLAG = 0;
    for (u32 b = 0; b < 4; b++) { REL(b)[0] = 0; REL(b)[1] = 0; }
}
static void relog(void) { nlog = 0; }
static int relis(u32 b, u32 mode, u32 sub) { u8 v = (u8)(0x80 | mode | sub << 3); return REL(b)[0] == v && REL(b)[1] == (u8)~v; }
static struct txn T;
static void fresh(void) { T.count = 0; MARK(&T) = 0; MARKTYPE(&T) = 0; }
static void post(void) { call((void *)0x410DC874, (u64)&T, 0, 0, 0); }
static int is(int i, u32 k, u64 a, u64 b, u64 c) { return nlog > i && L[i].kind == k && L[i].a == a && L[i].b == b && L[i].c == c; }
static int isc(int i, u64 s, u64 d, u64 list, u64 n) { return nlog > i && L[i].kind == K_COPY && L[i].a == s && L[i].b == d && L[i].c == list && L[i].d == n; }
static void dump(void) {
    for (int i = 0; i < nlog; i++) { puts_("    log "); puthex(L[i].kind); putc_(' '); puthex(L[i].a); putc_(' '); puthex(L[i].b); putc_(' '); puthex(L[i].c); putc_(' '); puthex(L[i].d); putc_('\n'); }
}


__attribute__((used)) void fault(u64 elr, u64 far) {
    puts_("FAIL unexpected exception at "); puthex(elr); puts_(" far "); puthex(far); putc_('\n');
    halt(3);
}


/* ---- focus shift end point: stubs of the lens / menu routines ------------------------------------------------ */
static int p_a0, p_a1, p_b0, p_b1;            /* the two (denominator, value) properties 0x2103 / 0x2821 */
static u32 r_num, r_den;                       /* 0x40C790DC result */
static int k_val, k_ok;                        /* lens coefficient model: pulses*256 = amount * k_val */
static int lens_pos;
static int fs_calls_refresh, fs_calls_redraw;
static u64 fs_last_state;
struct shown { u32 item, slot, style; char text[48]; };
static struct shown shown[8];
static int nshown;
static char pending[48];
static u32 pending_slot, pending_style;
__attribute__((section(".s_prop"), noinline, used)) u32 st_prop(u32 id, u32 size, int *buf) {
    if (size != 8) return 0;
    if (id == 0x2103) { buf[0] = p_a0; buf[1] = p_a1; }
    if (id == 0x2821) { buf[0] = p_b0; buf[1] = p_b1; }
    return 1;
}
__attribute__((section(".s_rescale"), noinline, used)) u32 st_rescale(int a0, int *b) {   /* as stock 0x40C78518 */
    if (a0 > 0x400 || a0 == -1) return 0;
    if (b[0] == -1 || b[0] > 0x400) return 0;
    if (b[0] == a0) return 1;
    b[1] = b[1] * a0 / b[0]; b[0] = a0;
    return 1;
}
__attribute__((section(".s_ratio"), noinline, used)) void st_ratio(int *a, u32 *out) { (void)a; out[0] = r_num; out[1] = r_den; }
__attribute__((section(".s_lensk"), noinline, used)) u32 st_lensk(int *buf) { buf[0] = k_val; buf[1] = 1; buf[2] = k_ok ? 0x3200 : -1; return 1; }
__attribute__((section(".s_def2pulse"), noinline, used)) u32 st_def2pulse(int *buf, int amount, int *out) {
    if (buf[2] < 0) return 0;
    *out = amount * buf[0];
    return 1;
}
__attribute__((section(".s_lenspos"), noinline, used)) int st_lenspos(void) { return lens_pos; }
__attribute__((section(".s_fsrefresh"), noinline, used)) u64 st_fsrefresh(u64 state) { fs_calls_refresh++; fs_last_state = state; return 0x77; }
__attribute__((section(".s_redraw"), noinline, used)) void st_redraw(u64 state) { fs_calls_redraw++; fs_last_state = state; }
__attribute__((section(".s_rowindex"), noinline, used)) int st_rowindex(u64 state, u32 item) { (void)state; return item == 0xDEAD ? -1 : (int)item; }
__attribute__((section(".s_rowobj"), noinline, used)) u64 st_rowobj(u64 rows, int idx, u32 z) { (void)z; return rows ? 0x500000UL + (u64)idx : 0; }
__attribute__((section(".s_settext"), noinline, used)) void st_settext(const char *t, u32 slot, u32 style) {
    int i = 0;
    for (; i < 47 && t[i]; i++) pending[i] = t[i];
    pending[i] = 0;
    pending_slot = slot; pending_style = style;
}
__attribute__((section(".s_setcontent"), noinline, used)) void st_setcontent(u64 obj, u32 slot) {
    if (nshown < 8) { shown[nshown].item = (u32)(obj - 0x500000UL) | (slot == pending_slot ? 0 : 0x80000000u); shown[nshown].slot = slot; shown[nshown].style = pending_style;
                      for (int i = 0; i < 48; i++) shown[nshown].text[i] = pending[i]; nshown++; }
}
__attribute__((section(".s_sprintf"), noinline, used)) int st_sprintf(char *buf, const char *fmt, int v) {
    char *o = buf;
    for (; *fmt; fmt++) {
        if (fmt[0] == '%' && fmt[1] == 'd') {
            char tmp[12]; int n = 0; u32 u = v < 0 ? (u32)-v : (u32)v;
            if (v < 0) *o++ = '-';
            do { tmp[n++] = '0' + u % 10; u /= 10; } while (u);
            while (n) *o++ = tmp[--n];
            fmt++;
        } else *o++ = *fmt;
    }
    *o = 0;
    return (int)(o - buf);
}
static int nshown_at_arrows;

/* slider page: element lookup and the stock arrow routine (body after its first instruction) */
static int elem_missing, arrows_calls, hidden_ten;
__attribute__((section(".s_visible"), noinline, used)) void st_visible(u64 obj, u32 on) { if (obj == 0x500000UL + 0x4DF) hidden_ten = on ? 0 : 1; }
static u64 arrows_state;
__attribute__((section(".s_element"), noinline, used)) u64 st_element(u32 id, u64 ctx) { (void)ctx; return elem_missing ? 0 : 0x500000UL + id; }
__attribute__((noinline, used)) void c_arrows(u64 state) { arrows_calls++; arrows_state = state; nshown_at_arrows = nshown; }
__asm__(".section .s_arrows,\"ax\"\n"
        "    b hook_sl_wrap\n"
        "    str x30, [sp, #0x18]\n"
        "    bl c_arrows\n"
        "    ldr x30, [sp, #0x18]\n"
        "    ldr x20, [sp], #0x20\n"
        "    ret\n"
        ".text\n");
extern char hook_sl_wrap[], hook_sl_text[];
#define SLV (*(volatile short *)SL_VALUE)
static int sl_is(const char *mid, int n1, int n2) {
    char e[48]; int k = 0;
    e[k++] = '1'; for (int i = 0; i < n1; i++) e[k++] = ' ';
    for (int i = 0; mid[i]; i++) e[k++] = mid[i];
    for (int i = 0; i < n2; i++) e[k++] = ' ';
    e[k++] = '1'; e[k++] = '0'; e[k] = 0;
    if (nshown < 1) return 0;
    struct shown *s = &shown[nshown - 1];
    if (s->item != 0x4DE || s->slot != 0 || s->style != 0x55) return 0;
    for (int i = 0; i <= k; i++) if (s->text[i] != e[i]) { puts_("    got '"); puts_(s->text); puts_("'\n"); return 0; }
    return 1;
}
extern char hook_fs_end_get[], hook_fs_pps[], hook_fs_est[], hook_fs_shots[], hook_fs_remain[], hook_fs_refresh[];
extern char hook_fs_set_end[], hook_fs_clear_end[];
extern void call_remain(u64 *io);
#define FSB(k) (*(volatile u8 *)(FS_END0 + 0x2D0UL * (k)))
#define FS_REM (*(volatile u32 *)FS_REMAIN)
#define FS_TOTAL (*(volatile u32 *)(FS_REMAIN + 0xA8))
#define FS_WIDTH (*(volatile u32 *)(FS_REMAIN + 0xB0))
#define DIVT ((volatile u8 *)FS_DIV_TABLE)
static void fs_set(int has, int pos) {
    u32 e = has ? ((u32)pos ^ 0x80000000u) : 0;
    for (int k = 0; k < 4; k++) FSB(k) = (u8)(e >> (8 * k));
}
static u32 fs_raw(void) { u32 e = 0; for (int k = 0; k < 4; k++) e |= (u32)FSB(k) << (8 * k); return e; }
static int ref_pps(int w) {
    if (w < 1 || w > 10) return 0;
    int b0 = p_b0, b1 = p_b1, bb[2] = {b0, b1};
    st_rescale(p_a0, bb);
    int diff = p_a1 - bb[1];
    int q = p_a0 ? diff / p_a0 : 0;
    int cls = q > 1 ? 0 : q == 1 ? 1 : q != 0 ? 3 : (diff <= 0 ? 3 : 2);
    u32 v = r_den ? (r_num * 256000u) / r_den : 0;
    int div = DIVT[cls * 10 + w - 1];
    int d = div ? (int)v / div : 0;
    if (!k_ok) return 0;
    int out = (d / 1000) * k_val;
    return out / 256;
}
static void fs_lens(int a0, int a1, int b0, int b1, u32 num, u32 den, int k) {
    p_a0 = a0; p_a1 = a1; p_b0 = b0; p_b1 = b1; r_num = num; r_den = den; k_val = k; k_ok = 1;
}
static int shown_is(int i, u32 item, const char *t) {
    if (i >= nshown || shown[i].item != item || shown[i].slot != (item == FS_ITEM_SHOTS ? 5u : 8u) || shown[i].style != 0x220) return 0;
    for (int j = 0; j < 16; j++) { if (shown[i].text[j] != t[j]) return 0; if (!t[j]) return 1; }
    return 1;
}

static void focus_tests(void) {
    for (int c = 0; c < 4; c++) for (int i = 0; i < 10; i++) DIVT[c * 10 + i] = (u8)(90 - 8 * i - c);
    /* storage */
    fs_set(0, 0);
    check(call(hook_fs_end_get, 0, 0, 0, 0) == 0, "focus end: nothing stored -> no end point");
    u64 st[0x20]; for (int i = 0; i < 0x20; i++) st[i] = 0; st[9] = 0x1000;     /* state; +0x48 = row container */
    u64 ctx[1] = { (u64)st };
    lens_pos = -12345; fs_calls_refresh = fs_calls_redraw = 0; nshown = 0;
    call(hook_fs_set_end, (u64)ctx, 0, 0, 0);
    check(fs_raw() == ((u32)-12345 ^ 0x80000000u) && call(hook_fs_end_get, 0, 0, 0, 0) == 1,
          "focus end: the action stores the current position (four padding bytes, position ^ 0x80000000)");
    check(fs_calls_refresh == 1 && fs_calls_redraw == 1 && fs_last_state == (u64)st, "focus end: the action refreshes the page and redraws it");
    lens_pos = 0; call(hook_fs_set_end, (u64)ctx, 0, 0, 0);
    check(call(hook_fs_end_get, 0, 0, 0, 0) == 1, "focus end: position 0 is a valid end point");
    call(hook_fs_clear_end, (u64)ctx, 0, 0, 0);
    check(fs_raw() == 0 && call(hook_fs_end_get, 0, 0, 0, 0) == 0 && fs_calls_redraw == 3, "focus end: clear forgets it and redraws");
    u8 relb[8]; for (int b = 0; b < 4; b++) { REL(b)[0] = (u8)(0x91 + b); REL(b)[1] = (u8)~(0x91 + b); relb[2 * b] = REL(b)[0]; relb[2 * b + 1] = REL(b)[1]; }
    u8 sw0 = SWITCH, bk0 = BKTFLAG;
    lens_pos = 0x7F00FF01; call(hook_fs_set_end, (u64)ctx, 0, 0, 0); call(hook_fs_clear_end, (u64)ctx, 0, 0, 0); lens_pos = -1; call(hook_fs_set_end, (u64)ctx, 0, 0, 0);
    int same = SWITCH == sw0 && BKTFLAG == bk0;
    for (int b = 0; b < 4; b++) same &= REL(b)[0] == relb[2 * b] && REL(b)[1] == relb[2 * b + 1];
    check(same && call(hook_fs_end_get, 0, 0, 0, 0) == 1, "focus end: switch, bracketing and release-mode bytes untouched by the end point");
    /* pulses per step: the stock arithmetic, every width and aperture class */
    int bad = 0;
    int cls_cases[4][4] = { {10, 56, 10, 30}, {10, 56, 10, 40}, {10, 56, 10, 50}, {10, 40, 10, 56} };   /* q=2, 1, 0+, <0 */
    for (int c = 0; c < 4; c++) {
        fs_lens(cls_cases[c][0], cls_cases[c][1], cls_cases[c][2], cls_cases[c][3], 500, 100, 5000);
        for (int w = 0; w <= 11; w++) {
            long got = call(hook_fs_pps, (u64)w, 0, 0, 0);
            if ((int)got != ref_pps(w)) { bad++; puts_("    pps class "); puthex(c); puts_(" width "); puthex(w); puts_(" got "); puthex((u32)got);
                                           puts_(" want "); puthex((u32)ref_pps(w)); putc_('\n'); }
        }
    }
    check(!bad, "focus pps: same as the stock step arithmetic for 4 aperture classes x widths 0..11 (0 outside 1..10)");
    fs_lens(10, 56, 20, 80, 500, 100, 5000);                       /* the second property has another denominator */
    check((int)call(hook_fs_pps, 5, 0, 0, 0) == ref_pps(5) && ref_pps(5) > 0, "focus pps: property rescaled to the first denominator");
    fs_lens(10, 56, 10, 40, 500, 100, -5000);
    check((int)call(hook_fs_pps, 3, 0, 0, 0) == ref_pps(3) && ref_pps(3) < 0, "focus pps: negative lens coefficient gives a negative step (rounded toward zero)");
    fs_lens(10, 56, 10, 40, 500, 100, 5000); k_ok = 0;
    check(call(hook_fs_pps, 3, 0, 0, 0) == 0, "focus pps: no lens data -> 0");
    /* estimate */
    fs_lens(10, 56, 10, 40, 500, 100, 5000);
    int p = ref_pps(5);
    lens_pos = 100000;
    fs_set(1, 100000 - 10 * p - 5);
    check(call(hook_fs_est, 5, 0, 0, 0) == 12, "focus estimate: 10 steps and a bit -> 12 frames (last frame at or past the end)");
    fs_set(1, 100000 - 10 * p);
    check(call(hook_fs_est, 5, 0, 0, 0) == 11, "focus estimate: exactly 10 steps -> 11 frames");
    fs_set(1, 100000);
    check(call(hook_fs_est, 5, 0, 0, 0) == 1, "focus estimate: end point = start -> 1 frame");
    fs_set(1, 100001);
    check((int)call(hook_fs_est, 5, 0, 0, 0) == -1, "focus estimate: end point behind the start -> -1");
    fs_set(1, 100000 - 1000 * p);
    check(call(hook_fs_est, 5, 0, 0, 0) == 300, "focus estimate: capped at 300");
    fs_set(0, 0);
    check(call(hook_fs_est, 5, 0, 0, 0) == 0, "focus estimate: no end point -> 0");
    fs_set(1, 0); k_ok = 0;
    check(call(hook_fs_est, 5, 0, 0, 0) == 0, "focus estimate: no lens data -> 0");
    fs_lens(10, 56, 10, 40, 500, 100, -5000); p = ref_pps(5);
    fs_set(1, 100000 - 10 * p);                                     /* p < 0: the end point lies at higher positions */
    check(call(hook_fs_est, 5, 0, 0, 0) == 11, "focus estimate: negative step direction handled");
    fs_set(1, 99000);
    check((int)call(hook_fs_est, 5, 0, 0, 0) == -1, "focus estimate: negative step, end point behind -> -1");
    /* sequence start */
    fs_lens(10, 56, 10, 40, 500, 100, 5000); p = ref_pps(5);
    ds_fsshots = 100; ds_fswidth = 5; lens_pos = 50000;
    fs_set(0, 0);
    check(call(hook_fs_shots, ID_FS_SHOTS, 0, 0, 0) == 100, "focus start: no end point -> the stock No. of shots");
    fs_set(1, 50000 - 20 * p);
    check(call(hook_fs_shots, ID_FS_SHOTS, 0, 0, 0) == 21, "focus start: end point set -> the estimate replaces No. of shots");
    fs_set(1, 60000);
    check(call(hook_fs_shots, ID_FS_SHOTS, 0, 0, 0) == 100 && fs_raw() == 0, "focus start: end point behind the start -> stock run, end point forgotten");
    fs_set(1, 0); k_ok = 0;
    check(call(hook_fs_shots, ID_FS_SHOTS, 0, 0, 0) == 100 && fs_raw() != 0, "focus start: no lens data -> stock run, end point kept");
    /* after every shot */
    fs_lens(10, 56, 10, 40, 500, 100, 5000); p = ref_pps(5);
    u64 io[9];
    #define REMAIN_CALL() do { for (int i = 0; i < 8; i++) io[i] = 0xAB00 + i; call_remain(io); } while (0)
    #define REGS_OK() (io[0] == 0xAB00 && io[1] == 0xAB01 && io[2] == 0xAB02 && io[3] == 0xAB03 && io[4] == 0xAB04 && io[5] == 0xAB05 && io[6] == 0xAB06 && io[7] == 0xAB07)
    fs_set(0, 0); FS_REM = 7; FS_TOTAL = 10; FS_WIDTH = 5; lens_pos = 1000;
    REMAIN_CALL();
    check((u32)io[8] == 7 && FS_REM == 7 && REGS_OK(), "focus frame: no end point -> stock count, x0..x7 preserved");
    fs_set(1, 1000 - 3 * p); FS_REM = 5;
    REMAIN_CALL();
    check((u32)io[8] == 5 && FS_REM == 5 && FS_TOTAL == 10 && REGS_OK(), "focus frame: end point ahead -> keep going");
    lens_pos = 1000 - 3 * p;
    REMAIN_CALL();
    check((u32)io[8] == 0 && FS_REM == 0 && REGS_OK(), "focus frame: at the end point -> that was the last frame");
    lens_pos = 1000 - 3 * p - 1; FS_REM = 5;
    REMAIN_CALL();
    check((u32)io[8] == 0 && FS_REM == 0, "focus frame: past the end point -> stop");
    lens_pos = 1000; FS_REM = 0; FS_TOTAL = 12;
    REMAIN_CALL();
    check((u32)io[8] == 1 && FS_REM == 1 && FS_TOTAL == 13 && REGS_OK(), "focus frame: estimate used up before the end point -> one more frame");
    FS_REM = 0; FS_TOTAL = 300;
    REMAIN_CALL();
    check((u32)io[8] == 0 && FS_REM == 0 && FS_TOTAL == 300, "focus frame: never beyond 300 frames");
    FS_REM = 4; FS_WIDTH = 0;
    REMAIN_CALL();
    check((u32)io[8] == 4 && FS_REM == 4, "focus frame: unknown step (width 0) -> stock count even with an end point");
    fs_lens(10, 56, 10, 40, 500, 100, -5000); p = ref_pps(5);
    FS_WIDTH = 5; lens_pos = 1000; fs_set(1, 1000 - 3 * p); FS_REM = 5;
    REMAIN_CALL();
    check((u32)io[8] == 5, "focus frame: negative step, end point ahead -> keep going");
    lens_pos = 1000 - 3 * p + 1;
    REMAIN_CALL();
    check((u32)io[8] == 0, "focus frame: negative step, past the end point -> stop");
    /* page texts */
    fs_lens(10, 56, 10, 40, 500, 100, 5000); p = ref_pps(5);
    ds_fswidth = 5; lens_pos = 20000;
    fs_set(0, 0); nshown = 0; fs_calls_refresh = 0;
    long rr = call(hook_fs_refresh, (u64)st, 0, 0, 0);
    check(rr == 0x77 && fs_calls_refresh == 1 && nshown == 1 && shown_is(0, FS_ITEM_SET, "OFF"), "focus page: stock refresh first, then OFF on the end point row; No. of shots untouched");
    fs_set(1, 20000 - 41 * p); nshown = 0;
    call(hook_fs_refresh, (u64)st, 0, 0, 0);
    check(nshown == 2 && shown_is(0, FS_ITEM_SET, "SET") && shown_is(1, FS_ITEM_SHOTS, "~42"), "focus page: SET (text slot 8), and ~42 on the No. of shots row (its own slot 5)");
    fs_set(1, 20001); nshown = 0;
    call(hook_fs_refresh, (u64)st, 0, 0, 0);
    check(nshown == 2 && shown_is(1, FS_ITEM_SHOTS, "--"), "focus page: end point behind the current position -> --");
    st[9] = 0; nshown = 0;
    call(hook_fs_refresh, (u64)st, 0, 0, 0);
    check(nshown == 0, "focus page: no row object -> nothing written");
    st[9] = 0x1000;
    nshown = 0; call(hook_fs_refresh, 0, 0, 0, 0);
    check(nshown == 0, "focus page: no state -> stock refresh only");

    /* ---------------- focus step width slider ---------------- */
    u64 sst[0x20]; for (int i = 0; i < 0x20; i++) sst[i] = 0;
    fs_lens(10, 56, 10, 40, 500, 100, 5000); p = ref_pps(5);
    lens_pos = 30000; ds_fsshots = 100; elem_missing = 0;
    fs_set(0, 0); SLV = 5; nshown = 0; arrows_calls = 0; hidden_ten = 0;
    call((void *)0x405F6A64, (u64)sst, 0, 0, 0);
    check(hidden_ten == 1, "slider: the separate 10 label is hidden");
    check(arrows_calls == 1 && arrows_state == (u64)sst && nshown_at_arrows == 0 && nshown == 1 && sl_is("100", 12, 10),
          "slider: stock arrow update first, then the line; no end point -> No. of shots (100), 3-character spacing");
    ds_fsshots = 5; nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("5", 12, 12), "slider: 1-character middle -> 12 / 12 spaces");
    ds_fsshots = 50; nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("50", 12, 11), "slider: 2-character middle -> 12 / 11 spaces");
    fs_set(1, 30000 - 41 * ref_pps(5)); SLV = 5; nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("~42", 12, 10), "slider: end point -> ~42 for the slider's width");
    SLV = 9; nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    { int q = ref_pps(9); int dist = 41 * ref_pps(5); int est = dist / q + (dist % q != 0) + 1; char m[8]; int k = 0;
      m[k++] = '~'; if (est >= 100) m[k++] = '0' + est / 100; if (est >= 10) m[k++] = '0' + est / 10 % 10; m[k++] = '0' + est % 10; m[k] = 0;
      check(est != 42 && sl_is(m, k >= 4 ? 11 : 12, k >= 3 ? 10 : 13 - k), "slider: the estimate follows the slider value, not the saved width"); }
    fs_set(1, 30000 - 7 * ref_pps(1)); SLV = 1; nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("~8", 12, 11), "slider: 2-character estimate (~8)");
    fs_set(1, 30000 - 141 * ref_pps(1)); nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("~142", 11, 10), "slider: 4-character estimate (~142) -> 11 / 10 spaces");
    fs_set(1, 30000 - 5000 * ref_pps(1)); nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("~300", 11, 10), "slider: capped estimate ~300");
    fs_set(1, 30001); nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("--", 12, 11), "slider: end point behind the current position -> --");
    fs_set(1, 0); k_ok = 0; nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(sl_is("--", 12, 11), "slider: no lens data -> --");
    k_ok = 1; elem_missing = 1; nshown = 0; call(hook_sl_text, (u64)sst, 0, 0, 0);
    check(nshown == 0, "slider: label element not found -> nothing written");
    elem_missing = 0; fs_set(0, 0);
}

void main_(void) {
    u32 r;
    /* ---------------- link off: the stock path ---------------- */
    reset(0, 0, 0); fresh();
    r = dispatch(&T, ID_BANK, 2); commit(&T);
    check(nlog == 1 && is(0, K_SMENU, 2, 1, 1) && r == 1 && T.count == 1 && ds_menu == 2 && ds_custom == 0, "link off: menu bank switches alone");
    reset(0, 0, 0); fresh();
    r = dispatch(&T, ID_CUSTOM, 3); commit(&T);
    check(nlog == 1 && is(0, K_SCUSTOM, 3, 1, 1) && r == 1 && T.count == 1 && ds_menu == 0 && ds_custom == 3, "link off: custom bank switches alone");
    reset(1, 0, 0); fresh();
    r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(nlog == 1 && is(0, K_SMENU, 1, 1, 1) && ds_custom == 0, "keep-only (no link): menu bank switches alone");
    reset(0, 0, 0); fresh(); s_menu_result = 0;
    r = dispatch(&T, ID_BANK, 2);
    check(r == 0 && nlog == 1, "link off: stock failure result passes through");
    reset(0, 0, 0); fresh(); s_custom_result = 7;
    r = dispatch(&T, ID_CUSTOM, 2);
    check(r == 7 && nlog == 1, "link off: stock result value passes through unchanged");
    reset(1, 2, 2); fresh();
    r = dispatch(&T, 0x1234, 5);
    check(r == 1 && nlog == 0, "unrelated item: no hook involved");

    /* ---------------- link on ---------------- */
    reset(2, 0, 0); fresh();
    r = dispatch(&T, ID_BANK, 2); commit(&T);
    check(nlog == 2 && is(0, K_SMENU, 2, 1, 1) && is(1, K_SCUSTOM, 2, 1, 2) && r == 1, "link on: menu A->C switches custom bank C too (stock switch first, then the other)");
    check(T.count == 2 && T.ids[0] == ID_BANK && T.ids[1] == ID_CUSTOM && T.values[0] == 2 && T.values[1] == 2, "link on: the other item is added to the same transaction");
    check(ds_menu == 2 && ds_custom == 2, "link on: both banks committed in sync");
    reset(2, 0, 0); fresh();
    r = dispatch(&T, ID_CUSTOM, 1); commit(&T);
    check(nlog == 2 && is(0, K_SCUSTOM, 1, 1, 1) && is(1, K_SMENU, 1, 1, 2) && r == 1 && ds_menu == 1 && ds_custom == 1, "link on: custom bank switch drags the menu bank");
    for (u32 from = 0; from < 4; from++) for (u32 to = 0; to < 4; to++) {
        if (from == to) continue;
        reset(2, from, from); fresh();
        r = dispatch(&T, ID_BANK, to); commit(&T);
        if (!(r == 1 && ds_menu == to && ds_custom == to && nlog == 2)) { check(0, "link on: every bank pair (menu side)"); dump(); goto pairs_custom; }
    }
    check(1, "link on: every bank pair syncs (menu side, 12 pairs)");
pairs_custom:
    for (u32 from = 0; from < 4; from++) for (u32 to = 0; to < 4; to++) {
        if (from == to) continue;
        reset(3, from, from); fresh();
        r = dispatch(&T, ID_CUSTOM, to); commit(&T);
        if (!(r == 1 && ds_menu == to && ds_custom == to && nlog == 2)) { check(0, "link on: every bank pair (custom side)"); dump(); goto pairs_done; }
    }
    check(1, "link on + keep: every bank pair syncs (custom side, 12 pairs)");
pairs_done:
    reset(2, 0, 2); fresh();
    r = dispatch(&T, ID_BANK, 2); commit(&T);
    check(nlog == 1 && is(0, K_SMENU, 2, 1, 1) && T.count == 1 && ds_custom == 2, "link on: other bank already on that letter -> no second switch");
    reset(2, 0, 0); fresh(); s_menu_result = 0;
    r = dispatch(&T, ID_BANK, 2); commit(&T);
    check(nlog == 1 && r == 0 && T.count == 1 && ds_custom == 0, "link on: stock switch failed -> nothing linked, result passed through");
    reset(2, 0, 0); fresh(); s_menu_result = 2;
    r = dispatch(&T, ID_BANK, 2);
    check(nlog == 1 && r == 2, "link on: stock result with bit 0 clear is not a success -> nothing linked");
    reset(2, 0, 0); fresh(); s_menu_result = 3;
    r = dispatch(&T, ID_BANK, 2);
    check(nlog == 2 && r == 3, "link on: stock result 3 (bit 0 set) is a success and is returned");
    reset(2, 0, 0); fresh();
    r = dispatch(&T, ID_BANK, 4);
    check(nlog == 1 && is(0, K_SMENU, 4, 1, 1), "link on: bank index above D is never linked");
    reset(2, 0, 0); fresh(); s_custom_result = 0;
    r = dispatch(&T, ID_BANK, 1);
    check(nlog == 2 && r == 1, "link on: second switch fails -> the first result is still returned (caller sees the stock outcome)");

    /* ---------------- requests that carry both ids ---------------- */
    reset(2, 0, 0); fresh();
    r = dispatch(&T, ID_BANK, 2); u32 r2 = dispatch(&T, ID_CUSTOM, 2); commit(&T);
    check(nlog == 2 && is(0, K_SMENU, 2, 1, 1) && is(1, K_SCUSTOM, 2, 1, 2) && r2 == 1, "request [menu=C, custom=C]: each bank switched exactly once");
    check(ds_menu == 2 && ds_custom == 2, "request [menu=C, custom=C]: banks in sync");
    reset(2, 0, 0); fresh();
    r = dispatch(&T, ID_CUSTOM, 3); r2 = dispatch(&T, ID_BANK, 3); commit(&T);
    check(nlog == 2 && is(0, K_SCUSTOM, 3, 1, 1) && is(1, K_SMENU, 3, 1, 2) && r2 == 1 && ds_menu == 3 && ds_custom == 3, "request [custom=D, menu=D]: each bank switched exactly once");
    reset(2, 0, 0); fresh();
    r = dispatch(&T, ID_BANK, 1); r2 = dispatch(&T, ID_CUSTOM, 2); commit(&T);
    /* KNOWN LIMITATION: one request that sets the two banks to DIFFERENT letters while the link is on.  The two switches
     * run once each (the first letter wins in the data), but the transaction still commits both entries in order.  No stock
     * caller builds such a request (menu rows and the shortcut set one id; the card load calls the switches directly). */
    check(nlog == 2, "request with conflicting letters (known limitation): no bank is switched twice");
    puts_("    note: committed ids after a conflicting request: menu "); puthex(ds_menu); puts_(" custom "); puthex(ds_custom); putc_('\n');
    reset(2, 0, 0); fresh();
    dispatch(&T, 0x1234, 7); dispatch(&T, 0x1235, 8); r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(nlog == 2 && is(0, K_SMENU, 1, 1, 3) && is(1, K_SCUSTOM, 1, 1, 4) && ds_custom == 1, "unrelated items earlier in the request do not disturb the link");
    reset(2, 0, 0); fresh();
    dispatch(&T, ID_BANK, 1); commit(&T); fresh();
    r = dispatch(&T, ID_BANK, 0); commit(&T);
    check(ds_menu == 0 && ds_custom == 0, "later request B->A syncs back to A (the first request's entries do not linger)");

    /* ---------------- link_sync (turning the link on) ---------------- */
    reset(2, 2, 0);
    r = (u32)call(hook_link_sync, 0, 0, 0, 0);
    check(nlog == 2 && nlog > 0 && L[0].kind == K_SETITEM && L[0].a == ID_CUSTOM && L[0].b == 2 && is(1, K_SCUSTOM, 2, 1, 1) && ds_custom == 2, "enable link: custom bank follows the menu bank through the stock set-item path (one switch, no echo)");
    reset(2, 1, 1);
    call(hook_link_sync, 0, 0, 0, 0);
    check(nlog == 0, "enable link: banks already equal -> nothing to do");
    reset(2, 9, 0);
    call(hook_link_sync, 0, 0, 0, 0);
    check(nlog == 0, "enable link: invalid menu bank value -> nothing to do");

    /* ---------------- copy gate ---------------- */
    for (u32 sw = 0; sw < 4; sw++) {
        int keep = sw & 1;
        for (u32 dst = 1; dst <= 4; dst++) {
            reset(sw, 0, 0);
            long cr = call((void *)0x41013A14, 0, dst, LIST_MAIN, N_MAIN);
            int ok = keep ? (cr == 0 && nlog == 0) : (cr == 0 && nlog == 1 && isc(0, 0, dst, LIST_MAIN, N_MAIN));
            if (!ok) { check(0, "copy gate: live->bank store (switch / slot combination)"); dump(); goto gate_done; }
        }
    }
    check(1, "copy gate: live->bank store skipped with keep, exactly the stock copy otherwise (16 combinations)");
gate_done:
    reset(1, 0, 0);
    call((void *)0x41013A14, 1, 0, LIST_MAIN, N_MAIN);
    check(nlog == 1 && isc(0, 1, 0, LIST_MAIN, N_MAIN), "bank->live load is not gated (keep on)");
    reset(1, 0, 0);
    call((void *)0x41013A14, 0, 5, LIST_MAIN, N_MAIN);
    check(nlog == 1 && isc(0, 0, 5, LIST_MAIN, N_MAIN), "live->stash (slot 5) is not gated");
    reset(1, 0, 0);
    call((void *)0x41013A14, 0, 0, LIST_MAIN, N_MAIN);
    call((void *)0x41013A14, 0, 6, LIST_MAIN, N_MAIN);
    check(nlog == 2, "slots 0 and 6 as destination are not gated");
    reset(0, 0, 0);
    call((void *)0x41013A14, 0, 2, LIST_CUSTOM, 0x1FF);
    check(nlog == 1 && isc(0, 0, 2, LIST_CUSTOM, 0x1FF), "custom list copy passes through unchanged");
    reset(0, 0, 0); copy_fail_at = 1;
    long cr = call((void *)0x41013A14, 0, 2, LIST_MAIN, N_MAIN);
    check(cr == -1 && nlog == 1, "stock copy failure is returned");

    /* ---------------- save command ---------------- */
    reset(0, 2, 1); ds_relmode = 1; ds_relsub = 1;
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 1 && nlog == 3 && isc(0, 0, 3, LIST_MAIN, N_MAIN) &&
          isc(1, 0, 2, LIST_CUSTOM, 0x1FF) && isc(2, 0, 2, LIST_CUSTOM + 4 * 0x1FF, N_CUSTOM - 0x1FF), "save: menu bank C + custom bank B stored (ext banks off)");
    check(relis(2, 1, 1) && REL(0)[0] == 0 && REL(1)[0] == 0 && REL(3)[0] == 0, "save: release mode remembered for the current menu bank only");
    reset(1, 2, 1); ds_ext = 1; ds_relmode = 4;
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 1 && nlog == 4 && isc(1, 0, 3, LIST_EXT, N_EXT) && relis(2, 4, 0), "save under keep + extended banks: still stores, ext list included, release mode remembered");
    reset(0, 9, 1);
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 0 && nlog == 0 && REL(0)[0] == 0, "save: invalid menu bank -> fail, nothing copied or remembered");
    reset(0, 1, 9);
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 0, "save: invalid custom bank -> fail");
    for (int k = 1; k <= 3; k++) {
        reset(0, 2, 1); copy_fail_at = k;
        r = (u32)call(hook_save, 0, 0, 0, 0);
        if (r != 0) { check(0, "save: a failing copy makes the command report failure"); goto save_done; }
    }
    check(1, "save: a failing copy (any of the 3) makes the command report failure");
save_done:

    /* ---------------- release mode per menu bank ---------------- */
    reset(0, 0, 0); ds_relmode = 1; ds_relsub = 1; fresh();           /* bank A: continuous, sub-type 1 */
    r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(r == 1 && nlog == 1 && is(0, K_SMENU, 1, 1, 1) && relis(0, 1, 1) && ds_relmode == 1 && ds_relsub == 1,
          "release: leaving A remembers it; B was never stored, so the mode is left alone");
    ds_relmode = 0; ds_relsub = 0; relog(); fresh();                   /* in B: single frame */
    r = dispatch(&T, ID_BANK, 0); commit(&T);
    check(nlog == 3 && is(0, K_SMENU, 0, 1, 1) && is(1, K_DISP, ID_REL_MODE, 1, 1) && is(2, K_DISP, ID_REL_SUB, 1, 2),
          "release: back to A sets both items through the dispatcher, after the stock switch, mode first");
    check(relis(1, 0, 0) && ds_relmode == 1 && ds_relsub == 1 && ds_menu == 0, "release: B remembered single frame; A's continuous mode is active again");
    relog(); fresh();
    r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(nlog == 3 && ds_relmode == 0 && ds_relsub == 0, "release: A -> B restores single frame");
    ds_relsub = 5; relog(); fresh();                                   /* B: only the sub-type differs from A's */
    ds_relmode = 1; REL(0)[0] = 0x80 | 1 | 2 << 3; REL(0)[1] = (u8)~(0x80 | 1 | 2 << 3);
    r = dispatch(&T, ID_BANK, 0); commit(&T);
    check(nlog == 2 && is(1, K_DISP, ID_REL_SUB, 2, 1) && ds_relsub == 2, "release: only the item that differs is set");
    reset(1, 0, 0); ds_relmode = 4; fresh();                           /* keep stored */
    REL(1)[0] = 0x80 | 1; REL(1)[1] = (u8)~(0x80 | 1);
    r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(REL(0)[0] == 0 && nlog == 2 && is(1, K_DISP, ID_REL_MODE, 1, 1) && ds_relmode == 1,
          "release + keep: leaving stores nothing, entering restores the bank's saved mode");
    reset(0, 0, 0); ds_relmode = 1; fresh();
    REL(1)[0] = 0x80; REL(1)[1] = 0x55;                                /* check byte wrong (stored mode 0, current 1) */
    r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(nlog == 1 && ds_relmode == 1, "release: a slot whose check byte does not match is ignored");
    reset(0, 0, 0); ds_relmode = 1; fresh();
    REL(1)[0] = 0x00; REL(1)[1] = 0xFF;                                /* bit 7 clear (stored mode 0, current 1) */
    r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(nlog == 1 && ds_relmode == 1, "release: a slot without the stored bit is ignored");
    reset(0, 0, 0); ds_relmode = 1; fresh(); s_menu_result = 0;
    REL(1)[0] = 0x80; REL(1)[1] = 0x7F;
    r = dispatch(&T, ID_BANK, 1); commit(&T);
    check(r == 0 && nlog == 1 && ds_relmode == 1, "release: stock switch failed -> nothing restored");
    reset(0, 9, 0); fresh();
    r = dispatch(&T, ID_BANK, 1);
    check(nlog == 1 && REL(0)[0] == 0 && REL(1)[0] == 0 && REL(2)[0] == 0 && REL(3)[0] == 0, "release: invalid current bank -> nothing remembered");
    reset(2, 0, 0); ds_relmode = 1; ds_relsub = 1; fresh();           /* link on, switch started from the custom side */
    REL(2)[0] = 0x80; REL(2)[1] = 0x7F;
    r = dispatch(&T, ID_CUSTOM, 2); commit(&T);
    check(nlog == 4 && is(0, K_SCUSTOM, 2, 1, 1) && is(1, K_SMENU, 2, 1, 2) && is(2, K_DISP, ID_REL_MODE, 0, 2) && is(3, K_DISP, ID_REL_SUB, 0, 3) &&
          relis(0, 1, 1) && ds_relmode == 0 && ds_menu == 2 && ds_custom == 2, "release + link: a custom-bank switch moves the menu bank and its release mode");
    reset(2, 0, 0); ds_relmode = 4; fresh();                           /* link on, menu side, then the request's own custom entry */
    REL(1)[0] = 0x80; REL(1)[1] = 0x7F;
    r = dispatch(&T, ID_BANK, 1); u32 r3 = dispatch(&T, ID_CUSTOM, 1); commit(&T);
    check(r3 == 1 && nlog == 3 && is(0, K_SMENU, 1, 1, 1) && is(1, K_DISP, ID_REL_MODE, 0, 1) && is(2, K_SCUSTOM, 1, 1, 3) && ds_relmode == 0 && ds_custom == 1,
          "release + link: entries added by the restore do not disturb the link or the double-switch guard");

    /* ---------------- change notice (one per bank type) ---------------- */
    reset(0, 0, 0); fresh(); dispatch(&T, ID_BANK, 1); relog(); post();
    check(nlog == 1 && is(0, K_POST, 1, 0, 1), "notice, link off: exactly the stock notice");
    reset(2, 0, 0); fresh(); dispatch(&T, ID_BANK, 1); relog(); post();
    check(nlog == 2 && is(0, K_POST, 1, 2, 2) && is(1, K_POST, 1, 0, 2) && MARKTYPE(&T) == 2,
          "notice, link on, menu side: Custom Settings list announced, then the menu list; marker left as stock left it");
    reset(2, 0, 0); fresh(); dispatch(&T, ID_CUSTOM, 3); relog(); post();
    check(nlog == 2 && is(0, K_POST, 1, 0, 2) && is(1, K_POST, 1, 2, 2) && MARKTYPE(&T) == 0,
          "notice, link on, custom side: menu list announced, then the Custom Settings list");
    reset(2, 0, 2); fresh(); dispatch(&T, ID_BANK, 2); relog(); post();
    check(nlog == 1 && is(0, K_POST, 1, 0, 1), "notice, link on but only one bank type switched: one notice");
    reset(2, 0, 0); fresh(); dispatch(&T, 0x1234, 5); relog(); post();
    check(nlog == 1 && is(0, K_POST, 0, 0, 1), "notice, link on, no bank switch in the transaction: one notice");
    reset(2, 0, 0); fresh(); dispatch(&T, ID_BANK, 1); MARKTYPE(&T) = 1; relog(); post();
    check(nlog == 1, "notice, link on, extended-banks marker: one notice");
    reset(3, 0, 0); fresh(); dispatch(&T, ID_BANK, 1); relog(); post();
    check(nlog == 2, "notice, keep + link: both notices");

    /* ---------------- Bracketing burst button with bracketing off ---------------- */
#define BKT(pressed) ((u32)call((void *)0x40D4D680, 0x19, pressed, 7, 9))
    reset(0, 0, 0); ds_bktdir = 1;
    r = BKT(1);
    check(r == 0x55 && nlog == 3 && L[0].kind == K_SETITEM && L[0].a == ID_BKT_DIR && L[0].b == 3 && L[1].kind == K_SETITEM && L[1].a == ID_BKT_SHOTS && L[1].b == 3 &&
          L[2].kind == K_BKT && L[2].a == 0x19 && L[2].b == 1 && L[2].c == 7 && L[2].d == (3 << 8 | 9) && ds_bktshots == 3 && ds_bktdir == 3 && BKTFLAG == 0x81,
          "bracketing burst, bracketing off: press sets 3 frames before the stock handler runs, arguments and result passed through");
    relog(); r = BKT(1);
    check(nlog == 1 && L[0].kind == K_BKT && BKTFLAG == 0x81, "bracketing burst: a repeated press changes nothing");
    relog(); r = BKT(0);
    check(r == 0x55 && nlog == 3 && L[0].kind == K_BKT && L[0].b == 0 && L[1].kind == K_SETITEM && L[1].a == ID_BKT_SHOTS && L[1].b == 0 && L[2].kind == K_SETITEM && L[2].a == ID_BKT_DIR && L[2].b == 1 &&
          ds_bktshots == 0 && ds_bktdir == 1 && BKTFLAG == 0, "bracketing burst: release runs the stock handler, then switches bracketing off and restores the direction");
    relog(); r = BKT(0);
    check(nlog == 1 && ds_bktshots == 0, "bracketing burst: a release without our press only runs the stock handler");
    reset(0, 0, 0); ds_bktshots = 5; ds_bktdir = 3;
    r = BKT(1); r = BKT(0);
    check(nlog == 2 && L[0].kind == K_BKT && L[1].kind == K_BKT && ds_bktshots == 5 && ds_bktdir == 3 && BKTFLAG == 0, "bracketing burst, bracketing already on: stock behaviour, settings untouched");
    reset(0, 0, 0); BKT(1); ds_bktshots = 7; relog(); BKT(0);
    check(ds_bktshots == 0 && BKTFLAG == 0, "bracketing burst: release switches off even if the frame count was changed while held");

    /* ---------------- has_prev ---------------- */
    fresh(); T.ids[0] = 5; T.ids[1] = 6; T.ids[2] = 7; T.count = 3;
    check(call(hook_has_prev, 5, (u64)&T, 0, 0) == 1 && call(hook_has_prev, 6, (u64)&T, 0, 0) == 1, "has_prev: finds earlier entries");
    check(call(hook_has_prev, 7, (u64)&T, 0, 0) == 0, "has_prev: ignores the newest entry");
    check(call(hook_has_prev, 8, (u64)&T, 0, 0) == 0, "has_prev: absent id");
    T.count = 1;
    check(call(hook_has_prev, 5, (u64)&T, 0, 0) == 0, "has_prev: single entry -> none earlier");
    T.count = 0;
    check(call(hook_has_prev, 5, (u64)&T, 0, 0) == 0, "has_prev: empty transaction");

    focus_tests();
    check(canary_bad == 0, "callee-saved registers x19..x29 and sp preserved by every routine called");
    if (canary_bad) { puts_("    canary mask "); puthex(canary_bad); putc_('\n'); }
    puts_("checks "); puthex(checks); puts_(" failures "); puthex(failures); putc_('\n');
    halt(failures ? 1 : 0);
}

__asm__(".section .text.start,\"ax\"\n"
        ".global _start\n_start:\n"
        "    ldr x0, =0x40F00000\n"
        "    mov sp, x0\n"
        "    adr x0, vectors\n"
        "    msr vbar_el1, x0\n"
        "    bl main_\n"
        "1:  b 1b\n"
        ".text\n"
        ".balign 2048\n"
        "vectors:\n"
        ".rept 16\n"
        "    mov x0, sp\n"
        "    ldr x1, =0x40F00000\n"
        "    mov sp, x1\n"
        "    mrs x0, elr_el1\n"
        "    mrs x1, far_el1\n"
        "    bl fault\n"
        ".balign 128\n"
        ".endr\n"
        ".global call_remain\n"
        "call_remain:\n"                                  /* io[0..7] -> x0..x7, x8 = remaining-shots address; back: x0..x8 */
        "    stp x29, x30, [sp, #-0x20]!\n"
        "    str x0, [sp, #0x10]\n"
        "    mov x9, x0\n"
        "    ldp x0, x1, [x9]\n    ldp x2, x3, [x9, #16]\n    ldp x4, x5, [x9, #32]\n    ldp x6, x7, [x9, #48]\n"
        "    ldr x8, =0xA03BC8070\n"
        "    bl hook_fs_remain\n"
        "    ldr x9, [sp, #0x10]\n"
        "    stp x0, x1, [x9]\n    stp x2, x3, [x9, #16]\n    stp x4, x5, [x9, #32]\n    stp x6, x7, [x9, #48]\n"
        "    str x8, [x9, #64]\n"
        "    ldp x29, x30, [sp], #0x20\n"
        "    ret\n"
        ".global call_canary\n"
        "call_canary:\n"                                  /* (fn, a0..a3, regs) */
        "    stp x29, x30, [sp, #-0x70]!\n"
        "    stp x19, x20, [sp, #0x10]\n"
        "    stp x21, x22, [sp, #0x20]\n"
        "    stp x23, x24, [sp, #0x30]\n"
        "    stp x25, x26, [sp, #0x40]\n"
        "    stp x27, x28, [sp, #0x50]\n"
        "    str x5, [sp, #0x60]\n"
        "    mov x9, x0\n"
        "    mov x0, x1\n    mov x1, x2\n    mov x2, x3\n    mov x3, x4\n"
        "    ldr x11, =0xC0DE000000000000\n"
        "    add x19, x11, #19\n    add x20, x11, #20\n    add x21, x11, #21\n    add x22, x11, #22\n"
        "    add x23, x11, #23\n    add x24, x11, #24\n    add x25, x11, #25\n    add x26, x11, #26\n"
        "    add x27, x11, #27\n    add x28, x11, #28\n    add x29, x11, #29\n"
        "    mov x12, sp\n"
        "    str x12, [sp, #0x68]\n"
        "    blr x9\n"
        "    ldr x5, [sp, #0x60]\n"
        "    stp x19, x20, [x5, #0]\n    stp x21, x22, [x5, #16]\n    stp x23, x24, [x5, #32]\n"
        "    stp x25, x26, [x5, #48]\n    stp x27, x28, [x5, #64]\n"
        "    str x29, [x5, #80]\n"
        "    ldr x12, [sp, #0x68]\n"
        "    mov x13, sp\n"
        "    stp x12, x13, [x5, #96]\n"                  /* regs[12] = sp before the call, regs[13] = sp after */
        "    ldp x19, x20, [sp, #0x10]\n"
        "    ldp x21, x22, [sp, #0x20]\n"
        "    ldp x23, x24, [sp, #0x30]\n"
        "    ldp x25, x26, [sp, #0x40]\n"
        "    ldp x27, x28, [sp, #0x50]\n"
        "    ldp x29, x30, [sp], #0x70\n"
        "    ret\n"
        ".ltorg\n");
