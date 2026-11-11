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
struct txn { u32 count; u32 ids[0x28F]; u32 pad; u32 values[0x28F]; };
_Static_assert(__builtin_offsetof(struct txn, values) == 0xA44, "transaction layout");

enum { K_SMENU = 1, K_SCUSTOM, K_COPY, K_SETITEM };
struct rec { u32 kind; u64 a, b, c, d; };
static struct rec L[64];
static int nlog;
static u32 ds_menu, ds_custom, ds_ext;
static u32 s_menu_result = 1, s_custom_result = 1;
static int copy_calls, copy_fail_at;     /* fail (return -1) on the Nth copy call, 0 = never */

static void logrec(u32 k, u64 a, u64 b, u64 c, u64 d) {
    if (nlog < 64) { L[nlog].kind = k; L[nlog].a = a; L[nlog].b = b; L[nlog].c = c; L[nlog].d = d; nlog++; }
}

__attribute__((section(".s_getds"), noinline, used)) u32 st_getds(u32 id) {
    if (id == ID_BANK) return ds_menu;
    if (id == ID_CUSTOM) return ds_custom;
    if (id == ID_EXT) return ds_ext;
    return 0;
}
__attribute__((section(".s_txnset"), noinline, used)) void st_txnset(u32 id, u32 value, struct txn *t) {
    t->ids[t->count] = id;
    t->values[t->count] = value;
    t->count++;
}
__attribute__((section(".s_smenu"), noinline, used)) u32 st_smenu(u32 bank, u32 flags, struct txn *t) {
    logrec(K_SMENU, bank, flags, t->count, 0);
    return s_menu_result;
}
__attribute__((section(".s_scustom"), noinline, used)) u32 st_scustom(u32 bank, u32 flags, struct txn *t) {
    logrec(K_SCUSTOM, bank, flags, t->count, 0);
    return s_custom_result;
}
/* the stock copy API body (the part after the first instruction, which the patch's `native` entry reproduces) */
__attribute__((noinline, used)) long c_copy(u32 src, u32 dst, u64 list, u32 count) {
    copy_calls++;
    logrec(K_COPY, src, dst, list, count);
    return (copy_fail_at && copy_calls == copy_fail_at) ? -1 : 0;
}
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
}
static struct txn T;
static void fresh(void) { T.count = 0; }
static int is(int i, u32 k, u64 a, u64 b, u64 c) { return nlog > i && L[i].kind == k && L[i].a == a && L[i].b == b && L[i].c == c; }
static int isc(int i, u64 s, u64 d, u64 list, u64 n) { return nlog > i && L[i].kind == K_COPY && L[i].a == s && L[i].b == d && L[i].c == list && L[i].d == n; }
static void dump(void) {
    for (int i = 0; i < nlog; i++) { puts_("    log "); puthex(L[i].kind); putc_(' '); puthex(L[i].a); putc_(' '); puthex(L[i].b); putc_(' '); puthex(L[i].c); putc_(' '); puthex(L[i].d); putc_('\n'); }
}

#define RELEASE_LIST ((u64)hook_texts + 16 * 6)

__attribute__((used)) void fault(u64 elr, u64 far) {
    puts_("FAIL unexpected exception at "); puthex(elr); puts_(" far "); puthex(far); putc_('\n');
    halt(3);
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

    /* ---------------- copy gate and the release-mode ride-along ---------------- */
    for (u32 sw = 0; sw < 4; sw++) {
        int keep = sw & 1, link = (sw >> 1) & 1;
        for (u32 dst = 1; dst <= 4; dst++) {
            reset(sw, 0, 0);
            long cr = call((void *)0x41013A14, 0, dst, LIST_MAIN, N_MAIN);
            int ok;
            if (keep) ok = cr == 0 && nlog == 0;
            else if (link) ok = cr == 0 && nlog == 1 && isc(0, 0, dst, LIST_MAIN, N_MAIN);
            else ok = cr == 0 && nlog == 2 && isc(0, 0, dst, LIST_MAIN, N_MAIN) && isc(1, 0, dst, RELEASE_LIST, 3);
            if (!ok) { check(0, "copy gate: live->bank store (switch / slot combination)"); dump(); goto gate_done; }
        }
    }
    check(1, "copy gate: live->bank store skipped with keep, one call with link, main list + release ids otherwise (16 combinations)");
gate_done:
    reset(1, 0, 0);
    call((void *)0x41013A14, 1, 0, LIST_MAIN, N_MAIN);
    check(nlog == 2 && isc(0, 1, 0, LIST_MAIN, N_MAIN) && isc(1, 1, 0, RELEASE_LIST, 3), "bank->live load is not gated, release ids ride along (keep on)");
    reset(1, 0, 0);
    call((void *)0x41013A14, 0, 5, LIST_MAIN, N_MAIN);
    check(nlog == 2 && isc(0, 0, 5, LIST_MAIN, N_MAIN) && isc(1, 0, 5, RELEASE_LIST, 3), "live->stash (slot 5) is not gated");
    reset(3, 0, 0);
    call((void *)0x41013A14, 1, 0, LIST_MAIN, N_MAIN);
    check(nlog == 1 && isc(0, 1, 0, LIST_MAIN, N_MAIN), "link on: bank->live load copies the main list only (custom bank carries release ids)");
    reset(0, 0, 0);
    call((void *)0x41013A14, 0, 2, LIST_CUSTOM, 0x1FF);
    check(nlog == 1 && isc(0, 0, 2, LIST_CUSTOM, 0x1FF), "custom list copy: no ride-along");
    reset(0, 0, 0);
    call((void *)0x41013A14, 0, 2, LIST_MAIN, 100);
    check(nlog == 1, "partial main list copy: no ride-along");
    reset(0, 0, 0); copy_fail_at = 1;
    long cr = call((void *)0x41013A14, 0, 2, LIST_MAIN, N_MAIN);
    check(cr == -1 && nlog == 1, "stock copy failure is returned and stops the ride-along");
    reset(0, 0, 0); copy_fail_at = 2;
    cr = call((void *)0x41013A14, 0, 2, LIST_MAIN, N_MAIN);
    check(nlog == 2, "ride-along failure still logged (return value reported)");

    /* ---------------- save command ---------------- */
    reset(0, 2, 1);
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 1 && nlog == 4 && isc(0, 0, 3, LIST_MAIN, N_MAIN) && isc(1, 0, 3, RELEASE_LIST, 3) &&
          isc(2, 0, 2, LIST_CUSTOM, 0x1FF) && isc(3, 0, 2, LIST_CUSTOM + 4 * 0x1FF, N_CUSTOM - 0x1FF), "save: menu bank C + custom bank B stored (ext banks off)");
    reset(1, 2, 1); ds_ext = 1;
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 1 && nlog == 5 && isc(2, 0, 3, LIST_EXT, N_EXT), "save under keep + extended banks: still stores, ext list included");
    reset(2, 2, 2);
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 1 && nlog == 3 && isc(0, 0, 3, LIST_MAIN, N_MAIN) && isc(1, 0, 3, LIST_CUSTOM, 0x1FF), "save with link on: no release ride-along (custom bank carries them)");
    reset(0, 9, 1);
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 0 && nlog == 0, "save: invalid menu bank -> fail, nothing copied");
    reset(0, 1, 9);
    r = (u32)call(hook_save, 0, 0, 0, 0);
    check(r == 0, "save: invalid custom bank -> fail");
    for (int k = 1; k <= 4; k++) {
        reset(0, 2, 1); copy_fail_at = k;
        r = (u32)call(hook_save, 0, 0, 0, 0);
        if (r != 0) { check(0, "save: a failing copy makes the command report failure"); goto save_done; }
    }
    check(1, "save: a failing copy (any of the first 4) makes the command report failure");
save_done:

    /* ---------------- has_prev ---------------- */
    fresh(); T.ids[0] = 5; T.ids[1] = 6; T.ids[2] = 7; T.count = 3;
    check(call(hook_has_prev, 5, (u64)&T, 0, 0) == 1 && call(hook_has_prev, 6, (u64)&T, 0, 0) == 1, "has_prev: finds earlier entries");
    check(call(hook_has_prev, 7, (u64)&T, 0, 0) == 0, "has_prev: ignores the newest entry");
    check(call(hook_has_prev, 8, (u64)&T, 0, 0) == 0, "has_prev: absent id");
    T.count = 1;
    check(call(hook_has_prev, 5, (u64)&T, 0, 0) == 0, "has_prev: single entry -> none earlier");
    T.count = 0;
    check(call(hook_has_prev, 5, (u64)&T, 0, 0) == 0, "has_prev: empty transaction");

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
