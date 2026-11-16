/* Instruction-level test of the e0 interval timer change (0 s and 0.1 s steps).
 *
 * The firmware code under test is loaded from the built EG image at its real addresses (run.py): the Interval page's
 * OK handler 0x405EBAB8, the shot-timing check 0x40FBDEDC, the time-to-next-shot routine 0x40FCAD00 and the patch's
 * guard code in the GUI area.  The stock routines they call are stubs at their real addresses (link.ld).  Run against
 * the stock image (--stock) the new-behaviour checks must fail.
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;
#define UART (*(volatile u32 *)0x09000000UL)
#define BLK(off) (*(volatile u32 *)(0xA03BC7620UL + (off)))
#define NEXT (*(volatile u64 *)(0xA03BC7620UL + 0x20))
#define SPIN(off) (*(volatile u32 *)(0xA02848EB8UL + (off)))

static void putc_(char c) { UART = (u32)c; }
static void puts_(const char *s) { while (*s) putc_(*s++); }
static void putdec(u64 v) { char b[24]; int n = 0; do { b[n++] = '0' + v % 10; v /= 10; } while (v); while (n) putc_(b[--n]); }
static void halt(int code) {
    static u64 blk[2];
    blk[0] = 0x20026; blk[1] = (u64)code;
    register u64 x0 __asm__("x0") = 0x18;
    register u64 x1 __asm__("x1") = (u64)blk;
    __asm__ volatile("hlt #0xf000" :: "r"(x0), "r"(x1) : "memory");
    for (;;) {}
}
static int checks, failures;
static void check(int ok, const char *name) {
    checks++; if (!ok) failures++;
    puts_(ok ? "PASS " : "FAIL "); puts_(name); putc_('\n');
}

/* ---- stubs ------------------------------------------------------------------------------------------------- */
static u64 now_ms;
static u32 ready_word, busy, set_vals[4], set_ids[4], set_n, state_req, msg;
__attribute__((noinline, used)) u64 c_now(void) { return now_ms; }
__attribute__((noinline, used)) u64 c_busy(void) { return busy; }
__attribute__((noinline, used)) u32 c_readyw(void) { return ready_word; }
__attribute__((noinline, used)) void c_setitems(const u32 *ids, const u32 *vals, u32 n) {
    set_n = n; for (u32 i = 0; i < 4 && i < n; i++) { set_ids[i] = ids[i]; set_vals[i] = vals[i]; }
}
__attribute__((noinline, used)) void c_state(u32 s) { state_req = s; }
__attribute__((noinline, used)) void c_msg(u32 m) { msg = m; }
__asm__(".section .s_now,\"ax\"\n    b c_now\n"
        ".section .s_busy,\"ax\"\n    b c_busy\n"
        ".section .s_readyw,\"ax\"\n    b c_readyw\n"
        ".section .s_setitems,\"ax\"\n    b c_setitems\n"
        ".section .s_state,\"ax\"\n    b c_state\n"
        ".section .s_msg,\"ax\"\n    b c_msg\n"
        ".section .s_nop1,\"ax\"\n    ret\n.section .s_nop2,\"ax\"\n    ret\n"
        ".section .s_nop3,\"ax\"\n    ret\n.section .s_nop4,\"ax\"\n    ret\n"
        ".text\n");

typedef u32 (*timing_fn)(u64 now, u64 tolerance);
typedef u64 (*next_fn)(void);
typedef void (*ok_fn)(void *);
#define TIMING ((timing_fn)0x40FBDEDCUL)
#define TO_NEXT ((next_fn)0x40FCAD00UL)
#define PAGE_OK ((ok_fn)0x405EBAB8UL)

static u32 timing(u32 interval, long next_minus_now, u64 tol) {
    now_ms = 1000000; BLK(0x4C) = interval; NEXT = now_ms + next_minus_now;
    return TIMING(now_ms, tol);
}
static u64 to_next(u32 interval, long next_minus_now) {
    now_ms = 5000000; BLK(0x8) = 1; BLK(0x4C) = interval; NEXT = now_ms + next_minus_now;
    return TO_NEXT();
}
static int page_ok(u32 h, u32 m, u32 tenths, u32 eh, u32 em, u32 es, u32 ems) {
    SPIN(0x4) = h; SPIN(0x28) = m; SPIN(0x4C) = tenths;
    set_n = 0; state_req = 0; msg = 0;
    for (int i = 0; i < 4; i++) set_vals[i] = set_ids[i] = 0xEEEE;
    PAGE_OK((void *)0);
    return set_n == 4 && set_ids[0] == 0x200051A && set_ids[1] == 0x200051B && set_ids[2] == 0x200051C &&
           set_ids[3] == 0x200051D && set_vals[0] == eh && set_vals[1] == em && set_vals[2] == es && set_vals[3] == ems &&
           state_req == 0x68D && msg == 0;
}

int main_(void) {
    /* late shot (the next shot time has passed), tolerance 0 as every stock caller passes */
    check(timing(0, -1, 0) == 5, "late, interval 0: shoot now (stock: skip the interval)");
    check(timing(100, -40, 0) == 5, "late, interval 0.1 s: shoot now");
    check(timing(500, -300, 0) == 5, "late, interval 0.5 s: shoot now");
    check(timing(999, -1, 0) == 5, "late, interval 0.999 s: shoot now");
    check(timing(1000, -1, 0) == 0, "late, interval 1 s: skip the interval (stock)");
    check(timing(60000, -5000, 0) == 0, "late, interval 1 min: skip the interval (stock)");
    check(timing(1000, -10, 20) == 5, "late within the caller's tolerance, interval 1 s: shoot (stock)");
    /* not late */
    busy = 0;
    check(timing(0, 100, 0) == 4 && timing(1000, 100, 0) == 4, "100 ms early: wait (stock)");
    check(timing(1000, 3000, 0) == 3 && timing(1000, 5000, 0) == 2, "2..4 s / > 4 s early: stock codes 3 / 2");
    busy = 1;
    check(timing(0, 100, 0) == 1, "busy: stock code 1");
    busy = 0;
    /* due within 5 ms: the readiness word decides */
    ready_word = 2;
    check(timing(0, 3, 0) == 5 && timing(1000, 3, 0) == 5, "due and ready: shoot (stock)");
    ready_word = 0;
    check(timing(0, 3, 0) == 4, "due, not ready, interval 0: wait (stock: skip the interval)");
    check(timing(500, 0, 0) == 4, "due, not ready, interval 0.5 s: wait");
    check(timing(1000, 3, 0) == 0, "due, not ready, interval 1 s: skip (stock)");
    /* time to the next shot */
    check(to_next(0, -2500) == 0, "time to next, interval 0, next shot overdue: 0 (stock: endless loop)");
    check(to_next(0, 700) == 700, "time to next, interval 0, next shot ahead: 700 ms");
    check(to_next(1000, -2500) == 500, "time to next, interval 1 s, 2.5 s overdue: 500 ms (stock catch-up)");
    check(to_next(100, -250) == 50, "time to next, interval 0.1 s, 0.25 s overdue: 50 ms");
    /* the Interval page's OK: hours, minutes, tenths of a second -> items h, m, s, ms */
    check(page_ok(0, 0, 0, 0, 0, 0, 0), "OK on 00:00'00\": stored as 0 (stock: refused)");
    check(page_ok(0, 0, 1, 0, 0, 0, 100), "OK on 0.1 s: 0 s + 100 ms (stock: 0 / 0, refused)");
    check(page_ok(0, 0, 5, 0, 0, 0, 500), "OK on 0.5 s: 0 s + 500 ms (stock)");
    check(page_ok(0, 0, 9, 0, 0, 0, 900), "OK on 0.9 s: 0 s + 900 ms");
    check(page_ok(0, 0, 10, 0, 0, 1, 0), "OK on 1 s: 1 s + 0 ms (stock)");
    check(page_ok(0, 0, 590, 0, 0, 59, 0), "OK on 59 s: 59 s + 0 ms (stock)");
    check(page_ok(1, 30, 250, 1, 30, 25, 0), "OK on 1:30'25\": stock values");
    puts_("checks "); putdec(checks); puts_(" failures "); putdec(failures); putc_('\n');
    halt(failures ? 1 : 0);
    return 0;
}

__attribute__((noinline, used)) void fault(u64 elr, u64 far) {
    puts_("FAIL exception at "); putdec(elr); puts_(" far "); putdec(far); putc_('\n');
    halt(2);
}
__asm__(".section .text.start,\"ax\"\n"
        ".global _start\n_start:\n"
        "    ldr x0, =0x40F00000\n    mov sp, x0\n"
        "    mov x0, #(3 << 20)\n    msr cpacr_el1, x0\n    isb\n"
        "    adr x0, vectors\n    msr vbar_el1, x0\n"
        "    bl main_\n1:  b 1b\n"
        ".text\n.balign 2048\nvectors:\n"
        ".rept 16\n    ldr x1, =0x40F00000\n    mov sp, x1\n    mrs x0, elr_el1\n    mrs x1, far_el1\n    bl fault\n.balign 128\n.endr\n"
        ".text\n");
