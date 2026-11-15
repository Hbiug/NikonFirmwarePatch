"""Build and run the instruction-level test of the bank-mode / link-banks code under QEMU (virt, AArch64).

  python3 tests/bankmode_harness/run_harness.py [--qemu PATH] [--out DIR]

The code under test is the real patch block from z8bankmode.patcher.code(), assembled at its real address; the stock
routines it calls are stubbed at their real 3.11 addresses (see harness.c / link.ld).  Needs clang, ld.lld and a
qemu-system-aarch64 with the `virt` machine; the persistent switch byte sits at its real address 0xA03D5C0DD, so the
guest gets 44 GiB of (untouched, lazily mapped) RAM.
"""
import argparse, os, shutil, struct, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from z8bankmode import patcher as P


NOP = 0xD503201F


def _words(data, lo, hi, base):
    return [(a, struct.unpack_from('<I', data, a - base)[0]) for a in range(lo, hi, 4)]


def _nop_first(data, lo, hi, base, mask, value, skip=0):
    for a, w in _words(data, lo, hi, base):
        if w & mask == value and skip:
            skip -= 1
        elif w & mask == value:
            struct.pack_into('<I', data, a - base, NOP)
            return
    raise SystemExit('mutation site not found')


def _always(data, lo, hi, base, cond_word):
    """Turn the first b.<cond> (low 5 bits = condition) in lo..hi into an unconditional branch to the same target."""
    for a, w in _words(data, lo, hi, base):
        if w & 0xFF00001F == cond_word:
            imm = (w >> 5) & 0x7FFFF
            imm = imm - (1 << 19) if imm & (1 << 18) else imm
            struct.pack_into('<I', data, a - base, 0x14000000 | (imm & 0x3FFFFFF))
            return
    raise SystemExit('mutation site not found')


MUTATIONS = {
    # bracketing is switched on even when it is already on (the press test of the shot number is gone)
    'bkt-always-on': lambda d, L, b: _nop_first(d, L['bkt_wrap'] + 0x44, L['bw_call'], b, 0xFF000000, 0x35000000),
    # the second change notice for a linked switch is never sent (the b3/b4 defect)
    'single-notice': lambda d, L, b: _nop_first(d, L['post_wrap'], L['pw_done'], b, 0xFF000000, 0x36000000) or struct.pack_into('<I', d, L['pw_both'] - b, 0x14000000 | ((L['pw_done'] - L['pw_both']) // 4)),
    # the link wrapper no longer tests the link bit: it links even when the link is off
    'always-link': lambda d, L, b: _nop_first(d, L['hook_menu'], L['hook_menu'] + 0x40, b, 0xFF000000, 0x36000000),
    # the "already moved by an earlier entry" test is gone: a request carrying both ids switches twice
    'no-has-prev': lambda d, L, b: _nop_first(d, L['hook_menu'], L['hook_custom'], b, 0xFF000000, 0x35000000),
    # copy_ex rides the release ids along even when the link is on
    # the release mode is restored even when the slot's check byte does not match
    'release-no-check': lambda d, L, b: _nop_first(d, L['rel_load'], L['rl_sub'], b, 0xFF00001F, 0x54000001),
    # leaving a bank stores the release mode even with keep stored settings
    'release-store-with-keep': lambda d, L, b: _nop_first(d, L['menu_switch'], L['ms_switch'], b, 0xFF000000, 0x37000000),
    # focus shift: the "past the end point" test is gone (the sequence never stops at the end point)
    'fs-no-stop': lambda d, L, b: _always(d, L['fs_remain'], L['rm_more'], b, 0x5400000A),
    # focus shift: the run is never extended when the estimate runs out before the end point
    'fs-no-extend': lambda d, L, b: struct.pack_into('<I', d, L['rm_more'] - b, 0x14000000 | ((L['rm_out'] - L['rm_more']) // 4)),
    # focus shift: an exhausted estimate is always extended, even within one step of the end point (one frame too many)
    'fs-extend-in-last-step': lambda d, L, b: _nop_first(d, L['rm_more'], L['rm_out'], b, 0xFF00001F, 0x5400000D),
    # focus shift: the direction of the step is ignored (negative pulses per step)
    'fs-no-direction': lambda d, L, b: _nop_first(d, L['fs_est'], L['est_dir'], b, 0xFFFFFFFF, 0x4B0803E8),
    # slider: the text routine always uses the 2-character spacing
    'sl-fixed-spacing': lambda d, L, b: _nop_first(d, L['sl_lenok'], L['sl_n1'], b, 0xFF00001F, 0x54000003),
    # going to standby no longer forgets the end point
    'fs-wake-keeps-end': lambda d, L, b: _nop_first(d, L['fs_wake'], L['fs_wake'] + 0x20, b, 0xFC000000, 0x94000000),
    # the gate no longer looks at the keep bit: live->bank stores are always skipped
    'gate-always-skips': lambda d, L, b: _nop_first(d, L['gate'], L['native'], b, 0xFF000000, 0x36000000),
}


# c5 second code block (GUI area in the image; any free address here)
LENS_VA = 0x40A02000
FRAME_VA = 0x40A02800        # the custom frame code (any address: it branches to stubs at their real addresses)
LENS_MUTATIONS = {
    # metre text: the interpolation between table entries is gone (steps of 2^(1/32))
    'dist-no-interp': lambda d, L, b: _nop_first(d, L['fs_dist_text'], L['fs_page_refresh'], b, 0xFFFFFFFF, 0x0B4F19CE),
    # metre text: no rounding to the nearest centimetre
    'dist-no-round': lambda d, L, b: _nop_first(d, L['fs_dist_text'], L['fs_page_refresh'], b, 0xFFFFFFFF, 0x8B0F01CE),
    # metre text: the 2/3 scale of the raw value is gone (the c5 formula)
    'dist-c5-scale': lambda d, L, b: _nop_first(d, L['fs_dist_text'], L['fs_page_refresh'], b, 0xFFFFFFFF, 0x1ACA0929),
    # Set end point no longer stores the lens distance
    'ok2-no-dist': lambda d, L, b: _nop_first(d, L['fs_end_ok2'], L['fs_dist_text'], b, 0xFFC00000, 0x79000000),
}
# focus shift page: the end point row keeps SET instead of the end point's distance
LENS_MUTATIONS['page-no-end-distance'] = lambda d, L, b: _nop_first(d, L['fs_page_refresh'], L['pr_now'], b, 0xFC000000, 0x94000000, skip=2)
# c8: the i-menu arm ignores a running series
LENS_MUTATIONS['imenu-no-busy'] = lambda d, L, b: _nop_first(d, L['fs_im_arm'], L['fs_menu_open'], b, 0xFC000000, 0x14000000)
# c8: the menu hook does not consume the armed start (every menu opening on the page starts a series)
LENS_MUTATIONS['tick-no-consume'] = lambda d, L, b: _nop_first(d, L['mn_tick'], L['exp'], b, 0xFFFFFFFF, 0x3900013F)
# c8: the menu hook starts wherever the menu opened (no focus shift page test)
LENS_MUTATIONS['tick-any-page'] = lambda d, L, b: _nop_first(d, L['mn_tick'], L['exp'], b, 0xFF00001F, 0x54000001)
# c8: the photo shooting menu row no longer disarms
LENS_MUTATIONS['menu-no-disarm'] = lambda d, L, b: _nop_first(d, L['fs_menu_open'], L['mn_tick'], b, 0xFFFFFFFF, 0x3900013F)
# without an end point the run no longer aims at the lens's infinity position (c5 behaviour)
MUTATIONS['fs-no-infinity'] = lambda d, L, b: _cb_always(d, L['fs_target_get'], L['tg_done'], b)


def _cb_always(data, lo, hi, base):
    """Turn the first cbnz w in lo..hi into an unconditional branch to the same target."""
    for a, w in _words(data, lo, hi, base):
        if w & 0xFF000000 == 0x35000000:
            imm = (w >> 5) & 0x7FFFF
            imm = imm - (1 << 19) if imm & (1 << 18) else imm
            struct.pack_into('<I', data, a - base, 0x14000000 | (imm & 0x3FFFFFF))
            return
    raise SystemExit('mutation site not found')


def _m_q16(u):
    T = P.FS_EXP_TABLE
    f = u & 0x7FF
    i, w = f >> 6, f & 63
    return (T[i] + ((((T[i + 1] - T[i]) * w) & 0xFFFFFFFF) >> 6)) & 0xFFFFFFFF


def dist_model(raw):
    """The integer arithmetic of fs_dist_text (2^((raw - 20480) / 3072) m), as text."""
    u = (2 * raw) // 3
    cm = (((_m_q16(u) * P.FS_DIST_SCALE) << (u >> 11)) + (1 << 31)) >> 32 & 0xFFFFFFFF
    if cm < 1000:
        return f'~{cm // 100}.{cm % 100:02d} m'
    dm = (cm + 5) // 10
    if dm < 1000:
        return f'~{dm // 10}.{dm % 10} m'
    return f'~{(dm + 5) // 10} m'


def dist_cases():
    for raw in range(1, 65536):                       # the model stays within 0.05 % of the true distance
        cm_true = 100 * 2 ** ((raw - 20480) / 3072)
        u = (2 * raw) // 3
        exact = _m_q16(u) * P.FS_DIST_SCALE * 2 ** (u >> 11) / 2 ** 32
        assert abs(exact - cm_true) <= 0.0005 * cm_true + 1e-9, raw
    for raw, text in ((15827, '~0.35 m'), (22520, '~1.58 m'), (33143, '~17.4 m')):   # the camera's live values
        assert dist_model(raw) == text, (raw, dist_model(raw))
    raws = [15827, 22520, 33143, 1, 3071, 3072, 3073, 10000, 13000, 15000, 16000, 17000, 18000, 19000, 20000, 20480,
            21000, 23000, 24000, 25000, 26000, 27000, 28000, 29000, 30000, 31000, 32000, 32767, 32768, 34000, 36000,
            38000, 40000, 45000, 50000, 65535] + [15827 + 37 * k for k in range(1, 8)]
    return [(r, dist_model(r)) for r in raws]


# d0 custom frame: the value limits, the fit direction of the frame, the mark on Custom frame
FRAME_MUTATIONS = {
    'cf-no-limit': lambda d, L, b: _nop_first(d, L['cs_lim'], L['cs_dec'], b, 0xFF00001F, 0x54000002),
    'cf-fit-swapped': lambda d, L, b: _flip_gt(d, L['cf_draw'], L['cf_load'], b),
    'cf-no-mark': lambda d, L, b: _nop_first(d, L['pe_mark'], L['pe_done'], b, 0xFC000000, 0x94000000),
}


def _flip_gt(data, lo, hi, base):
    for a, w in _words(data, lo, hi, base):
        if w & 0xFF00001F == 0x5400000C:
            struct.pack_into('<I', data, a - base, (w & ~0x1F) | 0xD)
            return
    raise SystemExit('mutation site not found')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--qemu', default=shutil.which('qemu-system-aarch64') or 'qemu-system-aarch64')
    ap.add_argument('--out', type=Path, default=HERE / 'build')
    ap.add_argument('--ram', default='44G')
    ap.add_argument('--mutate', choices=sorted(MUTATIONS) + sorted(LENS_MUTATIONS) + sorted(FRAME_MUTATIONS), help='deliberately break the code under test (the harness must then fail)')
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    blk, data, _ = P.code(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN))
    base = P.va(P.CODE_AT)
    lens, lens_data, _ = P.lens_code(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN), LENS_VA, blk.labels)
    if a.mutate in LENS_MUTATIONS:
        lens_data = bytearray(lens_data)
        LENS_MUTATIONS[a.mutate](lens_data, lens.labels, LENS_VA)
        lens_data = bytes(lens_data)
    (a.out / 'lens.bin').write_bytes(lens_data)
    frame, frame_data, _ = P.frame_code(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN), FRAME_VA, blk.labels)
    if a.mutate in FRAME_MUTATIONS:
        frame_data = bytearray(frame_data)
        FRAME_MUTATIONS[a.mutate](frame_data, frame.labels, FRAME_VA)
        frame_data = bytes(frame_data)
    require_gap = FRAME_VA >= LENS_VA + len(lens_data)
    if not require_gap:
        raise SystemExit('lens code overlaps the frame code in the harness layout')
    (a.out / 'frame.bin').write_bytes(frame_data)
    if a.mutate in MUTATIONS:
        data = bytearray(data)
        MUTATIONS[a.mutate](data, blk.labels, base)
        data = bytes(data)
    (a.out / 'hooks.bin').write_bytes(data)
    L = blk.labels
    th = lambda w: '"' + ','.join('0x%08X' % x for x in w) + '"'
    (a.out / 'gen.h').write_text('\n'.join([
        f'#define ID_BANK {P.ID_BANK:#x}u', f'#define ID_EXT {P.ID_EXT:#x}u', f'#define ID_CUSTOM {P.ID_CUSTOM:#x}u',
        f'#define ID_BKT_SHOTS {P.ID_BKT_SHOTS:#x}u', f'#define ID_BKT_DIR {P.ID_BKT_DIR:#x}u',
        f'#define ID_REL_MODE {P.ID_REL_MODE:#x}u', f'#define ID_REL_SUB {P.ID_REL_SUB:#x}u',
        f'#define LIST_MAIN {P.LIST_MAIN:#x}UL', f'#define N_MAIN {P.N_MAIN}',
        f'#define LIST_EXT {P.LIST_EXT:#x}UL', f'#define N_EXT {P.N_EXT}',
        f'#define LIST_CUSTOM {P.LIST_CUSTOM:#x}UL', f'#define N_CUSTOM {P.N_CUSTOM}',
        f'#define SWITCH_ADDR {P.SWITCH_RAM:#x}UL',
        f'#define FS_END0 {P.FS_END0:#x}UL', f'#define FS_REMAIN {P.FS_REMAIN:#x}UL', f'#define FS_DIV_TABLE {P.FS_DIV_TABLE:#x}UL',
        f'#define ID_FS_SHOTS {P.ID_FS_SHOTS:#x}u', f'#define ID_FS_WIDTH {P.ID_FS_WIDTH:#x}u',
        f'#define FS_ITEM_SET {P.FS_ITEM_SET:#x}u', f'#define SL_VALUE {P.SL_VALUE:#x}UL', f'#define FS_ITEM_SHOTS {P.FS_ITEM_SHOTS:#x}u', f'#define FS_ITEM_END0 {P.FS_ITEM_END0:#x}u',
        f'#define THUNK_MENU {th(P.THUNK_MENU_WORDS)}', f'#define THUNK_CUSTOM {th(P.THUNK_CUSTOM_WORDS)}',
        f'#define FS_DIST_RAM {P.FS_DIST_RAM:#x}UL', f'#define P_DISTANCE {P.P_DISTANCE:#x}u',
        f'#define P_INFINITY {P.P_INFINITY:#x}u', f'#define P_NEAR {P.P_NEAR:#x}u',
        f'#define CF_STORE {P.CF_STORE:#x}UL', f'#define CF_RAM {P.CF_RAM:#x}UL', f'#define CF_SLOT0 {P.CF_SLOT0}u',
        f'#define CF_PICK {P.CF_ITEM_PICK:#x}u', *[f'#define CF_ROW{i} {P.CF_ROW_ITEMS[i]:#x}u' for i in range(3)],
        f'#define FS_ITEM_CURRENT {P.FS_ITEM_CURRENT:#x}u', f'#define FS_SLOT_CURRENT {P.FS_SLOT_CURRENT}u',
        '#define DIST_CASES {' + ','.join(f'{{{r:#x}, "{t}"}}' for r, t in dist_cases()) + '}', '']))
    defs = [f'--defsym=hook_{n}={L[n]:#x}' for n in ('gate', 'save', 'has_prev', 'hook_menu', 'hook_custom', 'link_sync', 'texts', 'post_wrap', 'bkt_wrap',
                                                 'fs_end_get', 'fs_pps', 'fs_est', 'fs_shots', 'fs_remain', 'fs_refresh',
                                                 'fs_end_ok', 'fs_end_entry', 'fs_wake', 'sl_wrap', 'sl_text', 'fs_target_get')]
    defs += [f'--defsym=lens_{n}={lens.labels[n]:#x}' for n in ('fs_end_ok2', 'fs_dist_text', 'fs_page_refresh', 'fs_im_arm', 'fs_menu_open', 'mn_tick')]
    defs += [f'--defsym=frame_{n}={frame.labels[n]:#x}' for n in ('cf_draw', 'cf_load', 'cf_entry', 'cf_refresh', 'cf_up', 'cf_down',
                                                                    'cf_ok', 'cf_back', 'cf_pick', 'cf_pick_entry')]
    obj = a.out / 'harness.o'
    run = lambda *c: subprocess.run(c, check=True)
    run('clang', '--target=aarch64-none-elf', '-O1', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
        '-mgeneral-regs-only', '-mstrict-align', '-fno-pic', '-fno-asynchronous-unwind-tables', '-I', str(a.out), '-c', str(HERE / 'harness.c'),
        '-o', str(obj))
    elf = a.out / 'harness.elf'
    run('ld.lld', '-T', str(HERE / 'link.ld'), *defs, '-o', str(elf), str(obj))
    cmd = [a.qemu, '-M', 'virt,memory-backend=r0', '-cpu', 'max', '-m', a.ram,
           '-object', f'memory-backend-ram,id=r0,size={a.ram},reserve=off', '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
           '-semihosting', '-kernel', str(elf), '-device', f'loader,file={a.out / "hooks.bin"},addr={base:#x},force-raw=on',
           '-device', f'loader,file={a.out / "lens.bin"},addr={LENS_VA:#x},force-raw=on',
           '-device', f'loader,file={a.out / "frame.bin"},addr={FRAME_VA:#x},force-raw=on']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    fails = r.stdout.count('FAIL ')
    print(f'code block {base:#x}..{base + len(data):#x}, {len(data)} bytes; qemu exit {r.returncode}')
    sys.exit(1 if fails or r.returncode else 0)


if __name__ == '__main__':
    main()
