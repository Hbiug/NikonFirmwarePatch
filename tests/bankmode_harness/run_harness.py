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


def _nop_first(data, lo, hi, base, mask, value):
    for a, w in _words(data, lo, hi, base):
        if w & mask == value:
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
    # the gate no longer looks at the keep bit: live->bank stores are always skipped
    'gate-always-skips': lambda d, L, b: _nop_first(d, L['gate'], L['native'], b, 0xFF000000, 0x36000000),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--qemu', default=shutil.which('qemu-system-aarch64') or 'qemu-system-aarch64')
    ap.add_argument('--out', type=Path, default=HERE / 'build')
    ap.add_argument('--ram', default='44G')
    ap.add_argument('--mutate', choices=sorted(MUTATIONS), help='deliberately break the code under test (the harness must then fail)')
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    blk, data, _ = P.code(Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN))
    base = P.va(P.CODE_AT)
    if a.mutate:
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
        f'#define THUNK_MENU {th(P.THUNK_MENU_WORDS)}', f'#define THUNK_CUSTOM {th(P.THUNK_CUSTOM_WORDS)}', '']))
    defs = [f'--defsym=hook_{n}={L[n]:#x}' for n in ('gate', 'save', 'has_prev', 'hook_menu', 'hook_custom', 'link_sync', 'texts', 'post_wrap', 'bkt_wrap',
                                                 'fs_end_get', 'fs_pps', 'fs_est', 'fs_shots', 'fs_remain', 'fs_refresh',
                                                 'fs_end_ok', 'fs_end_entry', 'sl_wrap', 'sl_text')]
    obj = a.out / 'harness.o'
    run = lambda *c: subprocess.run(c, check=True)
    run('clang', '--target=aarch64-none-elf', '-O1', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
        '-mgeneral-regs-only', '-mstrict-align', '-fno-pic', '-fno-asynchronous-unwind-tables', '-I', str(a.out), '-c', str(HERE / 'harness.c'),
        '-o', str(obj))
    elf = a.out / 'harness.elf'
    run('ld.lld', '-T', str(HERE / 'link.ld'), *defs, '-o', str(elf), str(obj))
    cmd = [a.qemu, '-M', 'virt,memory-backend=r0', '-cpu', 'max', '-m', a.ram,
           '-object', f'memory-backend-ram,id=r0,size={a.ram},reserve=off', '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
           '-semihosting', '-kernel', str(elf), '-device', f'loader,file={a.out / "hooks.bin"},addr={base:#x},force-raw=on']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    fails = r.stdout.count('FAIL ')
    print(f'code block {base:#x}..{base + len(data):#x}, {len(data)} bytes; qemu exit {r.returncode}')
    sys.exit(1 if fails or r.returncode else 0)


if __name__ == '__main__':
    main()
