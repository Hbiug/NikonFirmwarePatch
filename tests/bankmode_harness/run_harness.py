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


MUTATIONS = {
    # the link wrapper no longer tests the link bit: it links even when the link is off
    'always-link': lambda d, L, b: _nop_first(d, L['hook_menu'], L['hook_menu'] + 0x40, b, 0xFF000000, 0x36000000),
    # the "already moved by an earlier entry" test is gone: a request carrying both ids switches twice
    'no-has-prev': lambda d, L, b: _nop_first(d, L['hook_menu'], L['hook_custom'], b, 0xFF000000, 0x35000000),
    # copy_ex rides the release ids along even when the link is on
    'ride-along-with-link': lambda d, L, b: _nop_first(d, L['copy_ex'], L['save'], b, 0xFF000000, 0x37000000),
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
        f'#define LIST_MAIN {P.LIST_MAIN:#x}UL', f'#define N_MAIN {P.N_MAIN}',
        f'#define LIST_EXT {P.LIST_EXT:#x}UL', f'#define N_EXT {P.N_EXT}',
        f'#define LIST_CUSTOM {P.LIST_CUSTOM:#x}UL', f'#define N_CUSTOM {P.N_CUSTOM}',
        f'#define SWITCH_ADDR {P.SWITCH_RAM:#x}UL',
        f'#define THUNK_MENU {th(P.THUNK_MENU_WORDS)}', f'#define THUNK_CUSTOM {th(P.THUNK_CUSTOM_WORDS)}', '']))
    defs = [f'--defsym=hook_{n}={L[n]:#x}' for n in ('gate', 'save', 'has_prev', 'hook_menu', 'hook_custom', 'link_sync', 'texts')]
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
