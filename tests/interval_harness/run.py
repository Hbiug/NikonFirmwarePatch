"""Instruction-level test of the e0 interval timer change, under QEMU (virt, AArch64).

  python3 tests/interval_harness/run.py BUILT_Z_8_0420.bin [--stock Z_8_0311.bin] [--qemu PATH]

Loads the tested firmware routines from the EG image of the given package at their real addresses (the stock routines
they call are stubs, see harness.c / link.ld).  With --stock the official image is loaded instead: the checks of the
new behaviour must then fail (the harness's own negative control).
"""
import argparse, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from z8prores.package import Package

BASE = 0x40160000
SLICES = [(0x405EBAB8, 0x405EBBAC), (0x40FBDEDC, 0x40FBDF6C), (0x40FCAD00, 0x40FCADB0), (0x42B31260, 0x42B31270),
          (0x40A02B00, 0x40A02F00)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('package', type=Path)
    ap.add_argument('--stock', action='store_true', help='the package is the official one (negative control)')
    ap.add_argument('--qemu', default=shutil.which('qemu-system-aarch64') or 'qemu-system-aarch64')
    a = ap.parse_args()
    eg = Package(a.package.read_bytes()).eg
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        run = lambda *c: subprocess.run(c, check=True)
        run('clang', '--target=aarch64-none-elf', '-O1', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
            '-mgeneral-regs-only', '-mstrict-align', '-fno-pic', '-fno-asynchronous-unwind-tables', '-c',
            str(HERE / 'harness.c'), '-o', str(d / 'h.o'))
        run('ld.lld', '-T', str(HERE / 'link.ld'), '-o', str(d / 'h.elf'), str(d / 'h.o'))
        loaders = []
        for lo, hi in SLICES:
            f = d / f'{lo:x}.bin'
            f.write_bytes(eg[lo - BASE:hi - BASE])
            loaders += ['-device', f'loader,file={f},addr={lo:#x},force-raw=on']
        cmd = [a.qemu, '-M', 'virt,memory-backend=r0', '-cpu', 'max', '-m', '44G',
               '-object', 'memory-backend-ram,id=r0,size=44G,reserve=off', '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-semihosting', '-kernel', str(d / 'h.elf'), *loaders]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            out, code = r.stdout, r.returncode
            sys.stderr.write(r.stderr)
        except subprocess.TimeoutExpired as e:      # the stock time-to-next loop never ends with a zero interval
            out = (e.stdout or b'').decode() + 'FAIL timeout (endless loop)\n'
            code = 1
    sys.stdout.write(out)
    failed = 'FAIL ' in out or code != 0
    if a.stock:
        print('negative control:', 'harness detects the stock behaviour' if failed else 'NOT DETECTED')
        sys.exit(0 if failed else 1)
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
