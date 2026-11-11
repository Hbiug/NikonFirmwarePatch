#!/usr/bin/env python3
"""Independent check of a bankmode.py output against the official C 3.11 package.

Reads both packages with the toolkit's reader only (not the builder), then verifies:
  * the package envelope, CRCs, SHA-1, unchanged modules and the EG module name/version identity;
  * every byte that differs from stock lies inside a window this patch is allowed to touch;
  * the data-store copy routine's first word is now one branch into the new code, and that code
    (re)executes the displaced instruction;
  * every branch in the new code lands inside the new code or on a known stock address.
"""
import argparse
import binascii
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
from z8prores.package import Package, require, require_official_input, sha
from z8prores import menu as pm

BASE = pm.BASE
CODE_REGION_END = 0x14E4000
COPY_API_OFF = 0x41013A14 - BASE


def windows(version, tag, n, stock):
    dup_table = struct.unpack_from('<Q', stock, pm.EVPTR_A + 8 * pm.ROW_DUP)[0] - BASE
    w = {
        'public version': (0xEB29FC, 12),
        'runtime identity': (0x14EAA90, 8),
        'trailer identity': (n - 11, 8),
        'EG CRC16': (n - 2, 2),
        'copy routine entry (gate hook)': (COPY_API_OFF, 4),
        'text loader boundary': (0x1024D8C, 8),
        'shared language directory': (0x311C5A0, 36 * 8),
        'shared strings text': (0x770000, 0x10000),
        'shared string tables': (0x780000, 0x70000),
        'new code, sub-page, state material': (0x8A0000, 0x2000),
        'video menu rows 7..9': (pm.ROWS_A + 44 * pm.ROW_DUP, 3 * 44),
        'video menu transition pointers 7..9': (pm.EVPTR_A + 8 * pm.ROW_DUP, 3 * 8),
        'reused row transition table (46 events)': (dup_table, 46 * 32),
        'video menu refresh callback': (pm.VIDEO_CALLBACKS + 32, 8),
        'video menu hide site': (pm.HIDE_SITE, 4),
        'stub state callbacks': (pm.STATE_TABLE + pm.STATE_SIZE * pm.STATE_NEW + 0x28, 8),
        'stub state page record': (pm.STATE_TABLE + pm.STATE_SIZE * pm.STATE_NEW + 0x50, 8),
    }
    return w


def diff_ranges(a, b):
    """Exact runs of differing bytes (a run never spans an unchanged byte)."""
    out, i, n = [], 0, len(a)
    while i < n:
        if a[i] != b[i]:
            j = i + 1
            while j < n and a[j] != b[j]:
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


def covering(allowed, a, b):
    """Names of the windows that together cover every byte of a..b, or [] when some byte is uncovered."""
    names, at = [], a
    spans = sorted((s, s + ln, name) for name, (s, ln) in allowed.items())
    while at < b:
        hit = [(e, name) for s, e, name in spans if s <= at < e]
        if not hit:
            return []
        end, name = max(hit)
        names.append(name)
        at = end
    return names


def disasm(raw, va):
    with tempfile.TemporaryDirectory() as d:
        r, o = Path(d) / 'c.bin', Path(d) / 'c.o'
        r.write_bytes(raw)
        subprocess.run(['llvm-objcopy', '-I', 'binary', '-O', 'elf64-littleaarch64',
                        '--rename-section', '.data=.text,code,alloc,load,readonly', str(r), str(o)], check=True)
        out = subprocess.run(['llvm-objdump', '-d', '--triple=aarch64', f'--adjust-vma={va:#x}', str(o)],
                             capture_output=True, text=True, check=True).stdout
    rows = []
    for ln in out.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)$', ln)
        if m:
            rows.append((int(m.group(1), 16), m.group(3), re.sub(r'\s*<.*$|\s*//.*$', '', m.group(4)).strip()))
    return rows


def verify(stock_raw, out_raw, version, tag):
    require_official_input(stock_raw)
    ref, new = Package(stock_raw), Package(out_raw)
    require(len(new.eg) == len(ref.eg) and binascii.crc_hqx(new.eg, 0) == 0, 'EG length or CRC')
    for i in (0, 1, 3, 4):
        require(new.modules[i] == ref.modules[i], f'module {i} changed')
    require(new.modules[2]['name'] == f'eg2070_{version.replace(".", "")}{tag}.bi', 'EG module name')
    eg0, eg1 = ref.eg, new.eg
    ident = f'{version}.{tag}'.encode()
    require(eg1[0x14EAA90:0x14EAA98] == ident and eg1[len(eg1) - 11:len(eg1) - 3] == ident, 'identity text')
    allowed = windows(version, tag, len(eg1), eg0)
    ranges = diff_ranges(eg0, eg1)
    report = []
    for a, b in ranges:
        owners = covering(allowed, a, b)
        require(owners, f'unexpected change {a:#x}..{b:#x}')
        report.append(dict(start=a, end=b, window=owners[0], windows=owners))
    # code region: only these windows may differ
    code_ok = {'public version', 'runtime identity', 'copy routine entry (gate hook)', 'text loader boundary',
               'video menu hide site', 'new code, sub-page, state material', 'shared strings text',
               'shared string tables'}
    for r in report:
        if r['start'] < CODE_REGION_END and not set(r['windows']) <= code_ok:
            raise ValueError(f'unexpected code-region change: {r}')
    # the hook
    word = struct.unpack_from('<I', eg1, COPY_API_OFF)[0]
    require(word >> 26 == 0b000101, 'hook is not an unconditional branch')
    delta = word & 0x3FFFFFF
    delta = delta - (1 << 26) if delta & (1 << 25) else delta
    gate = 0x41013A14 + (delta << 2)
    require(0x40A00000 <= gate < 0x40A00FF0, 'gate outside the new code page')
    code_all = eg1[0x8A0000:0x8A0000 + 0x1000]
    rows_all = disasm(code_all, BASE + 0x8A0000)
    by_addr = {a: (m, o) for a, m, o in rows_all}
    require(by_addr[gate][0] == 'cbnz', 'gate does not start with the source-slot test')
    native = [a for a, (m, o) in by_addr.items() if struct.unpack_from('<I', eg1, a - BASE)[0] == 0xF81E0FF4]
    require(len(native) == 1, 'expected exactly one displaced-instruction copy')
    nb = by_addr[native[0] + 4]
    require(nb[0] == 'b' and int(nb[1], 16) == 0x41013A18, 'native entry must continue at the copy routine body')
    # code extent: everything before the value texts (AUTO, KEEP, SAVED, FAILED), which are followed by the id list
    texts = code_all.find(b'AUTO\0\0\0\0')
    require(texts > 0 and texts % 4 == 0, 'value texts not found in the new code page')
    limit = BASE + 0x8A0000 + texts
    allowed_stock = {0x41012C84, 0x403AE0F8, 0x403B0048, 0x403B00B8, 0x40572B2C, 0x4050A6F0, 0x403F2920,
                     0x403F645C, 0x41013A18}
    for a, m, o in rows_all:
        if a >= limit:
            break
        if m in ('b', 'bl') or m.startswith('b.') or m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            tgt = int(o.split()[-1], 16)
            inside = BASE + 0x8A0000 <= tgt < limit
            require(inside or tgt in allowed_stock, f'branch at {a:#x} to unexpected {tgt:#x}')
    # release-mode ride-along list: exactly these three ids, each present in the stock Custom Settings list
    ids = struct.unpack_from('<3I', eg1, 0x8A0000 + texts + 32)
    require(ids == (0x6001A92, 0x6001A29, 0x6001A2A), f'release id list differs: {[hex(i) for i in ids]}')
    custom = struct.unpack_from('<609I', eg0, 0xA0299EFF8 - 0xA02808000 + 0x4B13000)
    main = struct.unpack_from('<465I', eg0, 0xA0299E888 - 0xA02808000 + 0x4B13000)
    for i in ids:
        require(i in custom and i not in main, f'id {i:#x}: expected in the stock custom list only')
    require(eg1[0x8A0000 + texts + 44:0x8A0000 + texts + 48] == b'\0\0\0\0', 'unexpected data after the id list')
    # copy_ex: calls the stock copy twice (main list, then the id list) and nothing else in the data store
    calls = [(a, o) for a, m, o in rows_all if a < limit and m == 'bl' and int(o.split()[-1], 16) == native[0]]
    require(len(calls) >= 4, 'copy_ex / save do not call the copy routine as expected')
    return dict(status='VERIFIED', changed_ranges=len(report), windows=sorted({w for r in report for w in r['windows']}),
                gate=hex(gate), native=hex(native[0]), output_sha256=sha(out_raw))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('stock', type=Path)
    ap.add_argument('output', type=Path)
    ap.add_argument('--version', required=True)
    ap.add_argument('--tag', required=True)
    a = ap.parse_args()
    print(json.dumps(verify(a.stock.read_bytes(), a.output.read_bytes(), a.version, a.tag), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError) as e:
        print(f'FAILED: {e}', file=sys.stderr)
        sys.exit(1)
