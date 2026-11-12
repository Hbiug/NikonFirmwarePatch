#!/usr/bin/env python3
"""Independent check of a bankmode.py output against the official C 3.11 package.

Reads both packages with the toolkit's reader only (not the builder), then verifies:
  * the package envelope, CRCs, SHA-1, unchanged modules and the EG module name/version identity;
  * every byte that differs from stock lies inside a window this patch is allowed to touch;
  * the data-store copy routine's first word is now one branch into the new code, and that code
    (re)executes the displaced instruction;
  * every branch in the new code lands inside the new code or on a known stock address;
  * the two dispatcher call sites (link banks) are now `bl`s into wrappers that call exactly the stock thunk, the
    transaction append and the other bank switch, and fall back to a tail call of the stock thunk.
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
MENU_SITE, CUSTOM_SITE = 0x410EA9CC, 0x410EAE38
MENU_THUNK, CUSTOM_THUNK = 0x410E958C, 0x410E9934
S_MENU, S_CUSTOM, TXN_SET, SET_ITEM = 0x410DD1EC, 0x410DE050, 0x410E9318, 0x410D61D0
DISPATCHER, REL_MODE, REL_SUB = 0x410EA70C, 0x6000108, 0x600010A
POST_COMMIT = 0x410DC874
BKT_HANDLER = 0x40D4D680
SETUP_ROWS, SETUP_EVPTR = 0x43D596D8 - BASE, 0x43D59E68 - BASE
SETUP_CALLBACKS = 0xA028ECA70 - 0xA02808000 + 0x4B13000
N_TEXTS, TEXT_SLOT = 6, 16


def windows(version, tag, n, stock):
    row_table = struct.unpack_from('<Q', stock, SETUP_EVPTR + 8 * 43)[0] - BASE
    w = {
        'public version': (0xEB29FC, 12),
        'runtime identity': (0x14EAA90, 8),
        'trailer identity': (n - 11, 8),
        'EG CRC16': (n - 2, 2),
        'copy routine entry (gate hook)': (COPY_API_OFF, 4),
        'dispatcher menu-bank call (link hook)': (MENU_SITE - BASE, 4),
        'dispatcher custom-bank call (link hook)': (CUSTOM_SITE - BASE, 4),
        'change-notice routine entry (second notice for linked switches)': (POST_COMMIT - BASE, 4),
        'Bracketing burst handler entry': (BKT_HANDLER - BASE, 4),
        'text loader boundary': (0x1024D8C, 8),
        'shared language directory': (0x311C5A0, 36 * 8),
        'shared strings text': (0x770000, 0x10000),
        'shared string tables': (0x780000, 0x70000),
        'new code, sub-page, state material': (0x8A0000, 0x2000),
        'Setup menu row 43': (SETUP_ROWS + 44 * 43, 44),
        'reused Setup row transition table (59 events)': (row_table, 59 * 32),
        'Setup menu refresh callback': (SETUP_CALLBACKS + 32, 8),
        'Setup menu hide site': (0x40597D8C - BASE, 4),
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
               'dispatcher menu-bank call (link hook)', 'dispatcher custom-bank call (link hook)',
               'change-notice routine entry (second notice for linked switches)', 'Bracketing burst handler entry',
               'Setup menu hide site', 'new code, sub-page, state material', 'shared strings text',
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
    # code extent: everything before the value texts (AUTO, KEEP, A+LINK, K+LINK, SAVED, FAILED in 16-byte slots)
    texts = code_all.find(b'AUTO' + b'\0' * 12 + b'KEEP' + b'\0' * 12)
    require(texts > 0 and texts % 4 == 0, 'value texts not found in the new code page')
    limit = BASE + 0x8A0000 + texts
    allowed_stock = {0x41012C84, 0x403AE0F8, 0x403B0048, 0x403B00B8, 0x40597E6C, 0x4050A6F0, 0x403F2920,
                     0x403F645C, 0x41013A18, CUSTOM_THUNK, TXN_SET, S_MENU, S_CUSTOM, SET_ITEM, DISPATCHER, POST_COMMIT + 4, BKT_HANDLER + 4}
    for a, m, o in rows_all:
        if a >= limit:
            break
        if m in ('b', 'bl') or m.startswith('b.') or m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            tgt = int(o.split()[-1], 16)
            inside = BASE + 0x8A0000 <= tgt < limit
            require(inside or tgt in allowed_stock, f'branch at {a:#x} to unexpected {tgt:#x}')
    texts_end = texts + N_TEXTS * TEXT_SLOT
    require(code_all[texts:texts_end] == b''.join(t.ljust(TEXT_SLOT, b'\0') for t in
                                                (b'AUTO', b'KEEP', b'A+LINK', b'K+LINK', b'SAVED', b'FAILED')),
            'value texts differ')
    require(not any(code_all[texts_end:]), 'unexpected data after the value texts')
    calls = [(a, o) for a, m, o in rows_all if a < limit and m == 'bl' and int(o.split()[-1], 16) == native[0]]
    require(len(calls) == 4, 'the save command does not call the copy routine as expected')
    code_rows = [r for r in rows_all if r[0] < limit]
    addrs = [a for a, _, _ in code_rows]

    def const_before(k):
        """The 32-bit constant built in w0 by the mov/movk pair that precedes row k (searching back a few rows)."""
        for j in range(k - 1, max(k - 6, 0), -1):
            a, m, o = code_rows[j]
            if m == 'movk' and o.startswith('w0,'):
                hi = int(o.split('#')[1].split(',')[0], 16)
                lo = int(code_rows[j - 1][2].split('#')[1], 16)
                require(code_rows[j - 1][1] == 'mov' and code_rows[j - 1][2].startswith('w0,'), 'constant load shape')
                return hi << 16 | lo
        raise ValueError('no constant before the call')
    # per-bank release mode: the stock dispatcher is called exactly twice, for the two release-mode items, and the two
    # stock handler calls for those items are where the notes say they are
    disp = [k for k, (a, m, o) in enumerate(code_rows) if m == 'bl' and int(o.split()[-1], 16) == DISPATCHER]
    require(len(disp) == 2 and [const_before(k) for k in disp] == [REL_MODE, REL_SUB],
            'release mode: dispatcher calls differ')
    require(struct.unpack_from('<I', eg0, 0x410EB6F0 - BASE)[0] == 0x97FFFACD and
            struct.unpack_from('<I', eg0, 0x410EB70C - BASE)[0] == 0x97FFFAC9, 'stock release-mode handler calls differ')
    require(struct.unpack_from('<5Q', eg0, 0x4C59188) == tuple(0xA03D5C0DC + 0x2D0 * k for k in range(5)),
            'stock slot addresses of the carrier item differ')
    for i in (REL_MODE, REL_SUB):                      # stock bank lists never carry them
        for lst, n in ((0xA0299E888, 465), (0xA0299EFCC, 11), (0xA0299EFF8, 609)):
            ids = struct.unpack_from(f'<{n}I', eg0, lst - 0xA02808000 + 0x4B13000)
            require(all((x & 0xFFFFFF) != (i & 0xFFFFFF) for x in ids), f'{i:#x} is in a stock bank list')
    # menu_switch: the only call of the stock menu-bank switch from the new code; its thunk has the stock shape
    smenu = [a for a, m, o in code_rows if m == 'bl' and int(o.split()[-1], 16) == S_MENU]
    require(len(smenu) == 1, 'expected exactly one call of the stock menu-bank switch')
    thunk_at = [a for a in addrs if struct.unpack_from('<3I', eg1, a - BASE) == (0x2A0103E8, 0x320003E1, 0x2A0803E0)]
    require(len(thunk_at) == 1, 'menu thunk not found')
    menu_thunk, menu_switch = thunk_at[0], thunk_at[0] + 12
    require(by_addr[menu_switch][0] == 'stp' and menu_switch < smenu[0] < menu_switch + 0x80, 'menu_switch shape')
    # change notice: the stock entry branches to a wrapper that calls the displaced-entry copy at most twice
    word = struct.unpack_from('<I', eg1, POST_COMMIT - BASE)[0]
    require(word >> 26 == 0b000101, 'change-notice hook is not an unconditional branch')
    d = word & 0x3FFFFFF
    post_wrap = POST_COMMIT + ((d - (1 << 26) if d & (1 << 25) else d) << 2)
    require(BASE + 0x8A0000 <= post_wrap < limit and by_addr[post_wrap][0] == 'stp', 'change-notice wrapper outside the new code')
    pn = [a for a in addrs if struct.unpack_from('<I', eg1, a - BASE)[0] == 0xA9BD5BF7]
    require(len(pn) == 1 and by_addr[pn[0] + 4][0] == 'b' and int(by_addr[pn[0] + 4][1], 16) == POST_COMMIT + 4,
            'displaced change-notice entry differs')
    require(sum(1 for a, m, o in code_rows if m == 'bl' and int(o.split()[-1], 16) == pn[0]) == 2,
            'change-notice wrapper: expected two calls of the stock routine')
    require(struct.unpack_from('<I', eg0, POST_COMMIT - BASE)[0] == 0xA9BD5BF7, 'stock change-notice entry differs')
    # bracketing burst: the stock handler entry branches to a wrapper that calls the displaced-entry copy exactly once
    word = struct.unpack_from('<I', eg1, BKT_HANDLER - BASE)[0]
    require(word >> 26 == 0b000101, 'bracketing-burst hook is not an unconditional branch')
    d = word & 0x3FFFFFF
    bkt_wrap = BKT_HANDLER + ((d - (1 << 26) if d & (1 << 25) else d) << 2)
    require(BASE + 0x8A0000 <= bkt_wrap < limit and by_addr[bkt_wrap][0] == 'stp', 'bracketing-burst wrapper outside the new code')
    bn = [a for a in addrs if struct.unpack_from('<I', eg1, a - BASE)[0] == 0xF81D0FF6]
    require(len(bn) == 1 and by_addr[bn[0] + 4][0] == 'b' and int(by_addr[bn[0] + 4][1], 16) == BKT_HANDLER + 4,
            'displaced bracketing-burst entry differs')
    require(sum(1 for a, m, o in code_rows if m == 'bl' and int(o.split()[-1], 16) == bn[0]) == 1,
            'bracketing-burst wrapper: expected one call of the stock handler')
    require(struct.unpack_from('<I', eg0, BKT_HANDLER - BASE)[0] == 0xF81D0FF6, 'stock bracketing-burst entry differs')
    # link banks: the two dispatcher calls

    def bl_target(site):
        w = struct.unpack_from('<I', eg1, site - BASE)[0]
        require(w >> 26 == 0b100101, f'dispatcher call {site:#x} is not a bl')
        d = w & 0x3FFFFFF
        d = d - (1 << 26) if d & (1 << 25) else d
        return site + (d << 2)
    wrappers = {}
    for site, thunk, out_expected, in_expected, name in (
            (MENU_SITE, menu_thunk, {TXN_SET, S_CUSTOM, 0x41012C84}, {menu_thunk}, 'menu'),
            (CUSTOM_SITE, CUSTOM_THUNK, {CUSTOM_THUNK, TXN_SET, 0x41012C84}, {menu_switch}, 'custom')):
        hook = bl_target(site)
        require(BASE + 0x8A0000 <= hook < limit, f'{name} link wrapper outside the new code')
        i = addrs.index(hook)
        body = code_rows[i:]
        # the wrapper = everything up to and including its closing tail call `b <thunk>`
        end = next(k for k, (a, m, o) in enumerate(body) if m == 'b' and int(o.split()[-1], 16) == thunk)
        body = body[:end + 1]
        first = [m for _, m, _ in body[:6]]
        require(first[:4] == ['mov', 'movk', 'movk', 'movk'] and first[4] == 'ldrb' and first[5] == 'tbz',
                f'{name} wrapper does not start with the switch-bit test')
        tgt = {int(o.split()[-1], 16) for a, m, o in body if m == 'bl'}
        inside = {t for t in tgt if BASE + 0x8A0000 <= t < limit}
        outside = tgt - inside
        require(outside == out_expected, f'{name} wrapper calls {[hex(t) for t in sorted(outside)]}')
        helper = inside - in_expected
        require(inside >= in_expected and len(helper) == 1 and by_addr[next(iter(helper))][0] == 'ldr',
                f'{name} wrapper: unexpected inner call')
        require(sum(1 for a, m, o in body if m == 'ret') == 1, f'{name} wrapper: expected one ret')
        wrappers[name] = hex(hook)
    return dict(status='VERIFIED', changed_ranges=len(report), windows=sorted({w for r in report for w in r['windows']}),
                gate=hex(gate), native=hex(native[0]), link_wrappers=wrappers, menu_switch=hex(menu_switch), output_sha256=sha(out_raw))


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
