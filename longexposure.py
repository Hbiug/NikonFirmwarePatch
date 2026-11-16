#!/usr/bin/env python3
"""Build the Z8 "Long exposure merge" firmware from the official C 3.11 package (experimental, not camera-tested).

A variant of the toolkit's pixel-shift merge: the same photo-menu row, browser, progress page and card access, but
the groups are sequences of ordinary NEFs (consecutive shutter counts, same exposure, at most 120 s apart, 2..256
frames) and the merge writes their rounded mean as <first file>_AVG.NEF, a normal 14-bit lossless NEF made from the
first frame's file. Source: z8longexp/src (compiled here with clang, unlike the toolkit's reviewed prebuilt units).

Standalone: it replaces the pixel-shift merge and does not combine with the toolkit's features or bankmode.py.
"""
import argparse
import binascii
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
from z8prores.package import Package, PACKAGE_BYTES, require, require_official_input, sha
from z8prores.patcher import public_words
from z8patch import shared
from z8patch.compiled import FLAGS
from z8patch.linker import link
import z8pixelshift.patcher as pp

ROOT = Path(__file__).resolve().parent
STOCK_EG_SHA = 'f85e0138e2f5e660ece8560de62e0d12cb795e0e14983e50f20b61dce906c46c'
SOURCE = ROOT / 'z8longexp' / 'src' / 'ps8.c'
CAVE, LIMIT = 0x40990000, 0x409D8000            # the pixel-shift unit's cave
ENTRY = 'psm_menu_action'
# label, help, row "browse", row "all", result title; glyphs must exist in each language's stock strings
MENU_TEXT = {
    'en': ('Long exposure merge',
           'Average series of 2-256 shots (FX, L, 14-bit lossless RAW, same settings, consecutive frames at most '
           '120 s apart) on both cards into a new AVG NEF file. Existing files are kept. MENU returns. MENU '
           'cancels a running merge.',
           '\uefffSelect', '\uea82\uea83Back', 'Last merge result'),
    'zh-CN': ('长时间曝光合成',
              '将两张卡上的连续拍摄 (2-256 张) 平均合成为 AVG NEF。原有文件保留。MENU 返回。合成时按 MENU 取消。',
              '\uefff选择', '\uea82\uea83返回', '上次合成结果'),
    'zh-TW': ('長時間曝光合成',
              '將兩張卡上的連續拍攝 (2-256 張) 平均合成為 AVG NEF。原有檔案保留。MENU 返回。合成時按 MENU 取消。',
              '\uefff選擇', '\uea82\uea83返回', '上次合成結果'),
}


def compile_unit(compiler='clang'):
    with tempfile.TemporaryDirectory(prefix='z8-longexp-') as folder:
        obj = Path(folder) / 'longexp.o'
        cmd = [compiler, *FLAGS, '-DPS11_REVIEW_LAYOUT=0x409ec800ull', '-c', str(SOURCE), '-o', str(obj)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        require(result.returncode == 0, 'Compiler failed: ' + result.stderr[-5000:])
        code, sections, symbols, relocations = link(obj.read_bytes(), CAVE, LIMIT, ENTRY)
    version = subprocess.check_output([compiler, '--version'], text=True).splitlines()[0]
    return code, symbols, version


def build(eg, version, tag, compiler='clang'):
    require(len(eg) == 81807711 and sha(eg) == STOCK_EG_SHA, 'Incompatible input: exact original C3.11 EG required')
    require(re.fullmatch(r'[a-z][0-9]', tag), 'Tag must be a lowercase letter and digit')
    public = public_words(version)
    code, symbols, compiler_version = compile_unit(compiler)
    stock_text = pp.MENU_TEXT
    pp.MENU_TEXT = MENU_TEXT
    try:
        strings = shared.Strings()
        part, detail = pp.build_main(eg, code, symbols, b'', strings)
    finally:
        pp.MENU_TEXT = stock_text
    img = part
    detail['code'] = dict(bytes=len(code), sha256=sha(code), cave=hex(CAVE), end=hex(CAVE + len(code)),
                          compiler=compiler_version, source=str(SOURCE.relative_to(ROOT)))
    detail['shared_strings'] = strings.emit(img)
    detail['loader'] = shared.loader(img, ['pixelshift'])
    text = f'{version}.{tag}'.encode()
    for at, raw, why in [(0xEB29FC, public, 'public version'), (0x14EAA90, text, 'runtime identity'),
                         (len(eg) - 11, text, 'trailer identity')]:
        img.put(at, raw, why)
    img.put(len(eg) - 2, binascii.crc_hqx(img.new[:-2], 0).to_bytes(2, 'big'), 'EG CRC16')
    result = bytes(img.new)
    require(binascii.crc_hqx(result, 0) == 0, 'Invalid final payload CRC')
    end, rows, preserved = 0, [], []
    for e in sorted(img.edits, key=lambda r: r['offset']):
        at = e['offset']
        require(end <= at and result[end:at] == eg[end:at], 'Change outside declared windows')
        if end < at:
            preserved.append(dict(start=end, end=at, sha256=sha(eg[end:at])))
        rows.append(dict(offset=at, bytes=len(e['new']), purpose=e['purpose'],
                         before_sha256=sha(e['old']), after_sha256=sha(e['new'])))
        end = e['end']
    require(result[end:] == eg[end:], 'Unlisted final change')
    return result, dict(feature='long-exposure-merge', output_identity=text.decode(), edits=rows,
                        preserved_ranges=preserved, all_bytes_outside_edits_preserved=True, details=detail)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('firmware', type=Path, help='Official Nikon Z8 C 3.11 firmware (Z_8_0311.bin)')
    ap.add_argument('--version', default='04.20', help='Output version NN.NN (default 04.20)')
    ap.add_argument('--tag', default='e0', help='Internal revision suffix: lowercase letter plus digit (default e0)')
    ap.add_argument('--output', type=Path, required=True, help='New output directory; must not already exist')
    ap.add_argument('--compiler', default='clang')
    a = ap.parse_args()
    require(a.firmware.is_file() and a.firmware.stat().st_size == PACKAGE_BYTES, 'Unsupported firmware length')
    require(not a.output.exists(), 'Output directory already exists; use a new directory')
    data = a.firmware.read_bytes()
    require_official_input(data)
    package = Package(data)
    eg, report = build(package.eg, a.version, a.tag, a.compiler)
    module_name = 'eg2070_' + a.version.replace('.', '') + a.tag + '.bi'
    packet, checked = package.replace_eg(eg, module_name)
    name = 'Z_8_' + a.version.replace('.', '') + '.bin'
    report.update(status='BUILT', input_sha256=package.sha256, input_filename=a.firmware.name,
                  output_sha256=sha(packet), output_bytes=len(packet), output_filename=name,
                  output_eg_sha256=sha(eg), input_modules=package.modules, output_modules=checked.modules,
                  scope='Long exposure merge (average of a sequence of ordinary NEFs into <first>_AVG.NEF) in place '
                        'of the pixel-shift merge; host-tested job and encoder, not camera-tested')
    a.output.mkdir(parents=True, exist_ok=False)
    with (a.output / name).open('xb') as f:
        f.write(packet)
        f.flush()
        os.fsync(f.fileno())
    require(sha((a.output / name).read_bytes()) == report['output_sha256'], 'Output readback mismatch')
    with (a.output / 'SHA256SUMS.txt').open('x') as f:
        f.write(report['output_sha256'] + '  ' + name + '\n')
    with (a.output / 'manifest.json').open('x') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(json.dumps(dict(status=report['status'], output=str(a.output / name), sha256=report['output_sha256'],
                          output_identity=report['output_identity']), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, ImportError, EOFError, subprocess.CalledProcessError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
