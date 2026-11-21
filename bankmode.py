#!/usr/bin/env python3
"""Build the Z8 menu-bank behaviour patch (auto-store switch, save command, link banks) from the official C 3.11 package.

It does not combine with the toolkit's ProRes feature (both use the same menu state 0x102 and text gap), nor, for
now, with pixel shift or open gate / N-RAW.  The toolkit's RAW pre-capture (v0.4.0, from its photo-tools group) can be added with
--precapture: it uses the reviewed v0.4.0 pre-capture code (resources/precapture.bin from the v0.4.0 Release toolkit,
copied to resources/precapture-v0.4.0.bin) and its reviewed edits (resources/precapture-v0.4.0.json), which touch no byte this patch changes (the text-copy boundary is computed for both).  Same safeguards as patch.py: exact official input, edits only
inside declared windows, new output directory, independent re-verification (verify_bankmode.py).
"""
import argparse
import binascii
import json
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from z8prores.package import Package, PACKAGE_BYTES, require, require_official_input, sha
from z8prores.patcher import public_words
from z8patch import shared
from z8bankmode import patcher as bp

STOCK_EG_SHA = 'f85e0138e2f5e660ece8560de62e0d12cb795e0e14983e50f20b61dce906c46c'


PRECAPTURE_RECIPE = Path(__file__).resolve().parent / 'resources/precapture-v0.4.0.json'


def add_precapture(img, eg):
    """The toolkit v0.4.0 pre-capture (part of its photo-tools group): reviewed code bytes and reviewed edit list
    (resources/precapture-v0.4.0.json, taken from the v0.4.0 toolkit's compiled.json and combinations.json)."""
    from z8precapture_v040.patcher import edits
    recipe = json.loads(PRECAPTURE_RECIPE.read_text())
    path = PRECAPTURE_RECIPE.parent.parent / recipe['code']['resource']
    require(path.is_file(), f'Missing {recipe["code"]["resource"]}: copy resources/precapture.bin from the v0.4.0 '
                            'Release toolkit ZIP to that name')
    code = path.read_bytes()
    require(len(code) == recipe['code']['bytes'] and sha(code) == recipe['code']['sha256'],
            'Pre-capture code is not the reviewed v0.4.0 resources/precapture.bin')
    root = Path(__file__).resolve().parent
    for name, digest in recipe['code']['source_sha256'].items():
        local = root / name.replace('z8precapture/', 'z8precapture_v040/')
        require(sha(local.read_bytes()) == digest, f'{local.name} differs from the v0.4.0 source')
    rows = edits(code, recipe['symbols'])
    mine = [dict(offset=hex(e['offset']), bytes=len(e['new']), purpose=e['purpose'],
                 old_sha256=sha(eg[e['offset']:e['offset'] + len(e['new'])]), new_sha256=sha(e['new'])) for e in rows]
    require(mine == recipe['edits'], 'Pre-capture edits differ from the reviewed v0.4.0 recipe')
    for e in rows:
        require(all(not (e['offset'] < o['end'] and o['offset'] < e['offset'] + len(e['new'])) for o in img.edits),
                f'Pre-capture edit {e["offset"]:#x} overlaps a menu-bank edit')
        img.put(e['offset'], e['new'], 'precapture: ' + e['purpose'])
    return dict(code_sha256=recipe['code']['sha256'], code_bytes=len(code), edits=len(rows),
                recipe='toolkit v0.4.0 pre-capture (photo-tools group)')


def build(eg, version, tag, precapture=False):
    require(len(eg) == 81807711 and sha(eg) == STOCK_EG_SHA, 'Incompatible input: exact original C3.11 EG required')
    require(re.fullmatch(r'[a-z][0-9]', tag), 'Tag must be a lowercase letter and digit')
    public = public_words(version)
    shared.STRING_IDS['bank-store'] = (bp.STRING_FIRST, bp.STRING_COUNT)
    shared.STRING_IDS['focus-end'] = (bp.FS_STRING_FIRST, bp.FS_STRING_COUNT)
    shared.STRING_IDS['grid-frame'] = (bp.CF_STRING_FIRST, bp.CF_STRING_COUNT)
    strings = shared.Strings()
    img, detail = bp.build_main(eg, strings)
    if precapture:
        detail['precapture'] = add_precapture(img, eg)
    detail['shared_strings'] = strings.emit(img)
    detail['loader'] = shared.loader(img, [])
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
    return result, dict(feature='menu-bank-behavior', output_identity=text.decode(), edits=rows,
                        preserved_ranges=preserved, all_bytes_outside_edits_preserved=True, details=detail)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('firmware', type=Path, help='Official Nikon Z8 C 3.11 firmware (Z_8_0311.bin)')
    ap.add_argument('--version', default='04.20', help='Output version NN.NN (default 04.20)')
    ap.add_argument('--tag', default='b0', help='Internal revision suffix: lowercase letter plus digit (default b0)')
    ap.add_argument('--precapture', action='store_true',
                    help="Also add the toolkit v0.4.0 RAW pre-capture (needs resources/precapture-v0.4.0.bin, see README)")
    ap.add_argument('--output', type=Path, required=True, help='New output directory; must not already exist')
    a = ap.parse_args()
    require(a.firmware.is_file() and a.firmware.stat().st_size == PACKAGE_BYTES, 'Unsupported firmware length')
    require(not a.output.exists(), 'Output directory already exists; use a new directory')
    data = a.firmware.read_bytes()
    require_official_input(data)
    package = Package(data)
    eg, report = build(package.eg, a.version, a.tag, a.precapture)
    module_name = 'eg2070_' + a.version.replace('.', '') + a.tag + '.bi'
    packet, checked = package.replace_eg(eg, module_name)
    name = 'Z_8_' + a.version.replace('.', '') + '.bin'
    if a.precapture:
        report['feature'] = 'menu-bank-behavior+precapture'
    report.update(status='BUILT', input_sha256=package.sha256, input_filename=a.firmware.name,
                  output_sha256=sha(packet), output_bytes=len(packet), output_filename=name,
                  output_eg_sha256=sha(eg), input_modules=package.modules, output_modules=checked.modules,
                  scope='Menu-bank behaviour option, link banks, per-bank release mode, bracketing burst hold, focus shift end point (distance on the page, sub-page to set / clear, current focus distance row, forgotten at standby), estimate (to the end point, else to the infinity position the lens reports), an i-menu start (the Focus shift shooting item starts the series) and a Custom frame photo grid (crop factor 1.00x-1.50x, aspect ratio X:Y); static and instruction-level checks, emulator menu runs; not all paths camera-tested')
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
    except (ValueError, OSError, ImportError, EOFError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
