"""Menu-bank behaviour patch for the exact Nikon Z8 C 3.11 EG image.

Stock behaviour: every live->bank store happens automatically whenever the bank changes, so a bank
always holds the last settings used in it.  This patch adds a Z7-style alternative:

  * "Menu bank behavior" row in the Video recording menu (same plumbing as the ProRes row in
    z8prores/menu.py: reused hidden row 0x311B, stub state 0x102, cloned N-RAW sub-page).
      - Auto-store (stock)            : nothing changes
      - Keep stored settings (Z7)     : live->bank stores are skipped, so leaving a bank discards the
                                        changes made since it was loaded
      - Save current settings to bank : explicit live->bank store of the current photo/video bank and
                                        the current Custom Settings bank
  * One gate at the entry of the data-store copy routine (the only path every live->bank store uses).
  * Release mode (single / continuous L / continuous H and the L and H speeds) follows the photo/video menu bank:
    stock keeps those three items only in the Custom Settings list.  Every copy of the whole main list (live ->
    bank, bank -> live, bank -> bank, and the explicit save) now copies the three items too, with the same slots;
    the gate skips them together with the main list, so Keep stored settings covers them as well.

The switch lives in the padding byte after the one-byte item 0x12:0x38 of the live movie block, which
the data store persists with the block and which the bank copy never touches (so it is global, not
per bank, and 0 = stock behaviour after a factory reset).  Everything is relative to the stock 3.11
image; every edited stock byte is checked against its expected value.
"""
import struct
from z8prores import menu as pm
from z8prores.a64 import Block
from z8prores.package import require

BASE = pm.BASE
va = pm.va

# ---- data-store facts (3.11 virtual addresses; all verified against the stock image) -------------------
COPY_API = 0x41013A14            # copy(src_slot, dst_slot, id_list*, count) -> 0 ok / -1 fail
COPY_API_OFF = COPY_API - BASE   # 0xEB3A14
COPY_API_STOCK = 0xF81E0FF4      # str x20,[sp,#-0x20]!   (first stock instruction, not PC-relative)
COPY_API_BODY = COPY_API + 4
GET_DS = 0x41012C84              # GetDS(item_id) -> value (other arguments are ignored)
ID_BANK, ID_EXT, ID_CUSTOM = 0x2000546, 0x200054B, 0x2001613   # current menu bank, extended flag, custom bank
LIST_MAIN, N_MAIN = 0xA0299E888, 465
LIST_EXT, N_EXT = 0xA0299EFCC, 11
LIST_CUSTOM, N_CUSTOM, CHUNK = 0xA0299EFF8, 609, 0x1FF
# Release mode (single / continuous L / continuous H, with the L and H speed): stock keeps these three items in the
# Custom Settings list only, so a menu-bank switch never touches them.  They ride along with every copy of the
# main list (live<->bank and bank<->bank), which is exactly when the menu bank is stored or loaded.
RELEASE_IDS = (0x6001A92, 0x6001A29, 0x6001A2A)      # mode 0/1/2 (S/CL/CH), CH speed, CL speed

# ---- persistent switch: padding byte of one-byte item 0x12:0x38 in the live movie block -------------------
ITEM_BLOCK_LIVE = 0xA03D5C0DC    # live address of item 0x1238 (type 0, one byte); +1..+3 are padding
SWITCH_RAM = ITEM_BLOCK_LIVE + 1
SWITCH_ITEM_DEFAULT_OFF = pm.MOVIE_DEFAULTS + (ITEM_BLOCK_LIVE - pm.MOVIE_BLOCK)

# ---- new material (same text-gap regions as the ProRes row; this patch does not combine with it) ------------
CODE_AT, CODE_LIMIT = pm.CODE_AT, pm.CODE_AT + 0x1000   # the code page is read-only at run time: no data lives in it
# last save result (0 none, 1 saved, 2 failed): second padding byte of the same one-byte item.  It sits in
# ordinary writable RAM (a store into the code page is a permission fault), is reset when the sub-page opens,
# and only affects the text at the right of the row.
SCRATCH_RAM = SWITCH_RAM + 1
STRING_FIRST, STRING_COUNT = 3137, 4                    # label + three options (ids from the shared pool)
STATE_TEXT = (b'AUTO', b'KEEP', b'SAVED', b'FAILED')    # right-hand value texts (<= 8 bytes)

ENGLISH = ('Menu bank behavior',
           'Auto-store changes (stock)',
           'Keep stored settings (Z7 style)',
           'Save current settings to bank')


def _add_wi(b, rd, rn, value):
    b.raw(0x11000000 | value << 10 | rn << 5 | rd)       # add wD,wN,#imm12


def _cset_eq(b, rd):
    b.raw(0x1A9F17E0 | rd)                                # cset wD,eq


def _cmn_wi(b, rn, value):
    b.raw(0x3100001F | value << 10 | rn << 5)             # cmn wN,#imm12


def _and1(b, rd, rn):
    b.raw(0x12000000 | rn << 5 | rd)                      # and wD,wN,#1


def _copy_call(b, slot_reg, list_va, count, entry='native'):
    b.mov_w(0, 0)
    b.mov_wr(1, slot_reg)
    b.mov_x64(2, list_va)
    b.mov_w(3, count)
    b.bl(entry)


def _get(b, item):
    b.mov_w(0, item & 0xFFFF)
    b.movk_w16(0, item >> 16)
    b.bl(GET_DS)


def code(cs):
    blk = Block(va(CODE_AT))
    # ---- gate: entry of the data-store copy routine ------------------------------------------------------
    # live (slot 0) -> user bank (slot 1..4) is skipped, reporting success, when the switch is exactly 1.
    blk.label('gate')
    blk.cbnz_w(0, 'copy_ex')                 # source is not the live slot
    blk.subs_wi(8, 1, 1)
    blk.cmp_wi(8, 3)
    blk.b_cond('hi', 'copy_ex')              # destination is not bank A..D (slot 5 keeps its stash role)
    blk.mov_x64(8, SWITCH_RAM)
    blk.ldrb_w(8, 8)
    blk.cmp_wi(8, 1)
    blk.b_cond('ne', 'copy_ex')              # anything but 1 = stock auto-store
    blk.mov_w(0, 0)
    blk.ret()
    blk.label('native')                      # also the gate-free entry used by the save command
    blk.raw(COPY_API_STOCK)
    blk.b(COPY_API_BODY)
    # ---- copy_ex: the stock copy, plus the release-mode items whenever the whole main list is copied -----------
    blk.label('copy_ex')
    blk.stp_pre(19, 30, -0x20)
    blk.str_x(20, 31, 0x10)
    blk.str_x(21, 31, 0x18)
    blk.mov_wr(19, 0)                         # source slot
    blk.mov_wr(20, 1)                         # destination slot
    blk.mov_w(21, 0)                          # 1 when this call copies the main list in full
    blk.mov_x64(8, LIST_MAIN)
    blk.raw(0xEB08005F)                       # cmp x2,x8
    blk.b_cond('ne', 'ex_copy')
    blk.cmp_wi(3, N_MAIN)
    blk.b_cond('ne', 'ex_copy')
    blk.mov_w(21, 1)
    blk.label('ex_copy')
    blk.bl('native')                          # arguments are still in w0,w1,x2,w3
    blk.cbnz_w(0, 'ex_done')                  # failure (-1) is returned as is
    blk.cbz_w(21, 'ex_done')                  # other lists: done (w0 is 0)
    blk.mov_wr(0, 19)
    blk.mov_wr(1, 20)
    blk.adr(9, 'texts')
    blk.add_xi(2, 9, 8 * len(STATE_TEXT))     # the id list sits right after the value texts
    blk.mov_w(3, len(RELEASE_IDS))
    blk.bl('native')
    blk.label('ex_done')
    blk.ldr_x(20, 31, 0x10)
    blk.ldr_x(21, 31, 0x18)
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    # ---- save: explicit live -> bank stores, exactly the store half of the two stock bank switches -----------
    blk.label('save')
    blk.stp_pre(19, 30, -0x20)
    _get(blk, ID_BANK)
    blk.cmp_wi(0, 3)
    blk.b_cond('hi', 'save_fail')
    _add_wi(blk, 19, 0, 1)
    _copy_call(blk, 19, LIST_MAIN, N_MAIN, 'copy_ex')
    _cmn_wi(blk, 0, 1)
    blk.b_cond('eq', 'save_fail')
    _get(blk, ID_EXT)
    blk.cmp_wi(0, 1)
    blk.b_cond('ne', 'save_custom')
    _copy_call(blk, 19, LIST_EXT, N_EXT)
    _cmn_wi(blk, 0, 1)
    blk.b_cond('eq', 'save_fail')
    blk.label('save_custom')
    _get(blk, ID_CUSTOM)
    blk.cmp_wi(0, 3)
    blk.b_cond('hi', 'save_fail')
    _add_wi(blk, 19, 0, 1)
    _copy_call(blk, 19, LIST_CUSTOM, CHUNK)
    _cmn_wi(blk, 0, 1)
    blk.b_cond('eq', 'save_fail')
    blk.mov_w(0, 0)
    blk.mov_wr(1, 19)
    blk.mov_x64(2, LIST_CUSTOM + 4 * CHUNK)
    blk.mov_w(3, N_CUSTOM - CHUNK)
    blk.bl('native')
    _cmn_wi(blk, 0, 1)
    blk.b_cond('eq', 'save_fail')
    blk.mov_w(0, 1)
    blk.b('save_done')
    blk.label('save_fail')
    blk.mov_w(0, 0)
    blk.label('save_done')
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    # ---- entry(state): cursor and mark on the stored mode (stock 4056c8f8 with our value) ----------------------
    blk.label('entry')
    blk.stp_pre(19, 30, -0x20)
    blk.str_x(20, 31, 0x10)
    blk.mov_x(19, 0)
    blk.mov_x64(8, SWITCH_RAM)
    blk.ldrb_w(8, 8)
    blk.cmp_wi(8, 1)
    _cset_eq(blk, 8)
    blk.mov_w(20, pm.ITEM_OPTION0)
    blk.add_w(20, 20, 8)
    blk.mov_x64(9, SCRATCH_RAM)
    blk.strb_w(31, 9)                         # entering the page forgets the last save result
    blk.bl(pm.F_ENTRY_GUARD)
    blk.cmp_wi(0, 1)
    blk.b_cond('eq', 'entry_mark')
    blk.mov_x(0, 19)
    blk.mov_wr(1, 20)
    blk.bl(pm.F_SET_CURSOR)
    blk.label('entry_mark')
    blk.mov_x(0, 19)
    blk.mov_wr(1, 20)
    blk.mov_w(2, 1)
    blk.ldr_x(20, 31, 0x10)
    blk.ldp_post(19, 30, 0x20)
    blk.b(pm.F_SET_MARK)
    # ---- ok(context): the chosen row's item id - first option id (stock 4056c964 without SetDS) ----------------
    blk.label('ok')
    blk.ldr_x(9, 0)
    blk.mov_w(8, 0x2C)
    blk.ldr_x(10, 9, 0x50)
    blk.ldrh_w(11, 9, 0x58)
    blk.ldrh_w(9, 9, 0x32)
    blk.ldr_x(10, 10, 0x10)
    blk.add_x(9, 9, 11)
    blk.madd_x(8, 9, 8, 10)
    blk.ldr_w(8, 8, 0x18)
    blk.mov_w(9, pm.ITEM_OPTION0)
    blk.sub_w(8, 8, 9)
    blk.and_w3(8, 8)
    blk.cmp_wi(8, 2)
    blk.b_cond('eq', 'ok_save')
    blk.mov_x64(9, SWITCH_RAM)                # Auto-store -> 0, Keep stored -> 1
    blk.strb_w(8, 9)
    blk.mov_x64(9, SCRATCH_RAM)
    blk.strb_w(31, 9)
    blk.ret()
    blk.label('ok_save')
    blk.raw(0xF81F0FFE)                       # str x30,[sp,#-0x10]!
    blk.bl('save')
    blk.mov_w(8, 2)                           # 2 = failed
    blk.cbz_w(0, 'ok_store')
    blk.mov_w(8, 1)                           # 1 = saved
    blk.label('ok_store')
    blk.mov_x64(9, SCRATCH_RAM)
    blk.strb_w(8, 9)
    blk.raw(0xF84107FE)                       # ldr x30,[sp],#0x10
    blk.ret()
    # ---- refresh(state): stock video-menu value refresh, then our row's text -----------------------------------
    blk.label('refresh')
    blk.stp_pre(19, 30, -0x20)
    blk.str_x(20, 31, 0x10)
    blk.mov_x(19, 0)
    blk.bl(pm.F_VIDEO_REFRESH)
    blk.mov_x(20, 0)                          # keep the stock return value
    blk.cbz_x(19, 'refresh_done')
    blk.mov_x(0, 19)
    blk.mov_w(1, pm.ITEM_ROW)
    blk.mov_w(2, pm.VALUE_CHILD)
    blk.bl(pm.F_CHILD)
    blk.cbz_x(0, 'refresh_done')
    blk.mov_x(19, 0)
    blk.mov_x64(8, SCRATCH_RAM)
    blk.ldrb_w(10, 8)                         # last save result: 0 none, 1 saved, 2 failed
    blk.mov_x64(8, SWITCH_RAM)
    blk.ldrb_w(8, 8)
    blk.cmp_wi(8, 1)
    _cset_eq(blk, 8)                          # mode text index 0/1
    blk.cbz_w(10, 'refresh_text')
    _add_wi(blk, 8, 10, 1)                    # 1 -> SAVED (2), 2 -> FAILED (3)
    blk.label('refresh_text')
    blk.adr(9, 'texts')
    blk.add_x(0, 9, 8, lsl=3)
    blk.mov_w(1, pm.TEXT_SLOT)
    blk.mov_w(2, pm.TEXT_STYLE)
    blk.bl(pm.F_SET_TEXT)
    blk.mov_x(0, 19)
    blk.mov_w(1, pm.TEXT_SLOT)
    blk.bl(pm.F_SET_CONTENT)
    blk.label('refresh_done')
    blk.mov_x(0, 20)
    blk.ldr_x(20, 31, 0x10)
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    blk.label('texts')
    listing = blk.listing(cs)
    data = blk.bytes() + b''.join(t.ljust(8, b'\0') for t in STATE_TEXT) + \
        b''.join(struct.pack('<I', i) for i in RELEASE_IDS)
    return blk, data, listing


def strings(context):
    """English text in every language: the stock string pool has no equivalent wording."""
    ids = context.add('bank-store', [list(ENGLISH) for _ in range(36)])
    return dict(label_id=ids[0], option_ids=ids[1:4])


def menu(img, ids, blk):
    """Sub-page, stub state and video-menu row; same plumbing as z8prores.menu.menu with three options."""
    layout = bytearray(img.old[pm.NRAW_LAYOUT:pm.NRAW_LAYOUT + 0x110])
    if struct.unpack_from('<I', layout, 0x44)[0] != 0x8A6:
        raise ValueError('stock layout: title id not where expected')
    struct.pack_into('<I', layout, 0x44, ids['label_id'])
    stock_row = struct.unpack_from('<11I', img.old, pm.NRAW_ROWS)
    if stock_row[0] != 0x35E or stock_row[6] != 0x3119:
        raise ValueError('stock N-RAW option row differs')
    rows = b''.join(struct.pack('<11I', ids['option_ids'][i], *stock_row[1:6], pm.ITEM_OPTION0 + i, *stock_row[7:])
                    for i in range(3))
    ok = blk.labels['ok']
    table = pm.events(img, pm.NRAW_EVENTS, 14, lambda e, a, g, t: (e, ok if a == pm.NRAW_OK else a, g, t))
    if table.count(struct.pack('<Q', ok)) != 3:
        raise ValueError('expected three OK transitions in the stock option table')
    at = pm.GUI_AT
    layout_at = at; at += len(layout)
    rows_at = at; at += len(rows)
    at = (at + 7) & ~7
    tables_at = at; at += 3 * len(table)
    evptr_at = at; at += 3 * 8
    callbacks_at = at; at += 5 * 8
    page_at = at; at += 0x50
    if at > pm.TEXT_AT:
        raise ValueError('GUI area too small')
    page = bytearray(img.old[pm.NRAW_PAGE:pm.NRAW_PAGE + 0x50])
    struct.pack_into('<3Q', page, 8, va(layout_at), va(rows_at), va(evptr_at))
    struct.pack_into('<H', page, 0x20, 3)
    callbacks = struct.pack('<5Q', blk.labels['entry'], *pm.NRAW_CALLBACKS[1:])
    img.put(layout_at, layout, 'sub-page layout (stock N-RAW quality layout, new title id)', expect_zero=True)
    img.put(rows_at, rows, 'sub-page rows: three options', expect_zero=True)
    img.put(tables_at, table * 3, 'sub-page transition tables, one per row', expect_zero=True)
    img.put(evptr_at, struct.pack('<3Q', *(va(tables_at + len(table) * i) for i in range(3))),
            'sub-page transition table pointers', expect_zero=True)
    img.put(callbacks_at, callbacks, 'sub-page state callbacks', expect_zero=True)
    img.put(page_at, page, 'sub-page page record', expect_zero=True)
    # ---- the stub state -------------------------------------------------------------------------------------
    record = pm.STATE_TABLE + pm.STATE_SIZE * pm.STATE_NEW
    stock_state = struct.unpack_from('<HHI11Q', img.old, record)
    nraw_state = struct.unpack_from('<HHI11Q', img.old, pm.STATE_TABLE + pm.STATE_SIZE * pm.STATE_NRAW)
    if stock_state[:2] != (2, pm.STATE_NEW) or stock_state[3] != nraw_state[3] or \
            (stock_state[7], stock_state[12]) != pm.STATE_NEW_STOCK or \
            any(stock_state[4:7] + stock_state[8:12] + stock_state[13:]):
        raise ValueError('stock state record differs')
    img.put(record + 0x28, struct.pack('<Q', va(callbacks_at)),
            f'state {pm.STATE_NEW:#x}: callbacks -> menu bank behavior sub-page',
            expect=struct.pack('<Q', pm.STATE_NEW_STOCK[0]))
    img.put(record + 0x50, struct.pack('<Q', va(page_at)),
            f'state {pm.STATE_NEW:#x}: page record -> menu bank behavior sub-page',
            expect=struct.pack('<Q', pm.STATE_NEW_STOCK[1]))
    # ---- the row in the video recording menu ------------------------------------------------------------------
    stock = [img.old[pm.ROWS_A + 44 * i:pm.ROWS_A + 44 * i + 44] for i in (pm.ROW_DUP, pm.ROW_FRAME, pm.ROW_NRAW)]
    nraw = struct.unpack('<11I', stock[2])
    dup = struct.unpack('<11I', stock[0])
    if dup[6] != pm.ITEM_ROW or nraw[6] != 0x3118 or nraw[0] != 0x8A6:
        raise ValueError('stock video menu rows differ')
    new_row = struct.pack('<11I', ids['label_id'], *nraw[1:6], pm.ITEM_ROW, *nraw[7:])
    img.put(pm.ROWS_A + 44 * pm.ROW_DUP, stock[1] + stock[2] + new_row,
            'video menu rows 7..9: frame size, N-RAW quality, new menu bank behavior row', expect=b''.join(stock))
    pointers = struct.unpack_from('<3Q', img.old, pm.EVPTR_A + 8 * pm.ROW_DUP)
    img.put(pm.EVPTR_A + 8 * pm.ROW_DUP, struct.pack('<3Q', pointers[1], pointers[2], pointers[0]),
            'video menu transition table pointers 7..9, same order as the rows')
    dup_table = pointers[0] - BASE
    changed = []

    def retarget(e, a, g, t):
        if t == pm.STATE_FILETYPE:
            changed.append(e)
            return e, a, g, pm.STATE_NEW
        return e, a, g, t
    table7 = pm.events(img, dup_table, 46, retarget)
    if changed != [0x286, 0x28B, 0x29F, 0x2AE]:
        raise ValueError(f'unexpected transitions to the file type page: {changed}')
    img.put(dup_table, table7, 'transition table of the reused row: enter the new state instead of the file type page')
    img.put(pm.HIDE_SITE, struct.pack('<I', 0x52800001 | 0x2E38 << 5),
            'video menu entry callback: hide item 2e38 again instead of hiding item 311b',
            expect=struct.pack('<I', 0x52800001 | pm.ITEM_ROW << 5))
    if img.u64(pm.VIDEO_CALLBACKS + 32) != pm.F_VIDEO_REFRESH:
        raise ValueError('stock video menu refresh callback differs')
    img.put(pm.VIDEO_CALLBACKS + 32, struct.pack('<Q', blk.labels['refresh']),
            'video menu value refresh callback -> wrapper')
    return dict(layout=hex(va(layout_at)), rows=hex(va(rows_at)), tables=hex(va(tables_at)),
                pointers=hex(va(evptr_at)), callbacks=hex(va(callbacks_at)), page=hex(va(page_at)),
                state=hex(pm.state_ram(pm.STATE_NEW)))


def build_main(eg, strings_context):
    """Return the edited Image and review metadata for the stock EG image."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    img = pm.Image(eg)
    require(not any(eg[pm.GAP[0]:pm.GAP[1]]), 'Required text gap is occupied (already patched or incompatible)')
    require(struct.unpack_from('<I', eg, COPY_API_OFF)[0] == COPY_API_STOCK,
            'stock data-store copy routine differs')
    word = struct.unpack_from('<I', eg, pm.MOVIE_DEFAULTS + 0)  # block starts here; sanity only
    # the carrier item must be a one-byte item with value 1 and zero padding in the factory defaults
    require(eg[SWITCH_ITEM_DEFAULT_OFF:SWITCH_ITEM_DEFAULT_OFF + 4] == b'\x01\0\0\0',
            'stock defaults: carrier item padding is not zero')
    ids = strings(strings_context)
    blk, code_bytes, listing = code(cs)
    require(CODE_AT + len(code_bytes) <= CODE_LIMIT, 'Code overruns its page')
    require(pm.CODE_AT + len(code_bytes) <= pm.GUI_AT, 'Code area too small')
    img.put(CODE_AT, code_bytes, 'code: copy gate, save command, sub-page entry/OK, refresh wrapper, value texts',
            expect_zero=True)
    where = menu(img, ids, blk)
    delta = blk.labels['gate'] - COPY_API
    img.put(COPY_API_OFF, struct.pack('<I', 0x14000000 | ((delta // 4) & 0x3FFFFFF)),
            'data-store copy routine entry -> gate', expect=struct.pack('<I', COPY_API_STOCK))
    return img, dict(strings=ids, menu=where,
                     hook=dict(site=hex(COPY_API), gate=hex(blk.labels['gate']), native=hex(blk.labels['native']),
                               save=hex(blk.labels['save'])),
                     switch=dict(ram=hex(SWITCH_RAM), carrier_item='0x1238', default=0, scratch=hex(SCRATCH_RAM)),
                     code=[dict(va=hex(x), word=w, text=t) for x, w, t in listing],
                     release_ids=[hex(i) for i in RELEASE_IDS], copy_ex=hex(blk.labels['copy_ex']))
