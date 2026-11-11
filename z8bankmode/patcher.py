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
  * Link banks (new): with it on, the photo/video shooting menu bank and the Custom Settings bank always switch
    together (A-A, B-B, C-C, D-D).  Every settings change - the menu rows and the "shooting menu bank" button + dial
    shortcut alike - reaches the two bank-switch routines through ONE dispatcher (0x410EA70C, called per item by the
    data-store transaction 0x410D6284); its one call for item 0x2000546 (menu bank) and its one call for item
    0x2001613 (Custom Settings bank) are redirected to wrappers that run the stock switch and then the same switch
    on the other bank type, adding the other item to the same transaction so both ids commit together.  Turning the
    link on syncs at once (Custom Settings bank := shooting menu bank) through the stock set-item API.
  * Release mode (single / continuous and its sub-type / self-timer) follows the photo/video menu bank: the bank being
    left remembers it (auto-store, or the explicit save command), the bank being entered sets it again through the
    stock dispatcher.  It is kept outside the stock bank lists (see ID_REL_MODE below).

The switch lives in the padding byte after the one-byte item 0x12:0x38 of the live movie block, which
the data store persists with the block and which the bank copy never touches (so it is global, not
per bank, and 0 = stock behaviour after a factory reset).  Bit 0 = keep stored settings (Z7 style), bit 1 = link
the banks; the sub-page offers the four combinations plus the save command.  Everything is relative to the stock 3.11
image; every edited stock byte is checked against its expected value.
"""
import struct
from z8prores import menu as pm
from z8prores.a64 import Block, _imm
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
# b2/b3 copied 0x6001A92 / 0x6001A29 / 0x6001A2A with the main list; a camera test showed they are not the active
# release mode, so that ride-along is gone.  The active release mode is two items of group 0x01, which has no bank
# slots (the group descriptor has no slot table), so no stock bank can carry them:
#   0x6000108  release mode: 0 single frame, 1 continuous, 4 self-timer
#   0x600010A  continuous sub-type (CL, CH, high-speed frame capture variants), meaningful when the mode is 1
# The shooting-display state builder 0x404249A0 takes them from the 439-item settings mirror (id list 0xA0283A9C4,
# offsets 0x4E4 and 0x4FC) and hard-codes the Z9's release dial position to "quick selection" (7).
# Each menu bank gets its own copy in two padding bytes of the bank's slot of the one-byte item 0x12:0x38
# (data byte, then its complement as a validity check); restoring goes through the stock dispatcher, i.e. exactly
# what a normal change of the two items does.
ID_REL_MODE, ID_REL_SUB = 0x6000108, 0x600010A
DISPATCHER = 0x410EA70C                              # dispatcher(item id, value, txn): record the item, run its handler
REL_SLOT_STEP = 0x2D0                                # distance between the slots of item 0x12:0x38 (live, A, B, C, D)
SLOT_TABLE_OFF = 0x4C59188                           # stock table of the five slot addresses of item 0x12:0x38

# ---- link banks: the dispatcher (0x410EA70C) is called once per item of a data-store transaction; it first records the
# item in the transaction (txn.Set), then runs the item's handler.  Its handler call for item 0x2000546 is
# `bl 0x410E958C` (thunk: switch(value, 1, txn) = S_MENU) and for item 0x2001613 `bl 0x410E9934` (thunk: S_CUSTOM).
DISPATCH_MENU_SITE, DISPATCH_MENU_THUNK = 0x410EA9CC, 0x410E958C
DISPATCH_CUSTOM_SITE, DISPATCH_CUSTOM_THUNK = 0x410EAE38, 0x410E9934
S_MENU, S_CUSTOM = 0x410DD1EC, 0x410DE050      # switch(new bank 0..3, flags (bit 0 = store the old bank first), txn)
TXN_SET = 0x410E9318                           # txn.Set(item id, value, txn): append to the transaction
SET_ITEM = 0x410D61D0                          # public set-item API: (id, value), runs a one-item transaction
DISPATCH_MENU_BL, DISPATCH_CUSTOM_BL = 0x97FFFAF0, 0x97FFFABF       # stock `bl` words at the two sites
THUNK_MENU_WORDS = (0x2A0103E8, 0x320003E1, 0x2A0803E0, 0x17FFCF15)   # mov w8,w1; orr w1,wzr,#1; mov w0,w8; b S_MENU
THUNK_CUSTOM_WORDS = (0x2A0103E8, 0x320003E1, 0x2A0803E0, 0x17FFD1C4)  # same, b S_CUSTOM

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
STRING_FIRST, STRING_COUNT = 3137, 6                    # label + five options (ids from the shared pool)
STATE_TEXT = (b'AUTO', b'KEEP', b'A+LINK', b'K+LINK', b'SAVED', b'FAILED')   # value texts, 16-byte slots; at most 6 characters: the text is centred in a fixed box left of the row arrow
TEXT_SLOT_BYTES = 16
N_OPTIONS = 5                                           # modes 0..3 (bit 0 keep, bit 1 link) + the save command

ENGLISH = ('Menu bank behavior',
           'Auto-store changes (stock)',
           'Keep stored settings (Z7 style)',
           'Auto-store + link banks',
           'Keep stored + link banks',
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


def _tbnz(b, rt, bit, target):
    b._rel(lambda pc: 0x37000000 | _imm(bit, 5) << 19 | _imm((b._target(target) - pc) >> 2, 14, True) << 5 | rt)


def _and7(b, rd, rn):
    b.raw(0x12000800 | rn << 5 | rd)                      # and wD,wN,#7


def _load_id(b, rd, item):
    b.mov_w(rd, item & 0xFFFF)
    b.movk_w16(rd, item >> 16)


def _switch_byte(b, rd):
    """wD = the persistent switch byte (bit 0 keep stored settings, bit 1 link the banks)."""
    b.mov_x64(rd, SWITCH_RAM)
    b.ldrb_w(rd, rd)


def _hook(b, name, own_id, other_id, stock_thunk, switch_other):
    """Wrapper for one dispatcher call site: the stock handler, then (link on) the same switch on the other bank type.

    In: w0 = item id, w1 = new bank (0..3), x2 = transaction.  Out: w0 = what the stock handler returned.
    Link off: a plain tail call of the stock thunk, so the stock path is untouched.
    """
    b.label(name)
    _switch_byte(b, 8)
    b.tbz_w(8, 1, name + '_stock')
    b.stp_pre(19, 30, -0x30)
    b.stp(20, 21, 0x10)
    b.str_x(22, 31, 0x20)
    b.mov_wr(19, 1)                           # new bank
    b.mov_x(20, 2)                            # transaction
    b.mov_w(21, 1)                            # reported when this bank type was already switched in this request
    _load_id(b, 0, own_id)
    b.mov_x(1, 20)
    b.bl('has_prev')
    b.cbnz_w(0, name + '_done')               # an earlier entry of the same request already moved this bank type
    b.mov_wr(1, 19)
    b.mov_x(2, 20)
    b.bl(stock_thunk)                         # stock: switch(new bank, 1, transaction)
    b.mov_wr(21, 0)
    b.tbz_w(21, 0, name + '_done')            # the stock switch failed: nothing to link
    b.cmp_wi(19, 3)
    b.b_cond('hi', name + '_done')
    _load_id(b, 0, other_id)
    b.mov_x(1, 20)
    b.bl('has_prev')
    b.cbnz_w(0, name + '_done')               # the request carries the other bank type itself: leave it alone
    _get(b, other_id)
    b.cmp_w(0, 19)
    b.b_cond('eq', name + '_done')            # already on that bank
    _load_id(b, 0, other_id)
    b.mov_wr(1, 19)
    b.mov_x(2, 20)
    b.bl(TXN_SET)                             # commit the other item together with this one
    b.mov_wr(0, 19)
    b.mov_w(1, 1)                             # store the old bank first, as both stock thunks do
    b.mov_x(2, 20)
    b.bl(switch_other)
    b.label(name + '_done')
    b.mov_wr(0, 21)
    b.ldr_x(22, 31, 0x20)
    b.ldp(20, 21, 0x10)
    b.ldp_post(19, 30, 0x30)
    b.ret()
    b.label(name + '_stock')
    b.b(stock_thunk)


def code(cs):
    blk = Block(va(CODE_AT))
    # ---- gate: entry of the data-store copy routine ------------------------------------------------------
    # live (slot 0) -> user bank (slot 1..4) is skipped, reporting success, when bit 0 of the switch is set.
    blk.label('gate')
    blk.cbnz_w(0, 'native')                  # source is not the live slot
    blk.subs_wi(8, 1, 1)
    blk.cmp_wi(8, 3)
    blk.b_cond('hi', 'native')               # destination is not bank A..D (slot 5 keeps its stash role)
    _switch_byte(blk, 8)
    blk.tbz_w(8, 0, 'native')                # bit 0 clear = stock auto-store
    blk.mov_w(0, 0)
    blk.ret()
    blk.label('native')                      # also the gate-free entry used by the save command
    blk.raw(COPY_API_STOCK)
    blk.b(COPY_API_BODY)
    # ---- per-bank release mode ----------------------------------------------------------------------------------
    # rel_addr(bank w0 = 0..3) -> x9 = address of the bank's data byte (the check byte follows); uses x10, x11
    blk.label('rel_addr')
    _add_wi(blk, 11, 0, 1)
    blk.mov_w(10, REL_SLOT_STEP)
    blk.mov_x64(9, SWITCH_RAM)
    blk.madd_x(9, 11, 10, 9)
    blk.ret()
    # rel_store(bank w0): remember the current release mode for that bank
    blk.label('rel_store')
    blk.stp_pre(19, 30, -0x20)
    blk.str_x(20, 31, 0x10)
    blk.mov_wr(19, 0)
    _get(blk, ID_REL_MODE)
    _and7(blk, 20, 0)
    _get(blk, ID_REL_SUB)
    _and7(blk, 0, 0)
    blk.raw(0x2A000E94)                       # orr w20,w20,w0,lsl #3
    blk.raw(0x32190294)                       # orr w20,w20,#0x80   (bit 7: a value has been stored)
    blk.mov_wr(0, 19)
    blk.bl('rel_addr')
    blk.strb_w(20, 9)
    blk.raw(0x2A3403EA)                       # mvn w10,w20
    blk.strb_w(10, 9, 1)
    blk.ldr_x(20, 31, 0x10)
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    # rel_load(bank w0, transaction x1): set the two items to the bank's remembered values, through the dispatcher
    blk.label('rel_load')
    blk.stp_pre(19, 30, -0x20)
    blk.stp(20, 21, 0x10)
    blk.mov_x(20, 1)
    blk.bl('rel_addr')
    blk.ldrb_w(19, 9)
    blk.ldrb_w(10, 9, 1)
    blk.raw(0x2A2A03EA)                       # mvn w10,w10
    blk.raw(0x53001D4A)                       # uxtb w10,w10
    blk.cmp_w(10, 19)
    blk.b_cond('ne', 'rl_done')               # never stored (or not ours): leave the release mode alone
    blk.tbz_w(19, 7, 'rl_done')
    _get(blk, ID_REL_MODE)
    _and7(blk, 21, 19)
    blk.cmp_w(0, 21)
    blk.b_cond('eq', 'rl_sub')
    _load_id(blk, 0, ID_REL_MODE)
    blk.mov_wr(1, 21)
    blk.mov_x(2, 20)
    blk.bl(DISPATCHER)
    blk.label('rl_sub')
    _get(blk, ID_REL_SUB)
    blk.raw(0x53031675)                       # ubfx w21,w19,#3,#3
    blk.cmp_w(0, 21)
    blk.b_cond('eq', 'rl_done')
    _load_id(blk, 0, ID_REL_SUB)
    blk.mov_wr(1, 21)
    blk.mov_x(2, 20)
    blk.bl(DISPATCHER)
    blk.label('rl_done')
    blk.ldp(20, 21, 0x10)
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    # menu_switch(new bank w0, flags w1, transaction x2): the stock menu-bank switch with the release mode around it
    blk.label('menu_thunk')                   # same shape as the stock dispatcher thunk: (id, new bank, txn)
    blk.raw(0x2A0103E8)                       # mov w8,w1
    blk.raw(0x320003E1)                       # orr w1,wzr,#1
    blk.raw(0x2A0803E0)                       # mov w0,w8
    blk.label('menu_switch')
    blk.stp_pre(19, 30, -0x20)
    blk.stp(20, 21, 0x10)
    blk.mov_wr(19, 0)
    blk.mov_wr(21, 1)
    blk.mov_x(20, 2)
    _switch_byte(blk, 8)
    _tbnz(blk, 8, 0, 'ms_switch')             # keep stored settings: leaving a bank stores nothing
    _get(blk, ID_BANK)
    blk.cmp_wi(0, 3)
    blk.b_cond('hi', 'ms_switch')
    blk.bl('rel_store')                       # auto-store: the bank being left remembers the release mode
    blk.label('ms_switch')
    blk.mov_wr(0, 19)
    blk.mov_wr(1, 21)
    blk.mov_x(2, 20)
    blk.bl(S_MENU)
    blk.mov_wr(21, 0)
    blk.tbz_w(21, 0, 'ms_done')               # the stock switch failed
    blk.cmp_wi(19, 3)
    blk.b_cond('hi', 'ms_done')
    blk.mov_wr(0, 19)
    blk.mov_x(1, 20)
    blk.bl('rel_load')
    blk.label('ms_done')
    blk.mov_wr(0, 21)
    blk.ldp(20, 21, 0x10)
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    # ---- save: explicit live -> bank stores, exactly the store half of the two stock bank switches -----------
    blk.label('save')
    blk.stp_pre(19, 30, -0x20)
    _get(blk, ID_BANK)
    blk.cmp_wi(0, 3)
    blk.b_cond('hi', 'save_fail')
    _add_wi(blk, 19, 0, 1)
    blk.bl('rel_store')                       # w0 is still the menu bank
    _copy_call(blk, 19, LIST_MAIN, N_MAIN)
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
    # ---- has_prev(id w0, transaction x1) -> w0 = 1 when an entry other than the newest already holds the id --------
    # The dispatcher records every item (newest entry) before it runs the item's handler, so "other than the newest"
    # means "an earlier entry of this request", which includes the entry a link wrapper added itself.
    blk.label('has_prev')
    blk.ldr_w(2, 1, 0)                        # entry count
    blk.cbz_w(2, 'hp_no')
    blk.subs_wi(2, 2, 1)
    blk.cbz_w(2, 'hp_no')
    blk.add_xi(1, 1, 4)                       # the id array starts at +4
    blk.mov_w(4, 0)
    blk.label('hp_loop')
    blk.ldr_w_idx(3, 1, 4)
    blk.cmp_w(3, 0)
    blk.b_cond('eq', 'hp_yes')
    _add_wi(blk, 4, 4, 1)
    blk.cmp_w(4, 2)
    blk.b_cond('lo', 'hp_loop')
    blk.label('hp_no')
    blk.mov_w(0, 0)
    blk.ret()
    blk.label('hp_yes')
    blk.mov_w(0, 1)
    blk.ret()
    # ---- the two dispatcher wrappers (link banks) -----------------------------------------------------------------
    _hook(blk, 'hook_menu', ID_BANK, ID_CUSTOM, 'menu_thunk', S_CUSTOM)
    _hook(blk, 'hook_custom', ID_CUSTOM, ID_BANK, DISPATCH_CUSTOM_THUNK, 'menu_switch')
    # ---- link_sync: Custom Settings bank := shooting menu bank, through the stock set-item API --------------------
    blk.label('link_sync')
    blk.stp_pre(19, 30, -0x20)
    _get(blk, ID_BANK)
    blk.mov_wr(19, 0)
    blk.cmp_wi(19, 3)
    blk.b_cond('hi', 'ls_done')
    _get(blk, ID_CUSTOM)
    blk.cmp_w(0, 19)
    blk.b_cond('eq', 'ls_done')
    _load_id(blk, 0, ID_CUSTOM)
    blk.mov_wr(1, 19)
    blk.bl(SET_ITEM)                          # runs the stock one-item transaction -> dispatcher -> hook_custom
    blk.label('ls_done')
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    # ---- entry(state): cursor and mark on the stored mode (stock 4056c8f8 with our value) ----------------------
    blk.label('entry')
    blk.stp_pre(19, 30, -0x20)
    blk.str_x(20, 31, 0x10)
    blk.mov_x(19, 0)
    _switch_byte(blk, 8)
    blk.and_w3(8, 8)                          # mode 0..3
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
    _and7(blk, 8, 8)
    blk.cmp_wi(8, N_OPTIONS - 1)
    blk.b_cond('eq', 'ok_save')
    blk.mov_x64(9, SWITCH_RAM)                # modes 0..3: bit 0 keep stored settings, bit 1 link the banks
    blk.strb_w(8, 9)
    blk.mov_x64(9, SCRATCH_RAM)
    blk.strb_w(31, 9)
    blk.tbz_w(8, 1, 'ok_ret')
    blk.raw(0xF81F0FFE)                       # str x30,[sp,#-0x10]!
    blk.bl('link_sync')                       # link just selected: bring the Custom Settings bank onto the menu bank
    blk.raw(0xF84107FE)                       # ldr x30,[sp],#0x10
    blk.label('ok_ret')
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
    _switch_byte(blk, 8)
    blk.and_w3(8, 8)                          # mode text index 0..3
    blk.cbz_w(10, 'refresh_text')
    _add_wi(blk, 8, 10, 3)                    # 1 -> SAVED (4), 2 -> FAILED (5)
    blk.label('refresh_text')
    blk.adr(9, 'texts')
    blk.add_x(0, 9, 8, lsl=4)                 # 16-byte text slots
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
    data = blk.bytes() + b''.join(t.ljust(TEXT_SLOT_BYTES, b'\0') for t in STATE_TEXT)
    return blk, data, listing


def strings(context):
    """English text in every language: the stock string pool has no equivalent wording."""
    ids = context.add('bank-store', [list(ENGLISH) for _ in range(36)])
    return dict(label_id=ids[0], option_ids=ids[1:1 + N_OPTIONS])


def menu(img, ids, blk):
    """Sub-page, stub state and video-menu row; same plumbing as z8prores.menu.menu with five options."""
    layout = bytearray(img.old[pm.NRAW_LAYOUT:pm.NRAW_LAYOUT + 0x110])
    if struct.unpack_from('<I', layout, 0x44)[0] != 0x8A6:
        raise ValueError('stock layout: title id not where expected')
    struct.pack_into('<I', layout, 0x44, ids['label_id'])
    stock_row = struct.unpack_from('<11I', img.old, pm.NRAW_ROWS)
    if stock_row[0] != 0x35E or stock_row[6] != 0x3119:
        raise ValueError('stock N-RAW option row differs')
    rows = b''.join(struct.pack('<11I', ids['option_ids'][i], *stock_row[1:6], pm.ITEM_OPTION0 + i, *stock_row[7:])
                    for i in range(N_OPTIONS))
    ok = blk.labels['ok']
    table = pm.events(img, pm.NRAW_EVENTS, 14, lambda e, a, g, t: (e, ok if a == pm.NRAW_OK else a, g, t))
    if table.count(struct.pack('<Q', ok)) != 3:
        raise ValueError('expected three OK transitions in the stock option table')
    at = pm.GUI_AT
    layout_at = at; at += len(layout)
    rows_at = at; at += len(rows)
    at = (at + 7) & ~7
    tables_at = at; at += N_OPTIONS * len(table)
    evptr_at = at; at += N_OPTIONS * 8
    callbacks_at = at; at += 5 * 8
    page_at = at; at += 0x50
    if at > pm.TEXT_AT:
        raise ValueError('GUI area too small')
    page = bytearray(img.old[pm.NRAW_PAGE:pm.NRAW_PAGE + 0x50])
    struct.pack_into('<3Q', page, 8, va(layout_at), va(rows_at), va(evptr_at))
    struct.pack_into('<H', page, 0x20, N_OPTIONS)
    callbacks = struct.pack('<5Q', blk.labels['entry'], *pm.NRAW_CALLBACKS[1:])
    img.put(layout_at, layout, 'sub-page layout (stock N-RAW quality layout, new title id)', expect_zero=True)
    img.put(rows_at, rows, 'sub-page rows: five options', expect_zero=True)
    img.put(tables_at, table * N_OPTIONS, 'sub-page transition tables, one per row', expect_zero=True)
    img.put(evptr_at, struct.pack(f'<{N_OPTIONS}Q', *(va(tables_at + len(table) * i) for i in range(N_OPTIONS))),
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
    require(struct.unpack_from('<5Q', eg, SLOT_TABLE_OFF) ==
            tuple(ITEM_BLOCK_LIVE + REL_SLOT_STEP * k for k in range(5)), 'stock slot addresses of the carrier item differ')
    require(struct.unpack_from('<I', eg, 0x410EB6F0 - BASE)[0] == 0x97FFFACD and
            struct.unpack_from('<I', eg, 0x410EB70C - BASE)[0] == 0x97FFFAC9, 'stock release-mode handler calls differ')
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
    # ---- link banks: the dispatcher's two handler calls -> wrappers -----------------------------------------------
    for thunk, words in ((DISPATCH_MENU_THUNK, THUNK_MENU_WORDS), (DISPATCH_CUSTOM_THUNK, THUNK_CUSTOM_WORDS)):
        require(struct.unpack_from('<4I', eg, thunk - BASE) == words, f'stock dispatcher thunk {thunk:#x} differs')
    for site, stock_bl, label, what in ((DISPATCH_MENU_SITE, DISPATCH_MENU_BL, 'hook_menu', 'shooting menu bank'),
                                        (DISPATCH_CUSTOM_SITE, DISPATCH_CUSTOM_BL, 'hook_custom', 'Custom Settings bank')):
        require(struct.unpack_from('<I', eg, site - BASE)[0] == stock_bl, f'stock dispatcher call {site:#x} differs')
        delta = blk.labels[label] - site
        img.put(site - BASE, struct.pack('<I', 0x94000000 | ((delta // 4) & 0x3FFFFFF)),
                f'dispatcher: {what} switch call -> link wrapper', expect=struct.pack('<I', stock_bl))
    return img, dict(strings=ids, menu=where,
                     hook=dict(site=hex(COPY_API), gate=hex(blk.labels['gate']), native=hex(blk.labels['native']),
                               save=hex(blk.labels['save'])),
                     link=dict(menu_site=hex(DISPATCH_MENU_SITE), custom_site=hex(DISPATCH_CUSTOM_SITE),
                               hook_menu=hex(blk.labels['hook_menu']), hook_custom=hex(blk.labels['hook_custom']),
                               has_prev=hex(blk.labels['has_prev']), sync=hex(blk.labels['link_sync'])),
                     switch=dict(ram=hex(SWITCH_RAM), carrier_item='0x1238', default=0, scratch=hex(SCRATCH_RAM),
                                 bits='bit0 keep stored settings, bit1 link banks'),
                     code=[dict(va=hex(x), word=w, text=t) for x, w, t in listing],
                     release=dict(mode_item=hex(ID_REL_MODE), sub_item=hex(ID_REL_SUB), dispatcher=hex(DISPATCHER),
                                  menu_switch=hex(blk.labels['menu_switch']), store=hex(blk.labels['rel_store']),
                                  load=hex(blk.labels['rel_load']),
                                  slots=[hex(SWITCH_RAM + REL_SLOT_STEP * k) for k in (1, 2, 3, 4)]))
