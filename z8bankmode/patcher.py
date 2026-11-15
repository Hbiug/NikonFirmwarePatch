"""Menu-bank behaviour patch for the exact Nikon Z8 C 3.11 EG image.

Stock behaviour: every live->bank store happens automatically whenever the bank changes, so a bank
always holds the last settings used in it.  This patch adds a Z7-style alternative:

  * "Menu bank behavior" row at the end of the Setup menu (reused slot of the hidden "Special shooting" row, item
    0x3968; stub state 0x102 and a cloned N-RAW sub-page as in z8prores/menu.py).
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

  * Focus shift end point (b8): two hidden rows of the Focus shift shooting page become "Focus end point" (OK stores the
    current focus position; the row shows SET / OFF) and "Clear focus end point".  With an end point the No. of shots
    row shows the estimated number of frames (~N, or -- when the end point is behind the current focus position), the
    sequence start uses that estimate as the number of shots, and the run ends once focus is at or past the end point
    (extended frame by frame, up to 300, if the estimate runs out first).  See FS_* below.

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
# After a committed transaction the firmware queues ONE change notice (0x410DC874): the transaction's own ids plus the
# id list of the bank type that switched.  A transaction has a single marker for that (byte +0x155C "a bank switched",
# word +0x1560 = 0 menu bank / 1 extended / 2 Custom Settings bank; the notice buffer holds 999 ids, the two lists
# are 465 + 609).  With the link both switches run in one transaction and the second marker replaces the first, so the
# first bank's settings were loaded but never announced (found on a camera with b3: displays and ISO handling kept
# the old bank's values).  The notice routine is wrapped: with the link on and both bank ids in the transaction it
# runs a second time for the other bank type.
POST_COMMIT, POST_COMMIT_STOCK = 0x410DC874, 0xA9BD5BF7             # first instruction: stp x23,x22,[sp,#-0x30]!
TXN_MARK, TXN_MARK_TYPE = 0x155C, 0x1560
# ---- "Bracketing burst" button with bracketing off --------------------------------------------------------------
# 0x40D4D680(button, pressed, a, b) is the press / release handler of the custom-control function "Bracketing burst"
# (called twice from the function-button dispatcher 0x40D3CBC4); it switches the burst state with 0x40D515D4(on).
# Stock does nothing useful when AE/flash bracketing is off.  The wrapper turns bracketing on for the time the button
# is held: on press, if eDSID_Setting_AeFlashBracketingShotNum (0x700067E) is 0, it sets 3 frames (shot number 3 with
# eDSID_Setting_AeFlashBracketingDirection 0x700068A = 3, the pair the stock picker uses for "3F", table 0x43A1A500)
# and remembers the old direction; on release it sets the shot number back to 0 and the direction back.
BKT_HANDLER, BKT_HANDLER_STOCK = 0x40D4D680, 0xF81D0FF6              # first instruction: str x22,[sp,#-0x30]!
ID_BKT_SHOTS, ID_BKT_DIR = 0x700067E, 0x700068A
BKT_FRAMES, BKT_DIR_SYMMETRIC = 3, 3
BKT_FLAG_RAM = 0xA03D5C0DC + 3                                       # third padding byte of the carrier item: 0x80 | old direction while ours
THUNK_MENU_WORDS = (0x2A0103E8, 0x320003E1, 0x2A0803E0, 0x17FFCF15)   # mov w8,w1; orr w1,wzr,#1; mov w0,w8; b S_MENU
THUNK_CUSTOM_WORDS = (0x2A0103E8, 0x320003E1, 0x2A0803E0, 0x17FFD1C4)  # same, b S_CUSTOM

# ---- persistent switch: padding byte of one-byte item 0x12:0x38 in the live movie block -------------------
ITEM_BLOCK_LIVE = 0xA03D5C0DC    # live address of item 0x1238 (type 0, one byte); +1..+3 are padding
SWITCH_RAM = ITEM_BLOCK_LIVE + 1
SWITCH_ITEM_DEFAULT_OFF = pm.MOVIE_DEFAULTS + (ITEM_BLOCK_LIVE - pm.MOVIE_BLOCK)

# ---- focus shift end point (b8) -------------------------------------------------------------------------------
# Focus shift shooting (state 0xB1) moves focus by a relative step per frame: 0x40FCE9DC runs after every shot (the
# remaining-shots counter FS_REMAIN is already decremented; 0 ends the sequence), then 0x40FDEE64(step width) turns
# the step width into a defocus amount and queues lens request type 4, which the lens service turns into lens pulses
# (0x40DB47F0 lens coefficients + 0x40DB76B0) and subtracts from the current focus position (0x40DB3F90).
# The patch remembers one focus position as the end point and
#   * at the sequence start (0x40FB3AC0 reads "No. of shots" with GetDS at FS_START_SITE) replaces the number of shots
#     with the estimate ceil(|start - end| / pulses per step) + 1 (at most 300),
#   * after every shot (FS_FRAME_SITE, the load of the remaining-shots counter) ends the sequence once the lens is at or
#     past the end point, and adds a frame while it is not there yet and the estimate ran out (at most 300 in total),
#   * shows the end point state and the estimate on the focus shift page (two hidden stock rows, items 0x2C86 and
#     0x2C4F, made visible: "Focus end point" and "Clear focus end point").
# The end point is kept in the four free padding bytes of the bank slots of the carrier item (third padding byte of
# slots A..D), as position ^ 0x80000000 so that 0 means "no end point".
FS_END0 = ITEM_BLOCK_LIVE + 3 + REL_SLOT_STEP          # low byte; the next ones follow at +0x2D0 each
FS_REMAIN, FS_TOTAL_OFF, FS_WIDTH_OFF = 0xA03BC8070, 0xA8, 0xB0   # focus shift run state: remaining, total, step width
ID_FS_SHOTS, ID_FS_WIDTH = 0x2000530, 0x2000531
FS_MAX_SHOTS = 300
F_LENS_POS = 0x40DB3F90                                # current focus position (lens pulses)
F_PROP, F_RESCALE, F_RATIO = 0x40EC4544, 0x40C78518, 0x40C790DC   # the helpers 0x40FDEE64 uses
FS_DIV_TABLE = 0xA029C8A84                             # [aperture class 0..3][step width 1..10] divisors
F_LENS_K, F_DEF2PULSE = 0x40DB47F0, 0x40DB76B0         # lens coefficients; defocus -> pulses * 256
F_SPRINTF, F_ROW_INDEX, F_ROW_OBJ, F_REDRAW = 0x4127D850, 0x403AF870, 0x40399EF0, 0x403B26C0
FS_FRAME_SITE, FS_FRAME_STOCK = 0x40FCEA2C, 0xB9400108             # ldr w8,[x8]   (x8 = FS_REMAIN)
FS_START_SITE, FS_START_STOCK = 0x40FB3B64, 0x94017C48             # bl GetDS      (w0 = 0x2000530)
FS_HIDE_SITES, FS_HIDE_STOCK, FS_SHOW = (0x405EF0F4, 0x405EF110), 0x320003E2, 0x2A1F03E2   # orr w2,wzr,#1 -> mov w2,wzr
FS_ROWS, FS_EVPTR, FS_COUNT = 0x43DF8EF0 - BASE, 0x43DF90D8 - BASE, 11
FS_ROW_SET, FS_ROW_CLEAR, FS_ROW_SHOTS, FS_ROW_RESET = 5, 6, 1, 7
FS_ITEM_SET, FS_ITEM_CLEAR, FS_ITEM_SHOTS = 0x2C86, 0x2C4F, 0x2C1F
FS_SLOT_SHOTS, FS_SLOT_SET = 5, 8
# cursor up / down on the focus shift page (0x405EF4BC) only moves from a row whose item is in the 9-entry table
# {item u32, up -1, down +1} at 0x42B29ED0 (searched by 0x403EB4D4); 0x2C4F is listed, 0x2C86 is not.  The table is
# copied with a tenth entry for 0x2C86 and the two instructions that load its address and count are changed.
FS_NAV_TABLE, FS_NAV_COUNT = 0x42B29ED0, 9
FS_NAV_SITES = {0x405EF4D0: 0xD293DA16, 0x405EF4D8: 0xF2A85656, 0x405EF4EC: 0x52800121}   # mov x22,#lo; movk x22,#hi; mov w1,#9
FS_GUI_LIMIT = 0x8A2F00                                # c5: the end point distance lives at 0x8A2F00
# ---- focus step width slider (state 0xB3, b9): the estimate on the slider page itself -----------------------------
# The page has two dynamic labels, "1" (element 0x4DE, text slot 0) and "10" (0x4DF, slot 1), style 0x55, both CENTRED in
# their layout box and clipped to it; every element paints its box background, so a box must not overlap another
# element's text.  The routine 0x405F6A64(state) that shows / hides the two arrows runs when the page opens and after
# every left / right / touch change (slider value: s16 at RAM 0xA03378E38).  It is wrapped: after the stock routine,
# the "1" label becomes one centred line "1 <spaces> N <spaces> 10" spanning the whole scale, and the "10" element is
# hidden (its box is also shrunk; a zero-size box alone does not clip its text, found in the emulator).  The spacing (emulator-tuned) keeps "1" and "10" on their stock positions for 1..4 characters in the
# middle.  The "Narrow" label (element 0x4DB, string 0x7AC) becomes the static line "Narrow  Est. shots  Wide" across
# both old boxes and the "Wide" element is emptied and shrunk.  N = "~estimate" with an end point, "--" when there is no
# estimate, and the No. of shots setting (what a stock series takes) without an end point.
SL_ARROWS, SL_ARROWS_STOCK = 0x405F6A64, 0xF81E0FF4                 # first instruction: str x20,[sp,#-0x20]!
SL_VALUE = 0xA03378E38
F_ELEMENT = 0x4039E810                                             # element(id, state + 0x18) -> object
SL_ELEM_ONE, SL_SLOT_ONE, SL_STYLE, SL_ELEM_TEN = 0x4DE, 0, 0x55, 0x4DF
F_VISIBLE = 0x403F621C                                             # visible(object, 0 / 1), used by the stock arrow routine
SL_LAYOUT = 0x43DF9450 - BASE
SL_ONE_RECT, SL_TEN_RECT = 0x43DF9754 - BASE, 0x43DF9798 - BASE      # {y1 << 16 | x1, y2 << 16 | x2}
SL_NARROW_STR, SL_NARROW_RECT = 0x43DF951C - BASE, 0x43DF9534 - BASE
SL_WIDE_STR, SL_WIDE_RECT = 0x43DF9560 - BASE, 0x43DF9578 - BASE
SL_RECTS_STOCK = {SL_ONE_RECT: (0xDF00AE, 0xF700DE), SL_TEN_RECT: (0xDF01F2, 0xF70222),
                  SL_NARROW_RECT: (0xB5005C, 0xDD0124), SL_WIDE_RECT: (0xB501AC, 0xDD0274)}
SL_RECTS_NEW = {SL_ONE_RECT: (0xDF00AE, 0xF70222), SL_TEN_RECT: (0xDF0222, 0xDF0222),
                SL_NARROW_RECT: (0xB5005C, 0xDD0274), SL_WIDE_RECT: (0xB50274, 0xB50274)}                     # global text slots (stock page: 5 shots, 6 step width, 7 interval)
FS_CALLBACKS = 0xA028E8060 - 0xA02808000 + 0x4B13000   # five pointers of state 0xB1 (data image)
F_FS_REFRESH, F_FS_TOGGLE = 0x405EF210, 0x4051226C
FS_TEXT = (b'SET', b'OFF', b'--', b'~%d', b'%d')      # after STATE_TEXT, same 16-byte slots
# ---- c5: distances and lens diagnostics on the Focus end point sub-page -------------------------------------------
# The lens module keeps the lens's data packets in RAM; 0x4109E130(id) reads one parameter from them (table 0xA02A147F8,
# id * 0x28: packet / offset for each protocol layout, reader, size; pure memory reads).  0x4107B704, which fills the lens
# block of every shot's MakerNote (found with an emulator write watch), takes FocusDistance from parameter 0x117 (packet
# 0xC +0x2E, u16) and FocusStepsFromInfinity from 0xF8 (packet 0xD +0xB).  Distance in metres =
# 2^((raw - 20480) / 3072): the camera's live values 15827 / 22520 / 33143 against ExifTool's 0.35 / 1.58 / 17.4 m for the
# same positions, exact to 1e-14 (c5 used 2^(raw/2048 - 10), fitted to the metres alone).  0x41068D8C(out) decodes
# the newest lens status record (position, drive-end bits, two unknown 32-bit fields).
F_LENS_PARAM, F_LENS_STATUS = 0x4109E130, 0x41068D8C
P_DISTANCE = 0x117
# c6, from the c5 diagnostic rows on the camera (24-120 mm at 24 / 120 mm): parameter 0xB0 (packet 0xD +0x21, s32) is the
# infinity end of the focus range (-7351 / -406; the infinity stop read -7361 / -408) and 0xAE (+0x29) its closest end
# (50150 / 47026; ExifTool's closest-focus shot 50153); both constant while focusing, following the zoom
P_INFINITY, P_NEAR = 0xB0, 0xAE
# distance of the stored end point (u16 raw, 0 = unknown): zero gap after the GUI material, written through the text RW
# alias (as the toolkit does for its own state); the loader copies the gap from the image at every boot, so it is 0 then.
FS_DIST_OFF = 0x8A2F00
FS_DIST_RAM = FS_DIST_OFF + 0x40160000 + 0xA0F800000 - 0x40200000      # 0xA10002F00
# c7: the focus shift page shows the end point's distance on its Focus end point row and the current focus distance on
# the second formerly hidden stock row (item 0x2C4F, text slot 9; the page uses 5..8), and both rows move up before
# "First-frame exposure lock": the page's 11 row records and transition pointers are reordered (rows are found by item).
# c5 / c6 had these values on the sub-page (c5 also 13 diagnostic rows, which found the lens's infinity position).
FS_ROW_CURRENT, FS_ITEM_CURRENT, FS_SLOT_CURRENT = 6, 0x2C4F, 9
# c8: the i menu's "Focus shift shooting" item starts the series.  OK on an i-menu item runs the live view handler
# 0x4044EF98: action code 0x85 (jump tables 0x42AEBE90 / 0x42AEBF78) loads menu state 0xB1 (the focus shift page) at
# 0x4044F2C8, stores it as the menu's requested state (0x40387E04, return marker 0x2923) and starts the menu, whose entry
# 0x405076F4 opens it through 0x405EF088 (state 0xBC, the "Off" page, while a series is running: 0x403971AC).  The
# instruction becomes a branch to fs_im_arm, which arms a flag unless a series is already running.  When the menu
# has opened, mn_tick (menu event 0xA) clears the flag and, on the focus shift page, calls the stock Start action
# 0x405EF5E4 (what OK on "Start" does, in the same menu context).  The photo shooting menu row (state 0x19, row 43, table 0x43E26400: four events open the page
# through 0x405EF0B4) clears the flag first, so the page opened from the menus never starts a series by itself.
IM_SITE, IM_SITE_STOCK, IM_NEXT_STOCK, IM_RESUME = 0x4044F2C8, 0x52801620, 0x14000004, 0x4044F2DC   # mov w0,#0xb1; b
IM_JUMPS = ((0x42AEBE90, 0x78), (0x42AEBF78, 0x82))     # handler jump tables (first action code); code 0x85 -> IM_SITE
IM_CODE = 0x85
F_FS_BUSY, F_FS_START, F_FS_OPEN = 0x403971AC, 0x405EF5E4, 0x405EF0B4
FS_MENU_EVPTR, FS_MENU_ROW, FS_MENU_ITEM = 0x43DCFFA8, 43, 0x2C1D   # photo shooting menu transition pointers / row
FS_MENU_EVENTS = [0x286, 0x28B, 0x29F, 0x2AE]
FS_MENU_PAGE = 0x4BD7480                               # its page record (data image offset)
FS_ARM_RAM = FS_DIST_RAM + 2                            # u8, zero at boot (same gap as the distance)
# the start itself runs in the menu app's event-0xA case (it runs once the menu has opened; c1 used the same hook):
# calling Start from inside the page's refresh (during the page show) made the emulator's stock refusal dialog end in
# "Error. Turn camera off and then on again", while Start from an event handler (OK on Start, c1's hook) does not.
MENU_EVENTS, MENU_EV_TICK, MENU_EV_TICK_STOCK = 0x42B086D8, 0xA, 0x40508260  # menu app's event switch, event 0xA case
MENU_TOP = 0x403DBDB4                                   # top of the menu stack (state record, u16 state at +2)
FS_ORDER = (0, 1, 2, 3, FS_ROW_SET, FS_ROW_CURRENT, 4, 7, 8, 9, 10)   # new position k shows stock row FS_ORDER[k]
FS_VALUE_ROW = 0x101009                                # row kind: text value, no arrow (emulator: 0x1x01 / 0x1x05 kinds show a picture)
FS_PAGE = 0xA028CF400 - 0xA02808000 + 0x4B13000             # page record of the focus shift page (state 0xB1)
FS_LAYOUT, FS_LAYOUT_BYTES = 0x43DF8D58 - BASE, 0x198
FS_GUIDE_STRING, FS_GUIDE_AT = 0xA4C, 0xCC              # "Interrupt after start ->" guide of the focus shift layout
FS_ENGLISH = ('Focus end point', 'Clear end point', 'Narrow' + ' ' * 4 + 'Est. shots' + ' ' * 6 + 'Wide ', '',
              'Set end point', 'Current focus')
FS_STRING_FIRST, FS_STRING_COUNT = 3143, len(FS_ENGLISH)
# Focus end point sub-page (c3): the end point row opens state 0xB5, the stock child page of that (formerly hidden) row,
# rebuilt from the N-RAW option page: "Set end point" / "Clear end point"; OK runs fs_end_ok and goes back.
STATE_FS_END = 0xB5
STATE_FS_END_STOCK = (0xA028E8100, 0xA028CF540)        # its stock callbacks and page record pointers
FS_ITEM_END0 = pm.ITEM_OPTION0 + 5                     # 0x35BA / 0x35BB: Set / Clear
F_MODE_REQUEST, WAKE_SITE, WAKE_STOCK = 0x40FBC66C, 0x40FADB58, 0x94003AC5   # shooting-control mode request; bl of mode 0xC (standby)

# ---- new material (same text-gap regions as the ProRes row; this patch does not combine with it) ------------
# ---- the row lives in the Setup menu (state 0x297), in the slot of its last row "Special shooting" (item 0x3968), which
# the stock entry callback hides unless internal flag 0x14 is set.  b0..b5 had the row in the Video recording menu.
SETUP_ROWS, SETUP_EVPTR, SETUP_COUNT = 0x43D596D8 - BASE, 0x43D59E68 - BASE, 44
SETUP_ROW = 43                                       # "Special shooting"
SETUP_ITEM, SETUP_STOCK_LABEL, SETUP_STOCK_TARGET = 0x3968, 1634, 0x4F1
SETUP_CALLBACKS = 0xA028ECA70 - 0xA02808000 + 0x4B13000   # five pointers of state 0x297 (data image)
F_SETUP_REFRESH = 0x40597E6C                         # its value-refresh callback
SETUP_HIDE_SITE, SETUP_HIDE_STOCK = 0x40597D8C, 0x35000100   # cbnz w0,0x40597dac: skip hiding item 0x3968 when the flag is set
VIDEO_NRAW_ROW = pm.ROWS_A + 44 * pm.ROW_NRAW        # stock row with a value text at the right: field template
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



def _r(b, word, text):
    """Raw instruction with the text Capstone must read back (checked in code())."""
    if not hasattr(b, 'expect'):
        b.expect = {}
    b.expect[len(b.items)] = text
    b.raw(word)


def _norm(text):
    """Disassembly text with every immediate in hex and single spaces."""
    import re
    return re.sub(r'#(-?)(0x[0-9a-f]+|\d+)', lambda m: '#' + m.group(1) + hex(int(m.group(2), 0)), ' '.join(text.replace('#-#', '#-').split()))


def _adr_text(b, rd, slot):
    """adr xD, value text `slot` (16-byte slots after the code, STATE_TEXT then FS_TEXT)."""
    def make(pc):
        delta = _imm(b.labels['texts'] + TEXT_SLOT_BYTES * slot - pc, 21, True)
        return 0x10000000 | (delta & 3) << 29 | (delta >> 2) << 5 | rd
    b._rel(make)


def _focus(b):
    """Focus shift end point: storage, estimate, per-frame stop, sequence start, page texts and the two row actions."""
    t_set, t_off, t_dash, t_fmt = (len(STATE_TEXT) + k for k in range(4))
    # fs_end_get -> w0 = 1 when an end point is stored, w1 = that position; uses x9..x13
    b.label('fs_end_get')
    b.mov_x64(9, FS_END0)
    b.ldrb_w(10, 9)
    b.ldrb_w(11, 9, REL_SLOT_STEP)
    b.ldrb_w(12, 9, 2 * REL_SLOT_STEP)
    b.ldrb_w(13, 9, 3 * REL_SLOT_STEP)
    _r(b, 0x2A0B214A, 'orr w10, w10, w11, lsl #8')
    _r(b, 0x2A0C414A, 'orr w10, w10, w12, lsl #16')
    _r(b, 0x2A0D614A, 'orr w10, w10, w13, lsl #24')
    b.cmp_wi(10, 0)
    _r(b, 0x1A9F07E0, 'cset w0, ne')
    _r(b, 0x52010141, 'eor w1, w10, #0x80000000')
    b.ret()
    # fs_end_put(w0 = encoded end point, 0 = none); uses x9
    b.label('fs_end_put')
    b.mov_x64(9, FS_END0)
    for k in range(4):
        if k:
            _r(b, 0x53087C00, 'lsr w0, w0, #8')
        b.strb_w(0, 9, k * REL_SLOT_STEP)
    b.ret()
    # fs_target_get -> w0 = 1 and w1 = the position a run aims at: the stored end point, else (c6) the lens's infinity
    # position (lens parameter 0xB0; unknown when it and the closest-focus position 0xAE both read 0, e.g. no Z lens)
    b.label('fs_target_get')
    b.stp_pre(19, 30, -0x10)
    b.bl('fs_end_get')
    b.cbnz_w(0, 'tg_done')
    b.mov_w(0, P_INFINITY)
    b.bl(F_LENS_PARAM)
    b.mov_wr(19, 0)
    b.mov_w(0, P_NEAR)
    b.bl(F_LENS_PARAM)
    _r(b, 0x2A130008, 'orr w8, w0, w19')
    b.mov_wr(1, 19)
    b.cmp_wi(8, 0)
    _r(b, 0x1A9F07E0, 'cset w0, ne')
    b.label('tg_done')
    b.ldp_post(19, 30, 0x10)
    b.ret()
    # fs_pps(w0 = step width 1..10) -> w0 = lens pulses one focus shift step subtracts from the position, 0 = unknown.
    # The defocus amount is computed exactly as 0x40FDEE64 does, the pulses exactly as lens request type 4 does.
    b.label('fs_pps')
    _r(b, 0xD10183FF, 'sub sp, sp, #0x60')
    b.str_x(20, 31, 0x48)
    b.stp(19, 30, 0x50)
    _r(b, 0x51000408, 'sub w8, w0, #1')
    b.cmp_wi(8, 9)
    b.b_cond('hi', 'pps_zero')
    b.mov_wr(19, 0)
    b.mov_w(0, 0x2103)
    b.mov_w(1, 8)
    b.add_xi(2, 31, 0x18)
    b.bl(F_PROP)
    b.mov_w(0, 0x2821)
    b.mov_w(1, 8)
    b.add_xi(2, 31, 0x8)
    b.bl(F_PROP)
    b.ldr_w(0, 31, 0x18)
    b.add_xi(1, 31, 0x8)
    b.bl(F_RESCALE)
    _r(b, 0x294327E8, 'ldp w8, w9, [sp, #0x18]')
    b.ldr_w(10, 31, 0xC)
    b.sub_w(9, 9, 10)
    _r(b, 0x1AC80D2A, 'sdiv w10, w9, w8')
    b.mov_w(20, 0)                            # aperture class, as 0x40FDEE64: q > 1 -> 0, q == 1 -> 1,
    b.cmp_wi(10, 1)                           # q < 0 -> 3, q == 0 -> 2 when the difference is positive, else 3
    b.b_cond('gt', 'pps_class')
    b.mov_w(20, 1)
    b.b_cond('eq', 'pps_class')
    b.mov_w(20, 3)
    b.cbnz_w(10, 'pps_class')
    b.cmp_wi(9, 0)
    b.b_cond('le', 'pps_class')
    b.mov_w(20, 2)
    b.label('pps_class')
    b.add_xi(0, 31, 0x18)
    b.add_xi(1, 31, 0)
    b.bl(F_RATIO)
    _r(b, 0x294033EB, 'ldp w11, w12, [sp]')
    b.mov_w(8, 0xE800)
    b.movk_w16(8, 3)
    _r(b, 0x1B087D68, 'mul w8, w11, w8')
    _r(b, 0x1ACC0908, 'udiv w8, w8, w12')
    b.mov_x64(9, FS_DIV_TABLE)
    b.mov_w(10, 10)
    b.madd_x(9, 20, 10, 9)
    _r(b, 0x5100066A, 'sub w10, w19, #1')
    b.ldrb_idx(10, 9, 10)
    _r(b, 0x1ACA0D13, 'sdiv w19, w8, w10')  # defocus amount of one step (w8 = the scaled ratio)
    _r(b, 0xA9027FFF, 'stp xzr, xzr, [sp, #0x20]')
    b.str_w(31, 31, 0x30)
    b.add_xi(0, 31, 0x20)
    b.bl(F_LENS_K)
    b.mov_w(8, 1000)
    _r(b, 0x1AC80E61, 'sdiv w1, w19, w8')
    b.add_xi(0, 31, 0x20)
    b.add_xi(2, 31, 0x30)
    b.bl(F_DEF2PULSE)
    b.ldr_w(8, 31, 0x30)
    _r(b, 0x1103FD09, 'add w9, w8, #0xff')
    b.cmp_wi(8, 0)
    _r(b, 0x1A88B128, 'csel w8, w9, w8, lt')
    _r(b, 0x13087D00, 'asr w0, w8, #8')
    b.b('pps_done')
    b.label('pps_zero')
    b.mov_w(0, 0)
    b.label('pps_done')
    b.ldr_x(20, 31, 0x48)
    b.ldp(19, 30, 0x50)
    _r(b, 0x910183FF, 'add sp, sp, #0x60')
    b.ret()
    # fs_est(w0 = step width) -> w0 = estimated frames from the current position to the end point (1..300),
    # 0 = unknown (no end point or no lens data), -1 = the end point is not in the shift direction
    b.label('fs_est')
    b.stp_pre(19, 30, -0x20)
    b.stp(20, 21, 0x10)
    b.bl('fs_pps')
    b.mov_wr(19, 0)
    b.cbz_w(19, 'est_zero')
    b.bl(F_LENS_POS)
    b.mov_wr(20, 0)
    b.bl('fs_target_get')
    b.cbz_w(0, 'est_zero')
    _r(b, 0x4B010288, 'sub w8, w20, w1')
    b.cmp_wi(19, 0)
    b.b_cond('ge', 'est_dir')
    _r(b, 0x4B1303F3, 'neg w19, w19')
    _r(b, 0x4B0803E8, 'neg w8, w8')
    b.label('est_dir')
    b.cmp_wi(8, 0)
    b.b_cond('lt', 'est_bad')
    _r(b, 0x1AD30909, 'udiv w9, w8, w19')      # frames at 0, s, 2s, ... up to the end point: floor(d / s) + 1
    _add_wi(b, 9, 9, 1)
    b.cmp_wi(9, FS_MAX_SHOTS)
    b.b_cond('ls', 'est_ok')
    b.mov_w(9, FS_MAX_SHOTS)
    b.label('est_ok')
    b.mov_wr(0, 9)
    b.b('est_done')
    b.label('est_bad')
    _r(b, 0x12800000, 'mov w0, #-1')
    b.b('est_done')
    b.label('est_zero')
    b.mov_w(0, 0)
    b.label('est_done')
    b.ldp(20, 21, 0x10)
    b.ldp_post(19, 30, 0x20)
    b.ret()
    # fs_shots(GetDS arguments): the sequence start's read of "No. of shots", replaced by the estimate when an end
    # point is set; an end point on the wrong side of the start is forgotten (the run then is a stock run)
    b.label('fs_shots')
    b.stp_pre(19, 30, -0x10)
    b.bl(GET_DS)
    b.mov_wr(19, 0)
    b.bl('fs_target_get')
    b.cbz_w(0, 'sh_done')
    _get(b, ID_FS_WIDTH)
    b.bl('fs_est')
    b.cmp_wi(0, 0)
    b.b_cond('gt', 'sh_use')
    b.b_cond('eq', 'sh_done')
    b.mov_w(0, 0)
    b.bl('fs_end_put')
    b.b('sh_done')
    b.label('sh_use')
    b.mov_wr(19, 0)
    b.label('sh_done')
    b.mov_wr(0, 19)
    b.ldp_post(19, 30, 0x10)
    b.ret()
    # fs_remain: replaces `ldr w8,[x8]` (remaining shots) after every shot; returns it in w8, x0..x7 preserved
    b.label('fs_remain')
    _r(b, 0xD101C3FF, 'sub sp, sp, #0x70')
    for k in range(4):
        b.stp(2 * k, 2 * k + 1, 0x10 * k)
    b.stp(19, 20, 0x40)
    b.stp(21, 22, 0x50)
    b.str_x(30, 31, 0x60)
    b.mov_x64(19, FS_REMAIN)
    b.ldr_w(20, 19)
    b.bl('fs_target_get')
    b.cbz_w(0, 'rm_out')                      # no end point and no infinity position: stock
    b.mov_wr(22, 1)
    b.ldr_w(0, 19, FS_WIDTH_OFF)
    b.bl('fs_pps')
    b.cbz_w(0, 'rm_out')                      # no lens data: stock
    b.mov_wr(21, 0)
    b.bl(F_LENS_POS)
    _r(b, 0x4B160008, 'sub w8, w0, w22')
    b.cmp_wi(21, 0)
    b.b_cond('ge', 'rm_dir')
    _r(b, 0x4B0803E8, 'neg w8, w8')
    b.label('rm_dir')
    # w8 = distance still to go (negative: past the end point).  The position read here may be the one of the frame
    # just taken or already the next one (the lens may not have moved yet), so both tests allow for one step.
    b.cmp_wi(8, 0)
    b.b_cond('ge', 'rm_more')
    b.str_w(31, 19)                           # past the end point: that was the last frame
    b.mov_w(20, 0)
    b.b('rm_out')
    b.label('rm_more')
    b.cbnz_w(20, 'rm_out')                    # frames left: stock
    b.cmp_wi(21, 0)
    _r(b, 0x5A95A6A9, 'cneg w9, w21, lt')     # |step|
    b.cmp_w(8, 9)
    b.b_cond('le', 'rm_out')                  # within one step of the end point: done
    b.ldr_w(8, 19, FS_TOTAL_OFF)              # estimate used up before the end point: one more frame
    b.cmp_wi(8, FS_MAX_SHOTS)
    b.b_cond('hs', 'rm_out')
    _add_wi(b, 8, 8, 1)
    b.str_w(8, 19, FS_TOTAL_OFF)
    b.mov_w(20, 1)
    b.str_w(20, 19)
    b.label('rm_out')
    b.mov_wr(8, 20)
    for k in range(4):
        b.ldp(2 * k, 2 * k + 1, 0x10 * k)
    b.ldp(19, 20, 0x40)
    b.ldp(21, 22, 0x50)
    b.ldr_x(30, 31, 0x60)
    _r(b, 0x9101C3FF, 'add sp, sp, #0x70')
    b.ret()
    # fs_row_text(text x0, item w1, state x2, text slot w3): the value text at the right of a focus shift row, as
    # 0x405EF210 does.  A text slot is one global text resource that a row object is bound to, so every row on the page
    # needs its own: the stock page uses 5 (No. of shots), 6 (step width), 7 (interval); the end point row uses 8.
    b.label('fs_row_text')
    b.stp_pre(19, 30, -0x30)
    b.stp(20, 21, 0x10)
    b.str_x(22, 31, 0x20)
    b.mov_x(19, 2)
    b.mov_x(20, 0)
    b.mov_wr(21, 1)
    b.mov_wr(22, 3)
    b.mov_x(0, 19)
    b.bl(F_ROW_INDEX)
    _cmn_wi(b, 0, 1)
    b.b_cond('eq', 'rt_done')
    b.mov_wr(1, 0)
    b.ldr_x(0, 19, 0x48)
    b.mov_w(2, 0)
    b.bl(F_ROW_OBJ)
    b.cbz_x(0, 'rt_done')
    b.mov_x(21, 0)
    b.mov_x(0, 20)
    b.mov_wr(1, 22)
    b.mov_w(2, 0x220)
    b.bl(pm.F_SET_TEXT)
    b.mov_x(0, 21)
    b.mov_wr(1, 22)
    b.bl(pm.F_SET_CONTENT)
    b.label('rt_done')
    b.ldr_x(22, 31, 0x20)
    b.ldp(20, 21, 0x10)
    b.ldp_post(19, 30, 0x30)
    b.ret()
    # fs_texts(state): "SET" / "OFF" on the end point row; "~N" (or "--") on the No. of shots row whenever there is an
    # estimate (to the end point, else to infinity); without one the stock value stays
    b.label('fs_texts')
    b.stp_pre(19, 30, -0x30)
    b.str_x(20, 31, 0x10)
    b.mov_x(19, 0)
    b.bl('fs_end_get')
    b.cbz_w(0, 'tx_off')
    _adr_text(b, 0, t_set)
    b.b('tx_mark')
    b.label('tx_off')
    _adr_text(b, 0, t_off)
    b.label('tx_mark')
    b.mov_w(1, FS_ITEM_SET)
    b.mov_x(2, 19)
    b.mov_w(3, FS_SLOT_SET)
    b.bl('fs_row_text')
    _get(b, ID_FS_WIDTH)
    b.bl('fs_est')
    b.cmp_wi(0, 0)
    b.b_cond('eq', 'tx_done')
    b.b_cond('lt', 'tx_dash')
    b.mov_wr(2, 0)
    _adr_text(b, 1, t_fmt)
    b.add_xi(0, 31, 0x18)
    b.bl(F_SPRINTF)
    b.add_xi(0, 31, 0x18)
    b.b('tx_shots')
    b.label('tx_dash')
    _adr_text(b, 0, t_dash)
    b.label('tx_shots')
    b.mov_w(1, FS_ITEM_SHOTS)
    b.mov_x(2, 19)
    b.mov_w(3, FS_SLOT_SHOTS)
    b.bl('fs_row_text')
    b.label('tx_done')
    b.ldr_x(20, 31, 0x10)
    b.ldp_post(19, 30, 0x30)
    b.ret()
    # fs_refresh(state): the focus shift page's stock value refresh, then our texts
    b.label('fs_refresh')
    b.stp_pre(19, 30, -0x20)
    b.str_x(20, 31, 0x10)
    b.mov_x(19, 0)
    b.bl(F_FS_REFRESH)
    b.mov_x(20, 0)
    b.cbz_x(19, 'rf_done')
    b.mov_x(0, 19)
    b.bl('fs_texts')
    b.label('rf_done')
    b.mov_x(0, 20)
    b.ldr_x(20, 31, 0x10)
    b.ldp_post(19, 30, 0x20)
    b.ret()
    # fs_wake(mode, reason, data): the only request of shooting-control mode 0xC (0x40FADB58: the standby timer puts the
    # camera to sleep; modes 0xE / 0xD follow).  The lens position counter restarts across the sleep, so a stored end
    # point would point elsewhere afterwards: forget it, then make the stock request.
    b.label('fs_wake')
    b.stp_pre(0, 30, -0x20)
    b.stp(1, 2, 0x10)
    b.mov_w(0, 0)
    b.bl('fs_end_put')
    b.ldp(1, 2, 0x10)
    b.ldp_post(0, 30, 0x20)
    b.b(F_MODE_REQUEST)
    # fs_end_entry(state): the Focus end point sub-page opens with the cursor on "Set end point"
    b.label('fs_end_entry')
    b.stp_pre(19, 30, -0x10)
    b.mov_x(19, 0)
    b.bl(pm.F_ENTRY_GUARD)
    b.cmp_wi(0, 1)
    b.b_cond('eq', 'fee_done')
    b.mov_x(0, 19)
    b.mov_w(1, FS_ITEM_END0)
    b.bl(pm.F_SET_CURSOR)
    b.label('fee_done')
    b.ldp_post(19, 30, 0x10)
    b.ret()
    # fs_end_ok(context): the chosen row (item computed as in the bank sub-page's ok): 0 set the end point to the
    # current focus position, 1 clear it.  The transition then goes back to the focus shift page, which redraws.
    b.label('fs_end_ok')
    b.stp_pre(19, 30, -0x10)
    b.ldr_x(9, 0)
    b.mov_w(8, 0x2C)
    b.ldr_x(10, 9, 0x50)
    b.ldrh_w(11, 9, 0x58)
    b.ldrh_w(9, 9, 0x32)
    b.ldr_x(10, 10, 0x10)
    b.add_x(9, 9, 11)
    b.madd_x(8, 9, 8, 10)
    b.ldr_w(8, 8, 0x18)
    b.mov_w(9, FS_ITEM_END0)
    b.sub_w(8, 8, 9)
    b.mov_w(0, 0)
    b.cbnz_w(8, 'eo_put')                      # Clear end point
    b.bl(F_LENS_POS)
    _r(b, 0x52010000, 'eor w0, w0, #0x80000000')
    b.label('eo_put')
    b.bl('fs_end_put')
    b.ldp_post(19, 30, 0x10)
    b.ret()

    # ---- focus step width slider ------------------------------------------------------------------------------------
    t_dec = len(STATE_TEXT) + 4                    # "%d"
    b.label('sl_native')
    b.raw(SL_ARROWS_STOCK)
    b.b(SL_ARROWS + 4)
    # sl_wrap(state): the stock arrow update, then the scale line
    b.label('sl_wrap')
    b.stp_pre(19, 30, -0x10)
    b.mov_x(19, 0)
    b.bl('sl_native')
    b.mov_x(0, 19)
    b.bl('sl_text')
    b.ldp_post(19, 30, 0x10)
    b.ret()
    # sl_text(state): "1" + n1 spaces + N + n2 spaces + "10" into the "1" label (buffer: sp+0x20, 48 bytes; N at sp+0x10)
    b.label('sl_text')
    b.stp_pre(19, 30, -0x60)
    b.stp(20, 21, 0x50)
    b.mov_x(21, 0)
    b.add_xi(1, 0, 0x18)
    b.mov_w(0, SL_ELEM_ONE)
    b.bl(F_ELEMENT)
    b.mov_x(19, 0)
    b.cbz_x(19, 'sl_done')                     # page not built: nothing to write
    b.bl('fs_target_get')
    b.cbz_w(0, 'sl_stock')
    b.mov_x64(8, SL_VALUE)
    _r(b, 0x79C00100, 'ldrsh w0, [x8]')
    b.bl('fs_est')
    b.cmp_wi(0, 0)
    b.b_cond('le', 'sl_dash')
    b.mov_wr(2, 0)
    _adr_text(b, 1, len(STATE_TEXT) + 3)       # "~%d"
    b.b('sl_fmt')
    b.label('sl_stock')
    _get(b, ID_FS_SHOTS)
    b.mov_wr(2, 0)
    _adr_text(b, 1, t_dec)                     # "%d"
    b.label('sl_fmt')
    b.add_xi(0, 31, 0x10)
    b.bl(F_SPRINTF)
    b.b('sl_build')
    b.label('sl_dash')
    _adr_text(b, 9, len(STATE_TEXT) + 2)       # "--"
    b.ldrh_w(10, 9)
    b.strh_w(10, 31, 0x10)
    b.strb_w(31, 31, 0x12)
    b.label('sl_build')
    # c = length of N (at most 8 characters are used)
    b.mov_w(20, 0)
    b.label('sl_len')
    b.add_xi(9, 31, 0x10)
    b.ldrb_idx(10, 9, 20)
    b.cbz_w(10, 'sl_lenok')
    _add_wi(b, 20, 20, 1)
    b.cmp_wi(20, 8)
    b.b_cond('lo', 'sl_len')
    b.label('sl_lenok')
    # n1 = 12, or 11 from 4 characters on; n2 = 13 - c, at least 10
    b.mov_w(8, 12)
    b.cmp_wi(20, 4)
    b.b_cond('lo', 'sl_n1')
    b.mov_w(8, 11)
    b.label('sl_n1')
    b.mov_w(9, 13)
    b.sub_w(9, 9, 20)
    b.cmp_wi(9, 10)
    b.b_cond('ge', 'sl_n2')
    b.mov_w(9, 10)
    b.label('sl_n2')
    b.add_xi(10, 31, 0x20)                    # write pointer
    b.mov_w(11, ord('1'))
    b.strb_post(11, 10, 1)
    b.mov_w(11, ord(' '))
    b.label('sl_sp1')
    b.strb_post(11, 10, 1)
    b.subs_wi(8, 8, 1)
    b.b_cond('ne', 'sl_sp1')
    b.add_xi(12, 31, 0x10)
    b.mov_wr(13, 20)
    b.cbz_w(13, 'sl_mid_done')
    b.label('sl_mid')
    b.ldrb_post(14, 12, 1)
    b.strb_post(14, 10, 1)
    b.subs_wi(13, 13, 1)
    b.b_cond('ne', 'sl_mid')
    b.label('sl_mid_done')
    b.label('sl_sp2')
    b.strb_post(11, 10, 1)
    b.subs_wi(9, 9, 1)
    b.b_cond('ne', 'sl_sp2')
    b.mov_w(11, ord('1'))
    b.strb_post(11, 10, 1)
    b.mov_w(11, ord('0'))
    b.strb_post(11, 10, 1)
    b.strb_w(31, 10)
    b.add_xi(0, 31, 0x20)
    b.mov_w(1, SL_SLOT_ONE)
    b.mov_w(2, SL_STYLE)
    b.bl(pm.F_SET_TEXT)
    b.mov_x(0, 19)
    b.mov_w(1, SL_SLOT_ONE)
    b.bl(pm.F_SET_CONTENT)
    # the "10" label: the stock entry wrote and showed it; a zero-size box does not clip, so hide the element
    b.add_xi(1, 21, 0x18)
    b.mov_w(0, SL_ELEM_TEN)
    b.bl(F_ELEMENT)
    b.cbz_x(0, 'sl_done')
    b.mov_w(1, 0)
    b.bl(F_VISIBLE)
    b.label('sl_done')
    b.ldp(20, 21, 0x50)
    b.ldp_post(19, 30, 0x60)
    b.ret()


FS_EXP_TABLE = tuple(round(65536 * 2 ** (i / 32)) for i in range(33))   # 2^(i/32) in Q16
FS_DIST_SCALE = round(100 * 2 ** (-20 / 3) * 65536)                    # 64508: centimetres, Q16
FS_DIST_TEXT = (b'--', b'~%d.%02d m', b'~%d.%d m', b'~%d m')


def lens_code(cs, at, main):
    """Second code block (GUI area, executable): the Focus end point sub-page's OK action, the focus shift page's value
    refresh wrapper (end point and current focus distances) and the metre text.  `main` = labels of the main code
    block (absolute addresses)."""
    b = Block(at)
    # fs_end_ok2(context): the c3 action (set / clear), then remember the lens distance of the new end point
    b.label('fs_end_ok2')
    b.stp_pre(19, 30, -0x10)
    b.bl(main['fs_end_ok'])
    b.bl(main['fs_end_get'])
    b.mov_w(19, 0)
    b.cbz_w(0, 'ok2_put')                     # cleared: distance unknown
    b.mov_w(0, P_DISTANCE)
    b.bl(F_LENS_PARAM)
    b.mov_wr(19, 0)
    b.label('ok2_put')
    b.mov_x64(9, FS_DIST_RAM)
    b.strh_w(19, 9)
    b.ldp_post(19, 30, 0x10)
    b.ret()
    # fs_dist_text(w0 = raw distance, x1 = buffer): "~0.35 m", "~1.58 m", "~17.4 m", "~120 m".
    # metres = 2^((raw - 20480) / 3072) = 2^(u / 2048) * 2^(-20/3) with u = 2 * raw / 3
    b.label('fs_dist_text')
    b.stp_pre(19, 30, -0x10)
    b.mov_x(19, 1)
    b.add_w(9, 0, 0)
    b.mov_w(10, 3)
    _r(b, 0x1ACA0929, 'udiv w9, w9, w10')       # u
    _r(b, 0x1200292A, 'and w10, w9, #0x7ff')    # f = u & 2047
    _r(b, 0x530B7D29, 'lsr w9, w9, #11')        # e = u >> 11
    _r(b, 0x53067D4B, 'lsr w11, w10, #6')       # table index
    _r(b, 0x1200154C, 'and w12, w10, #0x3f')    # interpolation weight /64
    b.adr(13, 'exp')
    _r(b, 0xB86B59AE, 'ldr w14, [x13, w11, uxtw #2]')
    _add_wi(b, 11, 11, 1)
    _r(b, 0xB86B59AF, 'ldr w15, [x13, w11, uxtw #2]')
    b.sub_w(15, 15, 14)
    _r(b, 0x1B0C7DEF, 'mul w15, w15, w12')
    _r(b, 0x0B4F19CE, 'add w14, w14, w15, lsr #6')   # m = 2^(f/2048) in Q16
    b.mov_w(15, FS_DIST_SCALE)
    _r(b, 0x9BAF7DCE, 'umull x14, w14, w15')
    _r(b, 0x9AC921CE, 'lsl x14, x14, x9')
    _r(b, 0xD2B0000F, 'mov x15, #0x80000000')
    _r(b, 0x8B0F01CE, 'add x14, x14, x15')
    _r(b, 0xD360FDCE, 'lsr x14, x14, #32')       # centimetres = round(m * 2^e * 100 * 2^(-20/3) / 2^16)
    b.mov_w(8, 100)
    b.cmp_wi(14, 1000)
    b.b_cond('hs', 'dt_dm')
    _r(b, 0x1AC809C2, 'udiv w2, w14, w8')
    _r(b, 0x1B08B843, 'msub w3, w2, w8, w14')
    b.adr(1, 'fmt_cm')
    b.b('dt_print')
    b.label('dt_dm')
    _add_wi(b, 14, 14, 5)
    b.mov_w(8, 10)
    _r(b, 0x1AC809CE, 'udiv w14, w14, w8')       # decimetres
    b.cmp_wi(14, 1000)
    b.b_cond('hs', 'dt_m')
    _r(b, 0x1AC809C2, 'udiv w2, w14, w8')
    _r(b, 0x1B08B843, 'msub w3, w2, w8, w14')
    b.adr(1, 'fmt_dm')
    b.b('dt_print')
    b.label('dt_m')
    _add_wi(b, 14, 14, 5)
    _r(b, 0x1AC809C2, 'udiv w2, w14, w8')
    b.adr(1, 'fmt_m')
    b.label('dt_print')
    b.mov_x(0, 19)
    b.bl(F_SPRINTF)
    b.ldp_post(19, 30, 0x10)
    b.ret()
    # fs_page_refresh(state): value refresh of the focus shift page (callback slot 4): the c3 wrapper (stock refresh,
    # OFF / SET, the estimate), then (c7) the end point's distance in place of SET when it is known, and the current
    # focus distance on the Current focus row (item 0x2C4F, text slot 9).  Text buffer at sp+0x20.
    b.label('fs_page_refresh')
    b.stp_pre(19, 30, -0x60)
    b.str_x(20, 31, 0x10)
    b.mov_x(19, 0)
    b.bl(main['fs_refresh'])
    b.mov_x(20, 0)
    b.cbz_x(19, 'pr_done')
    b.bl(main['fs_end_get'])
    b.cbz_w(0, 'pr_now')
    b.mov_x64(9, FS_DIST_RAM)
    b.ldrh_w(0, 9)
    b.cbz_w(0, 'pr_now')                      # end point without a known distance: SET stays
    b.add_xi(1, 31, 0x20)
    b.bl('fs_dist_text')
    b.add_xi(0, 31, 0x20)
    b.mov_w(1, FS_ITEM_SET)
    b.mov_x(2, 19)
    b.mov_w(3, FS_SLOT_SET)
    b.bl(main['fs_row_text'])
    b.label('pr_now')
    b.mov_w(0, P_DISTANCE)
    b.bl(F_LENS_PARAM)
    b.cbz_w(0, 'pr_dash')
    b.add_xi(1, 31, 0x20)
    b.bl('fs_dist_text')
    b.add_xi(0, 31, 0x20)
    b.b('pr_show')
    b.label('pr_dash')
    b.adr(0, 'txt_dash')
    b.label('pr_show')
    b.mov_w(1, FS_ITEM_CURRENT)
    b.mov_x(2, 19)
    b.mov_w(3, FS_SLOT_CURRENT)
    b.bl(main['fs_row_text'])
    b.label('pr_done')
    b.mov_x(0, 20)
    b.ldr_x(20, 31, 0x10)
    b.ldp_post(19, 30, 0x60)
    b.ret()
    # fs_im_arm (c8): replaces "mov w0, #0xB1" of the i-menu handler (x30 is saved by the handler); arm the start
    # unless a series is running (the menu then opens the stock "Off" page), then the stock path with w0 = 0xB1
    b.label('fs_im_arm')
    b.bl(F_FS_BUSY)
    b.tbz_w(0, 0, 'ia_arm')
    b.b('ia_open')
    b.label('ia_arm')
    b.mov_x64(9, FS_ARM_RAM)
    b.mov_w(10, 1)
    b.strb_w(10, 9)
    b.label('ia_open')
    b.mov_w(0, 0xB1)
    b.b(IM_RESUME)
    # fs_menu_open (c8): the photo shooting menu row's open action: disarm, then the stock action (x0 kept)
    b.label('fs_menu_open')
    b.mov_x64(9, FS_ARM_RAM)
    b.strb_w(31, 9)
    b.b(F_FS_OPEN)
    # mn_tick (c8): the menu app's event-0xA case (0x40508260, entered by the switch in 0x40508038 with its frame set
    # up; it runs once when the menu has opened).  If armed: disarm; if the menu is on the focus shift page, run the
    # stock Start action there (GUI task, after the page is shown, as an OK press on Start does); then the stock case.
    b.label('mn_tick')
    b.mov_x64(9, FS_ARM_RAM)
    b.ldrb_w(10, 9)
    b.cbz_w(10, 'mn_stock')
    b.strb_w(31, 9)                            # one use
    b.bl(MENU_TOP)
    b.cbz_x(0, 'mn_stock')
    b.ldrh_w(8, 0, 2)
    b.cmp_wi(8, 0xB1)
    b.b_cond('ne', 'mn_stock')
    b.bl(F_FS_START)                           # stock Start: waits for the series, then closes the menu / result
    b.label('mn_stock')
    b.b(MENU_EV_TICK_STOCK)
    # ---- data (read-only) ---------------------------------------------------------------------------------------
    code_len = len(b.items) * 4
    data = b''.join(struct.pack('<I', v) for v in FS_EXP_TABLE)
    labels = {'exp': 0}
    for name, text in zip(('txt_dash', 'fmt_cm', 'fmt_dm', 'fmt_m'), FS_DIST_TEXT):
        labels[name] = len(data)
        data += text.ljust(16, b'\0')
    for name, off in labels.items():
        b.labels[name] = at + code_len + off
    listing = b.listing(cs)
    for index, text in getattr(b, 'expect', {}).items():
        got = _norm(listing[index][2])
        if got != _norm(text):
            raise ValueError(f'lens code raw word {index}: {got!r} != {text!r}')
    return b, b.bytes() + data, listing


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
    blk.label('has_any')                      # same, over every entry
    blk.ldr_w(2, 1, 0)
    blk.cbz_w(2, 'hp_no')
    blk.b('hp_scan')
    blk.label('has_prev')
    blk.ldr_w(2, 1, 0)                        # entry count
    blk.cbz_w(2, 'hp_no')
    blk.subs_wi(2, 2, 1)
    blk.cbz_w(2, 'hp_no')
    blk.label('hp_scan')
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
    # ---- post_wrap(transaction x0): the stock change notice, twice when the link switched both bank types ------------
    blk.label('post_native')
    blk.raw(POST_COMMIT_STOCK)
    blk.b(POST_COMMIT + 4)
    blk.label('post_wrap')
    blk.stp_pre(19, 30, -0x20)
    blk.str_x(20, 31, 0x10)
    blk.mov_x(19, 0)
    blk.bl('post_native')                     # stock: announces the bank type that switched last
    _switch_byte(blk, 8)
    blk.tbz_w(8, 1, 'pw_done')                # link off: stock behaviour only
    blk.mov_w(8, TXN_MARK)
    blk.raw(0x38686A68)                       # ldrb w8,[x19,x8]
    blk.cbz_w(8, 'pw_done')                   # no bank switched in this transaction
    blk.ldr_w(20, 19, TXN_MARK_TYPE)
    blk.cmp_wi(20, 0)
    blk.b_cond('eq', 'pw_both')
    blk.cmp_wi(20, 2)
    blk.b_cond('ne', 'pw_done')               # extended-banks toggle: not a linked switch
    blk.label('pw_both')
    _load_id(blk, 0, ID_BANK)
    blk.mov_x(1, 19)
    blk.bl('has_any')
    blk.cbz_w(0, 'pw_done')
    _load_id(blk, 0, ID_CUSTOM)
    blk.mov_x(1, 19)
    blk.bl('has_any')
    blk.cbz_w(0, 'pw_done')                   # only one bank type switched
    blk.mov_w(8, 2)
    blk.sub_w(8, 8, 20)                       # the other bank type: 0 <-> 2
    blk.str_w(8, 19, TXN_MARK_TYPE)
    blk.mov_x(0, 19)
    blk.bl('post_native')
    blk.str_w(20, 19, TXN_MARK_TYPE)          # leave the transaction as the stock code left it
    blk.label('pw_done')
    blk.ldr_x(20, 31, 0x10)
    blk.ldp_post(19, 30, 0x20)
    blk.ret()
    # ---- bkt_wrap(button, pressed, a, b): bracketing on while the Bracketing burst button is held --------------------
    blk.label('bkt_native')
    blk.raw(BKT_HANDLER_STOCK)
    blk.b(BKT_HANDLER + 4)
    blk.label('bkt_wrap')
    blk.stp_pre(19, 30, -0x40)
    blk.stp(20, 21, 0x10)
    blk.stp(22, 23, 0x20)
    blk.str_x(24, 31, 0x30)
    blk.mov_wr(19, 0)
    blk.mov_wr(20, 1)
    blk.mov_wr(21, 2)
    blk.mov_wr(22, 3)
    blk.mov_x64(24, BKT_FLAG_RAM)
    blk.tbz_w(20, 0, 'bw_call')               # release: stock first
    blk.ldrb_w(8, 24)
    blk.cbnz_w(8, 'bw_call')                  # already switched on by us
    _get(blk, ID_BKT_SHOTS)
    blk.cbnz_w(0, 'bw_call')                  # bracketing is on: stock behaviour
    _get(blk, ID_BKT_DIR)
    _and7(blk, 0, 0)
    blk.raw(0x32190000)                       # orr w0,w0,#0x80
    blk.strb_w(0, 24)
    _load_id(blk, 0, ID_BKT_DIR)
    blk.mov_w(1, BKT_DIR_SYMMETRIC)
    blk.bl(SET_ITEM)
    _load_id(blk, 0, ID_BKT_SHOTS)
    blk.mov_w(1, BKT_FRAMES)
    blk.bl(SET_ITEM)
    blk.label('bw_call')
    blk.mov_wr(0, 19)
    blk.mov_wr(1, 20)
    blk.mov_wr(2, 21)
    blk.mov_wr(3, 22)
    blk.bl('bkt_native')
    blk.mov_wr(23, 0)
    _tbnz(blk, 20, 0, 'bw_done')              # press: done
    blk.ldrb_w(19, 24)
    blk.tbz_w(19, 7, 'bw_done')               # not switched on by us
    blk.strb_w(31, 24)
    _load_id(blk, 0, ID_BKT_SHOTS)
    blk.mov_w(1, 0)
    blk.bl(SET_ITEM)
    _load_id(blk, 0, ID_BKT_DIR)
    _and7(blk, 1, 19)
    blk.bl(SET_ITEM)
    blk.label('bw_done')
    blk.mov_wr(0, 23)
    blk.ldr_x(24, 31, 0x30)
    blk.ldp(22, 23, 0x20)
    blk.ldp(20, 21, 0x10)
    blk.ldp_post(19, 30, 0x40)
    blk.ret()
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
    # ---- refresh(state): stock Setup-menu value refresh, then our row's text -----------------------------------
    blk.label('refresh')
    blk.stp_pre(19, 30, -0x20)
    blk.str_x(20, 31, 0x10)
    blk.mov_x(19, 0)
    blk.bl(F_SETUP_REFRESH)
    blk.mov_x(20, 0)                          # keep the stock return value
    blk.cbz_x(19, 'refresh_done')
    blk.mov_x(0, 19)
    blk.mov_w(1, SETUP_ITEM)
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
    _focus(blk)
    blk.label('texts')
    listing = blk.listing(cs)
    for index, text in getattr(blk, 'expect', {}).items():
        got = _norm(listing[index][2])
        if got != _norm(text):
            raise ValueError(f'raw word {index}: {got!r} != {text!r}')
    data = blk.bytes() + b''.join(t.ljust(TEXT_SLOT_BYTES, b'\0') for t in STATE_TEXT + FS_TEXT)
    return blk, data, listing


def strings(context):
    """English text in every language: the stock string pool has no equivalent wording."""
    ids = context.add('bank-store', [list(ENGLISH) for _ in range(36)])
    fs = context.add('focus-end', [list(FS_ENGLISH) for _ in range(36)])
    return dict(label_id=ids[0], option_ids=ids[1:1 + N_OPTIONS], fs_set_id=fs[0], fs_clear_id=fs[1],
                sl_top_id=fs[2], sl_empty_id=fs[3], fs_end_ids=(fs[4], fs[1]), fs_current_id=fs[5])


def menu(img, ids, blk):
    """Sub-page, stub state and Setup-menu row; the sub-page plumbing follows z8prores.menu.menu, with five options."""
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
    # ---- the row in the Setup menu ---------------------------------------------------------------------------------
    row_at = SETUP_ROWS + 44 * SETUP_ROW
    stock_row = struct.unpack_from('<11I', img.old, row_at)
    nraw = struct.unpack_from('<11I', img.old, VIDEO_NRAW_ROW)
    if stock_row[0] != SETUP_STOCK_LABEL or stock_row[6] != SETUP_ITEM or nraw[6] != 0x3118 or nraw[0] != 0x8A6 or \
            stock_row[7:] != nraw[7:]:
        raise ValueError('stock Setup menu row differs')
    new_row = struct.pack('<11I', ids['label_id'], *nraw[1:6], SETUP_ITEM, *nraw[7:])
    img.put(row_at, new_row, 'Setup menu row 43: "Special shooting" slot -> menu bank behavior row',
            expect=struct.pack('<11I', *stock_row))
    row_table = img.u64(SETUP_EVPTR + 8 * SETUP_ROW) - BASE
    if sum(1 for k in range(SETUP_COUNT) if img.u64(SETUP_EVPTR + 8 * k) - BASE == row_table) != 1:
        raise ValueError('the transition table of the reused Setup row is shared')
    changed = []

    def retarget(e, a, g, t):
        if t == SETUP_STOCK_TARGET:
            changed.append(e)
            return e, a, g, pm.STATE_NEW
        return e, a, g, t
    table43 = pm.events(img, row_table, 59, retarget)
    if changed != [0x286, 0x28B, 0x29F, 0x2AE]:
        raise ValueError(f'unexpected transitions of the reused Setup row: {changed}')
    img.put(row_table, table43, 'transition table of the reused Setup row: enter the new state')
    img.put(SETUP_HIDE_SITE - BASE, struct.pack('<I', 0x14000008),
            'Setup menu entry callback: never hide item 3968 (b 0x40597dac)',
            expect=struct.pack('<I', SETUP_HIDE_STOCK))
    if img.u64(SETUP_CALLBACKS + 32) != F_SETUP_REFRESH:
        raise ValueError('stock Setup menu refresh callback differs')
    img.put(SETUP_CALLBACKS + 32, struct.pack('<Q', blk.labels['refresh']),
            'Setup menu value refresh callback -> wrapper')
    return dict(layout=hex(va(layout_at)), rows=hex(va(rows_at)), tables=hex(va(tables_at)),
                pointers=hex(va(evptr_at)), callbacks=hex(va(callbacks_at)), page=hex(va(page_at)),
                state=hex(pm.state_ram(pm.STATE_NEW)), gui_end=at)


def focus_menu(img, ids, blk, at, cs):
    """Focus shift page (state 0xB1): its two always-hidden rows become "Focus end point" (value: OFF / end point
    distance, opens the sub-page) and "Current focus" (value only), and both move up before "First-frame exposure lock"."""
    rows = [struct.unpack_from('<11I', img.old, FS_ROWS + 44 * k) for k in range(FS_COUNT)]
    if rows[FS_ROW_SHOTS][0] != 0xAB0 or rows[FS_ROW_SHOTS][4:7] != (0x101049, 0xFFFF, FS_ITEM_SHOTS) or \
            rows[FS_ROW_SET][6] != FS_ITEM_SET or rows[FS_ROW_CURRENT][6] != FS_ITEM_CURRENT or \
            rows[FS_ROW_RESET][0] != 0x8AD or rows[9][4:6] != (0x101040, 0xFFFF) or rows[4][6] != 0x2C85:
        raise ValueError('stock focus shift rows differ')
    tail = rows[FS_ROW_SHOTS][7:]
    if rows[FS_ROW_SET][7:] != tail or rows[FS_ROW_CURRENT][7:] != tail:
        raise ValueError('stock focus shift row tails differ')
    new = list(rows)
    new[FS_ROW_SET] = (ids['fs_set_id'], 0xFFFF, 0xFFFF, 0, 0x101049, 0xFFFF, FS_ITEM_SET) + tail
    new[FS_ROW_CURRENT] = (ids['fs_current_id'], 0xFFFF, 0xFFFF, 0, FS_VALUE_ROW, 0xFFFF, FS_ITEM_CURRENT) + tail
    # transitions: the stock "Focus position auto reset" row's table; for the end point row its three OK events open
    # the end point sub-page (state 0xB5) without an action, for the current focus row they stay (0x68C, no action)
    source = img.u64(FS_EVPTR + 8 * FS_ROW_RESET) - BASE
    count = 0
    while img.u64(source + 32 * count) != 0x3BB:
        count += 1
    count += 1
    pointers = [img.u64(FS_EVPTR + 8 * k) for k in range(FS_COUNT)]
    at = (at + 7) & ~7
    for row, target, what in ((FS_ROW_SET, STATE_FS_END, 'OK -> end point sub-page'), (FS_ROW_CURRENT, 0x68C, 'OK stays')):
        hits = []

        def change(e, a, g, t):
            if a == F_FS_TOGGLE:
                hits.append(e)
                return e, 0, g, target
            return e, a, g, t
        table = pm.events(img, source, count, change)
        if hits != [0x286, 0x28B, 0x2AE]:
            raise ValueError(f'unexpected transitions of the stock auto-reset row: {hits}')
        img.put(at, table, f'focus shift page row {row}: transition table ({what})', expect_zero=True)
        pointers[row] = va(at)
        at += len(table)
    img.put(FS_ROWS, b''.join(struct.pack('<11I', *new[k]) for k in FS_ORDER),
            'focus shift page rows: end point and current focus rows shown, moved before First-frame exposure lock',
            expect=b''.join(struct.pack('<11I', *r) for r in rows))
    img.put(FS_EVPTR, struct.pack(f'<{FS_COUNT}Q', *[pointers[k] for k in FS_ORDER]),
            'focus shift page transition pointers (same order as the rows)',
            expect=struct.pack(f'<{FS_COUNT}Q', *[img.u64(FS_EVPTR + 8 * k) for k in range(FS_COUNT)]))
    # cursor navigation table with the end point row added (0x2C4F is listed in the stock table)
    nav = [struct.unpack_from('<IHH', img.old, FS_NAV_TABLE - BASE + 8 * k) for k in range(FS_NAV_COUNT)]
    if [e[0] for e in nav] != [0x2C1E, FS_ITEM_SHOTS, 0x2C52, 0x2C20, 0x2C85, FS_ITEM_CURRENT, 0x2E04, 0x2E29, 0x2C21] or \
            any(e[1:] != (0xFFFF, 1) for e in nav):
        raise ValueError('stock focus shift cursor table differs')
    nav.append((FS_ITEM_SET, 0xFFFF, 1))
    nav_at = at
    img.put(nav_at, b''.join(struct.pack('<IHH', *e) for e in nav), 'focus shift page cursor table (+ end point row)',
            expect_zero=True)
    at += 8 * len(nav)
    if at > FS_GUI_LIMIT:
        raise ValueError('GUI area too small for the focus shift tables')
    if struct.unpack_from('<2I', img.old, 0x405EF4DC - BASE) != (0xF2C00016, 0xF2E00016):
        raise ValueError('stock focus shift cursor table load is not the expected four-instruction constant')
    for site, word in FS_NAV_SITES.items():
        if struct.unpack_from('<I', img.old, site - BASE)[0] != word:
            raise ValueError(f'stock focus shift cursor code differs at {site:#x}')
    nav_va = va(nav_at)
    if nav_va >> 32 or (nav_va >> 16) & 0xFFFF != 0x40A0:
        raise ValueError('cursor table address does not fit the two-instruction load')
    new_words = {0x405EF4D0: 0xD2800016 | (nav_va & 0xFFFF) << 5, 0x405EF4D8: 0xF2A00016 | (nav_va >> 16 & 0xFFFF) << 5,
                 0x405EF4EC: 0x52800001 | len(nav) << 5}
    for site, word in new_words.items():
        img.put(site - BASE, struct.pack('<I', word), f'focus shift cursor code {site:#x}: copied table / 10 entries',
                expect=struct.pack('<I', FS_NAV_SITES[site]))
    for site in FS_HIDE_SITES:
        img.put(site - BASE, struct.pack('<I', FS_SHOW), f'focus shift page entry: show the row instead of hiding it ({site:#x})',
                expect=struct.pack('<I', FS_HIDE_STOCK))
    at = (at + 15) & ~15
    lens, lens_bytes, lens_listing = lens_code(cs, va(at), blk.labels)
    img.put(at, lens_bytes, 'code (GUI area): end point OK + distance, page refresh with distances, metre text, data',
            expect_zero=True)
    lens_at = at
    at += len(lens_bytes)
    sub = end_menu(img, ids, blk, lens, at)
    at = int(sub.pop('gui_end'), 16)
    sub['lens_code'] = dict(at=hex(va(lens_at)), bytes=len(lens_bytes),
                            labels={k: hex(v) for k, v in lens.labels.items()},
                            listing=[dict(va=hex(x), word=w, text=t) for x, w, t in lens_listing])
    if img.u64(FS_CALLBACKS + 32) != F_FS_REFRESH:
        raise ValueError('stock focus shift refresh callback differs')
    img.put(FS_CALLBACKS + 32, struct.pack('<Q', lens.labels['fs_page_refresh']),
            'focus shift page value refresh callback -> wrapper (texts, distances)')
    # c8: i-menu "Focus shift shooting" starts the series; the photo shooting menu row disarms
    for table, first in IM_JUMPS:
        if img.u64(table - BASE + 8 * (IM_CODE - first)) != IM_SITE:
            raise ValueError('stock i-menu handler jump table differs')
    if struct.unpack_from('<2I', img.old, IM_SITE - BASE) != (IM_SITE_STOCK, IM_NEXT_STOCK):
        raise ValueError('stock i-menu focus shift case differs')
    img.put(IM_SITE - BASE, struct.pack('<I', _b_word(IM_SITE, lens.labels['fs_im_arm'])),
            'i-menu handler, focus shift item: branch to fs_im_arm (start the series)', expect=struct.pack('<I', IM_SITE_STOCK))
    mrow = struct.unpack_from('<11I', img.old, menu_rows_photo(img) + 44 * FS_MENU_ROW)
    mtable = img.u64(FS_MENU_EVPTR - BASE + 8 * FS_MENU_ROW)
    if mrow[0] != 0x561 or mrow[6] != FS_MENU_ITEM:
        raise ValueError('stock photo shooting menu focus shift row differs')
    opens = []
    k = 0
    while img.u64(mtable - BASE + 32 * k) != 0x3BB:
        if img.u64(mtable - BASE + 32 * k + 8) == F_FS_OPEN:
            opens.append(img.u64(mtable - BASE + 32 * k))
            img.put(mtable - BASE + 32 * k + 8, struct.pack('<Q', lens.labels['fs_menu_open']),
                    f'photo shooting menu, focus shift row: event {opens[-1]:#x} -> fs_menu_open (disarm)',
                    expect=struct.pack('<Q', F_FS_OPEN))
        k += 1
    if opens != FS_MENU_EVENTS:
        raise ValueError(f'unexpected focus shift open events in the photo shooting menu: {opens}')
    entry = MENU_EVENTS + 8 * MENU_EV_TICK - BASE
    if img.u64(entry) != MENU_EV_TICK_STOCK or struct.unpack_from('<2I', img.old, MENU_EV_TICK_STOCK - BASE) != (0x528004A0, 0xF90007FF) \
            or struct.unpack_from('<I', img.old, 0x4050804C - BASE)[0] != 0x7100581F:
        raise ValueError('stock menu event switch differs')
    img.put(entry, struct.pack('<Q', lens.labels['mn_tick']), 'menu event 0xA case -> i-menu start hook',
            expect=struct.pack('<Q', MENU_EV_TICK_STOCK))
    return dict(row_order=list(FS_ORDER), tables={k: hex(pointers[k]) for k in (FS_ROW_SET, FS_ROW_CURRENT)},
                imenu_start=dict(site=hex(IM_SITE), arm=hex(lens.labels['fs_im_arm']), menu_table=hex(mtable),
                                 menu_action=hex(lens.labels['fs_menu_open']), menu_hook=hex(lens.labels['mn_tick']),
                                 flag=hex(FS_ARM_RAM)),
                cursor_table=hex(nav_va), sub_page=sub, gui_end=hex(at))


def _b_word(at, to):
    off = (to - at) // 4
    if not -(1 << 25) <= off < (1 << 25):
        raise ValueError('branch out of range')
    return 0x14000000 | (off & 0x3FFFFFF)


def menu_rows_photo(img):
    """Row records of the photo shooting menu page (state 0x19): the page record before its transition pointers."""
    page = FS_MENU_PAGE
    if img.u64(page + 0x18) != FS_MENU_EVPTR or struct.unpack_from('<H', img.old, page + 0x20)[0] != 47:
        raise ValueError('stock photo shooting menu page record differs')
    return img.u64(page + 0x10) - BASE


def end_menu(img, ids, blk, lens, at):
    """Focus end point sub-page in state 0xB5, built on the focus shift page's own layout and page record (full-width
    rows, the "Interrupt after start" guide string emptied): "Set end point" / "Clear end point", OK -> fs_end_ok2,
    then back to the focus shift page."""
    layout = bytearray(img.old[FS_LAYOUT:FS_LAYOUT + FS_LAYOUT_BYTES])
    if struct.unpack_from('<I', layout, 0x44)[0] != 0x561 or img.u64(FS_PAGE + 8) != BASE + FS_LAYOUT or \
            img.u64(FS_PAGE + 0x10) != BASE + FS_ROWS or struct.unpack_from('<H', img.old, FS_PAGE + 0x20)[0] != FS_COUNT or \
            FS_LAYOUT + FS_LAYOUT_BYTES != FS_ROWS:
        raise ValueError('stock focus shift page record or layout differs')
    struct.pack_into('<I', layout, 0x44, ids['fs_set_id'])
    guide = [k for k in range(0, len(layout), 4) if struct.unpack_from('<I', layout, k)[0] == FS_GUIDE_STRING]
    if guide != [FS_GUIDE_AT]:
        raise ValueError(f'stock focus shift layout: guide string at {guide}')
    struct.pack_into('<I', layout, FS_GUIDE_AT, ids['sl_empty_id'])
    tail = struct.unpack_from('<11I', img.old, FS_ROWS + 44 * FS_ROW_SHOTS)[7:]
    plain = struct.unpack_from('<11I', img.old, FS_ROWS)[4]
    if plain != 0x101000:
        raise ValueError('stock focus shift row types differ')
    n = 2
    rows = b''.join(struct.pack('<11I', ids['fs_end_ids'][i], 0xFFFF, 0xFFFF, 0, plain, 0xFFFF, FS_ITEM_END0 + i, *tail)
                    for i in range(n))
    ok = lens.labels['fs_end_ok2']
    act = pm.events(img, pm.NRAW_EVENTS, 14, lambda e, a, g, t: (e, ok if a == pm.NRAW_OK else a, g, t))
    if act.count(struct.pack('<QQQ', ok, 0, 0x68D)) != 3:
        raise ValueError('expected three OK transitions (back) in the stock option table')
    at = (at + 15) & ~15
    layout_at = at; at += len(layout)
    rows_at = at; at += len(rows)
    at = (at + 7) & ~7
    act_at = at; at += len(act)
    evptr_at = at; at += n * 8
    callbacks_at = at; at += 5 * 8
    page_at = at; at += 0x50
    if at > FS_GUI_LIMIT:
        raise ValueError('GUI area too small for the end point sub-page')
    page = bytearray(img.old[FS_PAGE:FS_PAGE + 0x50])
    struct.pack_into('<3Q', page, 8, va(layout_at), va(rows_at), va(evptr_at))
    struct.pack_into('<H', page, 0x20, n)
    img.put(layout_at, layout, 'focus end point sub-page layout (focus shift layout, title "Focus end point")',
            expect_zero=True)
    img.put(rows_at, rows, 'focus end point sub-page rows (set, clear)', expect_zero=True)
    img.put(act_at, act, 'focus end point sub-page transition table (OK -> action, back)', expect_zero=True)
    img.put(evptr_at, struct.pack(f'<{n}Q', *[va(act_at)] * n), 'focus end point sub-page transition table pointers',
            expect_zero=True)
    img.put(callbacks_at, struct.pack('<5Q', blk.labels['fs_end_entry'], *pm.NRAW_CALLBACKS[1:]),
            'focus end point sub-page callbacks', expect_zero=True)
    img.put(page_at, page, 'focus end point sub-page page record (focus shift page record, new rows)', expect_zero=True)
    record = pm.STATE_TABLE + pm.STATE_SIZE * STATE_FS_END
    st = struct.unpack_from('<HHI11Q', img.old, record)
    nraw_state = struct.unpack_from('<HHI11Q', img.old, pm.STATE_TABLE + pm.STATE_SIZE * pm.STATE_NRAW)
    if st[:2] != (2, STATE_FS_END) or st[3] != nraw_state[3] or (st[7], st[12]) != STATE_FS_END_STOCK or \
            any(st[4:7] + st[8:12] + st[13:]):
        raise ValueError('stock state 0xB5 record differs')
    img.put(record + 0x28, struct.pack('<Q', va(callbacks_at)), 'state 0xB5: callbacks -> focus end point sub-page',
            expect=struct.pack('<Q', STATE_FS_END_STOCK[0]))
    img.put(record + 0x50, struct.pack('<Q', va(page_at)), 'state 0xB5: page record -> focus end point sub-page',
            expect=struct.pack('<Q', STATE_FS_END_STOCK[1]))
    return dict(page=hex(va(page_at)), callbacks=hex(va(callbacks_at)), table=hex(va(act_at)), rows=n, gui_end=hex(at))


def slider_layout(img, ids):
    """Focus step width slider page: the "1" label spans the scale, the "10" box is shrunk away, "Narrow" becomes the
    combined top line and "Wide" is emptied and shrunk (static layout data of state 0xB3)."""
    if img.u64(0x4C04030) != 0xA028CF4A0 or img.u64(0x4BDA4A8) != BASE + SL_LAYOUT:
        raise ValueError('stock slider page record differs')
    for at, (a, b) in SL_RECTS_STOCK.items():
        if struct.unpack_from('<2I', img.old, at) != (a, b):
            raise ValueError(f'stock slider layout box at {at:#x} differs')
    if img.u32(SL_ONE_RECT + 0x20) != SL_ELEM_ONE or img.u32(SL_TEN_RECT + 0x20) != 0x4DF or \
            img.u32(SL_NARROW_STR) != 0x7AC or img.u32(SL_WIDE_STR) != 0x7AD:
        raise ValueError('stock slider layout elements differ')
    names = {SL_ONE_RECT: '"1" label: box across the scale', SL_TEN_RECT: '"10" label: empty box',
             SL_NARROW_RECT: '"Narrow" label: box across Narrow..Wide', SL_WIDE_RECT: '"Wide" label: empty box'}
    for at, (a, b) in SL_RECTS_NEW.items():
        img.put(at, struct.pack('<2I', a, b), 'focus step width slider: ' + names[at],
                expect=struct.pack('<2I', *SL_RECTS_STOCK[at]))
    img.put(SL_NARROW_STR, struct.pack('<I', ids['sl_top_id']), 'focus step width slider: "Narrow  Est. shots  Wide" line',
            expect=struct.pack('<I', 0x7AC))
    img.put(SL_WIDE_STR, struct.pack('<I', ids['sl_empty_id']), 'focus step width slider: "Wide" label emptied',
            expect=struct.pack('<I', 0x7AD))
    return dict(top_string=ids['sl_top_id'], empty_string=ids['sl_empty_id'])


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
    require(struct.unpack_from('<I', eg, POST_COMMIT - BASE)[0] == POST_COMMIT_STOCK, 'stock change-notice routine differs')
    delta = blk.labels['post_wrap'] - POST_COMMIT
    img.put(POST_COMMIT - BASE, struct.pack('<I', 0x14000000 | ((delta // 4) & 0x3FFFFFF)),
            'change-notice routine entry -> wrapper (second notice for linked switches)',
            expect=struct.pack('<I', POST_COMMIT_STOCK))
    require(struct.unpack_from('<I', eg, BKT_HANDLER - BASE)[0] == BKT_HANDLER_STOCK and
            struct.unpack_from('<2I', eg, 0x40D4D6DC - BASE) == (0x320003E0, 0x94000FBD) and
            struct.unpack_from('<10I', eg, 0x43A1A500 - BASE)[:4] == (0, 0, 303, 3), 'stock bracketing-burst handler differs')
    delta = blk.labels['bkt_wrap'] - BKT_HANDLER
    img.put(BKT_HANDLER - BASE, struct.pack('<I', 0x14000000 | ((delta // 4) & 0x3FFFFFF)),
            'Bracketing burst button handler entry -> wrapper (bracketing on while held)',
            expect=struct.pack('<I', BKT_HANDLER_STOCK))
    # ---- focus shift end point ------------------------------------------------------------------------------------
    require(struct.unpack_from('<2I', eg, 0x405EF0E4 - BASE) == (0x528590C1, 0xAA1303E0) and
            struct.unpack_from('<I', eg, 0x405EF100 - BASE)[0] == 0x528589E1 and
            all(struct.unpack_from('<I', eg, a - BASE)[0] == FS_HIDE_STOCK for a in FS_HIDE_SITES) and
            all(struct.unpack_from('<I', eg, a + 8 - BASE)[0] == 0x97F70B75 - (a - 0x405EF0F4) // 4 for a in FS_HIDE_SITES),
            'stock focus shift page entry callback differs')
    fs_where = focus_menu(img, ids, blk, where.pop('gui_end'), cs)
    require(struct.unpack_from('<I', eg, FS_FRAME_SITE - BASE)[0] == FS_FRAME_STOCK and
            struct.unpack_from('<6I', eg, 0x40FCEA1C - BASE)[:1] == (0xD2900E08,), 'stock focus shift frame code differs')
    require(struct.unpack_from('<I', eg, FS_START_SITE - BASE)[0] == FS_START_STOCK and
            FS_START_SITE + 4 * (FS_START_STOCK & 0x3FFFFFF) == GET_DS and
            struct.unpack_from('<I', eg, 0x40FB3B58 - BASE)[0] == 0x2A1503E0 and
            struct.unpack_from('<I', eg, 0x40FB3B80 - BASE)[0] == 0xB90002E0, 'stock focus shift start code differs')
    for site, stock, label, what in ((FS_FRAME_SITE, FS_FRAME_STOCK, 'fs_remain', 'focus shift: remaining-shots load'),
                                     (FS_START_SITE, FS_START_STOCK, 'fs_shots', 'focus shift start: No. of shots read')):
        delta = blk.labels[label] - site
        img.put(site - BASE, struct.pack('<I', 0x94000000 | ((delta // 4) & 0x3FFFFFF)), f'{what} -> {label}',
                expect=struct.pack('<I', stock))
    require(struct.unpack_from('<I', eg, 0x40FDEF08 - BASE)[0] == 0xD291508A and
            struct.unpack_from('<I', eg, 0x40DAD924 - BASE)[0] == 0x94001BB3 and
            struct.unpack_from('<I', eg, 0x40DAD94C - BASE)[0] == 0x94002759 and
            struct.unpack_from('<I', eg, 0x40FCEAE4 - BASE)[0] == 0x940040E0 and
            struct.unpack_from('<I', eg, 0x40FB4418 - BASE)[0] == 0xB9000109, 'stock focus shift step code differs')
    # ---- forget the end point when the camera goes to standby -----------------------------------------------------
    require(struct.unpack_from('<I', eg, WAKE_SITE - BASE)[0] == WAKE_STOCK and
            WAKE_SITE + 4 * (WAKE_STOCK & 0x3FFFFFF) == F_MODE_REQUEST and
            struct.unpack_from('<3I', eg, WAKE_SITE - 12 - BASE) == (0x321E07E0, 0x321F03E1, 0xAA1F03E2) and
            struct.unpack_from('<I', eg, F_MODE_REQUEST - BASE)[0] == 0xD10183FF, 'stock standby (mode 0xC) request differs')
    delta = blk.labels['fs_wake'] - WAKE_SITE
    img.put(WAKE_SITE - BASE, struct.pack('<I', 0x94000000 | ((delta // 4) & 0x3FFFFFF)),
            'standby (mode 0xC request) -> forget the focus end point first', expect=struct.pack('<I', WAKE_STOCK))
    # ---- focus step width slider: estimate on the slider page ------------------------------------------------------
    require(struct.unpack_from('<2I', eg, SL_ARROWS - BASE) == (SL_ARROWS_STOCK, 0xA9017BF3) and
            sorted(a for a, k in [(0x405F6A1C, 'bl'), (0x405F6BE4, 'bl'), (0x405F6D7C, 'bl')]
                   if struct.unpack_from('<I', eg, a - BASE)[0] == 0x94000000 | (((SL_ARROWS - a) // 4) & 0x3FFFFFF)) ==
            [0x405F6A1C, 0x405F6BE4, 0x405F6D7C], 'stock slider arrow routine differs')
    require(struct.unpack_from('<4I', eg, 0x405F68BC - BASE)[:2] == (0xD29FF000, 0xF2A89740) and
            struct.unpack_from('<I', eg, 0x405F68CC - BASE)[0] == 0x52800AA2, 'stock slider "1" label code differs')
    sl_where = slider_layout(img, ids)
    delta = blk.labels['sl_wrap'] - SL_ARROWS
    img.put(SL_ARROWS - BASE, struct.pack('<I', 0x14000000 | ((delta // 4) & 0x3FFFFFF)),
            'focus step width slider: arrow update entry -> wrapper (estimate line)', expect=struct.pack('<I', SL_ARROWS_STOCK))
    return img, dict(strings=ids, menu=where, slider=dict(sl_where, wrapper=hex(blk.labels['sl_wrap']),
                                                          text=hex(blk.labels['sl_text'])),
                     focus_end=dict(fs_where, end_bytes=[hex(FS_END0 + REL_SLOT_STEP * k) for k in range(4)],
                                                     frame_site=hex(FS_FRAME_SITE), start_site=hex(FS_START_SITE),
                                                     remain=hex(blk.labels['fs_remain']), shots=hex(blk.labels['fs_shots']),
                                                     pps=hex(blk.labels['fs_pps']), estimate=hex(blk.labels['fs_est'])),
                     hook=dict(site=hex(COPY_API), gate=hex(blk.labels['gate']), native=hex(blk.labels['native']),
                               save=hex(blk.labels['save'])),
                     link=dict(menu_site=hex(DISPATCH_MENU_SITE), custom_site=hex(DISPATCH_CUSTOM_SITE),
                               hook_menu=hex(blk.labels['hook_menu']), hook_custom=hex(blk.labels['hook_custom']),
                               has_prev=hex(blk.labels['has_prev']), sync=hex(blk.labels['link_sync']),
                               notice_wrapper=hex(blk.labels['post_wrap'])),
                     switch=dict(ram=hex(SWITCH_RAM), carrier_item='0x1238', default=0, scratch=hex(SCRATCH_RAM),
                                 bits='bit0 keep stored settings, bit1 link banks'),
                     code=[dict(va=hex(x), word=w, text=t) for x, w, t in listing],
                     bracketing_burst=dict(wrapper=hex(blk.labels['bkt_wrap']), flag_ram=hex(BKT_FLAG_RAM),
                                           frames=BKT_FRAMES),
                     release=dict(mode_item=hex(ID_REL_MODE), sub_item=hex(ID_REL_SUB), dispatcher=hex(DISPATCHER),
                                  menu_switch=hex(blk.labels['menu_switch']), store=hex(blk.labels['rel_store']),
                                  load=hex(blk.labels['rel_load']),
                                  slots=[hex(SWITCH_RAM + REL_SLOT_STEP * k) for k in (1, 2, 3, 4)]))
