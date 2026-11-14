/* Test image for the bank-mode hooks: the stock routines are replaced by stubs placed at their real 3.11 addresses. */
ENTRY(_start)
/* Separate load segments below and above the patch code page (0x40A00000), which the test loads itself. */
PHDRS { low PT_LOAD; menu PT_LOAD; high PT_LOAD; }
SECTIONS {
  . = 0x40000000;
  .text   : { *(.text.start) *(.text*) } :low
  .rodata : { *(.rodata*) }
  . = 0x40100000;
  .data   : { *(.data*) }
  .bss    : { *(.bss*) *(COMMON) }
  .s_rowobj      0x40399EF0 : { *(.s_rowobj) } :menu
  .s_element     0x4039E810 : { *(.s_element) }
  .s_guard       0x403AE0F8 : { *(.s_guard) }
  .s_rowindex    0x403AF870 : { *(.s_rowindex) }
  .s_cursor      0x403B0048 : { *(.s_cursor) }
  .s_redraw      0x403B26C0 : { *(.s_redraw) }
  .s_settext     0x403F2920 : { *(.s_settext) }
  .s_visible     0x403F621C : { *(.s_visible) }
  .s_setcontent  0x403F645C : { *(.s_setcontent) }
  .s_fsrefresh   0x405EF210 : { *(.s_fsrefresh) }
  .s_arrows      0x405F6A64 : { *(.s_arrows) }
  .s_rescale     0x40C78518 : { *(.s_rescale) } :high
  .s_ratio       0x40C790DC : { *(.s_ratio) }
  .s_bkt         0x40D4D680 : { *(.s_bkt) }
  .s_lenspos     0x40DB3F90 : { *(.s_lenspos) }
  .s_lensk       0x40DB47F0 : { *(.s_lensk) }
  .s_def2pulse   0x40DB76B0 : { *(.s_def2pulse) }
  .s_prop        0x40EC4544 : { *(.s_prop) }
  .s_mode        0x40FBC66C : { *(.s_mode) }
  .s_getds       0x41012C84 : { *(.s_getds) }
  .s_copyentry   0x41013A14 : { *(.s_copyentry) *(.s_copybody) }
  .s_setitem     0x410D61D0 : { *(.s_setitem) }
  .s_post        0x410DC874 : { *(.s_post) }
  .s_smenu       0x410DD1EC : { *(.s_smenu) }
  .s_scustom     0x410DE050 : { *(.s_scustom) }
  .s_txnset      0x410E9318 : { *(.s_txnset) }
  .s_thunk_menu  0x410E958C : { *(.s_thunk_menu) }
  .s_thunk_custom 0x410E9934 : { *(.s_thunk_custom) }
  .s_disp        0x410EA70C : { *(.s_disp) }
  .s_sprintf     0x4127D850 : { *(.s_sprintf) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
