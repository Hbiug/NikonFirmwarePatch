/* Test image for the bank-mode hooks: the stock routines are replaced by stubs placed at their real 3.11 addresses. */
ENTRY(_start)
SECTIONS {
  . = 0x40000000;
  .text   : { *(.text.start) *(.text*) }
  .rodata : { *(.rodata*) }
  . = 0x40100000;
  .data   : { *(.data*) }
  .bss    : { *(.bss*) *(COMMON) }
  .s_bkt         0x40D4D680 : { *(.s_bkt) }
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
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
