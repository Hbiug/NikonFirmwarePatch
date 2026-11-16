/* Interval timer harness: stock routines the tested firmware code calls are stubs at their real 3.11 addresses. */
ENTRY(_start)
PHDRS { low PT_LOAD; p_s_nop3 PT_LOAD; p_s_state PT_LOAD; p_s_msg PT_LOAD; p_s_nop4 PT_LOAD; p_s_nop2 PT_LOAD; p_s_setitems PT_LOAD; p_s_nop1 PT_LOAD; p_s_now PT_LOAD; p_s_busy PT_LOAD; p_s_readyw PT_LOAD; }
SECTIONS {
  . = 0x40000000;
  .text   : { *(.text.start) *(.text*) } :low
  .rodata : { *(.rodata*) }
  . = 0x40100000;
  .data   : { *(.data*) }
  .bss    : { *(.bss*) *(COMMON) }
  .s_nop3     0x4038B3D4 : { *(.s_nop3) } :p_s_nop3
  .s_state    0x403AF53C : { *(.s_state) } :p_s_state
  .s_msg      0x403D3938 : { *(.s_msg) } :p_s_msg
  .s_nop4     0x403D4AD4 : { *(.s_nop4) } :p_s_nop4
  .s_nop2     0x403DB984 : { *(.s_nop2) } :p_s_nop2
  .s_setitems 0x403EC3C8 : { *(.s_setitems) } :p_s_setitems
  .s_nop1     0x403EFED8 : { *(.s_nop1) } :p_s_nop1
  .s_now      0x40FB30CC : { *(.s_now) } :p_s_now
  .s_busy     0x40FB33B4 : { *(.s_busy) } :p_s_busy
  .s_readyw   0x40FD9D3C : { *(.s_readyw) } :p_s_readyw
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
