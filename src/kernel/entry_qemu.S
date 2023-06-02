    .section .text.entry
    .global _entry 
_entry:
    
    add t0,t0,1
    slli t0,t0,14

    la sp, boot_stack
    add sp,sp,t0

    call kernel_start 

loop:
    j loop

    .section .bss.stack
    .align 12
    .global boot_stack
boot_stack:
    .space 4096*32
    .global boot_stack_top
boot_stack_top:
