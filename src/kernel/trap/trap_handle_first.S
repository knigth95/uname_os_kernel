.altmacro
.macro SAVE_GP n
    sd x\n, \n*8(sp)
.endm

.macro LOAD_GP n
    ld x\n, \n*8(sp)
.endm

    .section .text.tramponline
    .global _alltrap
    .global _trap_restore
    .align 2
_alltrap:
    csrrw sp, sscratch, sp
    addi sp, sp, -37*8

    sd x0, 0*8(sp)
    sd x1, 1*8(sp)
    sd x3, 3*8(sp)

    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr

    csrr t0, sstatus
    csrr t1, sepc
    csrr t2, sscratch
    csrr t3, satp
    csrr t4, stvec

    sd sp, 2*8(sp)

    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    sd t2, 34*8(sp)
    sd t3, 35*8(sp)
    sd t4, 36*8(sp)

    csrw satp ,0
    jal all_handler 

_trap_restore:
    csrr t0, satp
    beq a0, t0, .else
    csrw satp, a0
    sfence.vma
.else:

    mv sp, a1
    
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    ld t2, 34*8(sp)

    ld t4, 36*8(sp)

    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    csrw stvec , t4

    ld x1, 1*8(sp)
    ld x3, 3*8(sp)

    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    
    addi sp, sp, 37*8
    
    csrrw sp, sscratch, sp
    sret


