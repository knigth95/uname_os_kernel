#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#define MAX_CPU 2

/*
 * memorymap
 * see https://github.com/qemu/qemu/blob/master/hw/riscv/virt.c, virt_memmap[]
 * 0x00001000 -- boot rom, provided by qemu
 * 0x02000000 -- clint
 * 0x0c000000 -- plic
 * 0x10000000 -- uart0
 * 0x10001000 -- virtio disk
 * 0x80000000 -- boot rom jumps here in machine mode, where we load our kernel
 */

/* this machine puts uart registers here in physical memory. */
#define UART0_ADDRESS 0x10000000l
#define UART0_SIZE 0x100

/*
 * uart0 interrupt source
 * see https://github.com/qemu/qemu/blob/master/include/hw/riscv/virt.h
 * enum {
 *     uart0_irq = 10,
 *     ......
 * };
 */
#define UART0_IRQ 0x0a

#define VIRTIO_IRQ 1 /* 1 to 8 */
#define VIRTIO_COUNT 8

/*
 * This machine puts platform-level interrupt controller (PLIC) here.
 * Here only list PLIC registers in Machine mode.
 * see https://github.com/qemu/qemu/blob/master/include/hw/riscv/virt.h
 * #define VIRT_PLIC_HART_CONFIG "MS"
 * #define VIRT_PLIC_NUM_SOURCES 127
 * #define VIRT_PLIC_NUM_PRIORITIES 7
 * #define VIRT_PLIC_PRIORITY_BASE 0x04
 * #define VIRT_PLIC_PENDING_BASE 0x1000
 * #define VIRT_PLIC_ENABLE_BASE 0x2000
 * #define VIRT_PLIC_ENABLE_STRIDE 0x80
 * #define VIRT_PLIC_CONTEXT_BASE 0x200000
 * #define VIRT_PLIC_CONTEXT_STRIDE 0x1000
 * #define VIRT_PLIC_SIZE(__num_context) \
 *     (VIRT_PLIC_CONTEXT_BASE + (__num_context) * VIRT_PLIC_CONTEXT_STRIDE)
 */

#define VIRT_PLIC_PRIORITY_BASE 0x00
#define VIRT_PLIC_PENDING_BASE 0x1000
#define VIRT_PLIC_ENABLE_BASE 0x2000
#define VIRT_PLIC_ENABLE_STRIDE 0x80
#define VIRT_PLIC_CONTEXT_BASE 0x200000
#define VIRT_PLIC_CONTEXT_STRIDE 0x1000

#define VIRT_PLIC_SIZE(__num_context)                                          \
  (VIRT_PLIC_CONTEXT_BASE + (__num_context)*VIRT_PLIC_CONTEXT_STRIDE)

#define PLIC_BASE_ADDRESS 0x0c000000L
#define PLIC_REG_MEMSIZE VIRT_PLIC_SIZE(MAX_CPU * 2)

// context指的是每个hart的每个特权级都算一个context
// 因此M模式都是奇数个，S模式都是偶数个
#define PLIC_PRIORITY(id) (PLIC_BASE_ADDRESS + (id)*4)

#define PLIC_PENDING(id) (PLIC_BASE_ADDRESS + 0x1000 + ((id / 32) * 4))

// #define PLIC_INTERRUPT_ENABLE(hart) (PLIC_BASE_ADDRESS + 0x2080 +
// (hart)*0x100)
#define PLIC_INTERRUPT_ENABLE(hart) (PLIC_BASE_ADDRESS + 0x2000 + (hart)*0x80)

// #define PLIC_CLAIM(hart) (PLIC_BASE_ADDRESS + 0x201004 + (hart)*0x2000)
#define PLIC_CLAIM(hart) (PLIC_BASE_ADDRESS + 0x200004 + (hart)*0x1000)

#define PLIC_COMPLETE(hart) (PLIC_BASE_ADDRESS + 0x200004 + (hart)*0x1000)

// #define PLIC_THRESHOLD(hart) (PLIC_BASE_ADDRESS + 0x201000 + (hart)*0x2000)
#define PLIC_THRESHOLD(hart) (PLIC_BASE_ADDRESS + 0x200000 + (hart)*0x1000)

/*
 * The Core Local INTerruptor (CLINT) block holds memory-mapped control and
 * status registers associated with software and timer interrupts.
 * QEMU-virt reuses sifive configuration for CLINT.
 * see https://gitee.com/qemu/qemu/blob/master/include/hw/riscv/sifive_clint.h
 * enum {
 * 	SIFIVE_SIP_BASE     = 0x0,
 * 	SIFIVE_TIMECMP_BASE = 0x4000,
 * 	SIFIVE_TIME_BASE    = 0xBFF8
 * };
 *
 * enum {
 * 	SIFIVE_CLINT_TIMEBASE_FREQ = 10000000
 * };
 *
 * Notice:
 * The machine-level MSIP bit of mip register are written by accesses to
 * memory-mapped control registers, which are used by remote harts to provide
 * machine-mode interprocessor interrupts.
 * For QEMU-virt machine, Each msip register is a 32-bit wide WARL register
 * where the upper 31 bits are tied to 0. The least significant bit is
 * reflected in the MSIP bit of the mip CSR. We can write msip to generate
 * machine-mode software interrupts. A pending machine-level software
 * interrupt can be cleared by writing 0 to the MSIP bit in mip.
 * On reset, each msip register is cleared to zero.
 */
#define CLINT_BASE 0x2000000L
#define CLINT_REG_SIZE 0x10000L
#define CLINT_MSIP(hartid) (CLINT_BASE + 4 * (hartid))
#define CLINT_MTIMECMP(hartid) (CLINT_BASE + 0x4000 + 8 * (hartid))
#define CLINT_MTIME (CLINT_BASE + 0xBFF8) // cycles since boot.

/* 10000000 ticks per-second */
#define CLINT_TIMEBASE_FREQ 10000000

#endif
