#include "include/plic.h"
#include "include/log.h"
#include "include/platform.h"
#include "include/riscv.h"
#include "include/virtio.h"

/*
 * 参考自
 * https://github.com/plctlab/riscv-operating-system-mooc/blob/main/code/os/11-syscall/plic.c
 * */

static inline uint32_t CPU_TO_SHART(uint32_t cpu) {
    return 2 * cpu + 1;
}

static inline uint32_t CPU_TO_MHART(uint32_t cpu) {
    return 2 * cpu;
}

void plic_init() {

#define HART_ID r_tp();

    uint32_t hart = HART_ID;
    Info("%lx", hart);

    // 开启uart中断和virtio-blk设备中断
    Error("CPU_TO_HART %d %d", CPU_TO_SHART(hart), hart);
    *((volatile uint32_t *)PLIC_INTERRUPT_ENABLE(CPU_TO_SHART(hart))) =
        1 << UART0_IRQ | 1 << VIRTIO_IRQ;
    //    // 1=3
    //    // 2=5
    //    // 3=7

    // 设置uart的优先级
    *((volatile uint32_t *)PLIC_PRIORITY(VIRTIO_IRQ)) = 2;
    *((volatile uint32_t *)PLIC_PRIORITY(UART0_IRQ)) = 1;

    // 设置阈值
    *((volatile uint32_t *)PLIC_THRESHOLD(CPU_TO_SHART(hart))) = 0;
}

uint32_t plic_cliam() {
    uint32_t hart = HART_ID;
    return *(uint32_t *)PLIC_CLAIM(CPU_TO_SHART(hart));
}

void plic_complete(uint32_t irq) {
    uint32_t hart = HART_ID;
    *((volatile uint32_t *)PLIC_COMPLETE(CPU_TO_SHART(hart))) = irq;
}
