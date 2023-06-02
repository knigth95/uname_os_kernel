#ifndef __RISCV_H__
#define __RISCV_H__

#include "include/log.h"
#include "type.h"

#define STAP_MODE_SV39 8L

#define IRQ_U_SOFT 0
#define IRQ_S_SOFT 1
#define IRQ_H_SOFT 2
#define IRQ_M_SOFT 3
#define IRQ_U_TIMER 4
#define IRQ_S_TIMER 5
#define IRQ_H_TIMER 6
#define IRQ_M_TIMER 7
#define IRQ_U_EXT 8
#define IRQ_S_EXT 9
#define IRQ_H_EXT 10
#define IRQ_M_EXT 11
#define IRQ_COP 12
#define IRQ_HOST 13
#define APP_SWITCH 24

#define SIP_SSIP (1L << 1)
#define SIP_STIP (1L << 5)
#define SIP_SEIP (1L << 9)
#define SIE_SSIE (1L << 1)
#define SIE_STIE (1L << 5)
#define SIE_SEIE (1L << 9)

#define sie_ssie_enable                                                        \
  (write_csr(sie, read_csr(sie) | SIE_SSIE)) // software Interrupt
#define sie_stie_enable                                                        \
  (write_csr(sie, read_csr(sie) | SIE_STIE)) // timer Interrupt
#define sie_seie_enable                                                        \
  (write_csr(sie, read_csr(sie) | SIE_SEIE)) // extern Interrupt

#define SSTATUS_FS 0x00006000
#define SSTATUS_XS 0x00018000
#define SSTATUS_PUM 0x00040000
#define SSTATUS32_SD 0x80000000
#define SSTATUS64_SD 0x8000000000000000

#define SSTATUS_SPP (1L << 8)  // Previous mode, 1=Supervisor, 0=User
#define SSTATUS_SPIE (1L << 5) // Supervisor Previous Interrupt Enable
#define SSTATUS_UPIE (1L << 4) // User Previous Interrupt Enable
#define SSTATUS_SIE (1L << 1)  // Supervisor Interrupt Enable
#define SSTATUS_UIE (1L << 0)  // User Interrupt Enable
#define SSTATUS_SUM (1L << 18) // Smod read umod page

static inline uint64_t r_tp() {
    uint64_t x;
    asm volatile("mv %0, tp" : "=r"(x));
    return x;
}

static inline void w_tp(uint64_t x) {
    asm volatile("mv tp, %0" : : "r"(x));
}
/*
///#define r_tp \
///  ({ \
///    uint32_t _x; \
///    asm volatile("mv %0, tp" : "=r"(_x)); \
///    _x; \
///  })
*/

/* which hart (core) is this? */
#define current_hart_id                                                        \
  ({                                                                           \
    uint32_t x;                                                                \
    asm volatile("csrr %0, shartid" : "=r"(x));                                \
    x;                                                                         \
  })

// 由于操作系统寄存器的csr指令中源操作数仅5位，因此如果操作数小于1<<5时，可以直接使用操作数，否则需要先让编译器分配一个寄存器，存入寄存器，然后再存到系统寄存器中
// builtin_constand_p用于确定在编译时值是否是一个常量
#define write_csr(reg, val)                                                    \
  ({                                                                           \
    if (__builtin_constant_p(val) && (uint64_t)(val) < 32) {                   \
      asm volatile("csrw " #reg ",%0" ::"i"(val));                             \
    } else {                                                                   \
      asm volatile("csrw " #reg ",%0" ::"r"(val));                             \
    }                                                                          \
  })

#define read_csr(reg)                                                          \
  ({                                                                           \
    uint64_t _tmp;                                                             \
    asm volatile("csrr %0, " #reg : "=r"(_tmp));                               \
    _tmp;                                                                      \
  })

#define set_csr(reg, flag)                                                     \
  ({                                                                           \
    uint64_t _tmp;                                                             \
    if (__builtin_constant_p(flag) && (uint64_t)(flag) < 32) {                 \
      asm volatile("csrrs %0, " #reg ", %1" : "=r"(_tmp) : "i"(flag));         \
    } else {                                                                   \
      asm volatile("csrrs %0, " #reg ", %1" : "=r"(_tmp) : "r"(flag));         \
    }                                                                          \
    _tmp;                                                                      \
  })

#define clear_csr(reg, flag)                                                   \
  ({                                                                           \
    uint64_t _tmp;                                                             \
    if (__builtin_constant_p(flag) && (uint64_t)(flag) < 32) {                 \
      asm volatile("csrrc %0, " #reg ", %1" : "=r"(_tmp) : "i"(flag));         \
    } else {                                                                   \
      asm volatile("csrrc %0, " #reg ", %1" : "=r"(_tmp) : "r"(flag));         \
    }                                                                          \
    _tmp;                                                                      \
  })

#define smod_enable_trap (set_csr(sstatus, SSTATUS_SIE))
#define smod_disable_trap (clear_csr(sstatus, SSTATUS_SIE))
// #define smod_enable_trap (write_csr(sstatus, read_csr(sstatus) |
// SSTATUS_SIE))
// #define smod_disable_trap (write_csr(sstatus, read_csr(sstatus) &
// ~SSTATUS_SIE))

// 可能还需要设置spie
#define umod_enable_trap (write_csr(sstatus, read_csr(sstatus) | SSTATUS_UIE))
#define umod_disable_trap (write_csr(sstatus, read_csr(sstatus) & ~SSTATUS_UIE))

#define sret_umod (write_csr(sstatus, read_csr(sstatus) & ~SSTATUS_SPP))
#define sret_smod (write_csr(sstatus, read_csr(sstatus) | SSTATUS_SPP))

typedef union {
    struct {
        uint64_t ppn : 44, asid : 16, mode : 4;
    };
    uint64_t entry;
} satp_t;

#define flush_tlb ({ asm volatile("sfence.vma zero,zero"); })

#endif
