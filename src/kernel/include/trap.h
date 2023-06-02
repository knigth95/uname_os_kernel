#ifndef __TRAP_H__
#define __TRAP_H__

#include "type.h"

#define NORMAL_REG_NUM 32

// struct NormalRegs {
//     uint64_t reg[NORMAL_REG_NUM];
// };

union NormalRegs {
    uint64_t reg[NORMAL_REG_NUM];
    struct {
        uint64_t zero; // 0
        uint64_t ra;   // 1
        uint64_t sp;   // 2
        uint64_t gp;   // 3
        uint64_t tp;   // 4

        uint64_t t0; // 5
        uint64_t t1; // 6
        uint64_t t2; // 7
        uint64_t fp; // 8
        uint64_t s1; // 9

        uint64_t a0; // 10
        uint64_t a1; // 11
        uint64_t a2; // 12
        uint64_t a3; // 13
        uint64_t a4; // 14
        uint64_t a5; // 15
        uint64_t a6; // 16
        uint64_t a7; // 17

        uint64_t s2;  // 18
        uint64_t s3;  // 19
        uint64_t s4;  // 20
        uint64_t s5;  // 21
        uint64_t s6;  // 22
        uint64_t s7;  // 23
        uint64_t s8;  // 24
        uint64_t s9;  // 25
        uint64_t s10; // 26
        uint64_t s11; // 27

        uint64_t t3; // 28
        uint64_t t4; // 29
        uint64_t t5; // 30
        uint64_t t6; // 31
    };
};

struct CsrRegs {
    uint64_t sstatus;
    uint64_t sepc;
    uint64_t sscratch;
    uint64_t satp;
};

struct Regs {
    union NormalRegs normal_regs;
    struct CsrRegs csr_regs;
};

union Contect {
    uint64_t reg[NORMAL_REG_NUM + 4];
    struct {
        union NormalRegs normal_regs;
        struct CsrRegs csr_regs;
    };
};

struct TrapTagJumpTable {
    void *(*func)(struct Regs *regs, const char *name);
    const char *name;
};

void init_trap();
void info_registers(const struct Regs *regs);
#endif
