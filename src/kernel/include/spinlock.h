#ifndef __SPIN_LOCK__
#define __SPIN_LOCK__

#include "type.h"

struct cpu;

struct spinlock {
    uint32_t locked;
    char *name;
    struct cpu *cpu;
};

#endif
