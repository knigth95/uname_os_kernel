#ifndef __TYPE_H__
#define __TYPE_H__

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef int int32_t;

typedef unsigned long int uintptr_t;
typedef long int intptr_t;

typedef union {
    struct {
        uint64_t offset : 12, ppn : 44, ext : 8;
    };
    uint64_t addr : 64;
} paddr;

#define PADDR(addr) ((paddr)addr)
typedef union {
    struct {
        uint64_t offset : 12, vpn0 : 9, vpn1 : 9, vpn2 : 9, ext : 25;
    };
    uint64_t addr : 64;
} vaddr;
#define VADDR(addr) ((vaddr)addr)

#define NULL 0

#endif
