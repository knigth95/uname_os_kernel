#ifndef __PAGE_TABLE_H__
#define __PAGE_TABLE_H__

#define PTE_NUM 512

#include "type.h"

typedef struct {
    uint64_t flag : 8, NONE : 54;
} pte_flag_t;

// page table entry
typedef union {
    struct {
        uint64_t V : 1, R : 1, W : 1, X : 1, U : 1, G : 1, A : 1, D : 1, RSW : 2,
                 PPN0 : 9, PPN1 : 9, PPN2 : 26, RESERVED : 10;
    } pte_ppn;
    struct {
        uint64_t V : 1, R : 1, W : 1, X : 1, U : 1, G : 1, A : 1, D : 1, RSW : 2,
                 PPN : 44, RESERVED : 10;
    } pte_bits;
    struct {
        uint64_t pte_flag : 8, N : 56;
    };
    struct {
        uint64_t pte_entry : 64;
    };
} pte_t;

#define PN_MASK 0x1FF
#define OFFSET_MASK 0x1FFF
// 自satp中找到根页表所在页 root page
// 在页中通过virt vpn2找到一级页表页号，通过root page + vpn0找到表项
// 取出表项中的ppn 作为下一级页表地址page 2，根据vpn1 + page2
// 找到下一级页表项取出表地址page 3 根据page3 + vpn0 得到ppn 作为物理地址ppn 与
// virt_addr中的offset相加的到paddr

// 向align倍数方向增大为up
#define PALIGN_UP(x, align) (((x) + (align)-1) & ~((align)-1))
// 不足align的舍去为down
#define PALIGN_DOWN(x, align) ((x) & ~((align)-1))

#define FLAG_V (1 << 0)
#define FLAG_R (1 << 1)
#define FLAG_W (1 << 2)
#define FLAG_X (1 << 3)
#define FLAG_U (1 << 4)
#define FLAG_G (1 << 5)
#define FLAG_A (1 << 6)
#define FLAG_D (1 << 7)

typedef struct {
    pte_t entrys[PTE_NUM]; // 8*512=4096
} ptp_t;
// page table page

#endif
