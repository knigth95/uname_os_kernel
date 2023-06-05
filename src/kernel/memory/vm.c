#include "include/vm.h"
#include "include/alloc.h"
#include "include/buddy.h"
#include "include/common.h"
#include "include/extern_symbol.h"
#include "include/log.h"
#include "include/mm.h"
#include "include/page_table.h"
#include "include/platform.h"
#include "include/riscv.h"
#include "include/type.h"
#include "include/virtio.h"

#undef DEBUG

void free_ptp(ptp_t *ptp) {
    pte_t l1;
    l1.pte_entry = 0;
    pte_t l2;
    l2.pte_entry = 0;

    ptp_t *l1_ptp = NULL;

    // 取出一级页表
    for (int i = 0; i < 512; i++) {
        if (ptp->entrys[i].pte_bits.V == 1) {
            // 取出二级页表
            l1 = ptp->entrys[i];
            l1_ptp = pte2ptp(l1);
            for (int j = 0; j < 512; j++) {
                l2 = l1_ptp->entrys[j];
                if (l2.pte_bits.V == 1) {
                    // 释放物理页
                    pfree(pte2paddr(l2));
                    l2.pte_bits.V = 0;
#ifdef DEBUG
                    Debug("free l2 %x", pte2paddr(l2));
#endif
                }
            }
            // 释放一级页
            pfree(pte2paddr(l1));
            l1.pte_bits.V = 0;

#ifdef DEBUG
            Debug("free l1 %x", pte2paddr(l1));
#endif
        }
    }
    // 释放页表
    pfree((uintptr_t)ptp);
#ifdef DEBUG
    Debug("free ptp %x", ptp);
#endif
}

// 分配表项的时候V=1，其他rwx位=0
ptp_t *get_4Kpage_ptp(uintptr_t va, ptp_t *ptp, int alloc) {
    // 预初始化部分变量
    uintptr_t addr = 0;
    pte_t l1;
    l1.pte_entry = 0;
    pte_t l2;
    l2.pte_entry = 0;
    pte_flag_t perm;
    perm.flag = 0;
    perm.flag = perm.flag | FLAG_V;

    // 取出一级页表

    if (ptp->entrys[VADDR(va).vpn2].pte_bits.V == 0) {
        if (alloc == 1) {
            addr = palloc(4096);
            if (addr == NULL) {
                Error("addr null");
                goto err;
            }
            l1 = paddr2pte(addr, perm);
            ptp->entrys[VADDR(va).vpn2] = l1;
        } else {
            Error("goto err %d", alloc);
            goto err;
        }
    } else {
        l1 = ptp->entrys[VADDR(va).vpn2];
    }
#ifdef DEBUG
    Info("l1 %p addr ppn %p entrys %p", l1.pte_entry, VADDR(addr).vpn2,
         ptp->entrys);
#endif

    // 取出二级页表
    if (pte2ptp(l1)->entrys[VADDR(va).vpn1].pte_bits.V == 0) {
        if (alloc == 1) {
            addr = kalloc(4096);
            if (addr == NULL) {
                goto err;
            }

#ifdef DEBUG
            Info("addr %x", addr);
#endif
            l2 = paddr2pte(addr, perm);
            pte2ptp(l1)->entrys[VADDR(va).vpn1] = l2;

#ifdef DEBUG
            Error("ptp addr %x vpn0 %x vpn1 %x vpn2 %x xx alloc addr %lx pte2ptp %x",
                  ptp, VADDR(va).vpn0, VADDR(va).vpn1, VADDR(va).vpn2,
                  pte2paddr(pte2ptp(l1)->entrys[VADDR(va).vpn1]),
                  pte2ptp(l1)->entrys);
#endif

        } else {
#ifdef DEBUG
            Error("goto err vpn1 %x vpn2 %x ptp %x pte2ptp %lx", VADDR(va).vpn1,
                  VADDR(va).vpn2, ptp, pte2ptp(l1)->entrys);
#endif
            goto err;
        }
    } else {
        l2 = pte2ptp(l1)->entrys[VADDR(va).vpn1];
    }

#ifdef DEBUG
    Info("l2 %p addr ppn %p", l2.pte_entry, PADDR(addr).ppn);
#endif
    // 返回取出的二级页表
    return pte2ptp(l2);

err:
    Error("mem end");
    return NULL;
}

// page table entry转page table page
ptp_t *pte2ptp(pte_t pte) {
    paddr ptp_addr = {.ppn = pte.pte_bits.PPN, .offset = 0, .ext = 0};
    return (ptp_t *)ptp_addr.addr;
}

// 物理地址转page table entry
pte_t paddr2pte(uintptr_t addr, pte_flag_t perm) {
    pte_t new_pte;
    new_pte.pte_bits.PPN = PADDR(addr).ppn;
    new_pte.pte_flag = perm.flag;
    return new_pte;
}

uintptr_t pte2paddr(pte_t pte) {
    paddr pa;
    pa.ppn = pte.pte_bits.PPN;
    pa.offset = 0;
    return pa.addr;
}

// 虚拟地址转物理地址
uintptr_t va2pa(ptp_t *page_table, uintptr_t va) {
    paddr addr;
    addr.addr = NULL;

    ptp_t *page_ptp = get_4Kpage_ptp(va, page_table, 0);

    // Info("ptp %p Vflag %d vpn0 %d", page_ptp,
    //      page_ptp->entrys[VADDR(va).vpn0].pte_bits.V, VADDR(va).vpn0);
    if (page_ptp != NULL && page_ptp->entrys[VADDR(va).vpn0].pte_bits.V != 0) {
        addr.ppn = page_ptp->entrys[VADDR(va).vpn0].pte_bits.PPN;
        addr.offset = VADDR(va).offset;
        return addr.addr;
    } else {
        return addr.addr;
    }
}

void vmappage_test() {
    uintptr_t ptp_addr = palloc(4096);
    ptp_t *ptp = (void *)ptp_addr;
    vaddr va;
    va.addr = 0x80201234;
    pte_flag_t flag;
    flag.flag = 1;

    paddr pa = PADDR(palloc(4096 + 4096 + 4096));

    vmappage(ptp, va.addr, pa.addr, 4096 + 4096 + 4096, flag);

    paddr test_pa1 = PADDR(va2pa(ptp, va.addr));
    Info("paddr test %p paddr %p va %p", test_pa1.addr, pa.addr, va.addr);
    va.addr += 4096;
    pa.addr += 4096;
    paddr test_pa2 = PADDR(va2pa(ptp, va.addr));
    Info("paddr test %p paddr %p va %p", test_pa2.addr, pa.addr, va.addr);
    va.addr += 4096;
    pa.addr += 4096;
    paddr test_pa3 = PADDR(va2pa(ptp, va.addr));
    Info("paddr test %p paddr %p va %p", test_pa3.addr, pa.addr, va.addr);

    va.addr -= 4096;
    va.addr -= 4096;
    unvmappage(ptp, va.addr, 4096 + 4096 + 4096);
    Info("unmap");

    test_pa1 = PADDR(va2pa(ptp, va.addr));
    Info("paddr test %p paddr %p va %p", test_pa1.addr, pa.addr, va.addr);
    va.addr += 4096;
    pa.addr += 4096;
    test_pa2 = PADDR(va2pa(ptp, va.addr));
    Info("paddr test %p paddr %p va %p", test_pa2.addr, pa.addr, va.addr);
    va.addr += 4096;
    pa.addr += 4096;
    test_pa3 = PADDR(va2pa(ptp, va.addr));
    Info("paddr test %p paddr %p va %p", test_pa3.addr, pa.addr, va.addr);
}

// vaddr和paddr包装过的映射
int vmappage(ptp_t *page_table, uintptr_t va, uintptr_t pa, uint64_t size,
             pte_flag_t perm) {

    // 对齐地址，对齐页数
#define PAGE_SIZE (4096)
    int page_num =
        size % PAGE_SIZE == 0 ? size / PAGE_SIZE : size / PAGE_SIZE + 1;
    //    Info("palign size %x page num1 %d page num2 %d", align_page_size,
    //    page_num1,
    //         page_num);
    uintptr_t align_va = PALIGN_DOWN(va, PAGE_SIZE);
    uintptr_t align_pa = PALIGN_DOWN(pa, PAGE_SIZE);

#ifdef DEBUG
    Info("ptp %x va %x pa %x page num %d", page_table, align_va, align_pa,
         page_num);
#endif

    ptp_t *page_ptp;

    for (int page_idx = 0; page_idx < page_num;
            page_idx++, align_va += PAGE_SIZE, align_pa += PAGE_SIZE) {
        // 取到4K页的页表
        page_ptp = get_4Kpage_ptp(align_va, page_table, 1);
        if (page_ptp == NULL) {
            Error("map failed page ptp is null");
            return 1;
        }
        // 取出页表项并映射到物理地址
        //        Info("ptp %x page %x", page_table, page_ptp);
        page_ptp->entrys[VADDR(align_va).vpn0] = paddr2pte(align_pa, perm);

#ifdef DEBUG
        Info("paddr %p", paddr2pte(align_pa, perm));
#endif
    }
    return 0;
}

// 直接用pa和va映射
int vmap(uintptr_t ptp, uintptr_t va_start, uintptr_t pa_start, uint64_t size,
         uint8_t flag) {
    vaddr va;
    va.addr = va_start;
    paddr pa;
    pa.addr = pa_start;
    ptp_t *ptp_addr = (void *)ptp;

    pte_flag_t pte_flag;
    pte_flag.flag = flag;

#ifdef DEBUG
    Info("vmap va_start %x pa_start %x", va_start, pa_start);
#endif
    return vmappage(ptp_addr, va.addr, pa.addr, size, pte_flag);
}

// 解除映射
int unvmappage(ptp_t *page_table, uintptr_t va, uint64_t size) {
    // 对齐地址
    int page_num =
        size % PAGE_SIZE == 0 ? size / PAGE_SIZE : size / PAGE_SIZE + 1;
    vaddr align_va;
    align_va.addr = PALIGN_DOWN(va, PAGE_SIZE);

    ptp_t *page_ptp;

    for (int page_idx = 0; page_idx < page_num;
            page_idx++, align_va.addr += PAGE_SIZE) {
        page_ptp = get_4Kpage_ptp(align_va.addr, page_table, 0);
        if (page_ptp == NULL) {
            Error("unmap failed ptp is null");
            return 1;
        }
        page_ptp->entrys[VADDR(va).vpn0].pte_bits.V = 0;
    }
    return 0;
}

// 内核地址映射
void kvmmap(uintptr_t ptp_addr) {
    vaddr va;
    paddr pa;
    uint64_t size;
    pte_flag_t flag;
    ptp_t *kptp = (void *)PADDR(ptp_addr).addr;

    // text r-x
    va.addr = (uint64_t)s_text;
    pa.addr = (uint64_t)s_text;
    size = (uint64_t)e_text - (uint64_t)s_text;
    flag.flag = FLAG_V | FLAG_X | FLAG_R;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap text seg start %p end %p size %d va %p -> pa %p", s_text, e_text,
         size, va.addr, va2pa(kptp, va.addr));

    // rodata r--
    va.addr = (uint64_t)s_rodata;
    pa.addr = (uint64_t)s_rodata;
    size = (uint64_t)e_rodata - (uint64_t)s_rodata;
    flag.flag = FLAG_V | FLAG_R;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap rodata seg start %p end %p size %d va %p -> pa %p", s_rodata,
         e_rodata, size, va.addr, va2pa(kptp, va.addr));

    // data rw-
    va.addr = (uint64_t)s_data;
    pa.addr = (uint64_t)s_data;
    size = (uint64_t)e_data - (uint64_t)s_data;
    flag.flag = FLAG_V | FLAG_R | FLAG_W;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap data seg start %p end %p size %d va %p -> pa %p", s_data, e_data,
         size, va.addr, va2pa(kptp, va.addr));

    // bss rw-
    va.addr = (uint64_t)e_data;
    pa.addr = (uint64_t)e_data;
    size = (uint64_t)e_bss - (uint64_t)e_data;
    flag.flag = FLAG_V | FLAG_R | FLAG_W;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap bss seg start %p end %p size %d va %p -> pa %p", e_data, e_bss,
         size, va.addr, va2pa(kptp, va.addr));
}

void kvmmap_mem_pool(uintptr_t ptp_addr, mem_pool_t *mem) {
    uintptr_t va = (uintptr_t)mem->meta_data_start;
    uintptr_t pa = (uintptr_t)mem->meta_data_start;
    uint64_t size = mem->meta_data_size;
    pte_flag_t flag;
    ptp_t *kptp = (void *)PADDR(ptp_addr).addr;
    flag.flag = FLAG_R | FLAG_W | FLAG_X | FLAG_V;
    vmappage(kptp, va, pa, size, flag);
    Info("vmmap metadata seg start %p end %p size %x va %p -> pa %p", va,
         mem->meta_data_end, size, va, va2pa(kptp, va));

    // 不这样做的话，虚拟页表永远无法映射，会导致虚拟页永远无法用
    // 但是对于用户程序的话，没有必要映射页表，也没法映射页表
    va = (uintptr_t)mem->data_start;
    pa = (uintptr_t)mem->data_start;
    size = mem->mem_size;
    vmappage(kptp, va, pa, size, flag);
    Info("vmmap alldata seg start %p end %p size %x va %p -> pa %p", va,
         va + size, size, va, va2pa(kptp, va));
}

void kvmmap_virtio_mmio(uintptr_t ptp_addr) {
    pte_flag_t flag;
    flag.flag = FLAG_R | FLAG_W | FLAG_X | FLAG_V;
    vmappage((void *)ptp_addr, VIRTIO_REG_BASE, VIRTIO_REG_BASE, 8192, flag);
}

void kvmmap_plic(uintptr_t ptp_addr) {
    pte_flag_t flag;
    flag.flag = FLAG_R | FLAG_W | FLAG_V;
    vmappage((void *)ptp_addr, PLIC_BASE_ADDRESS, PLIC_BASE_ADDRESS, 0x6000,
             flag);

    vmappage((void *)ptp_addr, PLIC_BASE_ADDRESS + 0x200000,
             PLIC_BASE_ADDRESS + 0x200000, 0x6000, flag);
}

void kvmmap_uart(uintptr_t ptp_addr) {
    pte_flag_t flag;
    flag.flag = FLAG_R | FLAG_W | FLAG_V;
    vmappage((void *)ptp_addr, UART0_ADDRESS, UART0_ADDRESS, PAGE_SIZE, flag);
}

void map_trap(uintptr_t ptp_addr) {
    uintptr_t va;
    uintptr_t pa;
    uint64_t size;
    pte_flag_t flag;

    // text r-x
    va = (uint64_t)s_tramponline;
    pa = (uint64_t)s_tramponline;
    size = (uint64_t)e_tramponline - (uint64_t)s_tramponline;
    flag.flag = FLAG_V | FLAG_X | FLAG_R;
    vmappage((void *)ptp_addr, va, pa, size, flag);
#ifdef DEBUG
    Info("vmmap trap seg start %p end %p size %d va %p -> pa %p", s_tramponline,
         e_tramponline, size, va, va2pa((void *)ptp_addr, va));
#endif
}

void map_kernel(uintptr_t ptp_addr, mem_pool_t *mem) {

    kvmmap(ptp_addr);
    kvmmap_mem_pool(ptp_addr, mem);
    kvmmap_virtio_mmio(ptp_addr);
    kvmmap_plic(ptp_addr);
    kvmmap_uart(ptp_addr);
}

// 刷新页表
void flush_satp(uintptr_t ptp_addr) {
    satp_t ksatp;
    ksatp.ppn = PADDR(ptp_addr).ppn;
    ksatp.mode = 8;
    Info("ksatp %p", ksatp.entry);

    write_csr(satp, ksatp.entry);
    flush_tlb;
}

// 分配一个空的页表
uint64_t alloc_satp() {
    satp_t satp;
    uintptr_t satp_page = page4K_alloc();
    satp.ppn = PADDR(satp_page).ppn;
    satp.mode = 9;
    return satp.entry;
}

// satp 转pa
uintptr_t satp2pa(satp_t satp) {
    paddr pa;
    pa.ppn = satp.ppn;
    pa.offset = 0;
    return pa.addr;
}

uint64_t pa2satp(uintptr_t pa) {
    satp_t satp;
    satp.ppn = PADDR(pa).ppn;
    satp.mode = 8;
    return satp.entry;
}

// 映射dtb
void map_dtb(uintptr_t page_table, uint64_t dtb_pa) {
    vmap(page_table, dtb_pa, dtb_pa, 8192, FLAG_V | FLAG_W | FLAG_R);
}
