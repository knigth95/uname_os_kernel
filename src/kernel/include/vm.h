#ifndef __VM_H__
#define __VM_H__
#include "include/mm.h"
#include "include/page_table.h"
#include "include/riscv.h"
#include "include/type.h"

pte_t paddr2pte(uintptr_t addr, pte_flag_t perm);
uintptr_t pte2paddr(pte_t pte);

ptp_t *pte2ptp(pte_t pte);

// int pa2va(vaddr va, ptp_t *ptp, paddr pa, int alloc, pte_flag_t perm);
uintptr_t va2pa(ptp_t *page_table, uintptr_t va);

int vmappage(ptp_t *page_table, uintptr_t va, uintptr_t pa, uint64_t size,
             pte_flag_t perm);
int unvmappage(ptp_t *page_table, uintptr_t va, uint64_t size);

void vmappage_test();

// TODO:可以考虑直接inline
void kvmmap(uintptr_t ptp_addr);

// TODO:可以考虑直接inline
void kvmmap_mem_pool(uintptr_t ptp_addr, mem_pool_t *mem);

void map_trap(uintptr_t ptp_addr);
void map_kernel(uintptr_t ptp_addr, mem_pool_t *mem);

void flush_satp(uintptr_t ptp_addr);

int vmap(uintptr_t ptp, uintptr_t va_start, uintptr_t pa_start, uint64_t size,
         uint8_t flag);

void map_dtb(uintptr_t page_table, uint64_t dtb_pa);

uint64_t alloc_satp();

uintptr_t satp2pa(satp_t satp);
uint64_t pa2satp(uintptr_t pa);

void free_ptp(ptp_t *ptp);
#endif
